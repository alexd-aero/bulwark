// Telling others.
//
// Vendors: an address Bulwark banned for what it did here (payloads, a
// campaign) is checked against every vendor we can see (the lists, Spamhaus,
// DroneBL, GreyNoise, StopForumSpam, AbuseIPDB), and reported to those that
// take reports and missed it. Only evidence from here goes out: an address
// banned for being on a list is already known. Comments carry the request
// lines, never your host names.
//
//   AbuseIPDB   needs a free API key (abuseipdb.com/account/api); checked first,
//               reported when it has no report from the last week or a low score;
//               free tier: 1000 checks and 1000 reports a day, kept under 900
//
// Alerts: waves go to ntfy (a topic URL) and/or a webhook (JSON POST), if set.

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { categoryOf } from "./payloads.mjs";
import { abuseCategories, categoryById } from "./taxonomy.mjs";

const DAY = 86400e3;
// AbuseIPDB categories (abuseipdb.com/categories), from what the address did:
// each signature's category maps to them (taxonomy.mjs)
export function categories(sigs) {
  return abuseCategories(sigs.map((s) => categoryOf(s)).filter(Boolean));
}
const catNames = (sigs) => [...new Set(sigs.map((s) => categoryById(categoryOf(s))?.name).filter(Boolean))].slice(0, 4);

export class Reporters {
  constructor({ file, log, settings, fetchImpl }) {
    this.file = file; this.log = log || console.log;
    this.settings = settings;                 // () => {abuseipdbKey, ntfy, webhook, report}
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.state = { reported: {}, checks: {}, day: "", used: { check: 0, report: 0 }, log: [] };
    try { this.state = { ...this.state, ...JSON.parse(readFileSync(file, "utf8")) }; } catch { /* first run */ }
    this.queue = []; this.busy = false;
  }
  save() {
    const cut = Date.now() - 30 * DAY;
    for (const [ip, r] of Object.entries(this.state.reported)) if (r.at < cut) delete this.state.reported[ip];
    for (const [ip, r] of Object.entries(this.state.checks)) if (r.at < cut) delete this.state.checks[ip];
    this.state.log = this.state.log.slice(0, 300);
    try { writeFileSync(this.file + ".tmp", JSON.stringify(this.state)); renameSync(this.file + ".tmp", this.file); } catch { /* next time */ }
  }
  budget(kind) {
    const d = new Date().toISOString().slice(0, 10);
    if (this.state.day !== d) { this.state.day = d; this.state.used = { check: 0, report: 0 }; }
    return this.state.used[kind] < 900;
  }
  note(entry) { this.state.log.unshift({ at: Date.now(), ...entry }); }

  // ------------------------------------------------------------ vendors
  // ev: {ip, reason, source, sigs: [ids], lines: ["GET /.env", ...], first, last}
  enqueue(ev) {
    const s = this.settings();
    if (s.report === false || !["payload", "campaign", "manual-report"].includes(ev.source)) return;
    if (this.state.reported[ev.ip] && Date.now() - this.state.reported[ev.ip].at < 7 * DAY) return;
    if (this.queue.length < 1000 && !this.queue.some((q) => q.ip === ev.ip)) this.queue.push(ev);
    this.pump();
  }
  async pump() {
    if (this.busy) return;
    this.busy = true;
    try {
      while (this.queue.length) {
        const ev = this.queue.shift();
        await this.abuseipdb(ev).catch((e) => this.note({ ip: ev.ip, vendor: "AbuseIPDB", ok: false, why: e.message }));
        await new Promise((r) => setTimeout(r, 1500));          // gentle
      }
    } finally { this.busy = false; }
  }
  async abuseipdb(ev) {
    const key = this.settings().abuseipdbKey;
    if (!key) return;
    const H = { Key: key, Accept: "application/json" };
    let known = this.state.checks[ev.ip];
    if (!known || Date.now() - known.at > DAY) {
      if (!this.budget("check")) throw new Error("daily check allowance used up");
      const r = await this.fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ev.ip)}&maxAgeInDays=30`, { headers: H, signal: AbortSignal.timeout(15000) });
      this.state.used.check++;
      if (r.status === 429) throw new Error("rate-limited");
      if (!r.ok) throw new Error(`check: HTTP ${r.status}`);
      const d = (await r.json()).data || {};
      known = this.state.checks[ev.ip] = { at: Date.now(), score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0, last: d.lastReportedAt || null };
    }
    const fresh = known.last && Date.now() - Date.parse(known.last) < 7 * DAY;
    if (fresh && known.score >= 50) { this.note({ ip: ev.ip, vendor: "AbuseIPDB", ok: true, skipped: true, why: `already known (score ${known.score}, ${known.reports} reports)` }); return; }
    if (!this.budget("report")) throw new Error("daily report allowance used up");
    const lines = [...new Set(ev.lines || [])].slice(0, 6).map((l) => l.replace(/[\r\n]+/g, " ").slice(0, 150));
    const kinds = catNames(ev.sigs || []);
    const comment = `Web attack seen by Bulwark${kinds.length ? ` (${kinds.join(", ")})` : ""}: ${ev.reason.replace(/\b[\w.-]+\.(?:dev|com|net|org|io|top|app)\b/gi, "[host]")}. Requests: ${lines.join(" | ")}`.slice(0, 1000);
    const body = new URLSearchParams({ ip: ev.ip, categories: categories(ev.sigs || []).join(","), comment, timestamp: new Date(ev.last || Date.now()).toISOString() });
    const r = await this.fetch("https://api.abuseipdb.com/api/v2/report", { method: "POST", headers: { ...H, "Content-Type": "application/x-www-form-urlencoded" }, body, signal: AbortSignal.timeout(15000) });
    this.state.used.report++;
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.errors?.[0]?.detail || `report: HTTP ${r.status}`);
    this.state.reported[ev.ip] = { at: Date.now(), vendors: ["AbuseIPDB"], score: j.data?.abuseConfidenceScore ?? null };
    this.note({ ip: ev.ip, vendor: "AbuseIPDB", ok: true, why: `reported (now score ${j.data?.abuseConfidenceScore ?? "?"})` });
  }

  // which vendors know an address: from the lists, the last lookup, AbuseIPDB's check
  coverage(ip, lists = [], intel = null) {
    const out = [];
    const listed = new Set(lists.map((l) => l.id));
    const add = (vendor, knows, how, reportable = false) => out.push({ vendor, knows, how, reportable });
    add("FireHOL", listed.has("firehol1") || listed.has("firehol2") || listed.has("firehol3"), "list");
    add("blocklist.de", listed.has("blocklistde"), "list");
    add("CINS Army", listed.has("cins"), "list");
    add("Emerging Threats", listed.has("et"), "list");
    add("GreenSnow", listed.has("greensnow"), "list");
    add("IPsum", listed.has("ipsum"), "list");
    add("elsnet", listed.has("elsnet"), "list");
    const d = intel?.sources?.dnsbl?.result || {};
    if (intel) {
      add("Spamhaus", !!d.spamhaus?.listed, "DNS");
      add("DroneBL", !!d.dronebl?.listed, "DNS");
      const g = intel.sources?.greynoise?.result;
      if (g) add("GreyNoise", !!(g.seen && (g.scanner || g.classification === "malicious")), "API");
      const sfs = intel.sources?.sfs?.result;
      if (sfs) add("StopForumSpam", sfs.reports > 0, "API");
    }
    const c = this.state.checks[ip], rep = this.state.reported[ip];
    add("AbuseIPDB", !!(c && c.reports > 0) || !!rep, rep ? `reported by you ${new Date(rep.at).toLocaleDateString()}` : c ? `score ${c.score}, ${c.reports} reports` : "not checked", true);
    return out;
  }

  // ------------------------------------------------------------ alerts out
  async notify(alert, change) {
    const s = this.settings();
    if (!s.ntfy && !s.webhook) return;
    // a wave raises an alert per /24: at most 6 go out a minute (20 critical), the rest are counted into the next one
    const now = Date.now();
    if (now - (this.sentWindow || 0) > 60e3) { this.sentWindow = now; this.sentCount = 0; }
    if (++this.sentCount > (alert.sev === "critical" ? 20 : 6)) { this.heldBack = (this.heldBack || 0) + 1; return; }
    const held = this.heldBack || 0; this.heldBack = 0;
    const title = `Bulwark ${alert.sev === "critical" ? "CRITICAL" : alert.sev}: ${alert.title}`;
    const text = `${held ? `(${held} more alert${held === 1 ? "" : "s"} held back in the last minute - see the dashboard)\n` : ""}${alert.detail}${alert.members?.length ? `\n${alert.members.length} addresses: ${alert.members.slice(0, 8).join(", ")}${alert.members.length > 8 ? "…" : ""}` : ""}${alert.forecast ? `\nForecast: ~${alert.forecast.nextHour} more in the next hour (${alert.forecast.trend})` : ""}`;
    const jobs = [];
    if (s.ntfy && /^https:\/\//.test(s.ntfy) && alert.sev !== "info" && change !== "closed") {
      jobs.push(this.fetch(s.ntfy, { method: "POST", body: text, headers: { Title: title, Priority: alert.sev === "critical" ? "urgent" : "default", Tags: "shield" }, signal: AbortSignal.timeout(10000) }));
    }
    if (s.webhook && /^https?:\/\//.test(s.webhook)) {
      jobs.push(this.fetch(s.webhook, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ change, title, text, alert: { ...alert, arrivals: undefined } }), signal: AbortSignal.timeout(10000) }));
    }
    const r = await Promise.allSettled(jobs);
    for (const x of r) if (x.status === "rejected") this.log("notify:", x.reason?.message);
  }
  view() {
    return { used: this.state.used, day: this.state.day, queue: this.queue.length, log: this.state.log.slice(0, 100),
             reported: Object.keys(this.state.reported).length };
  }
}
