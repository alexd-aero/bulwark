// Telling others.
//
// Vendors: an address Bulwark banned for what it did here (payloads, a
// campaign, or one you report by hand) is reported to every vendor that takes
// reports and is set up, with the request lines as evidence (never your host
// names). Only evidence from here goes out: an address banned for being on a
// list is already known.
//
//   AbuseIPDB     a free API key (abuseipdb.com/account/api). Checked first, and
//                 reported when it has no fresh report or a low score. Free tier:
//                 1000 checks and 1000 reports a day, kept under 900
//   blocklist.de  a free account for your server (blocklist.de/en/register.html):
//                 its e-mail and API key. Its lists feed FireHOL, fail2ban users
//                 and others, so a report there reaches many firewalls
//
// Until a vendor is set up, what would have gone out waits (the last 1000
// addresses, a week), and goes out once one is: nothing is lost by adding the
// key later. Turning a vendor on also offers the bans it never heard of.
//
// Alerts: waves go to ntfy (a topic URL) and/or a webhook (JSON POST), if set.

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { categoryOf } from "./payloads.mjs";
import { abuseCategories, categoryById } from "./taxonomy.mjs";

const DAY = 86400e3;
const SOURCES = ["payload", "campaign", "manual-report"];
// AbuseIPDB categories (abuseipdb.com/categories), from what the address did:
// each signature's category maps to them (taxonomy.mjs)
export function categories(sigs) {
  return abuseCategories(sigs.map((s) => categoryOf(s)).filter(Boolean));
}
const catNames = (sigs) => [...new Set(sigs.map((s) => categoryById(categoryOf(s))?.name).filter(Boolean))].slice(0, 4);
// blocklist.de sorts reports by service (blocklist.de/en/httpreports.html)
export function blocklistdeService(sigs) {
  const cats = new Set(sigs.map((s) => categoryOf(s)));
  if (cats.has("sqli")) return "sql-injection";
  if (cats.has("bruteforce")) return [...sigs].some((s) => s === "wordpress") ? "wp-bruteforce" : "nginx-http-auth";
  if (cats.has("traversal") || cats.has("rce") || cats.has("cve") || cats.has("webshell") || cats.has("iot") || cats.has("log4shell") || cats.has("ssti") || cats.has("deser")) return "rfi-attack";
  if (cats.has("dos")) return "apacheddos";
  if (cats.size && [...cats].every((c) => c === "bot" || c === "recon")) return "badbot";
  return "phpids";
}
const clean = (reason) => String(reason || "web attack").replace(/\b[\w.-]+\.(?:dev|com|net|org|io|top|app|me|xyz|site|online|cloud|tech)\b/gi, "[host]");
const evidenceLines = (ev) => [...new Set(ev.lines || [])].slice(0, 8).map((l) => l.replace(/[\r\n]+/g, " ").slice(0, 150));

export const VENDORS = [
  { id: "abuseipdb", name: "AbuseIPDB", url: "https://www.abuseipdb.com/account/api", needs: "an API key", ready: (s) => !!s.abuseipdbKey },
  { id: "blocklistde", name: "blocklist.de", url: "https://www.blocklist.de/en/register.html", needs: "a server e-mail and API key", ready: (s) => !!(s.blocklistdeEmail && s.blocklistdeKey) },
];

export class Reporters {
  constructor({ file, log, settings, fetchImpl }) {
    this.file = file; this.log = log || console.log;
    this.settings = settings;                 // () => {abuseipdbKey, blocklistdeEmail, blocklistdeKey, ntfy, webhook, report}
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.state = { reported: {}, checks: {}, day: "", used: { check: 0, report: 0, blocklistde: 0 }, log: [], waiting: [], vendor: {} };
    try { this.state = { ...this.state, ...JSON.parse(readFileSync(file, "utf8")) }; } catch { /* first run */ }
    this.state.waiting ||= []; this.state.vendor ||= {}; this.state.used.blocklistde ||= 0;
    for (const r of Object.values(this.state.reported)) if (Array.isArray(r.vendors)) r.vendors = { abuseipdb: r.at };      // 1.9 kept names in a list
    this.queue = []; this.busy = false; this.gap = 1500;
  }
  save() {
    const cut = Date.now() - 30 * DAY;
    for (const [ip, r] of Object.entries(this.state.reported)) if (r.at < cut) delete this.state.reported[ip];
    for (const [ip, r] of Object.entries(this.state.checks)) if (r.at < cut) delete this.state.checks[ip];
    this.state.waiting = this.state.waiting.filter((w) => w.queued > Date.now() - 7 * DAY).slice(-1000);
    this.state.log = this.state.log.slice(0, 300);
    try { writeFileSync(this.file + ".tmp", JSON.stringify(this.state)); renameSync(this.file + ".tmp", this.file); } catch { /* next time */ }
  }
  budget(kind) {
    const d = new Date().toISOString().slice(0, 10);
    if (this.state.day !== d) { this.state.day = d; this.state.used = { check: 0, report: 0, blocklistde: 0 }; }
    return (this.state.used[kind] || 0) < 900;
  }
  note(entry) { this.state.log.unshift({ at: Date.now(), ...entry }); if (this.state.log.length > 400) this.state.log.length = 300; }
  ready() { const s = this.settings(); return VENDORS.filter((v) => v.ready(s)); }
  // which vendors still need this address (each one reported at most once a week)
  missing(ip) {
    const r = this.state.reported[ip];
    return this.ready().filter((v) => !(r?.vendors?.[v.id] && Date.now() - r.vendors[v.id] < 7 * DAY));
  }

  // ------------------------------------------------------------ vendors
  // ev: {ip, reason, source, sigs: [ids], lines: ["GET /.env", ...], first, last}
  // -> {queued: bool, why}: what happened, for the dashboard to say
  enqueue(ev) {
    const s = this.settings();
    if (!SOURCES.includes(ev.source)) return { queued: false, why: "only addresses banned for what they did here are reported" };
    if (s.report === false && ev.source !== "manual-report") return { queued: false, why: "reporting is off" };
    if (!(ev.lines || []).length && !(ev.sigs || []).length) return { queued: false, why: "no evidence on record" };
    const item = { ip: ev.ip, reason: clean(ev.reason), source: ev.source, sigs: (ev.sigs || []).slice(0, 12), lines: evidenceLines(ev), first: ev.first || null, last: ev.last || Date.now(), queued: Date.now() };
    if (!this.ready().length) {
      // nobody to tell yet: kept for when a vendor is set up
      const w = this.state.waiting;
      const i = w.findIndex((x) => x.ip === ev.ip);
      if (i >= 0) w.splice(i, 1);
      w.push(item);
      if (w.length > 1000) w.splice(0, w.length - 1000);
      return { queued: false, waiting: true, why: "no vendor is set up yet: it waits, and goes out when you add a key" };
    }
    const need = this.missing(ev.ip);
    if (!need.length) return { queued: false, why: "already reported this week" };
    if (this.queue.some((q) => q.ip === ev.ip)) return { queued: true, why: "already in line" };
    if (this.queue.length >= 1000) { this.state.waiting.push(item); return { queued: false, waiting: true, why: "the line is full: it waits" }; }
    this.queue.push(item);
    this.pump();
    return { queued: true, why: `in line for ${need.map((v) => v.name).join(" and ")}` };
  }
  // a vendor was set up (or reporting turned back on): what waited goes out, and the
  // bans it never heard of are offered too (bans: [{ip, reason, source, lines, sigs, at}])
  resume(bans = []) {
    if (!this.ready().length) return 0;
    const items = this.state.waiting.splice(0);
    const seen = new Set(items.map((x) => x.ip));
    for (const b of bans) if (!seen.has(b.ip) && SOURCES.includes(b.source) && (b.at || 0) > Date.now() - 7 * DAY && (b.lines?.length || b.sigs?.length)) items.push({ ...b, last: b.at });
    let n = 0;
    for (const it of items) if (this.enqueue(it).queued) n++;
    if (n) this.note({ ip: "", vendor: this.ready().map((v) => v.name).join(", "), ok: true, why: `${n} address${n === 1 ? "" : "es"} sent to report` });
    return n;
  }
  async pump() {
    if (this.busy) return;
    this.busy = true;
    try {
      while (this.queue.length) {
        const ev = this.queue.shift();
        for (const v of this.missing(ev.ip)) {
          try { await this[v.id](ev); this.vendorOk(v.id); }
          catch (e) {
            this.vendorFail(v.id, e.message);
            this.note({ ip: ev.ip, vendor: v.name, ok: false, why: e.message });
            if (/rate-limited|allowance|HTTP 5\d\d|timeout|fetch failed/i.test(e.message) && this.state.waiting.length < 1000) this.state.waiting.push(ev);     // try again later
          }
        }
        await new Promise((r) => setTimeout(r, this.gap));          // gentle
      }
    } finally { this.busy = false; }
  }
  vendorOk(id) { (this.state.vendor[id] ||= {}).ok = Date.now(); this.state.vendor[id].error = null; }
  vendorFail(id, why) { const v = (this.state.vendor[id] ||= {}); v.failed = Date.now(); v.error = String(why).slice(0, 200); }
  done(ip, vendor, extra = {}) {
    const r = (this.state.reported[ip] ||= { at: Date.now(), vendors: {} });
    r.at = Date.now(); r.vendors ||= {}; r.vendors[vendor] = Date.now();
    Object.assign(r, extra);
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
      if (r.status === 401 || r.status === 403) throw new Error("AbuseIPDB refused the key (check it in Vendors)");
      if (!r.ok) throw new Error(`check: HTTP ${r.status}`);
      const d = (await r.json()).data || {};
      known = this.state.checks[ev.ip] = { at: Date.now(), score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0, last: d.lastReportedAt || null };
    }
    const fresh = known.last && Date.now() - Date.parse(known.last) < 7 * DAY;
    if (fresh && known.score >= 50) { this.done(ev.ip, "abuseipdb", { score: known.score }); this.note({ ip: ev.ip, vendor: "AbuseIPDB", ok: true, skipped: true, why: `already known (score ${known.score}, ${known.reports} reports)` }); return; }
    if (!this.budget("report")) throw new Error("daily report allowance used up");
    const lines = evidenceLines(ev), kinds = catNames(ev.sigs || []);
    const comment = `Web attack seen by Bulwark${kinds.length ? ` (${kinds.join(", ")})` : ""}: ${clean(ev.reason)}. Requests: ${lines.join(" | ")}`.slice(0, 1000);
    const body = new URLSearchParams({ ip: ev.ip, categories: categories(ev.sigs || []).join(","), comment, timestamp: new Date(ev.last || Date.now()).toISOString() });
    const r = await this.fetch("https://api.abuseipdb.com/api/v2/report", { method: "POST", headers: { ...H, "Content-Type": "application/x-www-form-urlencoded" }, body, signal: AbortSignal.timeout(15000) });
    this.state.used.report++;
    const j = await r.json().catch(() => ({}));
    if (r.status === 429) throw new Error(/once every 15 minutes/i.test(j.errors?.[0]?.detail || "") ? "AbuseIPDB: already reported in the last 15 minutes" : "rate-limited");
    if (!r.ok) throw new Error(j.errors?.[0]?.detail || `report: HTTP ${r.status}`);
    this.done(ev.ip, "abuseipdb", { score: j.data?.abuseConfidenceScore ?? null });
    this.note({ ip: ev.ip, vendor: "AbuseIPDB", ok: true, why: `reported (now score ${j.data?.abuseConfidenceScore ?? "?"})` });
  }
  async blocklistde(ev) {
    const s = this.settings();
    if (!s.blocklistdeEmail || !s.blocklistdeKey) return;
    if (!this.budget("blocklistde")) throw new Error("daily allowance used up");
    const service = blocklistdeService(ev.sigs || []);
    const logs = `${new Date(ev.last || Date.now()).toISOString()} ${ev.ip} ${clean(ev.reason)}\n${evidenceLines(ev).map((l) => `${ev.ip} - - "${l} HTTP/1.1"`).join("\n")}`.slice(0, 4000);
    const body = new URLSearchParams({ server: s.blocklistdeEmail, apikey: s.blocklistdeKey, ip: ev.ip, service, format: "text", logs });
    const r = await this.fetch("https://www.blocklist.de/en/httpreports.html", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Bulwark (+https://github.com/alexd-aero/bulwark)" }, body, signal: AbortSignal.timeout(20000) });
    this.state.used.blocklistde++;
    const text = (await r.text().catch(() => "")).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    if (!r.ok) throw new Error(`blocklist.de: HTTP ${r.status}`);
    if (/wrong|invalid|error|not (found|allowed|valid)|falsch|fehler/i.test(text) && !/success|thank|danke|added|eingetragen/i.test(text)) throw new Error(`blocklist.de: ${text.slice(0, 140) || "refused"}`);
    this.done(ev.ip, "blocklistde");
    this.note({ ip: ev.ip, vendor: "blocklist.de", ok: true, why: `reported as ${service}` });
  }
  // is the AbuseIPDB key good? (one check of a documentation address)
  async testAbuseipdb() {
    const key = this.settings().abuseipdbKey;
    if (!key) throw new Error("No AbuseIPDB key is set.");
    const r = await this.fetch("https://api.abuseipdb.com/api/v2/check?ipAddress=192.0.2.1&maxAgeInDays=1", { headers: { Key: key, Accept: "application/json" }, signal: AbortSignal.timeout(15000) });
    this.state.used.check++;
    if (r.status === 401 || r.status === 403) { this.vendorFail("abuseipdb", "the key was refused"); throw new Error("AbuseIPDB refused this key."); }
    if (!r.ok) throw new Error(`AbuseIPDB answered HTTP ${r.status}.`);
    this.vendorOk("abuseipdb");
    return { ok: true, limit: r.headers.get?.("x-ratelimit-limit") || null, remaining: r.headers.get?.("x-ratelimit-remaining") || null };
  }

  // which vendors know an address: from the lists, the last lookup, AbuseIPDB's check
  coverage(ip, lists = [], intel = null) {
    const out = [];
    const listed = new Set(lists.map((l) => l.id));
    const add = (vendor, knows, how, reportable = false) => out.push({ vendor, knows, how, reportable });
    add("FireHOL", listed.has("firehol1") || listed.has("firehol2") || listed.has("firehol3"), "list");
    const mine = this.state.reported[ip]?.vendors || {};
    add("blocklist.de", listed.has("blocklistde") || !!mine.blocklistde, mine.blocklistde ? `reported by you ${new Date(mine.blocklistde).toLocaleDateString()}` : "list", true);
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
    const s = this.settings();
    return { used: this.state.used, day: this.state.day, queue: this.queue.length, waiting: this.state.waiting.length, log: this.state.log.slice(0, 100),
             reported: Object.keys(this.state.reported).length,
             vendors: VENDORS.map((v) => ({ id: v.id, name: v.name, url: v.url, needs: v.needs, ready: v.ready(s), ok: this.state.vendor[v.id]?.ok || null, failed: this.state.vendor[v.id]?.failed || null,
                                           error: this.state.vendor[v.id]?.error || null, used: v.id === "abuseipdb" ? this.state.used.report || 0 : this.state.used[v.id] || 0,
                                           reported: Object.values(this.state.reported).filter((r) => r.vendors?.[v.id]).length })) };
  }
}
