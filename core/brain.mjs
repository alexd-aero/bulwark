// The app's brain: everything the guards (inside the hosts) report comes here.
//
//   every request    enriched (network, country, hosting), logged in full,
//                    counted (charts), added to the address's profile, fed to
//                    the wave detector
//   every new        looked up in the background (intel.mjs: Spamhaus, DroneBL,
//   address          StopForumSpam, GreyNoise for probes); known-malicious = banned;
//                    known services (GreyNoise benign) are left alone
//   bans             kept here (state/bans.json), sent to every guard at once,
//                    and reported to the vendors that missed them
//   waves            alerts (and strict mode while one is critical)
//   the host's past  what the gate remembers from before Bulwark (Aegis's
//                    ctx.history: each tunnel's clients and recent requests,
//                    the audit log) comes into the log and the profiles, and
//                    anyone it shows hunting is banned by the same rules
//   warnings         waves and bans go to the host's dashboard too (Aegis's
//                    bell), unless Settings says not to
//
// Never banned: private addresses, addresses you signed in from (30 days),
// requests with your session, the allow list. This machine's own public
// address is neither trusted nor banned: other people's traffic leaves through
// it (Mysterium, proxyware).

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { isIP, isPrivate, normIp } from "./net.mjs";
import { Feeds, FEEDS } from "./lists.mjs";
import { Asn } from "./asn.mjs";
import { Logs, Series, Profiles } from "./store.mjs";
import { Waves } from "./waves.mjs";
import { Reporters } from "./report.mjs";
import { classifyRequest, SIGNATURES_VERSION } from "./payloads.mjs";
import { checkIp, useLists } from "./intel.mjs";
import { paths } from "./config.mjs";

const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
export const DEFAULT_SETTINGS = { auto: true, drop: true, lookups: true, report: true, abuseipdbKey: "", ntfy: "", webhook: "", keepDays: 30, strict: true, hostNotices: true };
const atomic = (file, obj) => { writeFileSync(file + ".tmp", JSON.stringify(obj)); renameSync(file + ".tmp", file); };

// A ban's reason, for a notice row: the gate's sign-in detour undone (the path
// the visitor really asked for), URLs and long lists trimmed.
export function shortReason(r) {
  return String(r || "")
    .replace(/\/__gate\/sso\?[^ ,)]*?next=([^ ,)&]+)[^ ,)]*/g, (_, n) => { try { return decodeURIComponent(n); } catch { return n; } })
    .replace(/https?:\/\/\S+/g, "…").replace(/\s+/g, " ").trim().slice(0, 110);
}

export class Brain {
  constructor({ home, log, fetchImpl, offline = false, remote }) {
    this.home = home; this.P = paths(home);
    for (const d of [this.P.feeds, this.P.asn, this.P.logs, this.P.state, this.P.run]) mkdirSync(d, { recursive: true });
    this.log = log || console.log;
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.offline = offline;
    this.file = join(this.P.state, "bulwark.json");
    this.state = { settings: { ...DEFAULT_SETTINGS }, bans: {}, allow: {}, trusted: {}, actions: [],
                   stats: { banned: 0, unbanned: 0, checked: 0, since: Date.now() }, imported: false, history: { seen: [], last: null } };
    try {
      const s = JSON.parse(readFileSync(this.file, "utf8"));
      this.state = { ...this.state, ...s, settings: { ...DEFAULT_SETTINGS, ...s.settings }, stats: { ...this.state.stats, ...s.stats } };
    } catch { /* first run */ }
    this.feeds = new Feeds({ dir: this.P.feeds, log: this.log, fetchImpl: this.fetch, onChange: () => this.broadcast({ t: "feeds" }) });
    // new addresses on a list, every 5 s: straight to the guards, only what's new
    this.feeds.onAdd = (id, adds) => {
      this.listAdds.unshift({ t: Date.now(), id, n: adds.length, sample: adds.slice(0, 5).map(([, e]) => e) });
      this.listAdds.length = Math.min(this.listAdds.length, 100);
      if (adds.length > 20000) this.broadcast({ t: "feeds" });
      else this.broadcast({ t: "listadd", id, adds: adds.map(([st, e, x]) => [st, e, x ?? null]) });
    };
    this.listAdds = [];
    this.asn = new Asn({ dir: this.P.asn, log: this.log, fetchImpl: this.fetch });
    this.logs = new Logs({ dir: this.P.logs, keepDays: this.state.settings.keepDays });
    this.series = new Series({ file: join(this.P.state, "series.json") });
    this.profiles = new Profiles({ file: join(this.P.state, "profiles.json") });
    this.waves = new Waves({ file: join(this.P.state, "waves.json"), onAlert: (a, ch) => this.alerted(a, ch) });
    this.reporters = new Reporters({ file: join(this.P.state, "reports.json"), log: this.log, settings: () => this.state.settings, fetchImpl: this.fetch });
    this.remote = remote || ((ip, { probe }) => checkIp(ip, { light: true, probe, deadline: 0 }));
    this.remoteInjected = !!remote;
    useLists((ip) => this.feeds.lookup(ip), (ip) => (this.feeds.lists.has("tor") ? this.feeds.lookup(ip).some((l) => l.id === "tor") : null), (ip) => this.asn.lookup(ip));
    this.sensors = new Set();
    this.own = new Set();
    this.verdicts = new Map();      // ip -> {at, level, why, bad, benign, intel}
    this.queued = new Map(); this.queue = []; this.running = 0; this.lat = [];
    this.strictUntil = 0;
    this.dirty = false; this.timers = [];
    this.seenRecent = new Map();    // ip -> last time a "blocked" action was noted (no flood)
  }

  start() {
    this.feeds.loadAll();
    this.asn.load().then(() => this.backfillAsn()).catch(() => {});
    const t = (fn, ms) => { const x = setInterval(fn, ms); x.unref?.(); this.timers.push(x); };
    const once = (fn, ms) => { const x = setTimeout(fn, ms); x.unref?.(); this.timers.push(x); };
    if (!this.offline) {
      once(() => this.feeds.refreshDue().catch(() => {}), 2000);
      once(() => this.asn.refreshDue().then(() => this.backfillAsn()).catch(() => {}), 4000);
      once(() => this.refreshOwn(), 1000);
      t(() => this.feeds.refreshDue().catch(() => {}), 15 * MIN);
      t(() => this.feeds.poll().catch(() => {}), 5000);
      t(() => this.asn.refreshDue().catch(() => {}), 6 * HOUR);
      t(() => this.refreshOwn(), HOUR);
    } else this.asn.load().catch(() => {});
    if ((this.state.sigVersion || 1) < SIGNATURES_VERSION) once(() => this.rescan(), 15000);
    t(() => this.save(), 30e3);
    t(() => this.tick(), 30e3);
    t(() => { this.profiles.save(); this.series.save(); this.waves.save(); this.reporters.save(); }, 2 * MIN);
    t(() => this.logs.prune(), 6 * HOUR);
    return this;
  }
  stop() {
    for (const x of this.timers) { clearInterval(x); clearTimeout(x); }
    clearTimeout(this.banNoteTimer);
    this.logs.flush(); this.save(true); this.profiles.save(); this.series.save(); this.waves.save(); this.reporters.save();
  }
  save(force) {
    if (!this.dirty && !force) return;
    const now = Date.now();
    for (const [ip, b] of Object.entries(this.state.bans)) if (b.until && b.until < now) delete this.state.bans[ip];
    for (const [ip, t] of Object.entries(this.state.trusted)) if (now - t > 30 * DAY) delete this.state.trusted[ip];
    this.state.actions = this.state.actions.slice(0, 500);
    try { atomic(this.file, this.state); this.writeSnapshot(); this.dirty = false; } catch (e) { this.log("save:", e.message); }
  }
  get settings() { return this.state.settings; }

  // ------------------------------------------------------------ guards
  snapshot() {
    const now = Date.now();
    return {
      settings: { auto: this.settings.auto, drop: this.settings.drop, lookups: this.settings.lookups },
      bans: Object.entries(this.state.bans).filter(([, b]) => !b.until || b.until > now).map(([ip, b]) => [ip, { reason: b.reason, until: b.until, source: b.source, at: b.at }]),
      allow: Object.keys(this.state.allow), trusted: Object.entries(this.state.trusted), own: [...this.own],
      verdicts: [...this.verdicts].filter(([, v]) => v.bad || v.benign).slice(-20000).map(([ip, v]) => [ip, { bad: v.bad, benign: v.benign, level: v.level, why: v.why }]),
      strictUntil: this.strictUntil,
    };
  }
  writeSnapshot() { try { atomic(this.P.snapshot, this.snapshot()); } catch { /* next time */ } }
  broadcast(m) { const line = JSON.stringify(m) + "\n"; for (const s of this.sensors) { try { s.write(line); } catch { /* gone */ } } }
  // one message from a guard
  onSensor(m, s) {
    switch (m.t) {
      case "hello":
        s.info = { host: m.host, hostVersion: m.hostVersion, since: Date.now(), stats: m.stats };
        s.write(JSON.stringify({ t: "state", ...this.snapshot() }) + "\n");
        if (m.legacy && !this.state.imported) this.importLegacy(m.legacy);
        break;
      case "ev":
        for (const e of m.list || []) { try { this.ingest(e); } catch (err) { this.log("ingest:", err.message); } }
        if (m.dropped) this.log(`a guard dropped ${m.dropped} log lines while the app was away`);
        break;
      case "ban": this.recordBan(m.ip, m.b, m.info || {}); break;
      case "trust": this.trust(m.ip, false); break;
      case "history": try { this.importHistory(m.data || {}, m.host); } catch (err) { this.log("history:", err.message); } break;
    }
  }
  // ask the guards for the host's past again (Settings → "Pull from Aegis")
  pullHistory() { if (!this.sensors.size) throw new Error("No host is connected."); this.broadcast({ t: "pull", since: 0 }); }

  // ------------------------------------------------------------ the host's past
  // data: {tunnels: [{port, host, clients: [{ip, country, agent, first, last, requests}], recent: [{t, ip, country, method, path, status, ms, bytes}]}],
  //        audit: [{t (ISO), event, ip, host, ua, path?}]}
  // Everything new comes into the log (src "aegis") and the profiles; whoever sent
  // payloads is judged by the guard's rules (two payloads, or score 6), then looked up.
  importHistory(data, host = "host") {
    const H = this.state.history ||= { seen: [], last: null };
    const seen = new Set(H.seen);
    const fresh = [], per = new Map(), clientsSeen = new Set();
    const add = (k, e) => { if (seen.has(k)) return; seen.add(k); H.seen.push(k); fresh.push(e); };
    for (const t of data.tunnels || []) {
      for (const r of t.recent || []) {
        if (!r?.ip || !r.t) continue;
        add(`r|${t.port}|${r.t}|${r.ip}|${r.method}|${r.path}`, { t: r.t, ip: normIp(r.ip), cc: r.country || "", host: t.host || "", port: t.port, main: false,
          m: r.method || "", path: String(r.path || "").slice(0, 600), ua: "", st: r.status || 0, b: r.bytes || 0, ms: r.ms ?? null, dec: "seen", src: host });
      }
      for (const c of t.clients || []) {
        if (!c?.ip) continue;
        const ip = normIp(c.ip); clientsSeen.add(ip);
        const p = this.profiles.get(ip);
        if (p) { p.first = Math.min(p.first, c.first || p.first); p.hostN = Math.max(p.hostN || 0, c.requests || 0); continue; }
        this.profiles.add({ t: c.first || Date.now(), ip, cc: c.country || "", host: t.host || "", path: "", dec: "seen", b: 0 });
        const np = this.profiles.get(ip); np.last = c.last || np.last; np.hostN = c.requests || 0; np.n = 0; np.dec = {}; np.paths = []; if (c.agent) np.agent = c.agent;
      }
    }
    for (const a of data.audit || []) {
      const ip = normIp(a.ip || "");
      if (!isIP(ip) || !/failed|refused|wrong|throttled|garbled/.test(a.event || "")) continue;
      const t = Date.parse(a.t) || 0;
      add(`a|${a.t}|${ip}|${a.event}`, { t, ip, cc: "", host: a.host || "", port: null, main: true, m: "", path: String(a.path || `(${a.event})`).slice(0, 600),
        ua: String(a.ua || "").slice(0, 300), st: 0, b: 0, ms: null, dec: "seen", src: host, why: a.event });
    }
    if (H.seen.length > 12000) H.seen.splice(0, H.seen.length - 10000);
    fresh.sort((x, y) => x.t - y.t);
    for (const e of fresh) {
      const sig = classifyRequest(e.path, e.ua);
      if (sig.score) { e.sig = sig.id; e.sc = sig.score; }
      const a = isIP(e.ip) ? this.asn.lookup(e.ip) : null;
      if (a) { e.asn = a.asn; e.org = a.name; if (a.hosting) e.dc = true; if (!e.cc) e.cc = a.cc; }
      this.profiles.add(e); this.logs.add(e);
      if (sig.score && !sig.ua) {
        const x = per.get(e.ip) || { score: 0, payloads: 0, paths: [], host: e.host, cc: e.cc };
        x.score += sig.score; if (sig.score === 3) x.payloads++; if (x.paths.length < 3 && !x.paths.includes(e.path)) x.paths.push(e.path.slice(0, 80));
        per.set(e.ip, x);
      }
    }
    // judged as the guard would have, had it been there
    const banned = [];
    for (const [ip, x] of per) {
      if (this.state.bans[ip] || this.state.allow[ip] || this.isTrusted(ip) || this.own.has(ip) || isPrivate(ip)) continue;
      const v = this.verdicts.get(ip);
      if (x.payloads >= 2 || (!v?.benign && x.score >= 6)) {
        const b = this.ban(ip, `found in ${host === "aegis-burrow" ? "Aegis's" : "the host's"} history: ${x.payloads >= 2 ? `${x.payloads} payloads` : "probing"} (${x.paths.join(", ")})`,
                           { source: "history", ttl: 30 * DAY, info: { host: x.host, country: x.cc } });
        if (b) banned.push(ip);
      }
    }
    const ips = new Set([...fresh.map((e) => e.ip), ...clientsSeen]);
    for (const ip of ips) if (isIP(ip) && !isPrivate(ip) && !this.own.has(ip) && !this.isTrusted(ip)) this.enqueue(ip, { probe: per.has(ip) });
    H.last = { at: Date.now(), host, rows: fresh.length, ips: ips.size, banned };
    this.dirty = true;
    if (fresh.length || banned.length) this.log(`history from ${host}: ${fresh.length} new lines, ${ips.size} addresses${banned.length ? `, banned ${banned.join(", ")}` : ""}`);
    if (banned.length) this.hostNotice({ level: "warn", key: "history", link: "/__gate/bulwark/#/addresses",
      title: "Bulwark found {n} {attacker|attackers} in Aegis's history", items: banned.map((ip) => this.noticeItem(ip, null, "history")) });
    return H.last;
  }

  // ------------------------------------------------------------ newer patterns, older lines
  // The log read again with the current signatures: lines that slipped through
  // get their pattern, and whoever they convict is banned by the guard's rules.
  rescan() {
    const per = new Map();
    let marked = 0;
    for (const e of this.logs.ring) {
      if (e.sig || e.dec !== "pass" && e.dec !== "seen" || e.auth || e.local || e.own) continue;
      const sig = classifyRequest(e.path, e.ua);
      if (!sig.score) continue;
      e.sig = sig.id; e.sc = sig.score; marked++;
      const p = this.profiles.get(e.ip); if (p) p.sigs[sig.id] = (p.sigs[sig.id] || 0) + 1;
      if (sig.ua) continue;
      const x = per.get(e.ip) || { score: 0, payloads: 0, paths: [], host: e.host, cc: e.cc };
      x.score += sig.score; if (sig.score === 3) x.payloads++; if (x.paths.length < 3 && !x.paths.includes(e.path)) x.paths.push(String(e.path).slice(0, 80));
      per.set(e.ip, x);
    }
    const banned = [];
    for (const [ip, x] of per) {
      if (this.state.bans[ip] || this.state.allow[ip] || this.isTrusted(ip) || this.own.has(ip) || isPrivate(ip)) continue;
      if (x.payloads >= 2 || (!this.verdicts.get(ip)?.benign && x.score >= 6)) {
        if (this.ban(ip, `newer patterns, older requests: ${x.payloads >= 2 ? `${x.payloads} payloads` : "probing"} (${x.paths.join(", ")})`, { source: "payload", ttl: 30 * DAY, info: { host: x.host, country: x.cc } })) banned.push(ip);
      }
    }
    this.state.sigVersion = SIGNATURES_VERSION; this.dirty = true;
    this.log(`patterns v${SIGNATURES_VERSION}: read the log again: ${marked} lines got a pattern${banned.length ? `, banned ${banned.join(", ")}` : ""}`);
    return { marked, banned };
  }

  // ------------------------------------------------------------ warnings on the host's dashboard
  hostNotice(n) {
    if (this.settings.hostNotices === false || !this.sensors.size) return;
    this.broadcast({ t: "notify", ...n });
  }
  // one address as a row of a notice: flag, address, why in a few words, what kind
  noticeItem(ip, reason, source) {
    const p = this.profiles.get(ip), b = this.state.bans[ip];
    return { label: ip, cc: p?.cc || b?.country || "", t: Date.now(), link: `/__gate/bulwark/#/ip/${encodeURIComponent(ip)}`,
             sub: [p?.org, shortReason(reason || b?.reason || "")].filter(Boolean).join(" · "),
             tag: { list: "blocklist", payload: "payloads", lookup: "known attacker", history: "history", campaign: "campaign" }[source || b?.source] || "" };
  }
  // bans come in bursts: sent once a minute, and the host adds them to the unread notice
  noteBan(ip, reason) {
    (this.banNotes ||= []).push(this.noticeItem(ip, reason));
    if (this.banNoteTimer) return;
    this.banNoteTimer = setTimeout(() => {
      this.banNoteTimer = null;
      const items = this.banNotes.splice(0);
      if (items.length) this.hostNotice({ level: "warn", key: "bans", link: "/__gate/bulwark/#/addresses", title: "Bulwark banned {n} {address|addresses}", items });
    }, 60e3);
    this.banNoteTimer.unref?.();
  }

  // ------------------------------------------------------------ requests
  isTrusted(ip) { const t = this.state.trusted[ip]; return !!t && Date.now() - t < 30 * DAY && !this.own.has(ip); }
  ingest(e) {
    e.ip = normIp(e.ip);
    const a = isIP(e.ip) && !e.local ? this.asn.lookup(e.ip) : null;
    if (a) { e.asn = a.asn; e.org = a.name; if (a.hosting) e.dc = true; if (!e.cc) e.cc = a.cc; }
    const mine = !!(e.local || e.auth || this.isTrusted(e.ip) || this.state.allow[e.ip]);
    if (e.auth && !e.own) this.trust(e.ip, true);
    const [p, isNew] = this.profiles.add(e);
    if (a) { p.asn = a.asn; p.org = a.name; p.dc = !!a.hosting; }
    this.series.add(e, isNew);
    this.logs.add(e);
    this.waves.feed(e, p, isNew, mine);
    if (e.dec === "block") { const b = this.state.bans[e.ip]; if (b) { b.hits = (b.hits || 0) + 1; b.last = e.t; this.dirty = true; } }
    if (!mine && !e.local && !e.own && isIP(e.ip)) this.enqueue(e.ip, { probe: !!e.sig });
  }

  // addresses seen before the network database was ready get their network now
  backfillAsn() {
    if (!this.asn.t4) return;
    let n = 0;
    for (const p of this.profiles.map.values()) {
      if (p.asn) continue;
      const a = this.asn.lookup(p.ip);
      if (a) { p.asn = a.asn; p.org = a.name; p.dc = !!a.hosting; if (!p.cc) p.cc = a.cc; n++; }
    }
    if (n) this.log(`networks filled in for ${n} addresses`);
  }

  // ------------------------------------------------------------ lookups (behind, never in the way)
  due(ip, probe) {
    if (!this.settings.lookups || this.offline && !this.remoteInjected) return false;
    const last = this.queued.get(ip);
    return !(last && Date.now() - last.at < 6 * HOUR && (last.probe || !probe));
  }
  enqueue(ip, { probe }) {
    if (!this.due(ip, probe)) return;
    this.queued.set(ip, { at: Date.now(), probe: !!probe });
    if (this.queued.size > 50000) this.queued.delete(this.queued.keys().next().value);
    if (this.queue.length > 1000) return;
    this.queue.push({ ip, probe });
    this.pump();
  }
  pump() {
    while (this.running < 6 && this.queue.length) {
      const { ip, probe } = this.queue.shift();
      this.running++;
      const t0 = Date.now();
      this.remote(ip, { probe }).then((r) => { this.lat.push(Date.now() - t0); if (this.lat.length > 300) this.lat.shift(); this.judge(ip, r); })
        .catch(() => {}).finally(() => { this.running--; this.pump(); });
    }
  }
  // Banned for a hard sign only (GreyNoise has seen it attack, DroneBL lists
  // it); anything else bad bans together with a probe. Known services: innocent.
  judge(ip, r) {
    if (!r?.verdict) return;
    this.state.stats.checked++; this.dirty = true;
    const level = r.verdict.level, src = r.sources || {};
    const benign = !!src.greynoise?.result?.benign;
    const bad = (level === "malicious" || level === "suspicious") && !benign;
    const v = { at: Date.now(), level, why: r.verdict.why, bad, benign, intel: r };
    this.verdicts.set(ip, v);
    if (this.verdicts.size > 50000) this.verdicts.delete(this.verdicts.keys().next().value);
    if (bad || benign) this.broadcast({ t: "verdict", ip, v: { bad, benign, level, why: v.why } });
    if (!this.settings.auto || this.state.allow[ip] || this.state.bans[ip] || this.isTrusted(ip) || this.own.has(ip) || benign) return;
    const hard = [];
    if (src.greynoise?.result?.classification === "malicious") hard.push("GreyNoise has seen it attack");
    if (src.dnsbl?.result?.dronebl?.listed) hard.push(`DroneBL: ${src.dnsbl.result.dronebl.why.join(", ")}`);
    if (!r.sources && level === "malicious") hard.push(...r.verdict.why.slice(0, 2));
    const p = this.profiles.get(ip);
    if (hard.length) this.ban(ip, hard.join(", "), { source: "lookup", ttl: 7 * DAY });
    else if (p?.seq?.length && (bad || level === "notice")) this.ban(ip, `probed (${p.paths.find((x) => x) || "?"}) and ${r.verdict.why.slice(0, 2).join(", ")}`, { source: "payload", ttl: 30 * DAY });
  }

  // ------------------------------------------------------------ bans
  evidence(ip) {
    const lines = [], sigs = new Set();
    for (let i = this.logs.ring.length - 1; i >= 0 && lines.length < 12; i--) {
      const e = this.logs.ring[i];
      if (e.ip !== ip || !e.sig) continue;
      lines.push(`${e.m} ${String(e.path).slice(0, 140)}`); sigs.add(e.sig);
    }
    return { lines: lines.reverse(), sigs: [...sigs] };
  }
  // a ban the guard made on the spot
  recordBan(ip, b, info) {
    ip = normIp(ip);
    if (!isIP(ip)) return;
    const had = this.state.bans[ip];
    this.state.bans[ip] = { ...b, hits: had?.hits || 1, last: Date.now(), country: info.country || had?.country || "", host: info.host || had?.host || "", ...this.evidence(ip) };
    this.state.stats.banned++; this.dirty = true;
    this.action(ip, "banned", b.reason, info);
    this.broadcast({ t: "ban", ip, b });
    this.noteBan(ip, b.reason);
    this.reporters.enqueue({ ip, reason: b.reason, source: b.source, ...this.state.bans[ip], first: this.profiles.get(ip)?.first, last: Date.now() });
  }
  ban(ip, reason, { source = "manual", ttl = 0, info = {} } = {}) {
    ip = normIp(ip);
    if (!isIP(ip)) throw new Error("That isn't an IP address.");
    if (source !== "manual" && (this.own.has(ip) || isPrivate(ip))) return null;
    const now = Date.now();
    const b = { at: now, until: ttl ? now + ttl : null, reason: String(reason).slice(0, 300), source };
    this.state.bans[ip] = { ...b, hits: 0, last: now, country: info.country || this.profiles.get(ip)?.cc || "", host: info.host || "", ...this.evidence(ip) };
    this.state.stats.banned++; this.dirty = true;
    this.action(ip, "banned", b.reason, info);
    this.log("banned", ip, "-", b.reason);
    if (source !== "manual" && source !== "history") this.noteBan(ip, b.reason);
    this.broadcast({ t: "ban", ip, b }); this.broadcast({ t: "kick", ip });
    this.reporters.enqueue({ ip, reason: b.reason, source, ...this.state.bans[ip], first: this.profiles.get(ip)?.first, last: now });
    this.writeSnapshot();
    return b;
  }
  unban(ip) {
    ip = normIp(ip);
    const had = !!this.state.bans[ip];
    delete this.state.bans[ip];
    this.verdicts.delete(ip);
    if (had) { this.state.stats.unbanned++; this.action(ip, "unbanned", "by you"); this.dirty = true; }
    this.broadcast({ t: "unban", ip });
    this.writeSnapshot();
    return had;
  }
  allow(ip, on = true, note = "") {
    ip = normIp(ip);
    if (!isIP(ip)) throw new Error("That isn't an IP address.");
    if (on) { this.state.allow[ip] = { at: Date.now(), note: String(note).slice(0, 80) }; this.unban(ip); }
    else delete this.state.allow[ip];
    this.dirty = true;
    this.broadcast({ t: "allow", ip, on });
  }
  trust(ip, quiet) {
    ip = normIp(ip);
    if (!isIP(ip) || isPrivate(ip) || this.own.has(ip)) return;
    const was = this.state.trusted[ip];
    this.state.trusted[ip] = Date.now();
    if (!was || Date.now() - was > HOUR) { this.dirty = true; this.broadcast({ t: "trust", ip, at: Date.now() }); }
    const b = this.state.bans[ip];
    if (b && b.source !== "manual") { delete this.state.bans[ip]; this.action(ip, "lifted", "it signed in"); this.broadcast({ t: "unban", ip }); }
    if (!quiet && !was) this.action(ip, "trusted", "signed in");
  }
  action(ip, act, why, info = {}) {
    this.state.actions.unshift({ t: Date.now(), ip, act, why: String(why || "").slice(0, 300), host: info.host || "", path: info.path ? String(info.path).slice(0, 200) : "", cc: info.country || "" });
    if (this.state.actions.length > 600) this.state.actions.length = 500;
    this.dirty = true;
  }

  // ------------------------------------------------------------ waves
  tick() {
    this.waves.tick(this.series.lastMinutes(90));
    const want = this.settings.strict && this.waves.critical() ? Date.now() + 30 * MIN : 0;
    if (want && want - this.strictUntil > 5 * MIN || (!want && this.strictUntil > Date.now() && !this.waves.critical())) {
      this.strictUntil = want;
      this.broadcast({ t: "strict", until: want });
      if (want) this.log("a critical wave: strict mode (a first payload bans)");
    }
  }
  alerted(a, change) {
    this.log(`wave ${change}: [${a.sev}] ${a.title}`);
    for (const fn of this.alertSubs || []) { try { fn(a, change); } catch { /* closed */ } }
    this.reporters.notify(a, change).catch(() => {});
    if (change !== "closed" && (a.sev === "warn" || a.sev === "critical")) {
      this.hostNotice({ level: a.sev, key: `wave:${a.key}`, link: "/__gate/bulwark/#/waves", title: `${a.sev === "critical" ? "Attack wave" : "Wave"}: ${a.title}`, body: a.detail || "",
        items: (a.members || []).slice(0, 40).map((ip) => this.noticeItem(ip, this.state.bans[ip] ? null : "in this wave")) });
    }
    // a campaign's members are reported as one (evidence: the same play from many)
    if (a.kind === "campaign" && a.sev !== "info") for (const ip of a.members) if (this.state.bans[ip]) this.reporters.enqueue({ ip, ...this.state.bans[ip], source: "campaign", reason: `${this.state.bans[ip].reason}; part of a campaign of ${a.members.length} addresses` });
  }
  onAlerts(fn) { (this.alertSubs ||= new Set()).add(fn); return () => this.alertSubs.delete(fn); }

  // ------------------------------------------------------------ this machine
  async refreshOwn() {
    const found = new Set();
    for (const url of ["https://api.ipify.org", "https://api6.ipify.org"]) {
      try {
        const r = await this.fetch(url, { signal: AbortSignal.timeout(8000) });
        const ip = normIp(await r.text());
        if (r.ok && isIP(ip)) found.add(ip);
      } catch { /* no IPv6, or offline */ }
    }
    if (found.size && [...found].join() !== [...this.own].join()) { this.own = found; this.broadcast({ t: "own", list: [...found] }); this.writeSnapshot(); }
  }

  // ------------------------------------------------------------ Aegis's old built-in shield (2.14)
  importLegacy(dir) {
    try {
      const f = join(dir, "state.json");
      if (!existsSync(f)) { this.state.imported = true; return; }
      const s = JSON.parse(readFileSync(f, "utf8"));
      let n = 0;
      for (const [ip, b] of Object.entries(s.bans || {})) if (!this.state.bans[ip] && (!b.until || b.until > Date.now())) { this.state.bans[ip] = { ...b, imported: true }; n++; }
      for (const [ip, a] of Object.entries(s.allow || {})) this.state.allow[ip] ||= a;
      for (const [ip, t] of Object.entries(s.trusted || {})) if (!this.state.trusted[ip] || this.state.trusted[ip] < t) this.state.trusted[ip] = t;
      for (const e of (s.events || []).slice(0, 300)) this.state.actions.push({ t: e.t, ip: e.ip, act: e.act, why: e.why, host: e.host, path: e.path, cc: e.country });
      this.state.actions.sort((a, b) => b.t - a.t);
      for (const feed of FEEDS) {
        const src = join(dir, "feeds", feed.id + ".txt"), dst = join(this.P.feeds, feed.id + ".txt");
        if (existsSync(src) && !existsSync(dst)) { copyFileSync(src, dst); this.feeds.load(feed); }
      }
      this.state.imported = true; this.dirty = true;
      this.log(`imported Aegis's shield: ${n} bans, ${Object.keys(s.allow || {}).length} allowed, ${Object.keys(s.trusted || {}).length} trusted`);
      this.save(true);
      this.broadcast({ t: "state", ...this.snapshot() });
    } catch (e) { this.log("import:", e.message); }
  }

  // ------------------------------------------------------------ views
  latency() {
    const v = [...this.lat].sort((a, b) => a - b), at = (q) => v[Math.min(v.length - 1, Math.floor(q * v.length))];
    return v.length ? { n: v.length, p50: at(0.5), p95: at(0.95), max: v[v.length - 1] } : null;
  }
  bansList() {
    const now = Date.now();
    return Object.entries(this.state.bans).filter(([, b]) => !b.until || b.until > now).map(([ip, b]) => {
      const p = this.profiles.get(ip), a = p?.asn ? null : this.asn.lookup(ip);
      return { ip, ...b, org: p?.org || a?.name || "", asn: p?.asn || a?.asn || null, dc: p ? !!p.dc : !!a?.hosting, country: b.country || p?.cc || a?.cc || "",
               n: p?.n || 0, reported: this.reporters.state.reported[ip] || null };
    }).sort((a, b) => (b.last || b.at) - (a.last || a.at));
  }
}
