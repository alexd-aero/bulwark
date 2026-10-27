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
//                    bell), unless Settings says not to; and by email when the
//                    selfmail addon is there and you turned it on (mail.mjs):
//                    waves, campaigns, strict mode, the guard gone, the app failing
//
// Never banned: private addresses, addresses you signed in from (30 days),
// requests with your session, the allow list. This machine's own public
// address is neither trusted nor banned: other people's traffic leaves through
// it (Mysterium, proxyware).

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, copyFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { isIP, isPrivate, normIp } from "./net.mjs";
import { Feeds, FEEDS } from "./lists.mjs";
import { Asn } from "./asn.mjs";
import { Logs, Series, Profiles } from "./store.mjs";
import { Waves } from "./waves.mjs";
import { Reporters } from "./report.mjs";
import { Mailer, MAIL_DEFAULTS } from "./mail.mjs";
import { inspect, categoryOf, signatureById, SIGNATURES_VERSION } from "./payloads.mjs";
import { checkIp, useLists } from "./intel.mjs";
import { paths } from "./config.mjs";

const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
export const CLEARED_FOR = 7 * DAY;     // a clean scan lets an address into public tunnels for this long (the guard keeps the same)
export const DEFAULT_SETTINGS = { auto: true, drop: true, lookups: true, scanFirst: true, report: true, abuseipdbKey: "", ntfy: "", webhook: "", keepDays: 30, strict: true, hostNotices: true, ...MAIL_DEFAULTS };
// what the engine found, on a log line (as the guard writes it)
function label(e, sig) {
  e.sig = sig.id; e.sc = sig.score;
  if (sig.cat) e.cat = sig.cat;
  if (sig.sev) e.sev = sig.sev;
  if (sig.pts) e.pts = sig.pts;
  if (sig.hits.length > 1) e.hits = sig.hits.slice(0, 8);
  if (sig.cve) e.cve = sig.cve;
  if (sig.det) e.det = String(sig.det).slice(0, 120);
}
const atomic = (file, obj) => { writeFileSync(file + ".tmp", JSON.stringify(obj)); renameSync(file + ".tmp", file); };

// A ban's reason, for a notice row: the gate's sign-in detour undone (the path
// the visitor really asked for), URLs and long lists trimmed.
export function shortReason(r) {
  return String(r || "")
    .replace(/\/__gate\/sso\?[^ ,)]*?next=([^ ,)&]+)[^ ,)]*/g, (_, n) => { try { return decodeURIComponent(n); } catch { return n; } })
    .replace(/https?:\/\/\S+/g, "…").replace(/\s+/g, " ").trim().slice(0, 110);
}

export class Brain {
  // dashboard: Bulwark's dashboard URL for links in emails (the config's, else the host's);
  // mesh: where to look for selfmail (tests); mailFetch: how to reach it (tests)
  constructor({ home, log, fetchImpl, offline = false, remote, dashboard = null, mesh, mailFetch, version = "" }) {
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
    this.dashboard = dashboard;
    this.mailer = new Mailer({ file: join(this.P.state, "mail.json"), settings: () => this.state.settings, log: this.log, dir: mesh, fetchImpl: mailFetch, version,
                               context: (kind, items) => this.mailContext(kind, items) });
    this.health = { hadGuard: false, lostAt: 0, downNoted: false, faults: [], faultNotedAt: 0 };
    this.remote = remote || ((ip, { probe }) => checkIp(ip, { light: true, probe, deadline: 0 }));
    this.remoteInjected = !!remote;
    useLists((ip) => this.feeds.lookup(ip), (ip) => (this.feeds.lists.has("tor") ? this.feeds.lookup(ip).some((l) => l.id === "tor") : null), (ip) => this.asn.lookup(ip));
    this.sensors = new Set();
    this.own = new Set();
    this.verdicts = new Map();      // ip -> {at, level, why, bad, benign}
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
    t(() => { this.profiles.save(); this.series.save(); this.waves.save(); this.reporters.save(); this.mailer.save(); }, 2 * MIN);
    t(() => this.logs.prune(), 10 * MIN);
    // a marker while running: still there at start means the last run ended without stop() (killed, crashed)
    this.marker = join(this.P.run, "app.running");
    if (existsSync(this.marker)) {
      let was = null; try { was = JSON.parse(readFileSync(this.marker, "utf8")); } catch { /* unreadable */ }
      this.log("the last run didn't stop cleanly");
      this.mailer.event({ type: "critical", sev: "critical", key: "crash", title: "Bulwark restarted after stopping unexpectedly",
        detail: `The app${was?.at ? `, running since ${new Date(was.at).toLocaleString()},` : ""} ended without shutting down (a crash, killed for memory, or the machine went down) and has started again. The guard kept enforcing meanwhile. Its journal says why: journalctl --user -u bulwark.` });
    }
    try { writeFileSync(this.marker, JSON.stringify({ pid: process.pid, at: Date.now() })); } catch { /* fine */ }
    return this;
  }
  stop() {
    for (const x of this.timers) { clearInterval(x); clearTimeout(x); }
    clearTimeout(this.banNoteTimer);
    this.logs.flush(); this.save(true); this.profiles.save(); this.series.save(); this.waves.save(); this.reporters.save(); this.mailer.stop();
    if (this.marker) try { unlinkSync(this.marker); } catch { /* gone */ }
  }
  save(force) {
    if (!this.dirty && !force) return;
    const now = Date.now();
    for (const [ip, b] of Object.entries(this.state.bans)) if (b.until && b.until < now) delete this.state.bans[ip];
    for (const [ip, t] of Object.entries(this.state.trusted)) if (now - t > 30 * DAY) delete this.state.trusted[ip];
    for (const [ip, t] of Object.entries(this.state.cleared ||= {})) if (now - t > CLEARED_FOR) delete this.state.cleared[ip];
    this.state.actions = this.state.actions.slice(0, 500);
    try { atomic(this.file, this.state); if (force) { this.snapAt = 0; clearTimeout(this.snapTimer); this.snapTimer = null; } this.writeSnapshot(); this.dirty = false; } catch (e) { this.log("save:", e.message); }
  }
  get settings() { return this.state.settings; }

  // ------------------------------------------------------------ guards
  snapshot() {
    const now = Date.now();
    return {
      settings: { auto: this.settings.auto, drop: this.settings.drop, lookups: this.settings.lookups, scanFirst: this.settings.scanFirst },
      cleared: Object.entries(this.state.cleared || {}).filter(([, t]) => now - t < CLEARED_FOR).slice(-30000),
      bans: Object.entries(this.state.bans).filter(([, b]) => !b.until || b.until > now).map(([ip, b]) => [ip, { reason: b.reason, until: b.until, source: b.source, at: b.at }]),
      allow: Object.keys(this.state.allow), trusted: Object.entries(this.state.trusted), own: [...this.own],
      verdicts: [...this.verdicts].filter(([, v]) => v.bad || v.benign).slice(-20000).map(([ip, v]) => [ip, { bad: v.bad, benign: v.benign, level: v.level, why: v.why }]),
      strictUntil: this.strictUntil,
    };
  }
  // at most every 5 s: a ban wave would otherwise write megabytes to disk per ban
  writeSnapshot() {
    const due = (this.snapAt || 0) + 5000 - Date.now();
    if (due > 0) { this.snapTimer ||= setTimeout(() => { this.snapTimer = null; this.writeSnapshot(); }, due); this.snapTimer.unref?.(); return; }
    this.snapAt = Date.now();
    try { atomic(this.P.snapshot, this.snapshot()); } catch { /* next time */ }
  }
  // A host that reads slower than we write (it is under a wave itself) is not
  // buried in a backlog: past 8 MB waiting, messages are dropped, and once it
  // has caught up it gets the whole state again.
  broadcast(m) {
    const line = JSON.stringify(m) + "\n";
    for (const s of this.sensors) {
      try {
        if (s.writableLength > 8e6) {
          if (!s.behind) { s.behind = true; s.once("drain", () => { s.behind = false; try { s.write(JSON.stringify({ t: "state", ...this.snapshot() }) + "\n"); } catch { /* gone */ } }); }
          continue;
        }
        s.write(line);
      } catch { /* gone */ }
    }
  }
  // one message from a guard
  onSensor(m, s) {
    switch (m.t) {
      case "hello":
        s.info = { host: m.host, hostVersion: m.hostVersion, since: Date.now(), stats: m.stats };
        if (typeof m.dashboard === "string" && /^https?:\/\/[^\s"'<>]+$/.test(m.dashboard) && m.dashboard.length < 300 && this.state.dashboard !== m.dashboard) { this.state.dashboard = m.dashboard; this.dirty = true; }
        this.guardUp();
        s.write(JSON.stringify({ t: "state", ...this.snapshot() }) + "\n");
        if (m.legacy && !this.state.imported) this.importLegacy(m.legacy);
        break;
      case "ev":
        for (const e of m.list || []) { try { this.ingest(e); } catch (err) { this.log("ingest:", err.message); this.fault("ingest", err.message); } }
        if (m.dropped) this.log(`a guard dropped ${m.dropped} log lines while the app was away`);
        break;
      case "ban": this.recordBan(m.ip, m.b, m.info || {}); break;
      case "trust": this.trust(m.ip, false); break;
      case "history": try { this.importHistory(m.data || {}, m.host); } catch (err) { this.log("history:", err.message); this.fault("history", err.message); } break;
      case "devices": this.useDevices(m); break;
      case "scan": this.scanNow(m.ip); break;
    }
  }
  // Your devices, from the host's device keys: {list: [{id, name, ips, hosts, last…}], addresses: {ip: {last, devices}}}.
  // Recognizing them is exact (a sealed key, not a guess); their addresses are trusted as of when they were used.
  useDevices(m) {
    this.devices = { list: Array.isArray(m.list) ? m.list : [], addresses: m.addresses || {}, at: Date.now() };
    for (const [raw, a] of Object.entries(this.devices.addresses)) {
      const ip = normIp(raw);
      if (!isIP(ip) || isPrivate(ip) || this.own.has(ip) || !(a?.last > 0)) continue;
      if ((this.state.trusted[ip] || 0) < a.last) { this.state.trusted[ip] = a.last; this.dirty = true; }
      const b = this.state.bans[ip];
      if (b && b.source !== "manual" && a.last > (b.at || 0)) { delete this.state.bans[ip]; this.action(ip, "lifted", "one of your devices uses it"); this.broadcast({ t: "unban", ip }); }
    }
  }
  devicesAt(ip) { return (this.devices?.list || []).filter((d) => d.ips?.some((x) => x.ip === ip)).map((d) => ({ id: d.id, name: d.name, last: d.ips.find((x) => x.ip === ip).last })); }
  refreshDevices() { this.broadcast({ t: "devices?" }); }
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
      const sig = inspect({ path: e.path, ua: e.ua || undefined, method: e.m || undefined });
      if (sig.id) label(e, sig);
      const a = isIP(e.ip) ? this.asn.lookup(e.ip) : null;
      if (a) { e.asn = a.asn; e.org = a.name; if (a.hosting) e.dc = true; if (!e.cc) e.cc = a.cc; }
      this.profiles.add(e); this.logs.add(e);
      if (sig.id && !sig.label) {
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
      const sig = inspect({ path: e.path, ua: e.ua || undefined, method: e.m || undefined });
      if (!sig.id || sig.probe && e.st >= 200 && e.st < 400) continue;      // a probe the app answered: it was here
      label(e, sig); marked++;
      const p = this.profiles.get(e.ip);
      if (p) { p.sigs[sig.id] = (p.sigs[sig.id] || 0) + 1; if (sig.cat) (p.cats ||= {})[sig.cat] = (p.cats[sig.cat] || 0) + 1; }
      if (sig.label) continue;
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
    if (e.sig && !e.cat) { const c = categoryOf(e.sig); if (c) e.cat = c; }      // an older guard: the category from the signature
    const a = isIP(e.ip) && !e.local ? this.asn.lookup(e.ip) : null;
    if (a) { e.asn = a.asn; e.org = a.name; if (a.hosting) e.dc = true; if (!e.cc) e.cc = a.cc; }
    const mine = !!(e.local || e.auth || this.isTrusted(e.ip) || this.state.allow[e.ip]);
    if (e.auth && !e.own) this.trust(e.ip, true);
    const [p, isNew] = this.profiles.add(e);
    if (a) { p.asn = a.asn; p.org = a.name; p.dc = !!a.hosting; }
    this.series.add(e, isNew, mine || !!e.local);
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
        .catch(() => {}).finally(() => { this.running--; this.scanning?.delete(ip); this.pump(); });
    }
  }
  // A public tunnel asked: this address, scanned now, first in line (even with
  // background lookups off: nobody new gets in without it). Clean -> cleared.
  scanNow(raw) {
    const ip = normIp(raw);
    if (!isIP(ip) || isPrivate(ip) || this.own.has(ip)) return;
    const v = this.verdicts.get(ip);
    if (v && Date.now() - v.at < CLEARED_FOR) {                  // already known: say it again
      if (!v.bad) this.clear(ip); else if (!this.state.bans[ip]) this.broadcast({ t: "verdict", ip, v: { bad: v.bad, benign: v.benign, level: v.level, why: v.why } });
      return;
    }
    if (this.offline && !this.remoteInjected) return;
    // a wave asks for tens of thousands of these: a Set, and a cap (the guard asks again in 10 s)
    if ((this.scanning ||= new Set()).has(ip) || this.scanning.size >= 2000) return;
    this.scanning.add(ip);
    this.queued.set(ip, { at: Date.now(), probe: false });
    this.queue.unshift({ ip, probe: false, first: true });
    this.pump();
  }
  clear(ip) {
    (this.state.cleared ||= {})[ip] = Date.now(); this.dirty = true;
    this.broadcast({ t: "cleared", ip, at: this.state.cleared[ip] });
  }
  // Banned for a hard sign only (GreyNoise has seen it attack, DroneBL lists
  // it); anything else bad bans together with a probe. Known services: innocent.
  judge(ip, r) {
    if (!r?.verdict) return;
    this.state.stats.checked++; this.dirty = true;
    const level = r.verdict.level, src = r.sources || {};
    const benign = !!src.greynoise?.result?.benign;
    const bad = (level === "malicious" || level === "suspicious") && !benign;
    const v = { at: Date.now(), level, why: r.verdict.why, bad, benign };          // the full lookup stays in intel's cache, not here: 50 000 of them is a lot of memory
    this.verdicts.set(ip, v);
    if (this.verdicts.size > 50000) this.verdicts.delete(this.verdicts.keys().next().value);
    if (bad || benign) this.broadcast({ t: "verdict", ip, v: { bad, benign, level, why: v.why } });
    if (!bad) this.clear(ip);                     // nothing against it: public tunnels let it in
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
    const stop = Math.max(0, this.logs.ring.length - 5000);                  // the recent past only: bans come by the hundred in a wave
    for (let i = this.logs.ring.length - 1; i >= stop && lines.length < 12; i--) {
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
      const was = this.strictUntil > Date.now();
      this.strictUntil = want;
      this.broadcast({ t: "strict", until: want });
      if (want) this.log("a critical wave: strict mode (a first payload bans)");
      if (want && !was) this.mailer.event({ type: "strict", sev: "critical", key: "strict", title: "Strict mode is on",
        detail: "A critical wave is under way: while it lasts (30 minutes at least) an address's first payload bans it." });
    }
    this.checkGuard();
    this.mailer.tick();
  }
  alerted(a, change) {
    this.log(`wave ${change}: [${a.sev}] ${a.title}`);
    for (const fn of this.alertSubs || []) { try { fn(a, change); } catch { /* closed */ } }
    this.reporters.notify(a, change).catch(() => {});
    if (change !== "closed" && (a.sev === "warn" || a.sev === "critical")) {
      this.mailer.event({ type: a.kind === "campaign" ? "campaign" : "wave", sev: a.sev, key: `wave:${a.key}`, alertKey: a.key, title: a.title, detail: a.detail || "" });
      this.hostNotice({ level: a.sev, key: `wave:${a.key}`, link: "/__gate/bulwark/#/waves", title: `${a.sev === "critical" ? "Attack wave" : "Wave"}: ${a.title}`, body: a.detail || "",
        items: (a.members || []).slice(0, 40).map((ip) => this.noticeItem(ip, this.state.bans[ip] ? null : "in this wave")) });
    }
    // a campaign's members are reported as one (evidence: the same play from many)
    if (a.kind === "campaign" && a.sev !== "info") for (const ip of a.members) if (this.state.bans[ip]) this.reporters.enqueue({ ip, ...this.state.bans[ip], source: "campaign", reason: `${this.state.bans[ip].reason}; part of a campaign of ${a.members.length} addresses` });
  }
  onAlerts(fn) { (this.alertSubs ||= new Set()).add(fn); return () => this.alertSubs.delete(fn); }

  // ------------------------------------------------------------ health (critical emails)
  // the guard: once one has connected, none for 5 minutes is "the guard is gone"
  // (a host restarting for an update is back well before that)
  guardUp() {
    const h = this.health;
    if (h.downNoted) this.mailer.event({ type: "critical", sev: "info", key: "guard", title: "The guard is back", detail: `A guard connected again after ${Math.max(1, Math.round((Date.now() - h.lostAt) / MIN))} minutes away.` });
    h.hadGuard = true; h.lostAt = 0; h.downNoted = false;
  }
  guardGone() { if (!this.sensors.size && this.health.hadGuard && !this.health.lostAt) this.health.lostAt = Date.now(); }
  checkGuard(now = Date.now()) {
    const h = this.health;
    if (this.sensors.size || !h.hadGuard || !h.lostAt || h.downNoted || now - h.lostAt < 5 * MIN) return;
    h.downNoted = true;
    this.log("no guard connected for 5 minutes");
    this.mailer.event({ type: "critical", sev: "critical", key: "guard", title: "The guard is disconnected",
      detail: `No host has been connected to Bulwark since ${new Date(h.lostAt).toLocaleTimeString()}: the gate stopped, or Bulwark's guard was unloaded from it. Until one is back, nothing is logged or watched for waves here.` });
  }
  // errors: 20 within 10 minutes is an app in trouble (an email at most once an hour)
  fault(where, msg, now = Date.now()) {
    const h = this.health;
    h.faults.push(now);
    while (h.faults.length && h.faults[0] < now - 10 * MIN) h.faults.shift();
    if (h.faults.length > 200) h.faults.splice(0, h.faults.length - 200);
    if (h.faults.length < 20 || now - h.faultNotedAt < HOUR) return;
    h.faultNotedAt = now;
    this.mailer.event({ type: "critical", sev: "critical", key: "faults", title: "Bulwark is failing",
      detail: `${h.faults.length} errors in the last 10 minutes; the latest (${where}): ${String(msg || "").slice(0, 200)}.` });
  }

  // ------------------------------------------------------------ what an email says (mail.mjs, mailview.mjs)
  dashboardUrl() {
    const ok = (u) => (typeof u === "string" && /^https?:\/\/[^\s"'<>]+$/.test(u) ? u : null);
    return ok(this.dashboard) || ok(this.state.dashboard) || null;
  }
  stranger(p) { return !(p.auth || isPrivate(p.ip) || this.own.has(p.ip) || this.isTrusted(p.ip) || this.state.allow[p.ip]); }
  // addresses -> the busiest networks: [{name, asn, n, banned}]
  netsOf(ps, max = 5) {
    const m = new Map();
    for (const p of ps) {
      const k = p.asn || 0, x = m.get(k) || { name: p.org || (p.asn ? `AS${p.asn}` : "unknown network"), asn: p.asn || null, n: 0, banned: 0 };
      x.n++; x.banned += this.state.bans[p.ip] ? 1 : 0; m.set(k, x);
    }
    return [...m.values()].sort((a, b) => b.n - a.n || b.banned - a.banned).slice(0, max);
  }
  // pattern counts -> [{name, n}]
  patternsOf(counts, max = 5) {
    return Object.entries(counts).filter(([id]) => signatureById(id)?.sev !== "info").sort((a, b) => b[1] - a[1]).slice(0, max)
      .map(([id, k]) => ({ name: signatureById(id)?.name || id, n: k }));
  }
  mailContext(kind, items = []) {
    const now = Date.now(), base = this.dashboardUrl();
    const hosts = [...this.sensors].map((x) => x.info?.host).filter(Boolean);
    if (kind === "test" || kind === "system") return { link: base, sensors: this.sensors.size, hosts };
    if (kind === "digest") {
      const since = now - DAY, t = this.series.total(DAY), sig = {};
      for (const p of this.series.range(DAY, 48).points) for (const [k, v] of Object.entries(p.sig || {})) sig[k] = (sig[k] || 0) + v;
      const ps = this.profiles.recent(since, 20000).filter((p) => this.stranger(p) && Object.keys(p.sigs).length);
      return { link: base, totals: { req: t.req, attacks: t.payload + t.probe, newIps: t.newIp, bans: this.bansList().filter((b) => (b.at || 0) >= since).length },
               waves: this.waves.list(200).filter((a) => a.first >= since && a.sev !== "info").map((a) => ({ title: a.title, sev: a.sev, first: a.first, members: a.members?.length || 0 })),
               nets: this.netsOf(ps), patterns: this.patternsOf(sig) };
    }
    // a wave: the numbers now against the hour before, who is in it, what they try
    const mins = this.series.lastMinutes(76), done = mins.slice(0, -1), last5 = done.slice(-5), before = done.slice(0, -15);
    const att = (b) => (b.payload || 0) + (b.probe || 0);
    const peak = (f) => Math.max(0, ...last5.map(f)), avg = (f) => (before.length ? before.reduce((a, b) => a + f(b), 0) / before.length : 0);
    const alerts = {}, members = new Set();
    for (const it of items) {
      const a = it.alertKey && this.waves.alerts.get(it.alertKey);
      if (!a) continue;
      alerts[it.alertKey] = { title: a.title, detail: a.detail, sev: a.sev, forecast: a.forecast || null, members: a.members?.length || 0, open: a.open };
      for (const ip of a.members || []) members.add(ip);
    }
    // a surge names no addresses: then the strangers of the last 15 minutes that tried something
    const ps = members.size ? [...members].map((ip) => this.profiles.get(ip) || { ip, sigs: {} })
                            : this.profiles.recent(now - 15 * MIN, 5000).filter((p) => this.stranger(p) && Object.keys(p.sigs).length);
    const sig = {};
    for (const b of done.slice(-15)) for (const [k, v] of Object.entries(b.sig || {})) sig[k] = (sig[k] || 0) + v;
    return {
      link: base ? `${base}#/waves` : null,
      rpm: peak((b) => b.req || 0), normalRpm: Math.round(avg((b) => b.req || 0) * 10) / 10,
      attacks: peak(att), normalAttacks: Math.round(avg(att) * 10) / 10,
      members: members.size, banned: members.size ? [...members].filter((ip) => this.state.bans[ip]).length : this.bansList().filter((b) => (b.at || 0) >= now - HOUR).length,
      bansHour: this.bansList().filter((b) => (b.at || 0) >= now - HOUR).length,
      strict: this.strictUntil > now ? this.strictUntil : 0,
      nets: this.netsOf(ps), patterns: this.patternsOf(sig), alerts,
    };
  }

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
