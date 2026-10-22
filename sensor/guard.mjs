// The guard: the part of Bulwark that answers for every request, inside the
// host (Aegis × Burrow's gate), synchronously, in microseconds. It decides
// only what can be decided on the spot:
//
//   banned / allowed / yours   from the state the app sends (bans, allow list,
//                              addresses you signed in from, this machine's own)
//   a strong blocklist         banned on sight (the lists, parsed off the main thread)
//   the engine                 (core/payloads.mjs) every request normalized and
//                              matched: a category, a severity, CVEs, and an
//                              anomaly score (Core Rule Set style). 5 points is a
//                              payload: dropped (404), never reaching the app
//   the address's score        what it sent adds up (a payload counts 5, a probe
//                              its points once the app said "not here"); 10 bans,
//                              and so does any hit from an address with a mark
//                              against it. During a wave ("strict") the first
//                              payload bans
//   behaviour                  per address, in one-minute windows (bounded): request
//                              floods, 4xx-heavy wordlist scanning across many paths,
//                              login hammering (brute force, credential stuffing),
//                              method fuzzing. Counted like hits
//   known services             (GreyNoise "benign": crawlers, research scanners)
//                              aren't banned for probes, behaviour or a list mark;
//                              but two payloads ban even them: an index of leaked
//                              secrets (LeakIX) is no friend of yours
//
// Everything slow (lookups, waves, reports, the logs) happens in the app; the
// guard tells it what it saw and did.

import { isIP, isPrivate, normIp } from "../core/net.mjs";
import { lookupIn, RangeSet } from "../core/lists.mjs";
import { inspect, verdictOf, signatureById } from "../core/payloads.mjs";

const HOUR = 3600e3, DAY = 24 * HOUR;
export const CLEARED_FOR = 7 * DAY;          // a clean scan lets an address into public tunnels for this long
const SCAN_ASK_EVERY = 10e3;
export const BAN_AT = 10;                    // an address's points that ban it (two payloads)
const PAYLOAD_PTS = 5;                       // what one payload adds, however bad (two ban)
const WINDOW = 60e3;                         // behaviour is counted per address per minute
const MAX_TRACKED = 20000;
// login endpoints: POSTs here are sign-in attempts
const LOGIN = /(^|\/)(wp-login\.php|xmlrpc\.php|login|log-in|signin|sign-in|sign_in|logon|authenticate|auth|session|sessions|j_security_check|j_spring_security_check|owa\/auth\.owa|logincheck|token|oauth\/token|user\/login|users\/sign_in|account\/login|admin\/login|administrator\/index\.php|api\/(v\d+\/)?(auth|login|session|token|signin))(\/|\.php|\.aspx?|\.jsp|\.do|\.action|\?|$)/i;
// answers that say a probed thing isn't here
const notHere = (st, info) => st === 0 || st === 404 || st === 410 || st === 400 || st === 405 || st === 501 || st >= 500 || (st >= 300 && st < 400 && info.access === "login");
const firstSeg = (p) => { const s = String(p || "/"); const e = s.indexOf("/", 1), q = s.indexOf("?"); return s.slice(0, Math.min(e < 0 ? s.length : e, q < 0 ? s.length : q)).slice(0, 60); };

export class Guard {
  constructor({ log, emit, now } = {}) {
    this.log = log || (() => {});
    this.now = now || Date.now;              // a clock (tests move it)
    this.emit = emit || (() => {});          // (msg) -> to the app
    this.lists = new Map();
    this.bans = new Map();                   // ip -> {reason, until, source}
    this.allow = new Set();
    this.trusted = new Map();                // ip -> last sign-in
    this.own = new Set();
    this.verdicts = new Map();               // ip -> {bad, benign, level, why}
    this.cleared = new Map();                // ip -> when a scan found nothing against it (public tunnels let it in)
    this.asked = new Map();                  // ip -> when the app was last asked to scan it
    this.edgeVersion = 0;                    // bumps whenever who may pass changes (Aegis mirrors it to your VPS)
    this.scores = new Map();                 // ip -> {score, probes, payloads, paths, last}
    this.behav = new Map();                  // ip -> this minute's behaviour: {w, n, nf, lp, lf, segs, meth, fired}
    this.settings = { auto: true, drop: true, lookups: true, scanFirst: true };
    this.strictUntil = 0;
    this.stats = { requests: 0, blocked: 0, dropped: 0, banned: 0, checks: 0, us: 0 };
  }

  // ------------------------------------------------------------ state from the app
  apply(m) {
    switch (m.t) {
      case "state":
        if (m.settings) this.settings = { ...this.settings, ...m.settings };
        if (m.bans) this.bans = new Map(m.bans);
        if (m.allow) this.allow = new Set(m.allow);
        if (m.trusted) this.trusted = new Map(m.trusted);
        if (m.own) this.own = new Set(m.own);
        if (m.verdicts) this.verdicts = new Map(m.verdicts);
        if (m.cleared) this.cleared = new Map(m.cleared);
        this.strictUntil = m.strictUntil || 0;
        this.edgeVersion++;
        break;
      case "ban": this.bans.set(m.ip, m.b); this.cleared.delete(m.ip); this.edgeVersion++; break;
      case "unban": this.bans.delete(m.ip); this.scores.delete(m.ip); this.behav.delete(m.ip); this.edgeVersion++; break;
      case "allow": if (m.on) { this.allow.add(m.ip); this.bans.delete(m.ip); } else this.allow.delete(m.ip); this.edgeVersion++; break;
      // a scan found nothing against it: public tunnels let it in
      case "cleared": this.cleared.set(m.ip, m.at || Date.now()); this.asked.delete(m.ip); if (this.cleared.size > 50000) this.cleared.delete(this.cleared.keys().next().value); this.edgeVersion++; break;
      case "verdict": this.verdicts.set(m.ip, m.v); if (this.verdicts.size > 50000) this.verdicts.delete(this.verdicts.keys().next().value); break;
      case "settings": this.settings = { ...this.settings, ...m.settings }; break;
      case "own": this.own = new Set(m.list); break;
      case "trust": this.trusted.set(m.ip, m.at || Date.now()); this.edgeVersion++; break;
      case "strict": this.strictUntil = m.until || 0; break;
      // the addresses your devices used lately (the host's device keys): yours, as of when they were used
      case "devices": for (const [ip, a] of Object.entries(m.addresses || {})) if (!this.own.has(ip) && (this.trusted.get(ip) || 0) < a.last) { this.trusted.set(ip, a.last); this.edgeVersion++; } break;
      case "listadd": {                                     // new addresses on a list: added in place
        let sets = this.lists.get(m.id);
        if (!sets) { sets = {}; this.lists.set(m.id, sets); }
        for (const [st, e, x] of m.adds || []) (sets[st] ||= RangeSet.empty()).addLive(e, x ?? undefined);
        break;
      }
    }
  }
  useLists(lists) { this.lists = lists; }
  isTrusted(ip) { const t = this.trusted.get(ip); return !!t && Date.now() - t < 30 * DAY && !this.own.has(ip); }
  // a sign-in (or a request with a valid session): yours from now on, and any ban on it is lifted
  trust(ip) {
    ip = normIp(ip);
    if (!isIP(ip) || isPrivate(ip) || this.own.has(ip)) return;
    const was = this.trusted.get(ip);
    this.trusted.set(ip, Date.now());
    const lifted = this.bans.has(ip) && this.bans.get(ip).source !== "manual";
    if (lifted) this.bans.delete(ip);
    if (!was || Date.now() - was > HOUR || lifted) this.emit({ t: "trust", ip });
  }

  // ------------------------------------------------------------ the check
  // info: {method, path, host, country, trusted: () => bool, ...}. -> null | {status, body, why}
  // What it found is left on info._bw for observe().
  gate(rawIp, info = {}) {
    const t0 = process.hrtime.bigint();
    const out = this.decide(normIp(rawIp), info);
    this.stats.requests++;
    this.stats.us += Number(process.hrtime.bigint() - t0) / 1000;
    return out;
  }
  decide(ip, info) {
    const bw = (info._bw = { dec: "pass" });
    if (!isIP(ip) || isPrivate(ip)) { bw.local = true; return null; }
    if (this.allow.has(ip)) { bw.allowed = true; return null; }
    let sig = inspect(info);
    let tr = null;
    const trusted = () => {
      if (tr === null) { tr = this.isTrusted(ip) || !!info.trusted?.(); if (tr) this.trust(ip); }
      bw.auth = tr;
      return tr;
    };
    const mark = () => {
      if (!sig.id) return;
      bw.sig = sig.id; bw.sc = sig.score; bw.cat = sig.cat; bw.sev = sig.sev; bw.pts = sig.pts;
      if (sig.hits.length > 1) bw.hits = sig.hits.slice(0, 8);
      if (sig.cve) bw.cve = sig.cve;
      if (sig.det) bw.det = String(sig.det).slice(0, 120);
    };
    // this machine's own address: other people's traffic leaves through it
    // (Mysterium, proxyware), so it is neither trusted nor banned by address
    if (this.own.has(ip)) {
      bw.own = true; mark();
      if (sig.score === 3 && this.settings.drop && !trusted()) return this.drop(bw, "a payload from this machine's own address");
      return null;
    }
    const now = this.now();
    const ban = this.bans.get(ip);
    if (ban && (!ban.until || ban.until > now)) {
      mark();
      if (ban.source !== "manual" && trusted()) return null;        // trust() lifted it
      this.stats.blocked++;
      bw.dec = "block"; bw.why = ban.reason;
      return { status: 403, body: "Blocked.", why: ban.reason, page: "blocked" };
    }
    // behaviour this minute: what the request alone can't show
    const extra = this.behave(ip, info, bw, now);
    if (extra) sig = verdictOf([...(sig.list || []), ...extra]);
    mark();
    const lists = lookupIn(this.lists, ip);
    if (lists.length) bw.lists = lists.map((l) => l.id);
    if (!this.settings.auto) {
      if (sig.score === 3 && this.settings.drop && !trusted()) return this.drop(bw, "a payload");
      return this.scanFirst(ip, info, bw, trusted);
    }
    const strong = lists.filter((l) => l.strength === "strong");
    if (strong.length && !trusted()) return this.ban(ip, `on ${strong.map((l) => l.name).join(", ")}`, "list", 7 * DAY, info, bw);
    if (!sig.id || sig.label) {                                       // a scanner's name only labels the request: it never adds up to a ban
      const due = this.scores.get(ip);                                // probes the app said weren't here may have tipped it over since
      if (due?.due && now - due.last < DAY && !this.verdicts.get(ip)?.benign && !trusted()) { due.due = false; return this.ban(ip, `scored ${due.score} (${due.paths.slice(0, 2).join(", ")})`, "payload", 30 * DAY, info, bw); }
      return this.scanFirst(ip, info, bw, trusted);
    }
    if (trusted()) return null;
    const sc = this.scores.get(ip) || { score: 0, probes: 0, payloads: 0, paths: [], last: now };
    if (now - sc.last > DAY) { sc.score = 0; sc.probes = 0; sc.payloads = 0; sc.paths = []; }
    sc.probes++; sc.last = now;
    if (sig.score === 3) { sc.payloads = (sc.payloads || 0) + 1; sc.score += PAYLOAD_PTS; }
    else if (sig.probe) bw.pend = sig.pts;                           // counted once the app answers "not here" (after())
    else sc.score += sig.pts;
    sc.paths.unshift(String(info.path).slice(0, 120)); sc.paths.length = Math.min(sc.paths.length, 8);
    this.scores.set(ip, sc);
    if (this.scores.size > MAX_TRACKED) this.scores.delete(this.scores.keys().next().value);
    const v = this.verdicts.get(ip);
    if (v?.benign && sc.payloads >= 2) {
      return this.ban(ip, `hunted secrets (${sc.paths.slice(0, 2).join(", ")}); a known scanner (${(v.why || []).slice(0, 1).join("") || "GreyNoise: benign"}), but not one you want indexing your leaks`, "payload", 30 * DAY, info, bw);
    }
    if (!v?.benign) {
      const marks = lists.filter((l) => l.strength !== "strong").map((l) => (l.id === "tor" ? "is a Tor exit" : `is on ${l.name}`));
      if (v?.bad) marks.push(...v.why.slice(0, 2));
      const strict = sig.score === 3 && now < this.strictUntil;
      const stuffing = extra?.find((h) => h.id === "brute-force" && h.sev === "critical");
      if (marks.length || sc.score >= BAN_AT || strict || stuffing) {
        const what = sig.cat ? ` [${sig.cat}${sig.cve ? ` ${sig.cve}` : ""}]` : "";
        const why = stuffing ? `${stuffing.why}${marks.length ? ` and ${marks.join(", ")}` : ""}`
          : strict ? `sent a payload (${sc.paths[0]})${what} during a wave`
          : marks.length ? `${sig.score === 3 ? "sent payloads" : "probed"} (${sc.paths[0]})${what} and ${marks.join(", ")}`
          : sc.payloads >= 2 ? `sent ${sc.payloads} payloads (${sc.paths.slice(0, 2).join(", ")})${what}`
          : `scored ${sc.score} (${sc.paths.slice(0, 2).join(", ")})${what}`;
        return this.ban(ip, why, "payload", 30 * DAY, info, bw);
      }
    }
    if (sig.score === 3 && this.settings.drop) return this.drop(bw, "a payload: never reached the app");
    return this.scanFirst(ip, info, bw, trusted);
  }
  // This minute's behaviour for an address: counted here (requests, methods,
  // sign-in attempts) and in after() (what the app answered). Each signal fires
  // once a window. -> null | [hits]
  behave(ip, info, bw, now) {
    const w = Math.floor(now / WINDOW);
    let b = this.behav.get(ip);
    if (!b) {
      b = { w, n: 0, nf: 0, lp: 0, lf: 0, segs: null, meth: 0, fired: 0 };
      this.behav.set(ip, b);
      if (this.behav.size > MAX_TRACKED) this.behav.delete(this.behav.keys().next().value);
    } else if (b.w !== w) { b.w = w; b.n = 0; b.nf = 0; b.lp = 0; b.lf = 0; b.segs = null; b.meth = 0; b.fired = 0; }
    b.n++;
    bw.b = b;
    const m = info.method;
    if (m && m !== "GET" && m !== "HEAD") {
      if (m === "POST" && LOGIN.test(info.path || "")) { b.lp++; bw.login = true; }
      if (m !== "POST" && m !== "OPTIONS") b.meth |= 1 << (m.charCodeAt(0) % 30);
    }
    let out = null;
    const fire = (bit, h) => { if (b.fired & bit) return; b.fired |= bit; (out ||= []).push(h); };
    const H = (id, sev, why) => { const s = signatureById(id); return { id, sev, cat: s.cat, why, probe: false }; };
    if (b.n > 1200) fire(1, H("flood", "medium", `${b.n} requests in a minute`));
    if (b.nf >= 25 && b.segs && b.segs.size >= 15 && b.nf >= 0.6 * b.n) fire(2, H("content-discovery", "high", `${b.nf} not-found answers across ${b.segs.size} paths in a minute`));
    if (b.lp >= 25) fire(4, H("brute-force", "critical", `credential stuffing: ${b.lp} sign-in attempts in a minute (${String(info.path).split("?")[0].slice(0, 60)})`));
    else if (b.lf >= 10) fire(8, H("brute-force", "high", `${b.lf} failed sign-ins in a minute`));
    let k = b.meth, bits = 0; while (k) { bits += k & 1; k >>>= 1; }
    if (bits >= 3) fire(16, H("method-fuzz", "medium", "several unusual HTTP methods in a minute"));
    return out;
  }
  // When the response is done (the host's observe): what the app answered.
  // A probe counts only if the thing isn't here; 4xx answers feed the
  // wordlist-scanning and brute-force signals.
  after(ip, info, res = {}) {
    const bw = info._bw;
    if (!bw || bw.local || bw.allowed || bw.auth) return;
    const st = Number(res.status) || 0, b = bw.b;
    if (b && st >= 400) {
      b.nf++;
      if (st === 404 || st === 410) { if (!b.segs) b.segs = new Set(); if (b.segs.size < 64) b.segs.add(firstSeg(info.path)); }
      if (bw.login) b.lf++;
    }
    if (bw.pend && notHere(st, info)) {
      const sc = this.scores.get(normIp(ip));
      if (sc) { sc.score += bw.pend; if (sc.score >= BAN_AT) sc.due = true; }
    }
  }
  isCleared(ip) { const t = this.cleared.get(ip); return !!t && Date.now() - t < CLEARED_FOR; }
  // A public tunnel lets in only addresses that are yours, or that a scan found
  // nothing against. Anyone else gets a "checking" page (403, it reloads by
  // itself) while the app scans them first in line; one the scan flagged is blocked.
  scanFirst(ip, info, bw, trusted) {
    if (info.access !== "public" || !this.settings.scanFirst || trusted() || this.isCleared(ip)) return null;
    const v = this.verdicts.get(ip);
    if (v?.benign) return null;
    this.stats.checks++;
    if (v?.bad) {
      bw.dec = "block"; bw.why = `flagged by the scan: ${(v.why || []).slice(0, 2).join(", ") || v.level}`;
      return { status: 403, body: "Blocked.", why: bw.why, page: "blocked" };
    }
    const asked = this.asked.get(ip) || 0;
    if (Date.now() - asked > SCAN_ASK_EVERY) {
      this.asked.set(ip, Date.now());
      if (this.asked.size > 20000) this.asked.delete(this.asked.keys().next().value);
      this.emit({ t: "scan", ip });
    }
    bw.dec = "check"; bw.why = "not scanned yet: checked before a public tunnel";
    return { status: 403, body: "Checking your address first. Try again in a few seconds.", why: "not scanned yet", page: "checking", retry: 2 };
  }
  // who may pass, for a relay in front (Aegis mirrors it to your VPS): addresses only
  edge() {
    const now = Date.now();
    const fresh = (m, ttl) => [...m].filter(([ip, t]) => now - t < ttl && !this.own.has(ip)).map(([ip]) => ip);
    return { version: this.edgeVersion, on: !!this.settings.scanFirst,
             cleared: [...new Set([...fresh(this.cleared, CLEARED_FOR), ...fresh(this.trusted, 30 * DAY), ...this.allow])],
             banned: [...this.bans].filter(([ip, b]) => (!b.until || b.until > now) && !this.allow.has(ip) && !this.isTrusted(ip)).map(([ip]) => ip) };
  }
  drop(bw, why) {
    this.stats.dropped++;
    bw.dec = "drop"; bw.why = why;
    return { status: 404, body: "Not found", why: "payload" };
  }
  ban(ip, reason, source, ttl, info, bw) {
    const now = Date.now();
    const b = { reason: String(reason).slice(0, 300), until: ttl ? now + ttl : null, source, at: now };
    this.bans.set(ip, b);
    this.stats.banned++;
    bw.dec = "ban"; bw.why = b.reason;
    this.emit({ t: "ban", ip, b, info: { host: info.host || "", country: info.country || "", path: String(info.path || "").slice(0, 200) } });
    return { status: 403, body: "Blocked.", why: b.reason, page: "blocked" };
  }

  // one line of the log, for the app: everything about the request, and what was done
  entry(ip, info, res = {}) {
    const bw = info._bw || {};
    const e = {
      t: info.t0 || Date.now(), ip: normIp(ip), cc: info.country || "", host: info.host || "", port: info.port ?? null, main: !!info.main,
      m: info.method || "", path: String(info.path || "").slice(0, 600), ua: String(info.ua || "").slice(0, 300),
      ref: String(info.referer || "").slice(0, 300), lang: String(info.lang || "").slice(0, 40), via: info.via || "",
      ray: info.ray || "", proto: info.proto || "", st: res.status ?? 0, b: res.bytes ?? 0, ms: res.ms ?? null,
      dec: bw.dec || "pass",
    };
    if (bw.why) e.why = bw.why;
    if (bw.sig && !bw.auth) {                     // your own signed-in requests are never attacks, not even as labels
      e.sig = bw.sig; e.sc = bw.sc;
      if (bw.cat) e.cat = bw.cat;
      if (bw.sev) e.sev = bw.sev;
      if (bw.pts) e.pts = bw.pts;
      if (bw.hits) e.hits = bw.hits;
      if (bw.cve) e.cve = bw.cve;
      if (bw.det) e.det = bw.det;
    }
    if (bw.lists) e.lists = bw.lists;
    if (bw.auth !== undefined) e.auth = bw.auth;
    if (bw.own) e.own = true;
    if (bw.local) e.local = true;
    if (info.ws) e.ws = true;
    if (info.device) e.dev = info.device;         // one of your devices, by its device key
    return e;
  }
}
