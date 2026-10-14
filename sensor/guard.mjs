// The guard: the part of Bulwark that answers for every request, inside the
// host (Aegis × Burrow's gate), synchronously, in microseconds. It decides
// only what can be decided on the spot:
//
//   banned / allowed / yours   from the state the app sends (bans, allow list,
//                              addresses you signed in from, this machine's own)
//   a strong blocklist         banned on sight (the lists, parsed off the main thread)
//   payloads                   dropped (404); two of them, or one from an
//                              address with any mark against it, and it's banned;
//                              during a wave ("strict"), the first one bans
//
// Everything slow (lookups, waves, reports, the logs) happens in the app; the
// guard tells it what it saw and did.

import { isIP, isPrivate, normIp } from "../core/net.mjs";
import { lookupIn, RangeSet } from "../core/lists.mjs";
import { classify } from "../core/payloads.mjs";

const HOUR = 3600e3, DAY = 24 * HOUR;

export class Guard {
  constructor({ log, emit } = {}) {
    this.log = log || (() => {});
    this.emit = emit || (() => {});          // (msg) -> to the app
    this.lists = new Map();
    this.bans = new Map();                   // ip -> {reason, until, source}
    this.allow = new Set();
    this.trusted = new Map();                // ip -> last sign-in
    this.own = new Set();
    this.verdicts = new Map();               // ip -> {bad, benign, level, why}
    this.scores = new Map();                 // ip -> {score, probes, paths, last}
    this.settings = { auto: true, drop: true, lookups: true };
    this.strictUntil = 0;
    this.stats = { requests: 0, blocked: 0, dropped: 0, banned: 0, us: 0 };
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
        this.strictUntil = m.strictUntil || 0;
        break;
      case "ban": this.bans.set(m.ip, m.b); break;
      case "unban": this.bans.delete(m.ip); this.scores.delete(m.ip); break;
      case "allow": if (m.on) { this.allow.add(m.ip); this.bans.delete(m.ip); } else this.allow.delete(m.ip); break;
      case "verdict": this.verdicts.set(m.ip, m.v); if (this.verdicts.size > 50000) this.verdicts.delete(this.verdicts.keys().next().value); break;
      case "settings": this.settings = { ...this.settings, ...m.settings }; break;
      case "own": this.own = new Set(m.list); break;
      case "trust": this.trusted.set(m.ip, m.at || Date.now()); break;
      case "strict": this.strictUntil = m.until || 0; break;
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
    const sig = classify(info.path);
    if (sig.score) { bw.sig = sig.id; bw.sc = sig.score; }
    let tr = null;
    const trusted = () => {
      if (tr === null) { tr = this.isTrusted(ip) || !!info.trusted?.(); if (tr) this.trust(ip); }
      bw.auth = tr;
      return tr;
    };
    // this machine's own address: other people's traffic leaves through it
    // (Mysterium, proxyware), so it is neither trusted nor banned by address
    if (this.own.has(ip)) {
      bw.own = true;
      if (sig.score === 3 && this.settings.drop && !trusted()) return this.drop(bw, "a payload from this machine's own address");
      return null;
    }
    const now = Date.now();
    const ban = this.bans.get(ip);
    if (ban && (!ban.until || ban.until > now)) {
      if (ban.source !== "manual" && trusted()) return null;        // trust() lifted it
      this.stats.blocked++;
      bw.dec = "block"; bw.why = ban.reason;
      return { status: 403, body: "Blocked.", why: ban.reason };
    }
    const lists = lookupIn(this.lists, ip);
    if (lists.length) bw.lists = lists.map((l) => l.id);
    if (!this.settings.auto) {
      if (sig.score === 3 && this.settings.drop && !trusted()) return this.drop(bw, "a payload");
      return null;
    }
    const strong = lists.filter((l) => l.strength === "strong");
    if (strong.length && !trusted()) return this.ban(ip, `on ${strong.map((l) => l.name).join(", ")}`, "list", 7 * DAY, info, bw);
    if (!sig.score) return null;
    if (trusted()) return null;
    const sc = this.scores.get(ip) || { score: 0, probes: 0, paths: [], last: now };
    if (now - sc.last > DAY) { sc.score = 0; sc.probes = 0; sc.paths = []; }
    sc.score += sig.score; sc.probes++; sc.last = now;
    sc.paths.unshift(String(info.path).slice(0, 120)); sc.paths.length = Math.min(sc.paths.length, 8);
    this.scores.set(ip, sc);
    if (this.scores.size > 20000) this.scores.delete(this.scores.keys().next().value);
    const v = this.verdicts.get(ip);
    if (!v?.benign) {
      const marks = lists.filter((l) => l.strength !== "strong").map((l) => (l.id === "tor" ? "is a Tor exit" : `is on ${l.name}`));
      if (v?.bad) marks.push(...v.why.slice(0, 2));
      const strict = sig.score === 3 && now < this.strictUntil;
      if (marks.length || sc.score >= 6 || strict) {
        const why = strict ? `sent a payload (${sc.paths[0]}) during a wave`
          : marks.length ? `${sig.score === 3 ? "sent payloads" : "probed"} (${sc.paths[0]}) and ${marks.join(", ")}`
          : `sent ${sc.probes} payloads (${sc.paths.slice(0, 2).join(", ")})`;
        return this.ban(ip, why, "payload", 30 * DAY, info, bw);
      }
    }
    if (sig.score === 3 && this.settings.drop) return this.drop(bw, "a payload: never reached the app");
    return null;
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
    return { status: 403, body: "Blocked.", why: b.reason };
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
    if (bw.sig) { e.sig = bw.sig; e.sc = bw.sc; }
    if (bw.lists) e.lists = bw.lists;
    if (bw.auth !== undefined) e.auth = bw.auth;
    if (bw.own) e.own = true;
    if (bw.local) e.local = true;
    if (info.ws) e.ws = true;
    return e;
  }
}
