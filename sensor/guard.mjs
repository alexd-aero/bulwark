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
//   shared addresses           (clients.mjs) a school, an office, a home or a
//                              carrier's NAT puts many people behind one address.
//                              One that carries several clients is judged client
//                              by client: scores, behaviour and bans belong to the
//                              client (its address and fingerprint), the address is
//                              banned only when many of its clients attack at once
//                              or it floods, and then for 15 minutes. A strong
//                              listing doesn't ban it on sight; a client you
//                              signed in with is never banned for the others
//   behaviour                  per address (per client on a shared one), in
//                              one-minute windows (bounded): request floods,
//                              4xx-heavy wordlist scanning across many paths, login
//                              hammering (brute force, credential stuffing), method
//                              fuzzing, sweeps through many probes (even when an app
//                              answers 200 to everything), and many kinds of attack
//                              from one client. Counted like hits
//   stuffing campaigns         many addresses each failing a few sign-ins on one
//                              page within minutes: for half an hour that page asks
//                              for a clean reputation (no list, no flag, no hosting
//                              network, nothing scored here; unknown addresses are
//                              scanned first). Nobody is banned for it
//   known services             (GreyNoise "benign": crawlers, research scanners)
//                              aren't banned for probes, behaviour or a list mark;
//                              but two payloads ban even them: an index of leaked
//                              secrets (LeakIX) is no friend of yours
//
// Every decision says why in plain words (info._bw.expl, the log line's expl).
// Everything slow (lookups, waves, reports, the logs) happens in the app; the
// guard tells it what it saw and did.

import { isIP, isPrivate, normIp } from "../core/net.mjs";
import { lookupIn, RangeSet } from "../core/lists.mjs";
import { inspect, verdictOf, signatureById } from "../core/payloads.mjs";
import { Crowds, fingerprint, SHARED_AT } from "./clients.mjs";

const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
const OPEN_BAN_FOR = HOUR;
// A ban earned by score alone (odd requests, probes) with no real attack payload lasts an hour:
// enough to stop a scanner, and one person's odd traffic doesn't lock an address out for a month.
// Payloads keep it 30 days.
const scoreBanFor = (sc) => ((sc?.payloads || 0) >= 1 ? 30 * DAY : HOUR);
export const CLEARED_FOR = 7 * DAY;          // a clean scan lets an address into public tunnels for this long
const SCAN_ASK_EVERY = 10e3;
export const BAN_AT = 10;                    // an address's points that ban it (two payloads)
const PAYLOAD_PTS = 5;                       // what one payload adds, however bad (two ban)
const WINDOW = 60e3;                         // behaviour is counted per address per minute
const MAX_TRACKED = 20000;
// A client behind a shared address: banned for an hour for payloads (15 minutes for a score
// alone), twice as long each time it comes back, a day at most. The address itself: 15 minutes,
// and only when many of its clients attack within ten minutes or it floods.
const CLIENT_BAN_FOR = HOUR, CLIENT_SCORE_BAN_FOR = 15 * MIN, CLIENT_BAN_MAX = DAY;
export const SHARED_BAN_FOR = 15 * MIN;
const ATTACK_WINDOW = 10 * MIN;
const MAX_CLIENT_BANS = 5000, MAX_CLIENT_TRUST = 2000;
// credential stuffing: 20 failed sign-ins on one page within 5-10 minutes, from 8 addresses or
// more, 6 or fewer each (one address hammering is brute force, judged on its own)
const STUFF_WINDOW = 5 * MIN, STUFF_FAILS = 20, STUFF_ADDRS = 8, STUFF_PER = 6, STUFF_HOLD = 30 * MIN, MAX_LOGINS = 256;
// login endpoints: POSTs here are sign-in attempts
const LOGIN = /(^|\/)(wp-login\.php|xmlrpc\.php|login|log-in|signin|sign-in|sign_in|logon|authenticate|auth|session|sessions|j_security_check|j_spring_security_check|owa\/auth\.owa|logincheck|token|oauth\/token|user\/login|users\/sign_in|account\/login|admin\/login|administrator\/index\.php|api\/(v\d+\/)?(auth|login|session|token|signin))(\/|\.php|\.aspx?|\.jsp|\.do|\.action|\?|$)/i;
// answers that say a probed thing isn't here
const notHere = (st, info) => st === 0 || st === 404 || st === 410 || st === 400 || st === 405 || st === 501 || st >= 500 || (st >= 300 && st < 400 && info.access === "login");
const firstSeg = (p) => { const s = String(p || "/"); const e = s.indexOf("/", 1), q = s.indexOf("?"); return s.slice(0, Math.min(e < 0 ? s.length : e, q < 0 ? s.length : q)).slice(0, 60); };
const loginKey = (info) => `${String(info.host || "").toLowerCase().slice(0, 100)} ${String(info.path || "").split("?")[0].toLowerCase().slice(0, 120)}`;
const span = (ms) => (ms >= DAY ? `${Math.round(ms / DAY)} day${ms >= 2 * DAY ? "s" : ""}` : ms >= HOUR ? `${Math.round(ms / HOUR)} hour${ms >= 2 * HOUR ? "s" : ""}` : `${Math.round(ms / MIN)} minutes`);
// who else is behind a shared address, in a few words
function others(n, why) {
  if (why === "marked") return "a network you marked as shared";
  if (why === "mobile") return "a mobile carrier's address, shared by many";
  const k = n - 1;
  return k >= 100 ? "over 100 others use it" : `${k} other${k === 1 ? " uses" : "s use"} it`;
}

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
    this.verdicts = new Map();               // ip -> {bad, benign, level, why, dc, mobile}
    this.cleared = new Map();                // ip -> when a scan found nothing against it (public tunnels let it in)
    this.asked = new Map();                  // ip -> when the app was last asked to scan it
    this.edgeVersion = 0;                    // bumps whenever who may pass changes (Aegis mirrors it to your VPS)
    this.scores = new Map();                 // ip, or ip#client on a shared address -> {score, probes, payloads, paths, last}
    this.behav = new Map();                  // the same keys -> this minute's behaviour: {w, n, nf, lp, lf, segs, meth, fired}
    this.crowds = new Crowds();              // ip -> how many clients it carries (clients.mjs)
    this.clientBans = new Map();             // ip#client -> {reason, until, source, at, ip, n}
    this.clientTrust = new Map();            // ip#device -> when it was last signed in (on a shared address)
    this.probed = new Map();                 // ip#device -> when the host was last asked whether it is signed in
    this.sharedNets = null;                  // RangeSet: networks you marked as shared (settings.sharedNets)
    this.logins = new Map();                 // "host path" -> failed sign-ins there, and from where
    this.settings = { auto: true, drop: true, lookups: true, scanFirst: true, sharedNets: "" };
    this.strictUntil = 0;
    this.stats = { requests: 0, blocked: 0, dropped: 0, banned: 0, clientBans: 0, checks: 0, us: 0 };
    this.onShared = (ip, n) => this.emit({ t: "shared", ip, n });
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
        if (m.clientBans) this.clientBans = new Map(m.clientBans);
        if (m.shared) for (const [ip, s] of m.shared) if (s?.n) this.crowds.known.set(ip, s);
        this.strictUntil = m.strictUntil || 0;
        this.useSharedNets();
        this.edgeVersion++;
        break;
      case "ban": this.bans.set(m.ip, m.b); this.cleared.delete(m.ip); this.edgeVersion++; break;
      // clients: you unbanned it, and the clients banned behind it go too (a sign-in lifting a ban doesn't do that)
      case "unban": this.bans.delete(m.ip); this.scores.delete(m.ip); this.behav.delete(m.ip); if (m.clients) this.forget(m.ip); this.edgeVersion++; break;
      case "clientban": if (m.key && m.b) { this.clientBans.delete(m.key); this.clientBans.set(m.key, { ...m.b, ip: m.ip }); this.trimClientBans(); } break;
      case "clientunban": this.clientBans.delete(m.key); this.scores.delete(m.key); this.behav.delete(m.key); break;
      case "shared": if (m.ip && m.n) this.crowds.remember(m.ip, m.n, m.at || Date.now()); break;
      case "allow": if (m.on) { this.allow.add(m.ip); this.bans.delete(m.ip); } else this.allow.delete(m.ip); this.edgeVersion++; break;
      // a scan found nothing against it: public tunnels let it in
      case "cleared": this.cleared.set(m.ip, m.at || Date.now()); this.asked.delete(m.ip); if (this.cleared.size > 50000) this.cleared.delete(this.cleared.keys().next().value); this.edgeVersion++; break;
      case "verdict": this.verdicts.set(m.ip, m.v); if (this.verdicts.size > 50000) this.verdicts.delete(this.verdicts.keys().next().value); break;
      case "settings": this.settings = { ...this.settings, ...m.settings }; this.useSharedNets(); break;
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
  // networks you marked as shared (Settings: a school's or an office's range), as ranges
  useSharedNets() {
    const s = String(this.settings.sharedNets || "");
    if (s === this.sharedNetsText) return;
    this.sharedNetsText = s;
    const r = new RangeSet();
    for (const x of s.split(/[\s,;]+/)) if (x) r.add(x);
    r.seal();
    this.sharedNets = r.start.length ? r : null;
  }
  // everything kept about the clients behind an address (it was unbanned: a fresh start)
  forget(ip) {
    const p = `${ip}#`;
    for (const m of [this.clientBans, this.scores, this.behav]) for (const k of m.keys()) if (k.startsWith(p)) m.delete(k);
    const rec = this.crowds.get(ip);
    if (rec) rec.att = null;
  }
  trimClientBans() { while (this.clientBans.size > MAX_CLIENT_BANS) this.clientBans.delete(this.clientBans.keys().next().value); }
  // A tunnel with "Check visitors' addresses" off (info.ipChecks === false) judges the
  // request, never the address: what the address is known for elsewhere doesn't
  // stop anyone. A ban you set does, and so does one this address earned by what
  // it sent, for an hour: long enough to stop a scanner, short enough that one
  // person behind a shared school or office address doesn't lock the rest out.
  forgiven(ban, now) { return ban.source !== "manual" && !(ban.source === "payload" && now - (ban.at || 0) < OPEN_BAN_FOR); }
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
  // On a shared address your sign-in vouches for your browser, not for everyone behind the
  // address: the device you signed in with is recognized there for 30 days
  trustClient(cl, now) {
    const k = cl.dkey ||= `${cl.ip}#${cl.fp.dev.toString(36)}`;
    this.clientTrust.delete(k); this.clientTrust.set(k, now);
    if (this.clientTrust.size > MAX_CLIENT_TRUST) this.clientTrust.delete(this.clientTrust.keys().next().value);
    if (this.clientBans.delete(cl.key)) this.emit({ t: "clientunban", ip: cl.ip, key: cl.key });
  }
  clientTrusted(cl, now) { const t = this.clientTrust.get(cl.dkey); return !!t && now - t < 30 * DAY && !this.own.has(cl.ip); }
  // How many clients an address carries, and so what a request is judged as: the address
  // itself, or (shared) the client behind it. -> {ip, fp, n, why, shared, key, dkey, desc}
  client(ip, info, now) {
    const fp = fingerprint(info);
    let n = this.crowds.size(this.crowds.get(ip), ip, now), why = n >= SHARED_AT ? "crowd" : null;
    if (!why && this.sharedNets?.has(ip)) { why = "marked"; n = SHARED_AT; }
    if (!why && this.verdicts.get(ip)?.mobile) { why = "mobile"; n = SHARED_AT; }
    if (!why) return { ip, fp, n, why, shared: false, key: ip, dkey: null, desc: "" };
    const dkey = `${ip}#${fp.dev.toString(36)}`;
    return { ip, fp, n, why, shared: true, dkey, key: fp.id ? `${dkey}.${fp.id.toString(36)}` : dkey, desc: others(n, why) };
  }
  sharedSize(ip) { const now = this.now(); return Math.max(this.crowds.size(this.crowds.get(ip), ip, now), this.sharedNets?.has(ip) || this.verdicts.get(ip)?.mobile ? SHARED_AT : 0); }

  // ------------------------------------------------------------ the check
  // info: {method, path, host, country, trusted: () => bool, headers, session?, tls?, ...}
  // -> null | {status, body, why}. What it found is left on info._bw for observe().
  gate(rawIp, info = {}) {
    const t0 = process.hrtime.bigint();
    const out = this.decide(normIp(rawIp), info);
    this.stats.requests++;
    this.stats.us += Number(process.hrtime.bigint() - t0) / 1000;
    return out;
  }
  decide(ip, info) {
    const bw = (info._bw = { dec: "pass" }), open = info.ipChecks === false;
    if (!isIP(ip) || isPrivate(ip)) { bw.local = true; bw.expl = "a private address: never judged"; return null; }
    if (this.allow.has(ip)) { bw.allowed = true; bw.expl = "on your allow list: never judged"; return null; }
    let sig = inspect(info);
    const now = this.now();
    const cl = this.client(ip, info, now);
    if (cl.shared) { bw.crowd = cl.n; bw.ck = cl.key.slice(cl.key.indexOf("#") + 1); bw.subj = cl.key; }
    if (!sig.id && cl.fp.ua) bw.fp = cl.fp;                      // an ordinary request: once answered, it counts toward the crowd
    let tr = null;
    const trusted = () => {
      if (tr === null) {
        // an address you signed in from is yours, unless others share it: then only your browser is
        if (!cl.shared && this.isTrusted(ip)) { tr = true; this.trust(ip); }
        else if (info.trusted?.()) { tr = true; if (cl.shared) this.trustClient(cl, now); this.trust(ip); }
        else if (cl.shared) { tr = this.clientTrusted(cl, now); if (tr) bw.mine = true; }
        else tr = false;
        bw.auth = tr && !bw.mine;
      }
      return tr;
    };
    const mark = () => {
      if (!sig.id) return;
      bw.sig = sig.id; bw.sc = sig.score; bw.cat = sig.cat; bw.sev = sig.sev; bw.pts = sig.pts;
      if (sig.hits.length > 1) bw.hits = sig.hits.slice(0, 8);
      if (sig.cve) bw.cve = sig.cve;
      if (sig.det) bw.det = String(sig.det).slice(0, 120);
    };
    const yours = () => { bw.expl = bw.mine ? "your browser on a shared address (you signed in with it): never judged" : "yours (signed in, or one of your devices): never judged"; return null; };
    // On a shared address each browser is asked once every ten minutes whether it is signed in
    // (the host's check costs more than the guard's), so yours is known before it is needed
    if (cl.shared && info.trusted && !sig.id) {
      const last = this.probed.get(cl.dkey) || 0;
      if (now - last > 10 * MIN) {
        this.probed.delete(cl.dkey); this.probed.set(cl.dkey, now);
        if (this.probed.size > MAX_CLIENT_TRUST * 2) this.probed.delete(this.probed.keys().next().value);
        trusted();
      }
    }
    // this machine's own address: other people's traffic leaves through it
    // (Mysterium, proxyware), so it is neither trusted nor banned by address
    if (this.own.has(ip)) {
      bw.own = true; mark();
      if (sig.score === 3 && this.settings.drop && !trusted()) { bw.expl = `dropped a payload (${sig.name}): this machine's own address is never banned, but what it sends is judged`; return this.drop(bw, "a payload from this machine's own address"); }
      bw.expl = "this machine's own address: not judged by address";
      return null;
    }
    const ban = this.bans.get(ip);
    if (ban && (!ban.until || ban.until > now) && !(open && this.forgiven(ban, now))) {
      mark();
      if (ban.source !== "manual" && trusted()) return yours();              // trust() lifted it (or it's your browser on a shared address)
      this.stats.blocked++;
      bw.dec = "block"; bw.why = ban.reason; bw.scope = "address";
      bw.expl = `blocked: this address is banned${ban.source === "manual" ? " by you" : ""} (${String(ban.reason).slice(0, 120)})`;
      return { status: 403, body: "Blocked.", why: ban.reason, page: "blocked" };
    }
    if (cl.shared) {
      const cb = this.clientBans.get(cl.key);
      if (cb && cb.until > now && !(open && this.forgiven(cb, now))) {
        mark();
        if (trusted()) return yours();
        this.stats.blocked++;
        bw.dec = "block"; bw.why = cb.reason; bw.scope = "client";
        bw.expl = `blocked this client, not the whole address (${cl.desc}): ${String(cb.reason).slice(0, 120)}`;
        return { status: 403, body: "Blocked.", why: cb.reason, page: "blocked" };
      }
      // the address as a whole: a flood that hurts the host bans it, briefly
      const rec = this.crowds.rec(ip, now), w = Math.floor(now / WINDOW);
      if (rec.w !== w) { rec.w = w; rec.rn = 0; }
      const cap = Math.max(2400, 40 * cl.n);
      if (++rec.rn > cap && !trusted()) { mark(); return this.ban(ip, `a flood: over ${cap} requests a minute from one shared address (${cl.desc})`, "payload", SHARED_BAN_FOR, info, bw, true); }
    }
    const subj = cl.key;
    // behaviour this minute: what the request alone can't show
    const extra = this.behave(subj, info, bw, now, sig);
    if (extra) sig = verdictOf([...(sig.list || []), ...extra]);
    mark();
    const lists = open ? [] : lookupIn(this.lists, ip);
    if (lists.length) bw.lists = lists.map((l) => l.id);
    // a sign-in page under a credential-stuffing campaign asks for a clean reputation
    if (bw.login && (!sig.id || sig.label) && this.logins.size) {
      const c = this.logins.get(loginKey(info));
      if (c && c.until > now && !trusted()) { const r = this.stuffingGate(ip, cl, info, bw, c, lists, now); if (r) return r; }
    }
    // no address check here, so a scanner's name turns it away instead of only labelling it
    if (open && this.settings.drop && sig.list?.some((h) => h.id === "scanner-ua") && !trusted()) { bw.expl = "dropped: a scanner, on a tunnel that judges requests only"; return this.drop(bw, "a scanner"); }
    if (!this.settings.auto) {
      if (sig.score === 3 && this.settings.drop && !trusted()) { bw.expl = `dropped a payload (${sig.name}, ${sig.pts} points): it never reached the app (automatic bans are off)`; return this.drop(bw, "a payload"); }
      return this.scanFirst(ip, info, bw, trusted);
    }
    const strong = lists.filter((l) => l.strength === "strong");
    // A shared address on a strong list (one infected laptop puts a whole school there) isn't banned
    // on sight: the listing is a mark against each of its clients instead
    if (strong.length && !cl.shared && !trusted()) return this.ban(ip, `on ${strong.map((l) => l.name).join(", ")}`, "list", 7 * DAY, info, bw);
    if (!sig.id || sig.label) {                                       // a scanner's name only labels the request: it never adds up to a ban
      const due = this.scores.get(subj);                              // probes the app said weren't here may have tipped it over since
      if (due?.due && now - due.last < DAY && (open || !this.verdicts.get(ip)?.benign) && !trusted()) { due.due = false; return this.banSubject(ip, cl, `scored ${due.score} (${due.paths.slice(0, 2).join(", ")})`, due.payloads >= 1, scoreBanFor(due), info, bw, now); }
      if (bw.mine || bw.auth) return yours();
      if (sig.label) bw.expl = `passed: ${sig.name} (a label, never a ban)`;
      return this.scanFirst(ip, info, bw, trusted);
    }
    if (trusted()) return yours();
    const sc = this.scores.get(subj) || { score: 0, probes: 0, payloads: 0, paths: [], last: now };
    if (now - sc.last > DAY) { sc.score = 0; sc.probes = 0; sc.payloads = 0; sc.paths = []; }
    sc.probes++; sc.last = now;
    if (sig.score === 3) { sc.payloads = (sc.payloads || 0) + 1; sc.score += PAYLOAD_PTS; }
    else if (sig.probe) bw.pend = sig.pts;                           // counted once the app answers "not here" (after())
    else sc.score += sig.pts;
    sc.paths.unshift(String(info.path).slice(0, 120)); sc.paths.length = Math.min(sc.paths.length, 8);
    this.scores.set(subj, sc);
    if (this.scores.size > MAX_TRACKED) this.scores.delete(this.scores.keys().next().value);
    bw.scope = cl.shared ? "client" : "address";
    // many clients of one shared address sending payloads at once: the address, briefly
    if (cl.shared && sig.score === 3) { const esc = this.attacked(ip, cl, now, info, bw); if (esc) return esc; }
    const v = open ? null : this.verdicts.get(ip);
    if (v?.benign && sc.payloads >= 2) {
      return this.banSubject(ip, cl, `hunted secrets (${sc.paths.slice(0, 2).join(", ")}); a known scanner (${(v.why || []).slice(0, 1).join("") || "GreyNoise: benign"}), but not one you want indexing your leaks`, true, 30 * DAY, info, bw, now);
    }
    if (!v?.benign) {
      const marks = lists.filter((l) => cl.shared || l.strength !== "strong").map((l) => (l.id === "tor" ? "is a Tor exit" : `is on ${l.name}`));
      if (v?.bad) marks.push(...v.why.slice(0, 2));
      const strict = sig.score === 3 && now < this.strictUntil;
      const stuffing = extra?.find((h) => h.id === "brute-force" && h.sev === "critical");
      // a listing or a bad lookup turns one hit into a ban only on a hosting address. Home,
      // school and mobile addresses are shared (one NAT, hundreds of people, and DroneBL lists
      // such networks for one infected laptop): there the request is stopped, and a ban takes
      // the address's own score. A client already judged on its own: its listing counts
      const listedBans = marks.length > 0 && (v?.dc !== false || cl.shared && strong.length > 0);
      if (listedBans || sc.score >= BAN_AT || strict || stuffing) {
        const what = sig.cat ? ` [${sig.cat}${sig.cve ? ` ${sig.cve}` : ""}]` : "";
        const why = stuffing ? `${stuffing.why}${marks.length ? ` and ${marks.join(", ")}` : ""}`
          : strict ? `sent a payload (${sc.paths[0]})${what} during a wave`
          : listedBans ? `${sig.score === 3 ? "sent payloads" : "probed"} (${sc.paths[0]})${what} and ${marks.join(", ")}`
          : sc.payloads >= 2 ? `sent ${sc.payloads} payloads (${sc.paths.slice(0, 2).join(", ")})${what}`
          : `scored ${sc.score} (${sc.paths.slice(0, 2).join(", ")})${what}`;
        return this.banSubject(ip, cl, why, sc.payloads >= 1 || listedBans || strict || !!stuffing, listedBans || strict || stuffing ? 30 * DAY : scoreBanFor(sc), info, bw, now);
      }
    }
    const whose = cl.shared ? `this client (not the whole address: ${cl.desc})` : "this address";
    if (sig.score === 3 && this.settings.drop) {
      bw.expl = `dropped a payload (${sig.name}, ${sig.pts} points): it never reached the app; ${whose} has ${sc.score} of ${BAN_AT} points`;
      return this.drop(bw, "a payload: never reached the app");
    }
    bw.expl = sig.probe ? `passed: ${sig.name} (a probe: it counts against ${whose} only if the app says it isn't here)` : `passed: ${sig.name} (${sig.pts} points against ${whose}, ${sc.score} of ${BAN_AT})`;
    return this.scanFirst(ip, info, bw, trusted);
  }
  // A ban for what was sent: the address, or on a shared one the client behind it.
  // heavy: payloads (or a mark) rather than a score alone; ttl: the address's ban
  banSubject(ip, cl, why, heavy, ttl, info, bw, now) {
    if (!cl.shared) return this.ban(ip, why, "payload", ttl, info, bw);
    const prev = this.clientBans.get(cl.key);
    const n = (prev?.n || 0) + 1;
    const len = Math.min(CLIENT_BAN_MAX, (heavy ? CLIENT_BAN_FOR : CLIENT_SCORE_BAN_FOR) * 2 ** Math.min(n - 1, 6));
    const b = { reason: String(why).slice(0, 300), until: now + len, source: "payload", at: now, ip, n, crowd: cl.n };
    this.clientBans.delete(cl.key); this.clientBans.set(cl.key, b); this.trimClientBans();
    this.stats.banned++; this.stats.clientBans++;
    bw.dec = "ban"; bw.why = b.reason; bw.scope = "client";
    bw.expl = `banned this client for ${span(len)}, not the whole address (${cl.desc}): ${b.reason.slice(0, 120)}`;
    b.expl = bw.expl;
    this.emit({ t: "clientban", ip, key: cl.key, b, info: { host: info.host || "", country: info.country || "", path: String(info.path || "").slice(0, 200), ua: String(info.ua || "").slice(0, 200) } });
    const esc = this.attacked(ip, cl, now, info, bw);
    return esc || { status: 403, body: "Blocked.", why: b.reason, page: "blocked" };
  }
  // A client of a shared address attacked (a payload, or a ban): if many different ones did within
  // ten minutes (at least 4, and half of those it carries, up to 64), it is the address that attacks:
  // banned for 15 minutes. One student probing never gets there; a scanner that changes its
  // User-Agent on every request does
  attacked(ip, cl, now, info, bw) {
    const rec = this.crowds.rec(ip, now);
    const att = (rec.att ||= new Map());
    att.delete(cl.key); att.set(cl.key, now);
    for (const [k, t] of att) { if (now - t <= ATTACK_WINDOW && att.size <= 128) break; att.delete(k); }
    const need = Math.max(4, Math.min(64, Math.ceil(cl.n / 2))), was = this.bans.get(ip);
    if (att.size < need || (was && (!was.until || was.until > now))) return null;
    const many = att.size;
    rec.att = null;
    return this.ban(ip, `${many} different clients behind this shared address attacked within ${ATTACK_WINDOW / MIN} minutes (${cl.desc})`, "payload", SHARED_BAN_FOR, info, bw, true);
  }
  // This minute's behaviour for an address (a client, on a shared one): counted here
  // (requests, methods, sign-in attempts) and in after() (what the app answered).
  // Each signal fires once a window. -> null | [hits]
  behave(ip, info, bw, now, sig) {
    const w = Math.floor(now / WINDOW);
    let b = this.behav.get(ip);
    if (!b) {
      b = { w, n: 0, nf: 0, lp: 0, lf: 0, segs: null, meth: 0, fired: 0, pr: null, cats: null };
      this.behav.set(ip, b);
      if (this.behav.size > MAX_TRACKED) this.behav.delete(this.behav.keys().next().value);
    } else if (b.w !== w) { b.w = w; b.n = 0; b.nf = 0; b.lp = 0; b.lf = 0; b.segs = null; b.meth = 0; b.fired = 0; b.pr = null; b.cats = null; }
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
    // what the requests themselves asked for, this minute: a sweep through many probes
    // (an app that answers 200 to everything never says "not here"), or many kinds of attack
    if (sig?.id && !sig.label && sig.pts > 0) {
      if (sig.probe) { if (!b.pr) b.pr = new Set(); if (b.pr.size < 32) b.pr.add(firstSeg(info.path) + "|" + sig.id + "|" + String(info.path).length); }
      if (sig.cat && sig.cat !== "bot") { if (!b.cats) b.cats = new Set(); for (const h of sig.list || []) if (h.cat && h.cat !== "bot" && h.cat !== "dos" && h.cat !== "protocol" && (h.sev !== "info")) b.cats.add(h.cat); }
      if (b.pr && b.pr.size >= 8) fire(32, H("probe-sweep", "high", `${b.pr.size} different probes in a minute`));
      if (b.cats && b.cats.size >= 4) fire(64, H("multi-vector", "high", `${b.cats.size} kinds of attack in a minute (${[...b.cats].slice(0, 5).join(", ")})`));
    }
    return out;
  }
  // When the response is done (the host's observe): what the app answered.
  // A probe counts only if the thing isn't here; 4xx answers feed the
  // wordlist-scanning, brute-force and stuffing-campaign signals; an ordinary
  // request the app served counts toward the address's crowd.
  after(ip, info, res = {}) {
    const bw = info._bw;
    if (!bw || bw.local || bw.allowed) return;
    const st = Number(res.status) || 0;
    if (bw.fp && st > 0 && st < 400) this.crowds.learn(normIp(ip), bw.fp, this.now(), this.onShared);
    if (bw.auth || bw.mine) return;
    const b = bw.b;
    if (b && st >= 400) {
      b.nf++;
      if (st === 404 || st === 410) { if (!b.segs) b.segs = new Set(); if (b.segs.size < 64) b.segs.add(firstSeg(info.path)); }
      if (bw.login) b.lf++;
    }
    if (bw.pend && notHere(st, info)) {
      const sc = this.scores.get(bw.subj || normIp(ip));
      if (sc) { sc.score += bw.pend; if (sc.score >= BAN_AT) sc.due = true; }
    }
    if (bw.login && st >= 400 && bw.dec === "pass") this.loginFailed(normIp(ip), info, this.now());
  }
  // A failed sign-in, counted per page: many addresses, a few tries each, is a campaign.
  // The app hears of it once (a wave of its own); the page stays strict for half an
  // hour after the last failure that kept it going.
  loginFailed(ip, info, now) {
    const key = loginKey(info), w = Math.floor(now / STUFF_WINDOW);
    let c = this.logins.get(key);
    if (!c) {
      c = { host: String(info.host || "").slice(0, 100), path: String(info.path || "").split("?")[0].slice(0, 120), w, f: 0, pf: 0, a: new Set(), pa: null, until: 0, since: 0 };
      this.logins.set(key, c);
      if (this.logins.size > MAX_LOGINS) this.logins.delete(this.logins.keys().next().value);
    }
    if (c.w !== w) { if (c.w === w - 1) { c.pf = c.f; c.pa = c.a; } else { c.pf = 0; c.pa = null; } c.w = w; c.f = 0; c.a = new Set(); }
    c.f++;
    if (c.a.size < 64) c.a.add(ip);
    const fails = c.f + c.pf;
    if (fails < STUFF_FAILS) return;
    let addrs = c.a.size;
    if (c.pa) for (const x of c.pa) if (!c.a.has(x)) addrs++;
    if (addrs < STUFF_ADDRS || fails > STUFF_PER * addrs) return;
    const fresh = c.until <= now;
    c.until = now + STUFF_HOLD;
    if (fresh) {
      c.since = now;
      this.emit({ t: "stuffing", host: c.host, path: c.path, fails, addresses: addrs, members: [...new Set([...c.a, ...(c.pa || [])])].slice(0, 50), since: now, until: c.until });
    }
  }
  // A sign-in on a page under a stuffing campaign: through if the address has a clean
  // reputation, refused (429, nobody banned) if anything is against it, held for a scan
  // if nothing is known about it yet.
  stuffingGate(ip, cl, info, bw, c, lists, now) {
    const v = this.verdicts.get(ip), sc = this.scores.get(cl.key);
    const marks = [];
    if (lists.length) marks.push(`is on ${lists.map((l) => l.name).join(", ")}`);
    if (v?.bad) marks.push(`was flagged (${(v.why || [])[0] || v.level})`);
    if (v?.dc) marks.push("is on a hosting network");
    if (sc && now - sc.last < DAY && sc.score > 0) marks.push(`scored ${sc.score} here today`);
    if (bw.b && bw.b.lf >= 3) marks.push(`failed ${bw.b.lf} sign-ins this minute`);
    const page = `${c.path} on ${c.host || "this host"}`;
    if (marks.length) {
      c.until = Math.max(c.until, now + STUFF_HOLD);                 // refused attempts are the campaign going on
      this.stats.blocked++;
      bw.dec = "block"; bw.why = `credential stuffing on ${c.path}: a sign-in refused (${cl.shared ? "this client" : "this address"} ${marks[0]})`;
      bw.expl = `refused a sign-in, nobody banned: ${page} is under a credential-stuffing campaign, so it asks for a clean reputation, and ${cl.shared ? "this client" : "this address"} ${marks.join(", ")}`;
      return { status: 429, body: "Too many sign-in attempts here right now. Try again in a few minutes.", why: bw.why, retry: 300 };
    }
    if (this.isCleared(ip) || (v && !v.bad && !v.dc) || v?.benign || !this.settings.lookups) return null;
    this.askScan(ip);
    this.stats.checks++;
    bw.dec = "check"; bw.why = `credential stuffing on ${c.path}: the address is scanned before it may sign in`;
    bw.expl = `held a sign-in for a scan: ${page} is under a credential-stuffing campaign, and nothing is known about this address yet`;
    return { status: 403, body: "Checking your address first. Try again in a few seconds.", why: "not scanned yet", page: "checking", retry: 2 };
  }
  askScan(ip) {
    const asked = this.asked.get(ip) || 0;
    if (Date.now() - asked <= SCAN_ASK_EVERY) return;
    this.asked.set(ip, Date.now());
    if (this.asked.size > 20000) this.asked.delete(this.asked.keys().next().value);
    this.emit({ t: "scan", ip });
  }
  isCleared(ip) { const t = this.cleared.get(ip); return !!t && Date.now() - t < CLEARED_FOR; }
  // A public tunnel lets in only addresses that are yours, or that a scan found
  // nothing against. Anyone else gets a "checking" page (403, it reloads by
  // itself) while the app scans them first in line; one the scan flagged is blocked.
  scanFirst(ip, info, bw, trusted) {
    if (info.ipChecks === false || info.access !== "public" || !this.settings.scanFirst || trusted() || this.isCleared(ip)) return null;
    const v = this.verdicts.get(ip);
    if (v?.benign) return null;
    this.stats.checks++;
    if (v?.bad) {
      bw.dec = "block"; bw.why = `flagged by the scan: ${(v.why || []).slice(0, 2).join(", ") || v.level}`;
      bw.expl = `blocked before a public tunnel: ${bw.why}`;
      return { status: 403, body: "Blocked.", why: bw.why, page: "blocked" };
    }
    this.askScan(ip);
    bw.dec = "check"; bw.why = "not scanned yet: checked before a public tunnel";
    bw.expl = "held until the address is scanned: a public tunnel lets in only addresses with nothing against them";
    return { status: 403, body: "Checking your address first. Try again in a few seconds.", why: "not scanned yet", page: "checking", retry: 2 };
  }
  // who may pass, for a relay in front (Aegis mirrors it to your VPS): addresses only
  // (a client ban behind a shared address is this machine's to keep)
  // openTunnels: some tunnel doesn't check addresses. The relay turns banned addresses
  // away for every name it carries, so it only gets the bans that tunnel keeps too;
  // this machine still applies the rest to the other tunnels.
  edge({ openTunnels = false } = {}) {
    const now = Date.now();
    const fresh = (m, ttl) => [...m].filter(([ip, t]) => now - t < ttl && !this.own.has(ip)).map(([ip]) => ip);
    return { version: this.edgeVersion, on: !!this.settings.scanFirst,
             cleared: [...new Set([...fresh(this.cleared, CLEARED_FOR), ...fresh(this.trusted, 30 * DAY), ...this.allow])],
             banned: [...this.bans].filter(([ip, b]) => (!b.until || b.until > now) && !this.allow.has(ip) && !this.isTrusted(ip) && !(openTunnels && this.forgiven(b, now))).map(([ip]) => ip) };
  }
  drop(bw, why) {
    this.stats.dropped++;
    bw.dec = "drop"; bw.why = why;
    bw.expl ||= `dropped: ${why}`;
    return { status: 404, body: "Not found", why: "payload" };
  }
  // shared: a ban on a shared address for what many of its clients did (brief)
  ban(ip, reason, source, ttl, info, bw, shared = false) {
    const now = Date.now();
    const b = { reason: String(reason).slice(0, 300), until: ttl ? now + ttl : null, source, at: now };
    if (shared) b.shared = true;
    this.bans.set(ip, b);
    this.stats.banned++;
    bw.dec = "ban"; bw.why = b.reason; bw.scope = "address";
    bw.expl = shared ? `banned the whole shared address for ${span(ttl)}: ${b.reason.slice(0, 160)}` : `banned this address${ttl ? ` for ${span(ttl)}` : ""}: ${b.reason.slice(0, 160)}`;
    b.expl = bw.expl;
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
    if (bw.sig && !bw.auth && !bw.mine) {         // your own requests are never attacks, not even as labels
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
    if (bw.mine) e.mine = true;
    if (bw.own) e.own = true;
    if (bw.local) e.local = true;
    if (info.ws) e.ws = true;
    if (info.device) e.dev = info.device;         // one of your devices, by its device key
    // why, in plain words (a plain pass has none: nothing was against it), and who was judged
    if (bw.expl) e.expl = bw.expl;
    if (bw.scope) e.scope = bw.scope;
    if (bw.crowd) { e.crowd = bw.crowd; e.ck = bw.ck; }
    return e;
  }
}
