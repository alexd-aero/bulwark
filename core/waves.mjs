// Waves: warning when many addresses move together, before (and while) they hit.
//
//   surge       new addresses (or attacks) per minute far above what is normal
//               here: an EWMA baseline of mean and variance, learned only from
//               finished minutes; z ≥ 4 warns, z ≥ 8 is critical
//   campaign    several addresses running the same play: the same sequence of
//               payload patterns, with the same kind of client, within an hour.
//               Two within ten minutes is an early warning ("forming")
//   network     several probing addresses from one network (AS), one /24 or one /16
//   discovery   a name that only you used is suddenly found by others: the
//               first strangers, then a crowd within 15 minutes (how a new
//               name in the certificate logs looks)
//
// Every open alert carries a forecast: how fast members arrive, and how many
// more to expect in the next hour at that rate (with the trend). Any critical
// alert puts the guard in strict mode (a first payload bans) while it lasts.

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { netOf } from "./net.mjs";
import { signatureById } from "./payloads.mjs";

const MIN = 60e3;
const SEV = { info: 0, warn: 1, critical: 2 };
const FEATURES = { newIp: { label: "new addresses", min: [5, 15] }, attacks: { label: "payloads and probes", min: [10, 30] } };

export function clientKind(ua) {
  const u = String(ua || "").toLowerCase();
  if (!u) return "none";
  for (const [k, re] of [["curl", /curl\//], ["python", /python|aiohttp|httpx|scrapy/], ["go", /go-http-client|\bgo\//], ["java", /java\/|okhttp|apache-httpclient/],
                         ["node", /node-fetch|axios|undici|node\.js/], ["scanner", /zgrab|masscan|nmap|nuclei|nikto|sqlmap|censys|shodan|leakix|expanse|internet-measurement/],
                         ["wget", /wget/], ["headless", /headlesschrome|phantomjs|puppeteer|playwright/], ["bot", /bot|crawl|spider|slurp/],
                         ["browser", /mozilla\/5\.0/]]) if (re.test(u)) return k;
  return "other";
}

// ip -> last seen, oldest first. A request costs a few steps however big the
// wave is: refresh moves the address to the end, the stale end is trimmed,
// and no map holds more than PER_KEY addresses.
const PER_KEY = 2000;
function track(m, ip, t, keep) {
  m.delete(ip); m.set(ip, t);
  for (const [old, at] of m) { if (t - at <= keep && m.size <= PER_KEY) break; m.delete(old); }
}
function prune(m, since) { for (const [ip, at] of m) { if (at >= since) break; m.delete(ip); } }
function countSince(m, since) {
  let n = 0;
  for (const at of [...m.values()].reverse()) { if (at < since) break; n++; }   // newest last; stops at the first old one
  return n;
}

export class Waves {
  constructor({ file, onAlert, now = () => Date.now() }) {
    this.file = file; this.onAlert = onAlert || (() => {}); this.now = now;
    this.alerts = new Map();          // key -> alert
    this.base = {};                   // feature -> {mean, var, n}
    this.lastMinute = 0;
    this.fps = new Map();             // fingerprint -> Map(ip -> t)
    this.nets = new Map();            // "as:123" | "net:1.2.3.0/24" -> Map(ip -> t)
    this.hosts = new Map();           // host -> {mine: t, found: t|null, strangers: Map(ip -> t)}
    try {
      const s = JSON.parse(readFileSync(file, "utf8"));
      this.alerts = new Map(s.alerts || []); this.base = s.base || {};
      this.hosts = new Map((s.hosts || []).map(([h, x]) => [h, { ...x, strangers: new Map(x.strangers || []) }]));
    } catch { /* first run */ }
  }
  save() {
    const hosts = [...this.hosts].map(([h, x]) => [h, { ...x, strangers: [...x.strangers].slice(-50) }]);
    const alerts = [...this.alerts].sort((a, b) => b[1].last - a[1].last).slice(0, 300);
    try { writeFileSync(this.file + ".tmp", JSON.stringify({ alerts, base: this.base, hosts })); renameSync(this.file + ".tmp", this.file); } catch { /* next time */ }
  }

  // ------------------------------------------------------------ one request
  // e: the log line; p: the address's profile; isNew: first time seen; mine: one of yours
  feed(e, p, isNew, mine) {
    const t = e.t;
    // discovery: names used only by you, then found by strangers
    if (e.host && !e.local) {
      let h = this.hosts.get(e.host);
      if (!h) { h = { mine: mine ? t : 0, found: null, strangers: new Map() }; this.hosts.set(e.host, h); }
      if (mine) h.mine = t;
      else {
        if (!h.strangers.has(e.ip)) {
          h.strangers.set(e.ip, t);
          if (h.strangers.size > 200) h.strangers.delete(h.strangers.keys().next().value);
          if (!h.found && h.mine) h.found = t;          // it had been yours alone until now
          if (h.found && t - h.found < 15 * MIN) {
            const crowd = [...h.strangers].filter(([, at]) => at >= h.found);
            if (crowd.length >= 2) this.raise(`discovery:${e.host}`, {
              kind: "discovery", sev: crowd.length >= 5 ? "critical" : crowd.length >= 3 ? "warn" : "info",
              title: `${e.host} was just found`,
              detail: `${crowd.length} strangers in ${Math.max(1, Math.round((t - h.found) / MIN))} min after the first; until ${new Date(h.found).toLocaleString()} only you used it. New names usually leak through the public certificate logs.`,
              members: crowd.map(([ip]) => ip), host: e.host,
            }, t);
          }
        }
      }
      if (this.hosts.size > 2000) this.hosts.delete(this.hosts.keys().next().value);
    }
    if (mine || !e.sig) return;
    // campaign: the same play from several addresses
    const seq = p.seq.slice(0, 3);
    if (seq.some((s) => signatureById(s)?.score === 3)) {
      const fp = `${seq.join(">")}|${clientKind(e.ua)}`;
      const m = this.fps.get(fp) || new Map();
      track(m, e.ip, t, 60 * MIN); this.fps.set(fp, m);
      if (this.fps.size > 2000) this.fps.delete(this.fps.keys().next().value);
      const n = m.size, recent = countSince(m, t - 10 * MIN);
      if (n >= 3 || recent >= 2) {
        const names = seq.map((s) => signatureById(s)?.name || s).join(" → ");
        this.raise(`campaign:${fp}`, {
          kind: "campaign", sev: n >= 6 ? "critical" : n >= 3 ? "warn" : "info",
          title: n >= 3 ? `Campaign: ${n} addresses running the same attack` : "A campaign may be forming",
          detail: `${names}, from ${clientKind(e.ua) === "none" ? "clients with no user agent" : clientKind(e.ua) + " clients"}.`,
          members: this.joined(`campaign:${fp}`, m, e.ip), fingerprint: fp,
        }, t);
      }
    }
    // network: probing addresses from one AS or one /24
    for (const key of [e.asn ? `as:${e.asn}` : null, `net:${netOf(e.ip)}`, `net:${netOf(e.ip, true)}`]) {
      if (!key || key === "net:null") continue;
      const m = this.nets.get(key) || new Map();
      track(m, e.ip, t, 30 * MIN); this.nets.set(key, m);
      if (this.nets.size > 5000) this.nets.delete(this.nets.keys().next().value);
      const need = key.startsWith("as:") ? 4 : 3;
      if (m.size >= need) {
        const label = key.startsWith("as:") ? `${e.org || "AS" + e.asn} (AS${e.asn})` : key.slice(4);
        this.raise(`network:${key}`, {
          kind: "network", sev: m.size >= need * 2 ? "critical" : "warn",
          title: `${m.size} addresses from ${label} probing`, detail: `within 30 minutes, from one ${key.startsWith("as:") ? "network" : key.endsWith("/16") ? "/16" : "/24"}.`,
          members: this.joined(`network:${key}`, m, e.ip), network: label,
        }, t);
      }
    }
  }

  // ------------------------------------------------------------ every 30 s
  // minutes: Series.lastMinutes(n), the last one still running
  tick(minutes) {
    const t = this.now();
    const done = minutes.slice(0, -1), cur = minutes[minutes.length - 1];
    const val = (b, f) => (f === "attacks" ? (b.payload || 0) + (b.probe || 0) : b[f] || 0);
    // learn from finished minutes we haven't seen
    for (const b of done) {
      if (b.k <= this.lastMinute) continue;
      this.lastMinute = b.k;
      for (const f of Object.keys(FEATURES)) {
        const x = val(b, f), s = (this.base[f] ||= { mean: x, var: 1, n: 0 });
        const a = s.n < 60 ? 1 / (s.n + 1) : 0.02;                  // quick at first, then a ~50 minute memory
        const d = x - s.mean;
        s.mean += a * d; s.var = (1 - a) * (s.var + a * d * d); s.n++;
      }
    }
    // the last finished minute and the running one (scaled up), against the baseline
    for (const [f, spec] of Object.entries(FEATURES)) {
      const s = this.base[f];
      if (!s || s.n < 30) continue;                                   // not enough history yet
      const lastDone = done.length ? val(done[done.length - 1], f) : 0;
      const frac = Math.max(0.25, (t % MIN) / MIN), running = val(cur, f) / frac;
      const x = Math.max(lastDone, running);
      const z = (x - s.mean) / Math.sqrt(s.var + 1);
      const sev = z >= 8 && x >= spec.min[1] ? "critical" : z >= 4 && x >= spec.min[0] ? "warn" : null;
      if (sev) this.raise(`surge:${f}`, {
        kind: "surge", sev, title: `Surge of ${spec.label}`,
        detail: `${Math.round(x)} a minute against a usual ${s.mean.toFixed(1)} (${z.toFixed(1)} standard deviations).`, rate: Math.round(x), z: Math.round(z * 10) / 10,
      }, t);
    }
    // forget addresses gone quiet (per request only the cheap end is trimmed)
    for (const [k, m] of this.fps) { prune(m, t - 60 * MIN); if (!m.size) this.fps.delete(k); }
    for (const [k, m] of this.nets) { prune(m, t - 30 * MIN); if (!m.size) this.nets.delete(k); }
    // forecasts, and close what has gone quiet
    for (const a of this.alerts.values()) {
      if (!a.open) continue;
      const quiet = a.kind === "surge" ? 10 * MIN : 30 * MIN;
      if (t - a.last > quiet) { a.open = false; a.closed = t; this.onAlert(a, "closed"); continue; }
      a.forecast = this.forecast(a, t);
    }
  }
  forecast(a, t) {
    const times = (a.arrivals || []).filter((x) => t - x < 30 * MIN);
    if (times.length < 2) return null;
    const half = t - 15 * MIN, early = times.filter((x) => x < half).length, late = times.length - early;
    const perHour = (late / 15) * 60;
    return { perHour: Math.round(perHour), nextHour: Math.round(perHour), trend: late > early * 1.3 ? "rising" : late < early * 0.7 ? "falling" : "steady" };
  }

  // who to add to an alert: everyone so far when it opens (at most 300), then only the newcomer
  joined(key, m, ip) { return this.alerts.get(key)?.open ? [ip] : [...m.keys()].slice(-300); }

  // open or update an alert; tell the app when it is new or got worse
  raise(key, x, t) {
    let a = this.alerts.get(key);
    const fresh = !a || !a.open;
    if (fresh) a = { id: `${key}|${t}`, key, first: t, arrivals: [], members: [], open: true, sev: "info" };
    const before = SEV[a.sev] ?? 0;
    if (!(a.known instanceof Set)) Object.defineProperty(a, "known", { value: new Set(a.members || []), writable: true, enumerable: false, configurable: true });
    const knew = a.known;
    const added = (x.members || []).filter((ip) => !knew.has(ip));
    for (const ip of added) { a.arrivals.push(t); knew.add(ip); }
    if (a.arrivals.length > 500) a.arrivals.splice(0, a.arrivals.length - 500);
    // members: the last 300 addresses, kept in step with `known` (a wave of
    // 50,000 addresses must not cost 50,000 steps a request)
    const members = added.length ? [...(a.members || []), ...added] : (a.members || []);
    if (members.length > 300) for (const ip of members.splice(0, members.length - 300)) knew.delete(ip);
    Object.assign(a, x, { last: t, members });
    a.sev = SEV[x.sev] >= before ? x.sev : a.sev;
    a.forecast = this.forecast(a, t);
    this.alerts.set(key, a);
    if (this.alerts.size > 400) {
      // closed ones first; in a huge wave the quietest open one goes too
      let oldest = null, oldestOpen = null;
      for (const y of this.alerts.values()) {
        if (y.key === key) continue;
        if (!y.open) { if (!oldest || y.last < oldest.last) oldest = y; }
        else if (y.sev !== "critical" && (!oldestOpen || y.last < oldestOpen.last)) oldestOpen = y;
      }
      const drop = oldest || (this.alerts.size > 600 ? oldestOpen : null);
      if (drop) this.alerts.delete(drop.key);
    }
    if (fresh) this.onAlert(a, "new"); else if (SEV[a.sev] > before) this.onAlert(a, "worse");
    return a;
  }
  open() { return [...this.alerts.values()].filter((a) => a.open).sort((a, b) => SEV[b.sev] - SEV[a.sev] || b.last - a.last); }
  list(limit = 100) { return [...this.alerts.values()].sort((a, b) => b.last - a.last).slice(0, limit).map(({ arrivals, ...a }) => a); }
  critical() { return this.open().some((a) => a.sev === "critical"); }
  baseline() { return this.base; }
}
