// Who is behind an address. A school, an office, a home with a few people in it
// or a mobile carrier's NAT puts many people behind one public address, and
// banning the address for what one of them did locks out all the others. So
// the guard learns how many clients each address carries, and judges a shared
// one client by client.
//
//   fingerprint   what a client says about itself the same way on every request:
//                 its User-Agent, its Accept-Language, the shape of its headers (a
//                 browser sends Sec-Fetch-*, a script rarely does; requests puts
//                 Accept-Encoding before Accept), TLS details when the host passes
//                 them (info.tls). A second part tells identical machines apart (a
//                 school's laptops are one model, one browser version): the session
//                 the host names (info.session), or a long-lived id cookie
//   crowd         per address, per hour: how many different fingerprints made more
//                 than one ordinary request (a scanner that changes its User-Agent on
//                 every request adds nothing), and the most it has had in a week.
//                 What the app remembers (shared addresses it was told about), the
//                 networks you marked as shared and mobile carriers count too
//
// Everything is bounded: 20 000 addresses, 128 fingerprints each, 5000 remembered.

const HOUR = 3600e3, DAY = 24 * HOUR;
export const SHARED_AT = 2;                  // clients behind one address that make it shared
const PEAK_MINS = 7 * DAY / 60e3;            // a crowd is remembered at its peak this long (in minutes: a small integer)
const mins = (t) => Math.floor(t / 60e3);
const MAX_ADDRS = 20000, MAX_PER = 128, MAX_KNOWN = 5000;

// FNV-1a, 32 bits: fast, and good enough to tell clients apart
export function fnv(s, h = 0x811c9dc5) {
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}
// long-lived ids: a session (Aegis's own, PHP, Java, Express, ASP.NET) or Google Analytics' client id
const ID_COOKIE = /(?:^|;\s*)(?:__Host-aegis|aegis|_ga|PHPSESSID|JSESSIONID|connect\.sid|sid|sessionid|session_id|ASP\.NET_SessionId)=([^;\s]{8,256})/i;

// -> {dev, id}: dev the device (never 0), id the identity on it (0: none seen)
export function fingerprint(info) {
  const h = info.headers;
  const ua = info.ua ?? h?.["user-agent"] ?? "";
  let lang = h ? h["accept-language"] : undefined;
  if (lang === undefined) lang = info.lang || "";
  let shape = 1;
  if (h) {
    if (h["sec-fetch-mode"] !== undefined) shape |= 2;
    if (h.accept !== undefined) {
      shape |= 4;
      if (h["accept-encoding"] !== undefined) for (const k in h) { if (k === "accept") break; if (k === "accept-encoding") { shape |= 8; break; } }
    }
  }
  let dev = fnv(String(lang), fnv(String(ua), (0x811c9dc5 ^ shape) >>> 0));
  if (info.tls) dev = fnv(String(info.tls), dev);
  let id = 0;
  if (typeof info.session === "string" && info.session) id = (fnv(info.session) & 0x3fffffff) || 1;
  else if (h?.cookie) { const m = ID_COOKIE.exec(String(h.cookie)); if (m) id = (fnv(m[1]) & 0x3fffffff) || 1; }
  return { dev: (dev & 0x3fffffff) || 1, id, ua: !!ua };       // 30 bits: small integers, no boxed numbers in the maps
}

// distinct values seen at least twice, exactly (up to MAX_PER of them)
class Twice {
  constructor() { this.f = 0; this.fc = 0; this.m = null; this.n = 0; }
  add(x) {
    if (!this.m) {
      if (!this.f) { this.f = x; this.fc = 1; return; }
      if (this.f === x) { if (this.fc === 1) { this.fc = 2; this.n = 1; } return; }
      this.m = new Map([[this.f, this.fc]]);
    }
    const c = this.m.get(x);
    if (c === undefined) {
      // full: the ones seen only once go (a scanner's rotating User-Agents), the real clients stay
      if (this.m.size >= MAX_PER) { for (const [k, v] of this.m) if (v === 1) this.m.delete(k); if (this.m.size >= MAX_PER) return; }
      this.m.set(x, 1);
    } else if (c === 1) { this.m.set(x, 2); this.n++; }
  }
}

export class Crowds {
  constructor() {
    this.map = new Map();        // ip -> {p, dev: Twice, ids: Twice|null, peak, peakAt, said, att, w, rn}
    this.known = new Map();      // ip -> {n, at}: shared addresses the app remembers (or this guard learned)
  }
  get(ip) { return this.map.get(ip) || null; }
  // what this address has carried: now, at its peak this week, as remembered
  size(rec, ip, now) {
    let n = 0;
    if (rec) {
      if (rec.p === Math.floor(now / HOUR)) n = Math.max(rec.dev.n, rec.ids ? rec.ids.n : 0);
      if (mins(now) - rec.peakAt < PEAK_MINS && rec.peak > n) n = rec.peak;
    }
    const k = this.known.get(ip);
    if (k && now - k.at < 30 * DAY && k.n > n) n = k.n;
    return n;
  }
  // an ordinary request from this client: counted -> the address's record
  // (onShared(ip, n) when it has just become shared, or doubled)
  learn(ip, fp, now, onShared) {
    let rec = this.map.get(ip);
    const p = Math.floor(now / HOUR);
    if (!rec) {
      rec = { p, dev: new Twice(), ids: null, peak: 0, peakAt: 0, said: 0, att: null, w: 0, rn: 0 };
      this.map.set(ip, rec);
      if (this.map.size > MAX_ADDRS) this.map.delete(this.map.keys().next().value);
    } else if (rec.p !== p) {
      const was = Math.max(rec.dev.n, rec.ids ? rec.ids.n : 0);
      if (was >= rec.peak || mins(now) - rec.peakAt >= PEAK_MINS) { rec.peak = was; rec.peakAt = mins(now); }
      rec.p = p; rec.dev = new Twice(); rec.ids = null;
    }
    rec.dev.add(fp.dev);
    if (fp.id) (rec.ids ||= new Twice()).add((fp.dev ^ fp.id) || 1);
    const n = Math.max(rec.dev.n, rec.ids ? rec.ids.n : 0);
    if (n > rec.peak) { rec.peak = n; rec.peakAt = mins(now); }
    if (n >= SHARED_AT && n >= 2 * (rec.said || 1)) {
      rec.said = n;
      this.remember(ip, n, now);
      onShared?.(ip, n);
    }
    return rec;
  }
  remember(ip, n, now) {
    const k = this.known.get(ip);
    if (k && k.n >= n && now - k.at < DAY) return;
    this.known.delete(ip);
    this.known.set(ip, { n: Math.max(n, k?.n || 0), at: now });
    if (this.known.size > MAX_KNOWN) this.known.delete(this.known.keys().next().value);
  }
  // the record, made if there is none yet (for counting attackers and floods)
  rec(ip, now) {
    let rec = this.map.get(ip);
    if (!rec) {
      rec = { p: Math.floor(now / HOUR), dev: new Twice(), ids: null, peak: 0, peakAt: 0, said: 0, att: null, w: 0, rn: 0 };
      this.map.set(ip, rec);
      if (this.map.size > MAX_ADDRS) this.map.delete(this.map.keys().next().value);
    }
    return rec;
  }
}
