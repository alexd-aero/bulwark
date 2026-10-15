// What Bulwark remembers:
//   Logs      every request, in full: the last 50 000 in memory, every one in
//             <home>/logs/YYYY-MM-DD.jsonl (kept `keepDays`), searchable
//   Series    per-minute counts for 7 days, per-hour for 90: the charts
//   Profiles  one record per address: when, how much, what it asked for, who holds it

import { appendFile, readdirSync, unlinkSync, readFileSync, writeFileSync, renameSync, mkdirSync, createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";

const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
const day = (t) => new Date(t).toISOString().slice(0, 10);
const atomicWrite = (file, obj) => { writeFileSync(file + ".tmp", JSON.stringify(obj)); renameSync(file + ".tmp", file); };

// ------------------------------------------------------------------ logs
export class Logs {
  constructor({ dir, keepDays = 30, ring = 50000 }) {
    this.dir = dir; mkdirSync(dir, { recursive: true });
    this.keepDays = keepDays; this.max = ring;
    this.ring = []; this.seq = 0; this.pending = []; this.subs = new Set();
    this.timer = setInterval(() => this.flush(), 1000); this.timer.unref?.();
    this.loadToday();
  }
  file(t) { return join(this.dir, `${day(t)}.jsonl`); }
  loadToday() {
    // the last day's lines come back into memory, so a restart keeps the recent past
    try {
      const lines = readFileSync(this.file(Date.now()), "utf8").trim().split("\n").slice(-this.max);
      for (const l of lines) { try { const e = JSON.parse(l); this.ring.push(e); if (e.id > this.seq) this.seq = e.id; } catch { /* torn line */ } }
    } catch { /* nothing today */ }
  }
  add(e) {
    e.id = ++this.seq;
    this.ring.push(e);
    if (this.ring.length > this.max * 1.1) this.ring.splice(0, this.ring.length - this.max);
    this.pending.push(e);
    for (const fn of this.subs) { try { fn(e); } catch { /* a closed stream */ } }
    return e;
  }
  flush() {
    if (!this.pending.length) return;
    const byFile = new Map();
    for (const e of this.pending.splice(0)) {
      const f = this.file(e.t);
      byFile.set(f, (byFile.get(f) || "") + JSON.stringify(e) + "\n");
    }
    for (const [f, text] of byFile) appendFile(f, text, () => {});
  }
  prune() {
    const cut = day(Date.now() - this.keepDays * DAY);
    for (const f of readdirSync(this.dir)) if (/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f) && f.slice(0, 10) < cut) { try { unlinkSync(join(this.dir, f)); } catch { /* gone */ } }
  }
  days() { return readdirSync(this.dir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).map((f) => f.slice(0, 10)).sort(); }

  // newest first. f: {q, ip, host, dec, sig, cc, st, since, until, before (id), limit}
  static match(e, f, q) {
    if (f.ip && e.ip !== f.ip) return false;
    if (f.host && e.host !== f.host) return false;
    if (f.dec && (f.dec === "bad" ? e.dec === "pass" || (e.dec === "seen" && !e.sig) : e.dec !== f.dec)) return false;
    if (f.sig && (f.sig === "any" ? !e.sig : e.sig !== f.sig)) return false;
    if (f.cc && e.cc !== f.cc) return false;
    if (f.st && String(e.st)[0] !== String(f.st)[0]) return false;
    if (f.asn && e.asn !== Number(f.asn)) return false;
    if (f.since && e.t < f.since) return false;
    if (f.until && e.t > f.until) return false;
    if (f.before && e.id >= f.before) return false;
    if (q && !`${e.ip} ${e.host} ${e.m} ${e.path} ${e.ua} ${e.ref} ${e.why || ""} ${e.org || ""} ${e.cc}`.toLowerCase().includes(q)) return false;
    return true;
  }
  async query(f = {}) {
    const limit = Math.min(Number(f.limit) || 200, 2000), q = f.q ? String(f.q).toLowerCase() : "";
    const out = [];
    for (let i = this.ring.length - 1; i >= 0 && out.length < limit; i--) if (Logs.match(this.ring[i], f, q)) out.push(this.ring[i]);
    // older than memory: the day files, newest first
    const oldest = this.ring[0]?.t ?? Date.now(), firstId = this.ring[0]?.id || 0;
    if (out.length < limit && (!f.since || f.since < oldest)) {
      const until = Math.min(f.until || Infinity, oldest - 1);
      for (const d of this.days().reverse()) {
        if (f.since && d < day(f.since)) break;
        if (d > day(until)) continue;
        const hits = [];
        const rl = createInterface({ input: createReadStream(join(this.dir, d + ".jsonl")), crlfDelay: Infinity });
        for await (const l of rl) {
          let e; try { e = JSON.parse(l); } catch { continue; }
          // still in memory (read above): history lines carry old times, so time alone doesn't tell
          if (firstId && e.id >= firstId) continue;
          if (e.t <= until && Logs.match(e, f, q)) { hits.push(e); if (hits.length > limit) hits.shift(); }
        }
        for (let i = hits.length - 1; i >= 0 && out.length < limit; i--) out.push(hits[i]);
        if (out.length >= limit) break;
      }
    }
    return out;
  }
  subscribe(fn) { this.subs.add(fn); return () => this.subs.delete(fn); }
}

// ------------------------------------------------------------------ series
const blank = () => ({ req: 0, pass: 0, drop: 0, block: 0, ban: 0, check: 0, newIp: 0, probe: 0, payload: 0, bytes: 0, ips: 0, sig: {} });
export class Series {
  constructor({ file }) {
    this.file = file;
    this.min = new Map(); this.hour = new Map(); this.seen = new Map();    // minute key -> Set of ips
    try {
      const s = JSON.parse(readFileSync(file, "utf8"));
      this.min = new Map(s.min); this.hour = new Map(s.hour);
    } catch { /* first run */ }
  }
  // mine: your own traffic (signed in, trusted, allowed, local) counts as traffic, never as attacks
  add(e, isNew, mine = false) {
    const k = Math.floor(e.t / MIN), h = Math.floor(e.t / HOUR);
    for (const [map, key] of [[this.min, k], [this.hour, h]]) {
      let b = map.get(key);
      if (!b) { b = blank(); map.set(key, b); }
      b.req++; b[e.dec] = (b[e.dec] || 0) + 1; b.bytes += e.b || 0;
      if (isNew) b.newIp++;
      if (mine) continue;
      if (e.sc === 3) b.payload++; else if (e.sc === 1) b.probe++;
      if (e.sig) b.sig[e.sig] = (b.sig[e.sig] || 0) + 1;
    }
    let s = this.seen.get(k);
    if (!s) { s = new Set(); this.seen.set(k, s); for (const old of this.seen.keys()) if (old < k - 2) this.seen.delete(old); }
    if (!s.has(e.ip)) { s.add(e.ip); this.min.get(k).ips++; }
  }
  prune() {
    const now = Date.now();
    for (const k of this.min.keys()) if (k < Math.floor((now - 7 * DAY) / MIN)) this.min.delete(k);
    for (const k of this.hour.keys()) if (k < Math.floor((now - 90 * DAY) / HOUR)) this.hour.delete(k);
  }
  save() { this.prune(); try { atomicWrite(this.file, { min: [...this.min], hour: [...this.hour] }); } catch { /* next time */ } }
  // a range as evenly spaced buckets: {step, points: [{t, ...counts}]}
  range(spanMs, points = 120) {
    const now = Date.now(), useHour = spanMs > 2 * DAY;
    const unit = useHour ? HOUR : MIN, map = useHour ? this.hour : this.min;
    const units = Math.max(1, Math.round(spanMs / unit)), per = Math.max(1, Math.ceil(units / points));
    const end = Math.floor(now / unit), start = end - units + 1;
    const out = [];
    for (let s = end - Math.floor((end - start) / per) * per; s <= end; s += per) {
      const p = { t: s * unit, ...blank() };
      for (let k = s; k < s + per; k++) {
        const b = map.get(k);
        if (!b) continue;
        for (const f of ["req", "pass", "drop", "block", "ban", "check", "newIp", "probe", "payload", "bytes", "ips"]) p[f] += b[f] || 0;
        for (const [sig, n] of Object.entries(b.sig || {})) p.sig[sig] = (p.sig[sig] || 0) + n;
      }
      out.push(p);
    }
    return { step: per * unit, points: out };
  }
  // every count over a window (minutes up to 2 days, hours beyond)
  total(spanMs) {
    const now = Date.now(), useHour = spanMs > 2 * DAY, unit = useHour ? HOUR : MIN, map = useHour ? this.hour : this.min;
    const from = Math.floor((now - spanMs) / unit), t = blank();
    for (const [k, b] of map) {
      if (k < from) continue;
      for (const f of ["req", "pass", "drop", "block", "ban", "check", "newIp", "probe", "payload", "bytes"]) t[f] += b[f] || 0;
    }
    delete t.sig; delete t.ips;
    return t;
  }
  // the last n minutes, as plain buckets (the wave detector's baseline)
  lastMinutes(n) {
    const end = Math.floor(Date.now() / MIN), out = [];
    for (let k = end - n + 1; k <= end; k++) out.push({ k, ...(this.min.get(k) || blank()) });
    return out;
  }
}

// ------------------------------------------------------------------ profiles
export class Profiles {
  constructor({ file, max = 50000 }) {
    this.file = file; this.max = max;
    this.map = new Map();
    try { this.map = new Map(JSON.parse(readFileSync(file, "utf8"))); } catch { /* first run */ }
  }
  get(ip) { return this.map.get(ip) || null; }
  // -> [profile, isNew]
  add(e) {
    let p = this.map.get(e.ip), isNew = false;
    if (!p) {
      isNew = true;
      p = { ip: e.ip, first: e.t, last: e.t, n: 0, bytes: 0, dec: {}, sigs: {}, seq: [], hosts: {}, uas: [], paths: [], cc: e.cc || "" };
      this.map.set(e.ip, p);
      if (this.map.size > this.max) this.evict();
    } else { this.map.delete(e.ip); this.map.set(e.ip, p); }             // newest last (eviction order)
    p.last = e.t; p.n++; p.bytes += e.b || 0;
    p.dec[e.dec] = (p.dec[e.dec] || 0) + 1;
    if (e.cc) p.cc = e.cc;
    if (e.host) p.hosts[e.host] = (p.hosts[e.host] || 0) + 1;
    if (e.sig) { p.sigs[e.sig] = (p.sigs[e.sig] || 0) + 1; if (p.seq.length < 6 && p.seq[p.seq.length - 1] !== e.sig) p.seq.push(e.sig); }
    if (e.ua && !p.uas.includes(e.ua)) { p.uas.push(e.ua); if (p.uas.length > 5) p.uas.shift(); }
    const path = String(e.path).slice(0, 200);
    if (!p.paths.includes(path)) { p.paths.push(path); if (p.paths.length > 25) p.paths.shift(); }
    if (e.auth) p.auth = true;
    return [p, isNew];
  }
  evict() { const drop = this.map.size - this.max; let i = 0; for (const k of this.map.keys()) { if (i++ >= drop) break; this.map.delete(k); } }
  save() { try { atomicWrite(this.file, [...this.map]); } catch { /* next time */ } }
  recent(since, limit = 500) {
    const out = [];
    for (const p of [...this.map.values()].reverse()) { if (p.last < since || out.length >= limit) break; out.push(p); }
    return out;
  }
}
