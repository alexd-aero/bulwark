// Blocklists: big public lists, downloaded every few hours and kept as sorted
// address ranges, so asking about an address is a binary search (microseconds).
//
// The app (Feeds) downloads them into <home>/feeds/; the sensor inside the gate
// reads the same files (parsed off its main thread, see sensor/lists-worker.mjs).

import { readFileSync, writeFileSync, existsSync, statSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { isIP, isPrivate, normIp, v4int, v6big } from "./net.mjs";

const HOUR = 3600e3;
const UA = "Mozilla/5.0 (bulwark)";
const GH = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/";

// strength: strong = banned on sight, weak = a mark against it (banned with a probe), info = shown only
// poll: how often the source is asked whether it changed (a conditional request;
//       "not modified" costs nothing), never more often than it publishes:
//       FireHOL's GitHub sets every minute, blocklist.de and the others less
// every: a full re-read (which also drops addresses that left a list)
export const FEEDS = [
  { id: "firehol1", poll: 60e3, name: "FireHOL level 1", vendor: "FireHOL", url: GH + "firehol_level1.netset", strength: "strong", every: 6 * HOUR,
    about: "Spamhaus DROP/EDROP, DShield top attackers, Feodo and other botnet controllers" },
  { id: "firehol2", poll: 60e3, name: "FireHOL level 2", vendor: "FireHOL", url: GH + "firehol_level2.netset", strength: "strong", every: 6 * HOUR,
    about: "attacks seen in the last two days (blocklist.de, DShield, GreenSnow)" },
  { id: "blocklistde", poll: 15 * 60e3, name: "blocklist.de", vendor: "blocklist.de", url: "https://lists.blocklist.de/lists/all.txt", strength: "strong", every: 6 * HOUR,
    about: "addresses reported for attacks on SSH, mail, web logins and more, IPv6 too" },
  { id: "cins", poll: 10 * 60e3, name: "CINS Army", vendor: "CINS", url: "https://cinsscore.com/list/ci-badguys.txt", strength: "strong", every: 6 * HOUR,
    about: "the worst-scoring addresses on Sentinel IPS sensors" },
  { id: "et", poll: 15 * 60e3, name: "Emerging Threats", vendor: "Proofpoint ET", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", strength: "strong", every: 6 * HOUR,
    about: "known compromised hosts" },
  { id: "greensnow", poll: 10 * 60e3, name: "GreenSnow", vendor: "GreenSnow", url: "https://blocklist.greensnow.co/greensnow.txt", strength: "strong", every: 6 * HOUR,
    about: "attackers seen by GreenSnow's honeypots" },
  { id: "ipsum", poll: 5 * 60e3, name: "IPsum", vendor: "IPsum", url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", strength: "weak", every: 12 * HOUR,
    about: "how many of 30+ blocklists name an address; 3 or more counts as strong", tier: (n) => (n >= 3 ? "strong" : "weak") },
  { id: "firehol3", poll: 60e3, name: "FireHOL level 3", vendor: "FireHOL", url: GH + "firehol_level3.netset", strength: "weak", every: 12 * HOUR,
    about: "attacks seen in the last 30 days" },
  { id: "elsnet", poll: 30 * 60e3, name: "elsnet ban list", vendor: "elsnet", url: "https://vonweber.nl/cgi/blacklister.cgi", strength: "weak", every: 12 * HOUR, timeout: 90000,
    about: "the hosts and addresses elsnet.org has banned (vonweber.nl)", kind: "elsnet" },
  { id: "tor", poll: 10 * 60e3, name: "Tor exits", vendor: "Tor Project", url: "https://check.torproject.org/torbulkexitlist", strength: "info", every: 3 * HOUR,
    about: "Tor exit nodes, per the Tor Project" },
];
export const feedById = (id) => FEEDS.find((f) => f.id === id);

// A list's addresses: IPv4 as merged [start, end] ranges, IPv6 as exact
// addresses and a few prefixes, plus an extra per exact address (IPsum's count,
// elsnet's host and date).
export class RangeSet {
  constructor() { this.raw = []; this.v6 = new Map(); this.v6nets = []; this.extra = new Map(); this.count = 0; this.live = null; }
  // an address (or range) that arrived after the list was sealed: kept beside it
  addLive(entry, extra) {
    const [addr, bits] = entry.split("/");
    const v = isIP(addr);
    if (!v) return false;
    const L = (this.live ||= { ips: new Map(), nets4: [], nets6: [] });
    const n = bits === undefined ? (v === 4 ? 32 : 128) : Number(bits);
    if ((v === 4 && n === 32) || (v === 6 && n === 128)) L.ips.set(v === 4 ? addr : v6big(addr.toLowerCase()).toString(), extra ?? true);
    else if (v === 4 && n >= 0 && n < 32) { const start = (v4int(addr) & (n === 0 ? 0 : (~0 << (32 - n)))) >>> 0; L.nets4.push([start, start + 2 ** (32 - n) - 1]); }
    else if (v === 6 && n >= 16 && n < 128) L.nets6.push([v6big(addr.toLowerCase()) >> BigInt(128 - n), n]);
    else return false;
    this.count++;
    return true;
  }
  hasLive(ip) {
    const L = this.live;
    if (!L) return false;
    if (isIP(ip) === 4) {
      if (L.ips.has(ip)) return L.ips.get(ip);
      const x = v4int(ip);
      for (const [a, b] of L.nets4) if (x >= a && x <= b) return true;
    } else if (isIP(ip) === 6) {
      const n = v6big(ip);
      if (L.ips.has(n.toString())) return L.ips.get(n.toString());
      for (const [pre, bits] of L.nets6) if (n >> BigInt(128 - bits) === pre) return true;
    }
    return false;
  }
  add(entry, extra) {
    const [addr, bits] = entry.split("/");
    const v = isIP(addr);
    if (v === 4) {
      const n = bits === undefined ? 32 : Number(bits);
      if (!(n >= 0 && n <= 32)) return;
      const start = (v4int(addr) & (n === 0 ? 0 : (~0 << (32 - n)))) >>> 0;
      this.raw.push([start, start + 2 ** (32 - n) - 1]);
      if (extra !== undefined && n === 32) this.extra.set(start, extra);
    } else if (v === 6) {
      const n = bits === undefined ? 128 : Number(bits);
      if (n === 128) this.v6.set(v6big(addr.toLowerCase()), extra ?? true);
      else if (n >= 16 && n < 128) this.v6nets.push([v6big(addr.toLowerCase()) >> BigInt(128 - n), n]);
      else return;
    } else return;
    this.count++;
  }
  seal() {
    this.raw.sort((a, b) => a[0] - b[0]);
    const s = [], e = [];
    for (const [a, b] of this.raw) {
      if (s.length && a <= e[e.length - 1] + 1) { if (b > e[e.length - 1]) e[e.length - 1] = b; }
      else { s.push(a); e.push(b); }
    }
    this.start = Float64Array.from(s); this.end = Float64Array.from(e);
    this.raw = null;
    return this;
  }
  has(ip) {
    if (isIP(ip) === 4) {
      const x = v4int(ip), S = this.start;
      let lo = 0, hi = S.length - 1;
      while (lo <= hi) { const mid = (lo + hi) >> 1; if (S[mid] <= x) lo = mid + 1; else hi = mid - 1; }
      if (hi < 0 || x > this.end[hi]) return this.hasLive(ip);
      return this.extra.get(x) ?? true;
    }
    if (isIP(ip) === 6) {
      const n = v6big(ip);
      if (this.v6.has(n)) return this.v6.get(n);
      for (const [pre, bits] of this.v6nets) if (n >> BigInt(128 - bits) === pre) return true;
      return this.hasLive(ip);
    }
    return false;
  }
  static empty() { return new RangeSet().seal(); }
  // to and from a plain object (structured clone, for a worker thread)
  pack() { return { start: this.start, end: this.end, v6: this.v6, v6nets: this.v6nets, extra: this.extra, count: this.count, live: this.live }; }
  static unpack(o) { return Object.assign(new RangeSet(), o, { raw: null }); }
}

// A list's text as [strength, entry, extra] (what parseFeed seals).
export function feedEntries(feed, text) {
  const out = [];
  if (feed.kind === "elsnet") {
    const plain = text.replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ");
    const re = /(?:^|\s)(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)\s+(\d{4})\/(\d{2})\/(\d{2})-(\d{2}:\d{2}:\d{2})\s+(\d+)(?=\s)/g;
    for (let m; (m = re.exec(plain));) {
      if (isIP(m[2]) && !isPrivate(normIp(m[2]))) out.push([feed.strength, m[2], { host: m[1] === "-" ? null : m[1], since: `${m[3]}-${m[4]}-${m[5]} ${m[6]}`, hits: Number(m[7]) }]);
    }
  } else {
    for (const line of text.split("\n")) {
      const l = line.trim();
      if (!l || l[0] === "#" || l[0] === ";") continue;
      const [entry, n] = l.split(/[\s;,]+/);
      if (feed.tier) out.push([feed.tier(Number(n) || 1), entry, Number(n) || 1]);
      else out.push([feed.strength, entry, undefined]);
    }
  }
  return out;
}

// What a list's text says: one RangeSet per strength (IPsum's counts split it).
export function parseFeed(feed, text) {
  const sets = {};
  const put = (strength, entry, extra) => (sets[strength] ||= new RangeSet()).add(entry, extra);
  if (feed.kind === "elsnet") {
    const plain = text.replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ");
    const re = /(?:^|\s)(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)\s+(\d{4})\/(\d{2})\/(\d{2})-(\d{2}:\d{2}:\d{2})\s+(\d+)(?=\s)/g;
    for (let m; (m = re.exec(plain));) {
      if (isIP(m[2]) && !isPrivate(normIp(m[2]))) put(feed.strength, m[2], { host: m[1] === "-" ? null : m[1], since: `${m[3]}-${m[4]}-${m[5]} ${m[6]}`, hits: Number(m[7]) });
    }
  } else {
    for (const line of text.split("\n")) {
      const l = line.trim();
      if (!l || l[0] === "#" || l[0] === ";") continue;
      const [entry, n] = l.split(/[\s;,]+/);
      if (feed.tier) put(feed.tier(Number(n) || 1), entry, Number(n) || 1);
      else put(feed.strength, entry);
    }
  }
  for (const s of Object.values(sets)) s.seal();
  return sets;
}

// Every list that names an address: [{id, name, strength, extra?}]. lists: Map id -> {strong?, weak?, info?}
export function lookupIn(lists, ip) {
  ip = normIp(ip);
  if (!isIP(ip) || isPrivate(ip)) return [];
  const out = [];
  for (const f of FEEDS) {
    const sets = lists.get(f.id);
    if (!sets) continue;
    for (const strength of ["strong", "weak", "info"]) {
      const hit = sets[strength]?.has(ip);
      if (hit) { out.push({ id: f.id, name: f.name, strength, ...(hit !== true ? { extra: hit } : {}) }); break; }
    }
  }
  return out;
}

// The app's side: download what's due, keep the last copy on disk, parse it.
export class Feeds {
  constructor({ dir, log, fetchImpl, onChange }) {
    this.dir = dir; mkdirSync(dir, { recursive: true });
    this.log = log || console.log;
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.onChange = onChange || null;
    this.lists = new Map();
    this.keys = new Map();         // feed id -> Set of "strength entry" (what's in it, for deltas)
    this.onAdd = null;             // (feedId, [[strength, entry, extra]...]) new addresses, as they arrive
    this.meta = {};
    try { this.meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8")); } catch { /* first run */ }
  }
  file(f) { return join(this.dir, f.id + ".txt"); }
  saveMeta() { try { writeFileSync(join(this.dir, "meta.json"), JSON.stringify(this.meta)); } catch { /* next time */ } }
  load(f, text) {
    const m = (this.meta[f.id] ||= {});
    try {
      if (text === undefined) { if (!existsSync(this.file(f))) return false; text = readFileSync(this.file(f), "utf8"); }
      const sets = parseFeed(f, text);
      const count = Object.values(sets).reduce((a, s) => a + s.count, 0);
      if (!count) throw new Error("no addresses in it");
      this.lists.set(f.id, sets);
      this.keys.set(f.id, new Set(feedEntries(f, text).map(([st, e]) => st + " " + e)));
      m.count = count; m.loaded = Date.now(); m.rebuilt = Date.now();
      return true;
    } catch (e) { m.error = e.message; return false; }
  }
  loadAll() { for (const f of FEEDS) this.load(f); }
  async refresh(f) {
    const m = (this.meta[f.id] ||= {});
    m.tried = Date.now();
    try {
      const r = await this.fetch(f.url, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(f.timeout || 30000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      if (!this.load(f, text)) throw new Error(m.error || "couldn't read it");
      m.etag = r.headers?.get?.("etag") || null; m.lastModified = r.headers?.get?.("last-modified") || null; m.checked = Date.now();
      writeFileSync(this.file(f) + ".tmp", text); renameSync(this.file(f) + ".tmp", this.file(f));
      m.at = Date.now(); delete m.error;
      return true;
    } catch (e) {
      m.error = e.message || String(e);
      this.log(`lists: ${f.name}: ${m.error}`);
      return false;
    } finally { this.saveMeta(); }
  }
  // Every 5 s: ask the sources that are due whether they changed (ETag /
  // Last-Modified), and add only the addresses that weren't there yet.
  async poll() {
    if (this.polling) return 0;
    this.polling = true;
    let added = 0;
    try {
      for (const f of FEEDS) {
        const m = (this.meta[f.id] ||= {});
        if (!this.lists.has(f.id)) continue;                         // not loaded yet: refreshDue does that
        if (Date.now() - (m.checked || 0) < (f.poll || f.every)) continue;
        if (Date.now() - (m.rebuilt || 0) > f.every) continue;       // a full re-read is due instead
        m.checked = Date.now();
        try {
          const headers = { "User-Agent": UA };
          if (m.etag) headers["If-None-Match"] = m.etag;
          if (m.lastModified) headers["If-Modified-Since"] = m.lastModified;
          const r = await this.fetch(f.url, { headers, signal: AbortSignal.timeout(f.timeout || 30000) });
          if (r.status === 304) { m.unchanged = (m.unchanged || 0) + 1; continue; }
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          if (r.headers.get("etag")) m.etag = r.headers.get("etag");
          if (r.headers.get("last-modified")) m.lastModified = r.headers.get("last-modified");
          const text = await r.text();
          const have = this.keys.get(f.id) || new Set(), sets = this.lists.get(f.id), fresh = [];
          for (const [st, e, extra] of feedEntries(f, text)) {
            const k = st + " " + e;
            if (have.has(k)) continue;
            have.add(k);
            const set = (sets[st] ||= RangeSet.empty());
            if (set.addLive(e, extra)) fresh.push([st, e, extra]);
          }
          this.keys.set(f.id, have);
          if (fresh.length) {
            added += fresh.length;
            m.count = (m.count || 0) + fresh.length; m.added = (m.added || 0) + fresh.length; m.addedAt = Date.now(); m.lastAdd = fresh.length;
            writeFileSync(this.file(f) + ".tmp", text); renameSync(this.file(f) + ".tmp", this.file(f));
            this.onAdd?.(f.id, fresh);
          }
          delete m.error;
        } catch (e) { m.error = e.message || String(e); }
      }
    } finally { this.polling = false; if (added) this.saveMeta(); }
    return added;
  }
  async refreshDue(force) {
    let changed = false;
    for (const f of FEEDS) {
      const m = this.meta[f.id] || {};
      let at = m.at || 0;
      if (!at) try { at = statSync(this.file(f)).mtimeMs; } catch { /* never fetched */ }
      const retry = m.error && Date.now() - (m.tried || 0) > 30 * 60e3;
      if (force || Date.now() - at > f.every || (!this.lists.has(f.id) && (retry || !m.tried))) changed = (await this.refresh(f)) || changed;
    }
    if (changed) this.onChange?.();
    return changed;
  }
  lookup(ip) { return lookupIn(this.lists, ip); }
  view() {
    return FEEDS.map((f) => ({ id: f.id, name: f.name, vendor: f.vendor, about: f.about, strength: f.strength, url: f.url, every: f.every,
                               ...(this.meta[f.id] || {}), loadedNow: this.lists.has(f.id) }));
  }
  total() { let n = 0; for (const f of FEEDS) if (this.lists.has(f.id)) n += this.meta[f.id]?.count || 0; return n; }
}
