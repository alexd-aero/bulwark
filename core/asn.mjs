// Who holds an address (its network, AS number, country), from iptoasn.com's
// free database, downloaded once a day and looked up locally: no rate limits,
// so every address that ever shows up gets one, and waves can be grouped by
// network. IPv6 ranges are kept by their top 64 bits.

import { createReadStream, existsSync, statSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { createGunzip } from "node:zlib";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { isIP, v4int, v6big } from "./net.mjs";

const DAY = 86400e3;
const SOURCES = { v4: "https://iptoasn.com/data/ip2asn-v4.tsv.gz", v6: "https://iptoasn.com/data/ip2asn-v6.tsv.gz" };
// hosting and cloud networks: where scanners (and scrapers) live
const HOSTING = /amazon|aws|google|microsoft|azure|digitalocean|ovh|hetzner|linode|akamai|vultr|choopa|oracle|alibaba|tencent|huawei cloud|contabo|scaleway|online s\.a\.s|leaseweb|m247|datacamp|cdn77|hostinger|ionos|1&1|godaddy|namecheap|hostwinds|colocrossing|psychz|quadranet|servers\.com|selectel|timeweb|aeza|stark industries|pfcloud|techoff|tc datacenter|ponynet|frantech|buyvm|ipxo|cogent|zenlayer|g-core|gcore|kamatera|netcup|ucloud|byteplus|bytedance|cloudflare|fastly|hivelocity|nforce|worldstream|serverion|clouvider|datapacket|cloudinnovation|hostkey|ishosting|vdsina|melbicom|globalconnect|sharktech|tzulo|limestone|constant|zappie|is\*hosting|host europe|interserver/i;

// ...but not the home and mobile networks of the same companies (Google Fiber)
const CONSUMER = /fiber|broadband|cable|residential|mobile|wireless|dsl|telecom|comcast|charter|verizon|t-mobile/i;

class Table {
  constructor(n, big) {
    this.n = 0;
    this.start = big ? new BigUint64Array(n) : new Float64Array(n);
    this.end = big ? new BigUint64Array(n) : new Float64Array(n);
    this.asn = new Uint32Array(n); this.meta = new Uint32Array(n);
  }
  find(x) {
    let lo = 0, hi = this.n - 1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (this.start[mid] <= x) lo = mid + 1; else hi = mid - 1; }
    return hi >= 0 && x <= this.end[hi] ? hi : -1;
  }
}

export class Asn {
  constructor({ dir, log, fetchImpl }) {
    this.dir = dir; mkdirSync(dir, { recursive: true });
    this.log = log || console.log;
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.t4 = null; this.t6 = null;
    this.names = [];            // meta index -> {cc, name}
    this.loading = null;
    this.at = 0; this.error = null;
  }
  file(k) { return join(this.dir, `ip2asn-${k}.tsv.gz`); }
  async download(k) {
    const r = await this.fetch(SOURCES[k], { headers: { "User-Agent": "Mozilla/5.0 (bulwark)" }, signal: AbortSignal.timeout(120000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const buf = Buffer.from(await r.arrayBuffer());
    writeFileSync(this.file(k) + ".tmp", buf); renameSync(this.file(k) + ".tmp", this.file(k));
  }
  async refreshDue(force) {
    try {
      let got = false;
      for (const k of ["v4", "v6"]) {
        let age = Infinity;
        try { age = Date.now() - statSync(this.file(k)).mtimeMs; } catch { /* none yet */ }
        if (force || age > DAY) { await this.download(k); got = true; }
      }
      if (got || !this.t4) await this.load();
      this.error = null;
    } catch (e) { this.error = e.message; this.log("asn:", e.message); if (!this.t4) await this.load().catch(() => {}); }
  }
  async load() {
    if (this.loading) return this.loading;
    this.loading = (async () => {
      const names = [], index = new Map();
      const metaOf = (cc, name) => {
        const k = cc + "\t" + name;
        let i = index.get(k);
        // a copy, not a slice: a sliced string keeps the whole decompressed text it came from
        // alive, and 85k names held ~40 MB of it (too much on a 1 GB machine)
        if (i === undefined) { i = names.length; const own = Buffer.from(name).toString(); names.push({ cc: cc === "None" ? "" : Buffer.from(cc).toString(), name: own, hosting: HOSTING.test(own) && !CONSUMER.test(own) }); index.set(k, i); }
        return i;
      };
      const read = async (k, big) => {
        if (!existsSync(this.file(k))) return null;
        let t = new Table(1 << 16, big);
        const grow = () => {
          const g = new Table(t.start.length * 2, big);
          g.start.set(t.start); g.end.set(t.end); g.asn.set(t.asn); g.meta.set(t.meta); g.n = t.n; t = g;
        };
        const rl = createInterface({ input: createReadStream(this.file(k)).pipe(createGunzip()), crlfDelay: Infinity });
        for await (const line of rl) {
          const i1 = line.indexOf("\t"), i2 = line.indexOf("\t", i1 + 1), i3 = line.indexOf("\t", i2 + 1), i4 = line.indexOf("\t", i3 + 1);
          const asn = Number(line.slice(i2 + 1, i3));
          if (!asn) continue;
          if (t.n === t.start.length) grow();
          const a = line.slice(0, i1), b = line.slice(i1 + 1, i2);
          if (big) { t.start[t.n] = v6big(a) >> 64n; t.end[t.n] = v6big(b) >> 64n; }
          else { t.start[t.n] = v4int(a); t.end[t.n] = v4int(b); }
          t.asn[t.n] = asn; t.meta[t.n] = metaOf(line.slice(i3 + 1, i4 < 0 ? undefined : i4), i4 < 0 ? "" : line.slice(i4 + 1)); t.n++;
        }
        // grown by doubling: down to what's used
        const fit = new Table(Math.max(1, t.n), big);
        fit.start.set(t.start.subarray(0, t.n)); fit.end.set(t.end.subarray(0, t.n)); fit.asn.set(t.asn.subarray(0, t.n)); fit.meta.set(t.meta.subarray(0, t.n)); fit.n = t.n;
        return fit;
      };
      const t4 = await read("v4", false), t6 = await read("v6", true);
      if (t4) { this.t4 = t4; this.t6 = t6; this.names = names; this.at = Date.now(); }
    })().finally(() => { this.loading = null; });
    return this.loading;
  }
  // {asn, name, cc, hosting} or null
  lookup(ip) {
    let t, i;
    if (isIP(ip) === 4 && this.t4) { t = this.t4; i = t.find(v4int(ip)); }
    else if (isIP(ip) === 6 && this.t6) { t = this.t6; i = t.find(v6big(ip) >> 64n); }
    if (!t || i < 0) return null;
    const m = this.names[t.meta[i]];
    return { asn: t.asn[i], name: m.name, cc: m.cc, hosting: m.hosting };
  }
  view() { return { ranges: (this.t4?.n || 0) + (this.t6?.n || 0), at: this.at, error: this.error }; }
}
