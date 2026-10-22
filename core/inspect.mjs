// The IP Inspector: everything that can be known about one address, on
// demand. Free sources that need no key run in parallel; AbuseIPDB too when
// you have a key. Each answer is kept (per source, for hours), each host is
// asked politely (one request at a time, spaced), each request times out, and
// the only thing ever sent is the address being inspected (and, for routing,
// the network it belongs to).
//
//   ptr        reverse DNS, each name confirmed forward
//   cymru      Team Cymru's IP-to-ASN over DNS (origin, prefix, registry, date)
//   rdap       the registry's record (rdap.org -> ARIN, RIPE, APNIC, LACNIC, AFRINIC):
//              owner, abuse contact, allocation, dates
//   ripestat   RIPEstat: prefix and holder, routing visibility, geolocation, abuse
//              contact, its blocklist widget, the AS's announced prefixes, RPKI
//   internetdb Shodan InternetDB: open ports, CPEs, known vulnerabilities, tags
//   greynoise  GreyNoise community: scanner, malicious, or a known service
//   otx        AlienVault OTX: threat-intel pulses that name it
//   abuseipdb  AbuseIPDB (with your key): confidence, reports and their comments
//   dnsbl      Spamhaus, DroneBL, SpamCop, blocklist.de, PSBL, UCEPROTECT, Mailspike, s5h
//   tor        the local exit list, and Onionoo for relay details
//   sfs        StopForumSpam
//   ipinfo, ipwhois   geolocation and the network, from two free services
//
// Plus Bulwark's own knowledge: its log, profile, bans, lists, waves and
// campaigns, devices, and the neighbours seen here (same /24, same network).
//
// new Inspector({brain, fetchImpl, dns, offline}).inspect(ip, {fresh}) -> job;
// job.view() -> the report so far (pending sources listed), job.done -> Promise

import { Resolver } from "node:dns/promises";
import { isIP, isPrivate, normIp, netOf } from "./net.mjs";
import { signatureById, categoryOf } from "./payloads.mjs";
import { categoryById } from "./taxonomy.mjs";

const MIN = 60e3, HOUR = 60 * MIN;
const UA = "Bulwark-Inspector (+https://github.com/alexd-aero/bulwark)";
// how long an answer is kept, and how far apart requests to one host are
const HOSTS = { "rdap.org": 1000, "stat.ripe.net": 250, "internetdb.shodan.io": 400, "api.greynoise.io": 2000, "otx.alienvault.com": 1500,
                "api.abuseipdb.com": 1000, "onionoo.torproject.org": 1000, "api.stopforumspam.org": 1000, "ipinfo.io": 600, "ipwho.is": 1500 };
const reverse4 = (ip) => ip.split(".").reverse().join(".");
function nibbles(ip) {
  const [head, tail] = ip.includes("::") ? ip.split("::") : [ip, null];
  const hp = head ? head.split(":") : [], tp = tail ? tail.split(":") : [];
  const groups = tail === null ? hp : [...hp, ...Array(8 - hp.length - tp.length).fill("0"), ...tp];
  return groups.map((g) => g.padStart(4, "0")).join("").split("").reverse().join(".");
}

// ------------------------------------------------------------------ the sources
const DNSBLS = [
  { id: "spamhaus", name: "Spamhaus ZEN", zone: "zen.spamhaus.org", what: { "127.0.0.2": "SBL: spam source", "127.0.0.3": "SBL CSS: snowshoe spam", "127.0.0.4": "XBL: exploited / infected", "127.0.0.9": "DROP: hijacked network" },
    ignore: ["127.0.0.10", "127.0.0.11"], url: (ip) => `https://check.spamhaus.org/results/?query=${ip}` },
  { id: "dronebl", name: "DroneBL", zone: "dnsbl.dronebl.org", what: { "127.0.0.3": "IRC drone", "127.0.0.5": "bottler", "127.0.0.6": "spambot or drone", "127.0.0.7": "DDoS drone", "127.0.0.8": "SOCKS proxy",
    "127.0.0.9": "HTTP proxy", "127.0.0.10": "proxy chain", "127.0.0.11": "web page proxy", "127.0.0.13": "brute-force attacker", "127.0.0.14": "open Wingate", "127.0.0.15": "compromised router",
    "127.0.0.16": "autorooting worm", "127.0.0.17": "botnet", "127.0.0.18": "DNS/MX on IRC", "127.0.0.19": "abused VPN" } },
  { id: "spamcop", name: "SpamCop", zone: "bl.spamcop.net", what: { "127.0.0.2": "spam source" } },
  { id: "blocklistde", name: "blocklist.de", zone: "bl.blocklist.de", what: { "127.0.0.2": "reported attacker" } },
  { id: "psbl", name: "PSBL", zone: "psbl.surriel.com", what: { "127.0.0.2": "spam trap hit" } },
  { id: "uceprotect", name: "UCEPROTECT L1", zone: "dnsbl-1.uceprotect.net", what: { "127.0.0.2": "spam source" } },
  { id: "mailspike", name: "Mailspike", zone: "bl.mailspike.net", what: { "127.0.0.2": "spam wave", "127.0.0.10": "worst reputation", "127.0.0.11": "very bad", "127.0.0.12": "bad" } },
  { id: "s5h", name: "s5h", zone: "all.s5h.net", what: { "127.0.0.2": "spam or abuse" } },
];
export const SOURCES = [
  { id: "ptr", name: "Reverse DNS", ttl: 6 * HOUR, about: "The PTR names, each confirmed forward (does the name lead back here?)" },
  { id: "cymru", name: "Team Cymru", ttl: 24 * HOUR, about: "IP to ASN over DNS: origin AS, prefix, registry, allocation date" },
  { id: "rdap", name: "RDAP (registry)", ttl: 24 * HOUR, host: "rdap.org", about: "The regional registry's record: owner, abuse contact, allocation, dates" },
  { id: "ripestat", name: "RIPEstat", ttl: 6 * HOUR, host: "stat.ripe.net", about: "Prefix, holder, routing visibility, geolocation, abuse contact, blocklists, the AS's prefixes, RPKI" },
  { id: "internetdb", name: "Shodan InternetDB", ttl: 6 * HOUR, host: "internetdb.shodan.io", about: "Open ports, software (CPEs), known vulnerabilities, tags" },
  { id: "greynoise", name: "GreyNoise", ttl: 6 * HOUR, host: "api.greynoise.io", about: "Internet-wide scanner? Malicious, or a known business service?" },
  { id: "otx", name: "AlienVault OTX", ttl: 6 * HOUR, host: "otx.alienvault.com", about: "Threat-intelligence pulses that name it" },
  { id: "abuseipdb", name: "AbuseIPDB", ttl: 6 * HOUR, host: "api.abuseipdb.com", key: true, about: "Abuse confidence, reports and their comments (needs your free key)" },
  { id: "dnsbl", name: "DNS blocklists", ttl: HOUR, about: DNSBLS.map((d) => d.name).join(", ") },
  { id: "tor", name: "Tor", ttl: 3 * HOUR, host: "onionoo.torproject.org", about: "Is it a Tor relay or exit? (the exit list, then Onionoo)" },
  { id: "sfs", name: "StopForumSpam", ttl: 6 * HOUR, host: "api.stopforumspam.org", about: "Reports of forum and sign-up spam" },
  { id: "ipinfo", name: "IPinfo", ttl: 24 * HOUR, host: "ipinfo.io", about: "Geolocation, host name, network (free tier)" },
  { id: "ipwhois", name: "ipwho.is", ttl: 24 * HOUR, host: "ipwho.is", about: "Geolocation and the connection's ISP (free tier)" },
];

export class Inspector {
  constructor({ brain = null, fetchImpl, dns, offline = false, now = () => Date.now(), key = () => brain?.settings?.abuseipdbKey || "", timeoutMs = 20000, spacing = 1 } = {}) {
    this.brain = brain; this.offline = offline; this.now = now; this.key = key;
    this.timeoutMs = timeoutMs; this.spacing = spacing;        // tests shrink both
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.dns = dns || new Resolver({ timeout: 4000, tries: 1 });
    this.cache = new Map();           // "source|ip" -> {at, result}
    this.gates = new Map();           // host -> the time its next request may start
    this.jobs = new Map();            // ip -> job
  }

  // ------------------------------------------------------------ politeness
  async polite(host, fn) {
    const gap = (HOSTS[host] ?? 500) * this.spacing, now = this.now();
    const at = Math.max(now, this.gates.get(host) || 0);
    this.gates.set(host, at + gap);
    if (at > now) await new Promise((r) => setTimeout(r, at - now));
    return fn();
  }
  async json(url, { headers = {}, ms = 9000, notFound = null } = {}) {
    const u = new URL(url);
    return this.polite(u.hostname, async () => {
      const r = await this.fetch(url, { headers: { "User-Agent": UA, Accept: "application/json, application/rdap+json", ...headers }, redirect: "follow", signal: AbortSignal.timeout(Math.min(ms, this.timeoutMs)) });
      if (r.status === 404) return notFound;
      if (r.status === 429) throw new Error("rate-limited: try again later");
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    });
  }
  timeout(p, ms, what) {
    let t;
    return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} took longer than ${ms / 1000} s`)), ms); })]).finally(() => clearTimeout(t));
  }

  // ------------------------------------------------------------ each source: -> {data, raw}
  async ptr(ip) {
    let names = [];
    try { names = await this.dns.reverse(ip); } catch (e) { if (e.code === "ENOTFOUND" || e.code === "ENODATA") return { data: { names: [] }, raw: { ptr: [] } }; throw e; }
    const forward = {};
    const out = await Promise.all(names.slice(0, 6).map(async (name) => {
      let addrs = [];
      try { addrs = isIP(ip) === 6 ? await this.dns.resolve6(name) : await this.dns.resolve4(name); } catch { /* no forward record */ }
      forward[name] = addrs;
      return { name, confirmed: addrs.map((a) => normIp(a)).includes(ip) };
    }));
    return { data: { names: out }, raw: { ptr: names, forward } };
  }
  async cymru(ip) {
    const q = isIP(ip) === 4 ? `${reverse4(ip)}.origin.asn.cymru.com` : `${nibbles(ip)}.origin6.asn.cymru.com`;
    let txt;
    try { txt = (await this.dns.resolveTxt(q)).map((x) => x.join("")); } catch (e) { if (e.code === "ENOTFOUND" || e.code === "ENODATA") return { data: null, raw: null }; throw e; }
    const [asn, prefix, cc, registry, allocated] = (txt[0] || "").split("|").map((x) => x.trim());
    const first = String(asn || "").split(" ")[0];
    let name = null, asRaw = null;
    if (first) {
      try { asRaw = (await this.dns.resolveTxt(`AS${first}.asn.cymru.com`)).map((x) => x.join("")); name = (asRaw[0] || "").split("|").map((x) => x.trim())[4] || null; } catch { /* no name */ }
    }
    return { data: { asn: first ? Number(first) : null, prefix: prefix || null, cc: cc || null, registry: registry || null, allocated: allocated || null, name }, raw: { origin: txt, as: asRaw } };
  }
  async rdap(ip) {
    const j = await this.json(`https://rdap.org/ip/${ip}`, { ms: 12000 });
    if (!j) return { data: null, raw: null };
    const vc = (e) => {
      const card = e?.vcardArray?.[1] || [];
      const get = (k) => card.find((x) => x[0] === k)?.[3];
      const adr = card.find((x) => x[0] === "adr");
      return { name: get("fn") || null, email: [].concat(get("email") || []).join(", ") || null, phone: get("tel") || null, address: adr ? (adr[1]?.label || [].concat(adr[3] || []).filter(Boolean).join(", ")) : null };
    };
    const flat = (list, out = []) => { for (const e of list || []) { out.push(e); flat(e.entities, out); } return out; };
    const ents = flat(j.entities);
    const role = (r) => ents.filter((e) => e.roles?.includes(r)).map((e) => ({ handle: e.handle || null, ...vc(e) }));
    const ev = (a) => j.events?.find((e) => e.eventAction === a)?.eventDate || null;
    const cidr = (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
    return { data: { handle: j.handle || null, name: j.name || null, type: j.type || null, country: j.country || null, start: j.startAddress || null, end: j.endAddress || null,
                     cidr, parent: j.parentHandle || null, registered: ev("registration"), changed: ev("last changed"), port43: j.port43 || null,
                     registrant: role("registrant")[0] || null, abuse: role("abuse")[0] || null, tech: role("technical")[0] || null,
                     remarks: (j.remarks || []).flatMap((r) => r.description || []).slice(0, 6), source: j.links?.find((l) => l.rel === "self")?.href || null }, raw: j };
  }
  async ripestat(ip) {
    const call = (name, resource, extra = "") => this.json(`https://stat.ripe.net/data/${name}/data.json?resource=${encodeURIComponent(resource)}${extra}&sourceapp=bulwark`, { ms: 12000 })
      .then((j) => j?.data ?? null).catch((e) => ({ error: e.message }));
    const [net, overview, geo, abuse, block] = await Promise.all([call("network-info", ip), call("prefix-overview", ip), call("maxmind-geo-lite", ip), call("abuse-contact-finder", ip), call("blocklist", ip)]);
    const prefix = net?.prefix || overview?.resource || null, asn = Number(net?.asns?.[0] || overview?.asns?.[0]?.asn) || null;
    const [routing, announced, rpki] = await Promise.all([
      prefix ? call("routing-status", prefix) : null,
      asn ? call("announced-prefixes", `AS${asn}`) : null,
      prefix && asn ? call("rpki-validation", `AS${asn}`, `&prefix=${encodeURIComponent(prefix)}`) : null,
    ]);
    let loc = geo?.located_resources?.[0]?.locations?.[0] || null;
    if (loc && (!loc.country || loc.country === "?") && !loc.city && !loc.latitude && !loc.longitude) loc = null;     // anycast, or nobody knows
    const blocks = (block?.sources ? Object.entries(block.sources) : []).filter(([, v]) => Array.isArray(v) ? v.length : v).map(([k, v]) => ({ list: k, entries: Array.isArray(v) ? v.length : 1 }));
    const ann = announced?.prefixes || [];
    return { data: { prefix, asn, holder: overview?.asns?.[0]?.holder || null, announced: !!overview?.announced, block: overview?.block?.desc || overview?.block?.resource || null,
                     visibility: routing?.visibility ? { v4: routing.visibility.v4 ? `${routing.visibility.v4.ris_peers_seeing}/${routing.visibility.v4.total_ris_peers}` : null,
                                                         v6: routing.visibility.v6 ? `${routing.visibility.v6.ris_peers_seeing}/${routing.visibility.v6.total_ris_peers}` : null } : null,
                     firstSeen: routing?.first_seen?.time || null, origins: (routing?.origins || []).map((o) => o.origin),
                     geo: loc ? { country: loc.country && loc.country !== "?" ? loc.country : null, city: loc.city || null, lat: loc.latitude || null, lon: loc.longitude || null, covered: loc.covered_percentage ?? null } : null,
                     abuse: abuse?.abuse_contacts || [], blocklists: blocks, asPrefixes: { count: ann.length, sample: ann.slice(0, 12).map((p) => p.prefix) },
                     rpki: rpki?.status || null },
             raw: { "network-info": net, "prefix-overview": overview, "routing-status": routing, "maxmind-geo-lite": geo, "abuse-contact-finder": abuse, blocklist: block, "announced-prefixes": announced ? { ...announced, prefixes: ann.slice(0, 200) } : null, "rpki-validation": rpki } };
  }
  async internetdb(ip) {
    const j = await this.json(`https://internetdb.shodan.io/${ip}`);
    if (!j || j.detail) return { data: { seen: false }, raw: j };
    return { data: { seen: true, ports: j.ports || [], cpes: j.cpes || [], vulns: j.vulns || [], tags: j.tags || [], hostnames: j.hostnames || [] }, raw: j };
  }
  async greynoise(ip) {
    const j = await this.json(`https://api.greynoise.io/v3/community/${ip}`, { notFound: { noise: false, riot: false, message: "IP not observed scanning the internet or contained in RIOT data set." } });
    return { data: { seen: !!(j?.noise || j?.riot), scanner: !!j?.noise, benign: !!j?.riot, classification: j?.classification || null, name: j?.name && j.name !== "unknown" ? j.name : null, lastSeen: j?.last_seen || null }, raw: j };
  }
  async otx(ip) {
    const j = await this.json(`https://otx.alienvault.com/api/v1/indicators/${isIP(ip) === 6 ? "IPv6" : "IPv4"}/${ip}/general`, { ms: 12000 });
    if (!j) return { data: { pulses: 0 }, raw: null };
    const pulses = (j.pulse_info?.pulses || []).slice(0, 25).map((p) => ({ id: p.id, name: p.name, created: p.created, modified: p.modified, tags: (p.tags || []).slice(0, 8),
                                                                        adversary: p.adversary || null, malware: (p.malware_families || []).map((m) => m.display_name || m).slice(0, 5) }));
    return { data: { pulses: j.pulse_info?.count || 0, list: pulses, reputation: j.reputation ?? null, whitelisted: (j.validation || []).map((v) => v.name || v.source).filter(Boolean),
                     families: [...new Set(pulses.flatMap((p) => p.malware))].slice(0, 10) }, raw: { ...j, pulse_info: { ...j.pulse_info, pulses: (j.pulse_info?.pulses || []).slice(0, 25) } } };
  }
  async abuseipdb(ip) {
    const key = this.key();
    if (!key) return { skipped: "add your free AbuseIPDB key (Vendors) to include it" };
    const rep = this.brain?.reporters;
    if (rep && !rep.budget("check")) throw new Error("today's AbuseIPDB allowance is used up");
    const j = await this.json(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, { headers: { Key: key } });
    if (rep) rep.state.used.check++;
    const d = j?.data || {};
    if (rep) rep.state.checks[ip] = { at: this.now(), score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0, last: d.lastReportedAt || null };
    const cats = new Map();
    for (const r of d.reports || []) for (const c of r.categories || []) cats.set(c, (cats.get(c) || 0) + 1);
    return { data: { score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0, users: d.numDistinctUsers ?? 0, last: d.lastReportedAt || null, usage: d.usageType || null, isp: d.isp || null,
                     domain: d.domain || null, tor: !!d.isTor, whitelisted: !!d.isWhitelisted, country: d.countryCode || null, categories: [...cats].sort((a, b) => b[1] - a[1]).map(([id, n]) => ({ id, n, name: ABUSE_CATS[id] || `#${id}` })),
                     comments: (d.reports || []).slice(0, 25).map((r) => ({ at: r.reportedAt, comment: String(r.comment || "").slice(0, 400), categories: r.categories || [], cc: r.reporterCountryCode || null })) },
             raw: { ...j, data: { ...d, reports: (d.reports || []).slice(0, 50) } } };
  }
  async dnsbl(ip) {
    if (isIP(ip) !== 4) return { skipped: "the DNS blocklists list IPv4 addresses" };
    const data = {}, raw = {};
    await Promise.all(DNSBLS.map(async (b) => {
      try {
        const a = await this.timeout(this.dns.resolve4(`${reverse4(ip)}.${b.zone}`), 5000, b.name);
        raw[b.id] = a;
        if (a.some((x) => x.startsWith("127.255.255."))) { data[b.id] = { name: b.name, error: "refuses this resolver (a public DNS)" }; return; }
        const real = a.filter((x) => !(b.ignore || []).includes(x));
        data[b.id] = { name: b.name, listed: real.length > 0, why: [...new Set(real.map((x) => b.what[x] || x))], note: real.length ? null : a.length ? "home or mobile range (PBL)" : null };
      } catch (e) { raw[b.id] = e.code || e.message; data[b.id] = e.code === "ENOTFOUND" || e.code === "ENODATA" ? { name: b.name, listed: false } : { name: b.name, error: e.code || e.message }; }
    }));
    return { data, raw };
  }
  async tor(ip) {
    const local = this.brain?.feeds?.lists?.has("tor") ? this.brain.feeds.lookup(ip).some((l) => l.id === "tor") : null;
    let relay = null, raw = null;
    try {
      raw = await this.json(`https://onionoo.torproject.org/details?search=${encodeURIComponent(ip)}&fields=nickname,fingerprint,flags,running,first_seen,last_seen,contact,platform,exit_policy_summary,or_addresses,exit_addresses,as,as_name,country`);
      const r = raw?.relays?.[0];
      if (r) relay = { nickname: r.nickname, fingerprint: r.fingerprint, flags: r.flags || [], running: !!r.running, firstSeen: r.first_seen, lastSeen: r.last_seen, contact: r.contact || null, platform: r.platform || null,
                       exit: (r.flags || []).includes("Exit"), policy: r.exit_policy_summary || null };
    } catch (e) { if (local === null) throw e; }
    return { data: { exit: !!(local || relay?.exit), relay, listed: local }, raw };
  }
  async sfs(ip) {
    const j = await this.json(`https://api.stopforumspam.org/api?ip=${encodeURIComponent(ip)}&json`);
    const x = j?.ip || {};
    return { data: { reports: Number(x.frequency) || 0, lastSeen: x.lastseen || null, confidence: x.confidence ? Number(x.confidence) : null, tor: !!x.torexit }, raw: j };
  }
  async ipinfo(ip) {
    const j = await this.json(`https://ipinfo.io/${ip}/json`);
    if (!j || j.bogon) return { data: null, raw: j };
    const [lat, lon] = String(j.loc || "").split(",").map(Number);
    return { data: { org: j.org || null, hostname: j.hostname || null, city: j.city || null, region: j.region || null, country: j.country || null, timezone: j.timezone || null, lat: lat || null, lon: lon || null, anycast: !!j.anycast }, raw: j };
  }
  async ipwhois(ip) {
    const j = await this.json(`https://ipwho.is/${ip}`);
    if (!j || j.success === false) throw new Error(j?.message || "no answer");
    return { data: { type: j.type || null, country: j.country || null, cc: j.country_code || null, region: j.region || null, city: j.city || null, lat: j.latitude ?? null, lon: j.longitude ?? null,
                     isp: j.connection?.isp || null, org: j.connection?.org || null, asn: j.connection?.asn || null, domain: j.connection?.domain || null, timezone: j.timezone?.id || null }, raw: j };
  }

  // ------------------------------------------------------------ a job
  inspect(raw, { fresh = false } = {}) {
    const ip = normIp(raw);
    if (!isIP(ip)) throw new Error("That isn't an IP address.");
    const old = this.jobs.get(ip);
    if (old && !fresh && (old.running || this.now() - old.at < 10 * MIN)) return old;
    const job = { ip, at: this.now(), running: true, results: {}, local: null, calls: [] };
    // the sources ask through this, so the job knows exactly what went out
    const ctx = Object.create(this);
    ctx.json = (url, o) => { const u = new URL(url); job.calls.push({ at: this.now(), host: u.hostname, path: (u.pathname + u.search).replace(/key=[^&]+/i, "key=…") }); return this.json(url, o); };
    this.jobs.set(ip, job);
    if (this.jobs.size > 50) this.jobs.delete(this.jobs.keys().next().value);
    const priv = isPrivate(ip);
    const jobs = SOURCES.map(async (s) => {
      const t0 = this.now();
      const ck = `${s.id}|${ip}`, hit = this.cache.get(ck);
      if (priv) { job.results[s.id] = { state: "skipped", why: "a private address: nothing outside knows it" }; return; }
      if (this.offline) { job.results[s.id] = { state: "skipped", why: "offline" }; return; }
      if (!fresh && hit && this.now() - hit.at < s.ttl) { job.results[s.id] = { ...hit.result, cached: true }; return; }
      job.results[s.id] = { state: "pending" };
      try {
        const r = await this.timeout(this[s.id].call(ctx, ip), this.timeoutMs, s.name);
        const result = r.skipped ? { state: "skipped", why: r.skipped } : { state: "ok", data: r.data, raw: r.raw, at: this.now(), took: this.now() - t0 };
        job.results[s.id] = result;
        if (result.state === "ok") { this.cache.set(ck, { at: this.now(), result }); if (this.cache.size > 3000) this.cache.delete(this.cache.keys().next().value); }
      } catch (e) { job.results[s.id] = { state: "error", error: String(e.message || e).slice(0, 200), took: this.now() - t0 }; }
    });
    job.done = Promise.all([this.localFor(ip).then((l) => { job.local = l; }), ...jobs]).then(async () => { job.local = await this.localFor(ip); job.running = false; });
    job.view = () => assemble(job);
    return job;
  }

  // what Bulwark itself knows
  async localFor(ip) {
    const b = this.brain;
    if (!b) return null;
    const p = b.profiles.get(ip);
    const logs = await b.logs.query({ ip, limit: 500 });
    const lists = b.feeds.lookup(ip);
    const v = b.verdicts.get(ip);
    const alerts = b.waves.list(300).filter((a) => a.members?.includes(ip)).map(({ id, key, title, sev, kind, open, first, last, members }) => ({ id, key, title, sev, kind, open, first, last, members: members.length }));
    // neighbours: the same /24 (or /48), the same network, seen here
    const n24 = netOf(ip), asn = p?.asn || b.asn.lookup(ip)?.asn || null;
    const same24 = [], sameAs = [];
    for (const q of b.profiles.map.values()) {
      if (q.ip === ip) continue;
      const row = () => ({ ip: q.ip, n: q.n, last: q.last, cc: q.cc, org: q.org || "", banned: !!b.state.bans[q.ip], cats: Object.keys(q.cats || {}).length ? Object.keys(q.cats) : [...new Set(Object.keys(q.sigs || {}).map(categoryOf).filter(Boolean))] });
      if (netOf(q.ip) === n24) same24.push(row());
      else if (asn && q.asn === asn) sameAs.push(row());
    }
    const byLast = (a, c) => c.last - a.last;
    return {
      profile: p, ban: b.state.bans[ip] || null, allowed: b.state.allow[ip] || null, trusted: b.isTrusted(ip), own: b.own.has(ip), devices: b.devicesAt(ip),
      lists, verdict: v ? { level: v.level, why: v.why, bad: v.bad, benign: v.benign, at: v.at } : null, asn: b.asn.lookup(ip), alerts, logs,
      reported: b.reporters.state.reported[ip] || null,
      neighbours: { net: n24, same: same24.sort(byLast).slice(0, 60), sameCount: same24.length, sameBanned: same24.filter((x) => x.banned).length,
                    asn, asnName: p?.org || b.asn.lookup(ip)?.name || null, network: sameAs.sort(byLast).slice(0, 60), networkCount: sameAs.length, networkBanned: sameAs.filter((x) => x.banned).length },
    };
  }
}

// AbuseIPDB's categories, by number
export const ABUSE_CATS = { 1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
  9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
  19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted" };

// where to look further (opened in a new tab, without a referrer)
export function linksFor(ip, asn) {
  const e = encodeURIComponent(ip);
  const L = [
    ["Reputation", "AbuseIPDB", `https://www.abuseipdb.com/check/${e}`], ["Reputation", "GreyNoise", `https://viz.greynoise.io/ip/${e}`], ["Reputation", "VirusTotal", `https://www.virustotal.com/gui/ip-address/${e}`],
    ["Reputation", "AlienVault OTX", `https://otx.alienvault.com/indicator/ip/${e}`], ["Reputation", "Cisco Talos", `https://talosintelligence.com/reputation_center/lookup?search=${e}`],
    ["Reputation", "CrowdSec CTI", `https://app.crowdsec.net/cti/${e}`], ["Reputation", "IBM X-Force", `https://exchange.xforce.ibmcloud.com/ip/${e}`], ["Reputation", "Spamhaus", `https://check.spamhaus.org/results/?query=${e}`],
    ["Threats", "ThreatFox (abuse.ch)", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e}`], ["Threats", "URLhaus (abuse.ch)", `https://urlhaus.abuse.ch/browse.php?search=${e}`],
    ["Exposure", "Shodan", `https://www.shodan.io/host/${e}`], ["Exposure", "Censys", `https://search.censys.io/hosts/${e}`],
    ["Network", "IPinfo", `https://ipinfo.io/${e}`], ["Network", "bgp.he.net", `https://bgp.he.net/ip/${e}`], ["Network", "RIPEstat", `https://stat.ripe.net/resource/${e}`],
    ["Network", "Robtex", `https://www.robtex.com/ip-lookup/${e}`], ["Network", "MXToolbox blacklists", `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${e}&run=toolpage`],
  ];
  if (asn) L.push(["Network", `AS${asn} on bgp.he.net`, `https://bgp.he.net/AS${asn}`], ["Network", `AS${asn} on IPinfo`, `https://ipinfo.io/AS${asn}`]);
  return L.map(([group, name, url]) => ({ group, name, url }));
}

// ------------------------------------------------------------------ the report
const ok = (r) => (r?.state === "ok" ? r.data : null);
export function assemble(job) {
  const R = job.results, L = job.local;
  const ip = job.ip;
  const d = (id) => ok(R[id]);
  const rd = d("rdap"), rs = d("ripestat"), cy = d("cymru"), ii = d("ipinfo"), iw = d("ipwhois"), gn = d("greynoise"), ab = d("abuseipdb"), sh = d("internetdb"), ot = d("otx"),
        bl = d("dnsbl"), tor = d("tor"), sfs = d("sfs"), ptr = d("ptr");
  // the verdict: a risk score from 0 to 100, with every reason and what it weighed
  const why = [];
  const add = (w, text, source) => why.push({ w, text, source });
  const p = L?.profile, here = L?.logs || [];
  const mine = !!(L?.trusted || L?.allowed || L?.own || L?.devices?.length || isPrivate(ip));
  if (L?.ban) add(L.ban.source === "manual" ? 30 : 40, `banned here: ${L.ban.reason}`, "bulwark");
  const sigs = p ? Object.entries(p.sigs || {}) : [];
  const payloads = sigs.filter(([s]) => signatureById(s)?.score === 3).reduce((a, [, n]) => a + n, 0);
  if (payloads) add(Math.min(30, 10 + payloads * 4), `${payloads} payload${payloads === 1 ? "" : "s"} sent here`, "bulwark");
  else if (sigs.length) add(Math.min(12, sigs.length * 4), `probed here (${sigs.map(([s]) => signatureById(s)?.name || s).slice(0, 3).join(", ")})`, "bulwark");
  for (const l of L?.lists || []) if (l.id !== "tor") add(l.strength === "strong" ? 25 : 10, `on ${l.name}`, "lists");
  if (gn?.classification === "malicious") add(35, "GreyNoise has seen it attack", "greynoise");
  else if (gn?.scanner && !gn.benign) add(12, "an internet-wide scanner (GreyNoise)", "greynoise");
  if (gn?.benign) add(-30, `a known service${gn.name ? `: ${gn.name}` : ""} (GreyNoise)`, "greynoise");
  if (ab) { if (ab.whitelisted) add(-20, "whitelisted by AbuseIPDB", "abuseipdb"); else if (ab.score) add(Math.round(ab.score * 0.5), `AbuseIPDB confidence ${ab.score}% (${ab.reports} reports by ${ab.users} users)`, "abuseipdb"); }
  let dn = 0;
  for (const x of Object.values(bl || {})) if (x.listed) { const w = /drone|exploit|botnet|brute|hijack|worm|router/i.test(x.why.join(" ")) ? 25 : 10; dn += w; add(w, `${x.name}: ${x.why.join(", ")}`, "dnsbl"); }
  if (ot?.pulses) add(Math.min(25, 5 * ot.pulses), `in ${ot.pulses} OTX pulse${ot.pulses === 1 ? "" : "s"}${ot.families.length ? ` (${ot.families.slice(0, 3).join(", ")})` : ""}`, "otx");
  if (ot?.whitelisted?.length) add(-15, `OTX whitelists it (${ot.whitelisted.slice(0, 2).join(", ")})`, "otx");
  if (sh?.tags?.some((t) => /compromised|malware|c2|botnet/i.test(t))) add(20, `Shodan tags it ${sh.tags.join(", ")}`, "internetdb");
  if (sh?.vulns?.length) add(5, `${sh.vulns.length} known vulnerabilit${sh.vulns.length === 1 ? "y" : "ies"} in its own services (likely to be someone's foothold)`, "internetdb");
  if (tor?.exit) add(10, "a Tor exit", "tor");
  if (sfs?.reports) add(Math.min(15, sfs.reports), `${sfs.reports} StopForumSpam report${sfs.reports === 1 ? "" : "s"}`, "sfs");
  const hosting = L?.asn?.hosting || /hosting|data ?cent|cloud|server/i.test(ab?.usage || "");
  if (hosting) add(5, "a hosting or cloud network (where scanners live)", "network");
  if (L?.verdict?.bad && !why.some((x) => x.source === "greynoise" || x.source === "dnsbl")) add(15, `the background lookup flagged it: ${(L.verdict.why || []).slice(0, 2).join(", ")}`, "bulwark");
  let score = Math.max(0, Math.min(100, why.reduce((a, x) => a + x.w, 0)));
  if (mine) { score = 0; why.unshift({ w: 0, text: isPrivate(ip) ? "a private address: yours" : L?.devices?.length ? "one of your devices uses it" : L?.own ? "this machine's own address" : L?.allowed ? "on your allow list" : "you signed in from it", source: "bulwark" }); }
  const level = mine ? "yours" : score >= 70 ? "malicious" : score >= 40 ? "suspicious" : score >= 15 ? "notice" : "clean";
  // who and where, from whoever knows
  const asn = rs?.asn || cy?.asn || L?.asn?.asn || null;
  const owner = rd?.registrant?.name || rd?.name || null;
  const abuse = [...new Set([...(rs?.abuse || []), ...(rd?.abuse?.email ? rd.abuse.email.split(", ") : [])])];
  const summary = {
    score, level, why: why.sort((a, b) => Math.abs(b.w) - Math.abs(a.w)),
    asn, asName: rs?.holder || cy?.name || L?.asn?.name || ab?.isp || null, prefix: rs?.prefix || cy?.prefix || rd?.cidr?.[0] || null, owner, netName: rd?.name || null,
    country: rs?.geo?.country || ii?.country || iw?.cc || cy?.cc || L?.asn?.cc || null, city: ii?.city || iw?.city || rs?.geo?.city || null,
    lat: rs?.geo?.lat ?? ii?.lat ?? iw?.lat ?? null, lon: rs?.geo?.lon ?? ii?.lon ?? iw?.lon ?? null,
    ptr: ptr?.names || [], hostname: ptr?.names?.[0]?.name || ii?.hostname || null, abuse, registry: cy?.registry || null, allocated: cy?.allocated || rd?.registered || null,
    usage: ab?.usage || (hosting ? "hosting" : null), anycast: !!ii?.anycast, isp: iw?.isp || ab?.isp || null, tor: !!tor?.exit, ports: sh?.ports || [], vulns: sh?.vulns?.length || 0,
    here: p ? { first: p.first, last: p.last, requests: p.n, banned: !!L.ban } : null,
  };
  // its activity here, over time: buckets by decision
  const timeline = (() => {
    if (!here.length) return null;
    const t1 = Math.max(...here.map((e) => e.t)), t0 = Math.min(...here.map((e) => e.t)), span = Math.max(t1 - t0, 60e3), n = 48, step = span / n;
    const buckets = Array.from({ length: n }, (_, i) => ({ t: t0 + i * step, pass: 0, stopped: 0, attack: 0 }));
    for (const e of here) { const b = buckets[Math.min(n - 1, Math.floor((e.t - t0) / step))]; if (e.dec === "pass" || e.dec === "seen") b.pass++; else b.stopped++; if (e.sig) b.attack++; }
    return { from: t0, to: t1, step, buckets };
  })();
  const cats = {};
  for (const [s, n] of sigs) { const c = categoryOf(s); if (c) cats[c] = (cats[c] || 0) + n; }
  const sources = {};
  for (const s of SOURCES) {
    const r = R[s.id] || { state: "pending" };
    sources[s.id] = { id: s.id, name: s.name, about: s.about, state: r.state, why: r.why || null, error: r.error || null, cached: !!r.cached, at: r.at || null, took: r.took ?? null, data: r.data ?? null, raw: r.raw ?? null };
  }
  return {
    ip, version: isIP(ip), private: isPrivate(ip), at: job.at, running: job.running, pending: Object.entries(sources).filter(([, s]) => s.state === "pending").map(([k]) => k),
    summary, sources,
    here: L ? { profile: p || null, ban: L.ban, allowed: L.allowed, trusted: L.trusted, own: L.own, devices: L.devices, lists: L.lists, verdict: L.verdict, alerts: L.alerts, reported: L.reported,
                cats: Object.entries(cats).sort((a, b) => b[1] - a[1]).map(([id, n]) => ({ id, n, name: categoryById(id)?.name || id, color: categoryById(id)?.color || null })),
                cves: p?.cves || [...new Set(here.map((e) => e.cve).filter(Boolean))], timeline, logs: here.slice(0, 300) } : null,
    neighbours: L?.neighbours || null,
    links: linksFor(ip, asn),
    sent: job.calls.slice(0, 60),
  };
}
