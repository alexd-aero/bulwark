// The IP Inspector (core/inspect.mjs): every source asked, the answers kept,
// one report assembled. The network is faked: no request leaves the machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Inspector, linksFor, SOURCES } from "../core/inspect.mjs";

const IP = "203.0.113.45";
const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
// what the internet answers (shapes as the real services send them)
function internet({ fail = {}, hang = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    const u = new URL(url);
    calls.push({ url: String(url), headers: opts?.headers || {} });
    if (hang[u.hostname]) return new Promise(() => {});
    if (fail[u.hostname]) return json({}, fail[u.hostname]);
    if (u.hostname === "rdap.org") return json({ handle: "NET-203-0-113-0-1", name: "EXAMPLE-NET", type: "ASSIGNED PA", country: "NL", startAddress: "203.0.113.0", endAddress: "203.0.113.255",
      cidr0_cidrs: [{ v4prefix: "203.0.113.0", length: 24 }], events: [{ eventAction: "registration", eventDate: "2019-04-01T00:00:00Z" }, { eventAction: "last changed", eventDate: "2024-02-02T00:00:00Z" }],
      entities: [{ roles: ["registrant"], handle: "ORG-EX1", vcardArray: ["vcard", [["fn", {}, "text", "Example Hosting B.V."]]] },
                 { roles: ["technical"], entities: [{ roles: ["abuse"], handle: "AB-1", vcardArray: ["vcard", [["fn", {}, "text", "Abuse desk"], ["email", {}, "text", "abuse@hosting.example"]]] }] }] });
    if (u.hostname === "stat.ripe.net") {
      const name = u.pathname.split("/")[2], res = u.searchParams.get("resource");
      const data = {
        "network-info": { asns: ["64500"], prefix: "203.0.113.0/24" },
        "prefix-overview": { resource: "203.0.113.0/24", announced: true, asns: [{ asn: 64500, holder: "EXAMPLE-AS - Example Hosting B.V." }], block: { desc: "TEST-NET-3" } },
        "maxmind-geo-lite": { located_resources: [{ locations: [{ country: "NL", city: "Amsterdam", latitude: 52.37, longitude: 4.89, covered_percentage: 100 }] }] },
        "abuse-contact-finder": { abuse_contacts: ["abuse@hosting.example", "noc@hosting.example"] },
        blocklist: { sources: { uceprotect: [{ prefix: res }], spamhaus: [] } },
        "routing-status": { visibility: { v4: { ris_peers_seeing: 320, total_ris_peers: 330 } }, first_seen: { time: "2019-05-01T00:00:00" }, origins: [{ origin: 64500 }] },
        "announced-prefixes": { prefixes: [{ prefix: "203.0.113.0/24" }, { prefix: "198.51.100.0/24" }] },
        "rpki-validation": { status: "valid" },
      }[name];
      return json({ data });
    }
    if (u.hostname === "internetdb.shodan.io") return json({ ip: IP, ports: [22, 80, 8080], cpes: ["cpe:/a:openbsd:openssh:8.2"], vulns: ["CVE-2023-38408"], tags: ["compromised"], hostnames: [] });
    if (u.hostname === "api.greynoise.io") return json({ ip: IP, noise: true, riot: false, classification: "malicious", name: "unknown", last_seen: "2026-10-21" });
    if (u.hostname === "otx.alienvault.com") return json({ reputation: 0, validation: [], pulse_info: { count: 3, pulses: [{ id: "p1", name: "SSH brute force", created: "2026-10-01", tags: ["ssh"], malware_families: [{ display_name: "Mirai" }] }] } });
    if (u.hostname === "api.abuseipdb.com") return json({ data: { abuseConfidenceScore: 100, totalReports: 812, numDistinctUsers: 140, lastReportedAt: "2026-10-22T08:00:00Z", usageType: "Data Center/Web Hosting/Transit",
      isp: "Example Hosting", domain: "hosting.example", isTor: false, isWhitelisted: false, countryCode: "NL", reports: [{ reportedAt: "2026-10-22T08:00:00Z", comment: "GET /.env", categories: [21, 15], reporterCountryCode: "DE" }] } });
    if (u.hostname === "onionoo.torproject.org") return json({ relays: [] });
    if (u.hostname === "api.stopforumspam.org") return json({ ip: { frequency: 2, lastseen: "2026-09-01", confidence: 40 } });
    if (u.hostname === "ipinfo.io") return json({ ip: IP, hostname: "scan-45.hosting.example", city: "Amsterdam", region: "North Holland", country: "NL", loc: "52.37,4.89", org: "AS64500 Example Hosting B.V.", timezone: "Europe/Amsterdam" });
    if (u.hostname === "ipwho.is") return json({ success: true, type: "IPv4", country: "Netherlands", country_code: "NL", city: "Amsterdam", latitude: 52.37, longitude: 4.89, connection: { asn: 64500, org: "Example Hosting", isp: "Example Hosting B.V.", domain: "hosting.example" }, timezone: { id: "Europe/Amsterdam" } });
    return json({}, 404);
  };
  const enoent = () => Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  const dns = {
    reverse: async (ip) => (ip === IP ? ["scan-45.hosting.example", "spoof.other.example"] : []),
    resolve4: async (name) => {
      if (name === "scan-45.hosting.example") return [IP];
      if (name === "spoof.other.example") return ["198.51.100.1"];
      if (name.endsWith("dnsbl.dronebl.org")) return ["127.0.0.13"];
      if (name.endsWith("zen.spamhaus.org")) return ["127.0.0.4", "127.0.0.11"];
      throw enoent();
    },
    resolve6: async () => { throw enoent(); },
    resolveTxt: async (name) => {
      if (name.endsWith(".origin.asn.cymru.com")) return [["64500 | 203.0.113.0/24 | NL | ripencc | 2019-04-01"]];
      if (name === "AS64500.asn.cymru.com") return [["64500 | NL | ripencc | 2001-01-01 | EXAMPLE-AS Example Hosting, NL"]];
      throw enoent();
    },
  };
  return { fetchImpl, dns, calls };
}
// what Bulwark itself remembers
function fakeBrain() {
  const now = Date.now();
  const prof = (ip, extra = {}) => ({ ip, first: now - 864e5, last: now - 6e4, n: 4, sigs: {}, cats: {}, seq: [], hosts: { "x.example": 4 }, uas: ["Go-http-client/1.1"], paths: ["/.env"], dec: { drop: 2 }, asn: 64500, org: "EXAMPLE-AS", cc: "NL", ...extra });
  const profiles = new Map([
    [IP, prof(IP, { sigs: { "env-file": 2, "vcs": 1, "sqli": 1 }, cats: { secrets: 3, sqli: 1 }, cves: [] })],
    ["203.0.113.46", prof("203.0.113.46", { sigs: { "env-file": 1 }, cats: { secrets: 1 } })],
    ["198.51.100.20", prof("198.51.100.20", { sigs: { wordpress: 1 } })],
    ["192.0.2.9", prof("192.0.2.9", { asn: 64999 })],
  ]);
  const logs = [{ t: now - 3e5, ip: IP, m: "GET", path: "/.env", host: "x.example", dec: "drop", sig: "env-file", cat: "secrets", st: 404 },
                { t: now - 2e5, ip: IP, m: "GET", path: "/.git/config", host: "x.example", dec: "ban", sig: "vcs", cat: "secrets", st: 403 },
                { t: now - 1e5, ip: IP, m: "GET", path: "/", host: "x.example", dec: "block", st: 403 }];
  return {
    settings: { abuseipdbKey: "secret-key-123" },
    profiles: { get: (ip) => profiles.get(ip) || null, map: profiles },
    logs: { query: async ({ ip }) => logs.filter((e) => e.ip === ip).reverse() },
    feeds: { lookup: (ip) => (ip === IP ? [{ id: "firehol2", name: "FireHOL level 2", strength: "strong" }] : []), lists: new Map() },
    verdicts: new Map([[IP, { level: "malicious", why: ["GreyNoise: known malicious"], bad: true, benign: false, at: now }]]),
    waves: { list: () => [{ id: "w1", key: "c1", title: "a campaign: env-file → vcs", sev: "warn", kind: "campaign", open: true, first: now - 4e5, last: now, members: [IP, "203.0.113.46"] }] },
    asn: { lookup: () => ({ asn: 64500, name: "EXAMPLE-AS", cc: "NL", hosting: true }) },
    state: { bans: { [IP]: { reason: "sent 2 payloads (/.git/config, /.env)", source: "payload", at: now - 2e5 }, "203.0.113.46": { reason: "x", source: "payload" } }, allow: {} },
    isTrusted: () => false, own: new Set(), devicesAt: () => [],
    reporters: { state: { reported: {}, checks: {}, used: { check: 0 } }, budget: () => true },
  };
}

test("a full inspection: every source, one report, a verdict with its reasons", async () => {
  const net = internet(), brain = fakeBrain();
  const ins = new Inspector({ brain, ...net, spacing: 0.01 });
  const job = ins.inspect(IP);
  const early = job.view();
  assert.ok(early.running);
  await job.done;
  const r = job.view();
  assert.equal(r.running, false); assert.deepEqual(r.pending, []);
  for (const s of SOURCES) assert.equal(r.sources[s.id].state, "ok", `${s.id}: ${r.sources[s.id].error || r.sources[s.id].why || ""}`);
  const S = r.summary;
  assert.equal(S.asn, 64500); assert.equal(S.prefix, "203.0.113.0/24"); assert.equal(S.owner, "Example Hosting B.V."); assert.equal(S.country, "NL"); assert.equal(S.city, "Amsterdam");
  assert.deepEqual(S.abuse.sort(), ["abuse@hosting.example", "noc@hosting.example"]);
  assert.deepEqual(S.ptr, [{ name: "scan-45.hosting.example", confirmed: true }, { name: "spoof.other.example", confirmed: false }], "a PTR name counts only if it leads back");
  assert.equal(S.level, "malicious"); assert.equal(S.score, 100);
  for (const src of ["bulwark", "lists", "greynoise", "abuseipdb", "dnsbl", "otx", "internetdb"]) assert.ok(S.why.some((w) => w.source === src), `a reason from ${src}`);
  assert.ok(S.why.some((w) => /DroneBL: brute-force attacker/.test(w.text)));
  assert.ok(!S.why.some((w) => /PBL/.test(w.text)), "Spamhaus's PBL code (a home range) is not a listing");
  // the record of its own: sources' details, raw answers kept
  assert.equal(r.sources.rdap.data.abuse.email, "abuse@hosting.example");
  assert.equal(r.sources.ripestat.data.rpki, "valid");
  assert.equal(r.sources.ripestat.data.asPrefixes.count, 2);
  assert.deepEqual(r.sources.ripestat.data.blocklists, [{ list: "uceprotect", entries: 1 }]);
  assert.equal(r.sources.abuseipdb.data.categories[0].name, "Web App Attack");
  assert.equal(r.sources.cymru.data.name, "EXAMPLE-AS Example Hosting, NL");
  assert.ok(r.sources.internetdb.raw.ports.includes(8080), "the raw answer is there to expand");
  // what Bulwark knows: its log, its categories, its campaign, its neighbours
  assert.equal(r.here.logs.length, 3); assert.ok(r.here.timeline.buckets.length);
  assert.deepEqual(r.here.cats.map((c) => c.id), ["secrets", "sqli"]);
  assert.equal(r.here.alerts[0].kind, "campaign");
  assert.deepEqual(r.neighbours.same.map((x) => x.ip), ["203.0.113.46"]); assert.equal(r.neighbours.sameBanned, 1);
  assert.deepEqual(r.neighbours.network.map((x) => x.ip), ["198.51.100.20"], "the same network, another /24");
  // links to look further
  assert.ok(r.links.some((l) => l.url === `https://www.abuseipdb.com/check/${IP}`));
  assert.ok(r.links.some((l) => l.url === "https://bgp.he.net/AS64500"));
  for (const name of ["GreyNoise", "Shodan", "Censys", "VirusTotal", "AlienVault OTX", "ThreatFox (abuse.ch)", "Cisco Talos", "IPinfo", "bgp.he.net", "RIPEstat"]) assert.ok(r.links.some((l) => l.name === name), name);
  assert.ok(r.sent.length >= 12, "what went out is on the record");
});

test("only the address goes out (and its network, for routing); the key only in a header", async () => {
  const net = internet(), brain = fakeBrain();
  await new Inspector({ brain, ...net, spacing: 0.01 }).inspect(IP).done;
  assert.ok(net.calls.length >= 12);
  for (const c of net.calls) {
    const u = new URL(c.url);
    assert.ok(u.protocol === "https:", `${c.url}: encrypted`);
    assert.ok(c.url.includes(IP) || c.url.includes("AS64500") || c.url.includes("203.0.113.0%2F24"), `${c.url} carries nothing but the address`);
    assert.ok(!/x\.example|Go-http-client|\/\.env/.test(c.url.replace(/stat\.ripe\.net|sourceapp=bulwark/g, "")), `${c.url}: nothing from the log`);
    assert.ok(!c.url.includes("secret-key-123"), "the key never in a URL");
    assert.ok(!c.headers.Cookie && !c.headers.Referer);
  }
  assert.equal(net.calls.find((c) => c.url.includes("abuseipdb")).headers.Key, "secret-key-123");
});

test("answers are kept: asking again costs nothing; fresh asks again", async () => {
  const net = internet(), brain = fakeBrain();
  const ins = new Inspector({ brain, ...net, spacing: 0.01 });
  await ins.inspect(IP).done;
  const n = net.calls.length;
  assert.equal(ins.inspect(IP), ins.inspect(IP), "the same job within minutes");
  ins.jobs.clear();
  const j2 = ins.inspect(IP); await j2.done;
  assert.equal(net.calls.length, n, "a new job, from the cache");
  assert.ok(Object.values(j2.view().sources).every((s) => s.cached));
  await ins.inspect(IP, { fresh: true }).done;
  assert.ok(net.calls.length > n, "fresh: asked again");
});

test("a source that fails or hangs is reported, the rest still answer; hosts are asked politely", async () => {
  const net = internet({ fail: { "otx.alienvault.com": 500, "api.greynoise.io": 429 }, hang: { "ipwho.is": true } }), brain = fakeBrain();
  const ins = new Inspector({ brain, ...net, spacing: 0.01, timeoutMs: 150 });
  const job = ins.inspect(IP); await job.done;
  const r = job.view();
  assert.equal(r.sources.otx.state, "error"); assert.match(r.sources.otx.error, /HTTP 500/);
  assert.match(r.sources.greynoise.error, /rate-limited/);
  assert.equal(r.sources.ipwhois.state, "error");
  assert.equal(r.sources.rdap.state, "ok"); assert.equal(r.summary.asn, 64500);
  // spacing: RIPEstat's calls are never at once
  const p = new Inspector({ spacing: 1 }), t = [];
  p.fetch = async (url) => { t.push(Date.now()); return json({ data: {} }); };
  await Promise.all([1, 2, 3].map(() => p.json("https://stat.ripe.net/data/x/data.json?resource=203.0.113.1")));
  assert.ok(t[2] - t[0] >= 450, `three requests to one host spread out (${t[2] - t[0]} ms)`);
});

test("without a key AbuseIPDB is skipped; a private address asks nobody; yours is never 'malicious'", async () => {
  const net = internet(), brain = fakeBrain();
  brain.settings.abuseipdbKey = "";
  const ins = new Inspector({ brain, ...net, spacing: 0.01 });
  const r = await (async () => { const j = ins.inspect(IP); await j.done; return j.view(); })();
  assert.equal(r.sources.abuseipdb.state, "skipped");
  const n = net.calls.length;
  const p = ins.inspect("192.168.1.20"); await p.done;
  assert.equal(net.calls.length, n);
  assert.equal(p.view().summary.level, "yours");
  brain.isTrusted = (ip) => ip === "198.51.100.20";
  const y = ins.inspect("198.51.100.20"); await y.done;
  assert.equal(y.view().summary.level, "yours"); assert.equal(y.view().summary.score, 0);
  assert.throws(() => ins.inspect("not-an-ip"), /isn't an IP/);
  assert.ok(linksFor("2001:db8::1").every((l) => l.url.includes("2001%3Adb8%3A%3A1")), "IPv6, encoded");
});
