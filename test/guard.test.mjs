// The guard (sensor/guard.mjs): what is decided on the spot, inside the host.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Guard } from "../sensor/guard.mjs";
import { FEEDS, parseFeed, RangeSet, lookupIn } from "../core/lists.mjs";
import { classify, classifyRequest } from "../core/payloads.mjs";
import { netOf } from "../core/net.mjs";

const feed = (id) => FEEDS.find((f) => f.id === id);
function guard(lists = {}) {
  const sent = [];
  const g = new Guard({ emit: (m) => sent.push(m) });
  const m = new Map();
  for (const [id, text] of Object.entries(lists)) m.set(id, parseFeed(feed(id), text));
  g.useLists(m);
  return { g, sent };
}

test("ranges: CIDRs merge, edges hold, IPv6; pack/unpack survives a worker hop", () => {
  const r = new RangeSet();
  for (const e of ["10.0.0.0/8", "11.0.0.0/8", "45.148.10.0/24", "1.2.3.4", "2001:db8::1", "2a01:4f8::/32", "bogus"]) r.add(e);
  r.seal();
  assert.equal(r.start.length, 3);
  const u = RangeSet.unpack(structuredClone(r.pack()));
  for (const ip of ["11.255.255.255", "45.148.10.120", "1.2.3.4", "2001:db8::1", "2a01:4f8:1:2::3"]) assert.ok(u.has(ip), ip);
  for (const ip of ["12.0.0.0", "45.148.11.0", "1.2.3.5", "2001:db8::2"]) assert.equal(u.has(ip), false, ip);
});

test("list formats: IPsum tiers, the elsnet page", () => {
  const ipsum = parseFeed(feed("ipsum"), "45.148.10.120\t4\n57.129.136.57\t1\n");
  assert.ok(ipsum.strong.has("45.148.10.120"));
  assert.ok(ipsum.weak.has("57.129.136.57"));
  const els = parseFeed(feed("elsnet"), "<pre>\n host_bb.x.com 223.223.149.161 2015/08/28-11:12:21 1\n - 10.1.2.3 2021/01/01-00:00:00 1</pre>");
  assert.deepEqual(els.weak.has("223.223.149.161"), { host: "host_bb.x.com", since: "2015-08-28 11:12:21", hits: 1 });
  assert.equal(els.weak.count, 1);
  assert.deepEqual(lookupIn(new Map([["ipsum", ipsum]]), "45.148.10.120").map((l) => l.strength), ["strong"]);
});

test("payload signatures have names", () => {
  assert.equal(classify("/backup/.env").id, "env-file");
  assert.equal(classify("/.git/config").id, "vcs");
  assert.equal(classify("/%2e%2e/%2e%2e/etc/passwd").id, "traversal");
  assert.equal(classify("/?x=${jndi:ldap://a/b}").id, "log4shell");
  assert.equal(classify("/wp-login.php").id, "wordpress");
  assert.equal(classify("/ihfdfhdsif.php").id, "php-probe");
  for (const p of ["/", "/test", "/api/status", "/assets/x.js", "/docs/env.md", "/wp-content/uploads/a.png"]) assert.equal(classify(p).score, 0, p);
});

test("networks for grouping", () => {
  assert.equal(netOf("35.236.186.124"), "35.236.186.0/24");
  assert.equal(netOf("35.236.186.124", true), "35.236.0.0/16");
  assert.equal(netOf("2a00:1450:4001:82a::4"), "2a00:1450:4001::/48");
});

test("strong list: banned on sight, and the app is told", () => {
  const { g, sent } = guard({ ipsum: "45.148.10.120\t4\n57.129.136.57\t1\n" });
  const info = { path: "/", host: "x.example", country: "NL" };
  assert.equal(g.gate("45.148.10.120", info).status, 403);
  assert.equal(info._bw.dec, "ban");
  assert.equal(sent[0].t, "ban");
  assert.match(sent[0].b.reason, /IPsum/);
  assert.equal(g.gate("45.148.10.120", { path: "/" }).status, 403);
  assert.equal(g.gate("57.129.136.57", { path: "/" }), null, "weak alone: through");
});

test("payloads: dropped, banned on the second; probe + mark bans; strict bans the first", () => {
  const { g } = guard({ ipsum: "57.129.136.57\t1\n" });
  assert.equal(g.gate("35.236.186.124", { path: "/svelte/.env" }).status, 404);
  assert.equal(g.gate("35.236.186.124", { path: "/vite/.env" }).status, 403);
  assert.equal(g.gate("165.227.62.8", { path: "/wp-login.php" }), null);
  assert.equal(g.gate("57.129.136.57", { path: "/ihfdfhdsif.php" }).status, 403);
  g.apply({ t: "strict", until: Date.now() + 60000 });
  assert.equal(g.gate("203.0.113.5", { path: "/.git/config" }).status, 403, "during a wave the first payload bans");
});

test("never you: private, signed-in, a session, allow list; a sign-in lifts a ban", () => {
  const { g, sent } = guard({ firehol1: "93.184.0.0/16\n185.199.0.0/16\n8.8.8.0/24\n" });
  assert.equal(g.gate("192.168.1.20", { path: "/.env" }), null);
  g.trust("93.184.216.34");
  assert.equal(g.gate("93.184.216.34", { path: "/.env" }), null);
  assert.equal(g.gate("185.199.108.153", { path: "/", trusted: () => true }), null);
  assert.ok(sent.some((m) => m.t === "trust" && m.ip === "185.199.108.153"), "the app hears of it");
  g.apply({ t: "allow", ip: "8.8.8.8", on: true });
  assert.equal(g.gate("8.8.8.8", { path: "/.env" }), null);
  assert.equal(g.gate("8.8.8.9", { path: "/" }).status, 403);
  g.trust("8.8.8.9");
  assert.equal(g.gate("8.8.8.9", { path: "/" }), null);
});

test("this machine's own address: not trusted, not banned, payloads dropped unless it's your session", () => {
  const { g } = guard({ firehol1: "93.184.0.0/16\n" });
  g.apply({ t: "own", list: ["93.184.216.34"] });
  g.trust("93.184.216.34");
  assert.equal(g.isTrusted("93.184.216.34"), false);
  assert.equal(g.gate("93.184.216.34", { path: "/" }), null);
  assert.equal(g.gate("93.184.216.34", { path: "/.env" }).status, 404);
  assert.equal(g.gate("93.184.216.34", { path: "/.env", trusted: () => true }), null);
});

test("known services (benign verdict): probes and a list mark don't ban; two secret hunts do", () => {
  const { g } = guard({ ipsum: "138.68.86.32\t1\n66.249.66.1\t1\n" });
  g.apply({ t: "verdict", ip: "66.249.66.1", v: { benign: true, bad: false, level: "notice", why: ["Googlebot"] } });
  for (const p of ["/wp-login.php", "/phpmyadmin/", "/x.php", "/cgi-bin/", "/owa/"]) g.gate("66.249.66.1", { path: p });
  assert.equal(g.bans.has("66.249.66.1"), false, "a crawler asking for software that isn't here");
  g.apply({ t: "verdict", ip: "138.68.86.32", v: { benign: true, bad: false, level: "malicious", why: ["LeakIX"] } });
  assert.equal(g.gate("138.68.86.32", { path: "/.env" }).status, 404, "the first: dropped");
  assert.equal(g.gate("138.68.86.32", { path: "/.git/config" }).status, 403, "the second: banned");
  assert.match(g.bans.get("138.68.86.32").reason, /hunted secrets.*LeakIX/);
});

test("new patterns: phishing-kit hunters, edge exploits, cluster APIs, attack tools by User-Agent", () => {
  const { g } = guard();
  // 146.70.134.142's walk on 2026-10-14: a phishing-kit hunter
  assert.equal(g.gate("146.70.134.142", { path: "/js/raif_ch.js" }).status, 404);
  assert.equal(g.gate("146.70.134.142", { path: "/js/twint_ch.js" }).status, 403);
  assert.equal(classify("/static/style/sys_files/index.js").id, "phish-kit");
  assert.equal(classify("/remote/fgt_lang?lang=/../../../..//////////dev/").score, 3);
  assert.equal(classify("/api/v1/namespaces/default/secrets").id, "infra-api");
  assert.equal(classify("/index.php?s=/Index/\\think\\app/invokefunction").id, "rce");
  assert.equal(classify("/phpinfo.php").id, "info-leak");
  assert.equal(g.gate("198.51.100.7", { path: "/", ua: "sqlmap/1.8#stable" }).status, 404, "an attack tool's request never reaches the app");
  assert.equal(g.gate("198.51.100.8", { path: "/", ua: "l9explore/1.2.2" }), null, "a mass scanner only marks");
  for (let i = 0; i < 12; i++) g.gate("198.51.100.8", { path: "/", ua: "l9explore/1.2.2" });
  assert.equal(g.bans.has("198.51.100.8"), false, "its name alone never adds up to a ban");
  assert.equal(classifyRequest("/", "curl/7.81.0").score, 0, "curl is just curl");
  for (const p of ["/assets/js/auth.js", "/css/support_parent.css", "/api/query?q=hello", "/search?query=cats", "/docs/info.md", "/js/app_main.js"]) assert.equal(classify(p).score, 0, p);
});

test("state from the app replaces the guard's, and the log line carries everything", () => {
  const { g } = guard();
  g.apply({ t: "state", bans: [["203.0.113.9", { reason: "by hand", until: null, source: "manual" }]], allow: [], trusted: [], own: [], verdicts: [], settings: { auto: true } });
  const info = { path: "/x?y=1", method: "GET", host: "27715.tunnel.example", country: "US", ua: "curl/8", referer: "", port: 27715 };
  assert.equal(g.gate("203.0.113.9", info).status, 403);
  const e = g.entry("203.0.113.9", info, { status: 403, bytes: 8, ms: 0 });
  assert.equal(e.dec, "block"); assert.equal(e.why, "by hand"); assert.equal(e.port, 27715); assert.equal(e.st, 403); assert.equal(e.ua, "curl/8");
});

test("your devices: their addresses are trusted as of when used; a request with a device key is marked and never banned", () => {
  const { g } = guard({ ipsum: "45.148.10.120\t4\n" });
  const long = Date.now() - 40 * 864e5, recent = Date.now() - 864e5;
  g.apply({ t: "devices", addresses: { "198.51.100.7": { last: recent }, "198.51.100.8": { last: long } } });
  assert.equal(g.isTrusted("198.51.100.7"), true);
  assert.equal(g.isTrusted("198.51.100.8"), false, "used 40 days ago: no longer");
  g.trust("198.51.100.9");
  g.apply({ t: "devices", addresses: { "198.51.100.9": { last: long } } });
  assert.equal(g.isTrusted("198.51.100.9"), true, "an older time never pushes back a newer one");
  // a device key on a strong-listed address (a phone on a dirty mobile network)
  const info = { path: "/.env", host: "x.example", device: "dev-a", trusted: () => true };
  assert.equal(g.gate("45.148.10.120", info), null);
  assert.equal(g.bans.has("45.148.10.120"), false);
  assert.equal(g.entry("45.148.10.120", info, { status: 200 }).dev, "dev-a");
  assert.equal(g.entry("203.0.113.1", { path: "/" }, {}).dev, undefined);
});

test("fast: 100k decisions well under a second", () => {
  const lines = [];
  for (let i = 0; i < 50000; i++) lines.push(`${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}.${(i * 7) & 255}\t1`);
  const { g } = guard({ ipsum: lines.join("\n"), firehol1: "5.188.10.0/23\n" });
  const t0 = performance.now();
  for (let i = 0; i < 100000; i++) g.gate(`${(i * 13) & 255}.${(i >> 3) & 255}.${i & 255}.${(i * 3) & 255}`, { path: i % 7 ? "/assets/app.js" : "/index.html" });
  const ms = performance.now() - t0;
  assert.ok(ms < 1500, `took ${Math.round(ms)} ms`);
  assert.ok(g.stats.us / g.stats.requests < 15, `${(g.stats.us / g.stats.requests).toFixed(1)} µs a request`);
});
