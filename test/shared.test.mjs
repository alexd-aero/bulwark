// Shared addresses (sensor/clients.mjs, the guard): a school, a home, a carrier's
// NAT puts many people behind one address. What one of them does is held
// against that client, not the address; the address only for overwhelming
// evidence, briefly. Then credential-stuffing campaigns, and the plain-English
// reason every decision carries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Guard, SHARED_BAN_FOR } from "../sensor/guard.mjs";
import { fingerprint, Crowds } from "../sensor/clients.mjs";
import { FEEDS, parseFeed } from "../core/lists.mjs";
import { traffic } from "./bench.mjs";

const HOUR = 3600e3, DAY = 24 * HOUR;
function setup(lists = {}) {
  const sent = [];
  let t = Date.parse("2026-11-19T10:00:00Z");
  const clock = { now: () => t, move: (ms) => { t += ms; } };
  const g = new Guard({ emit: (m) => sent.push(m), now: () => t });
  const m = new Map();
  for (const [id, text] of Object.entries(lists)) m.set(id, parseFeed(FEEDS.find((f) => f.id === id), text));
  g.useLists(m);
  return { g, sent, clock };
}
const chromebook = (i) => `Mozilla/5.0 (X11; CrOS x86_64 ${15600 + (i % 3)}.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`;
// a browser's request: a person behind the address, with the headers a browser sends
function req(c, path = "/", extra = {}) {
  const headers = { host: "app.example", "user-agent": c.ua, accept: "text/html,*/*;q=0.8", "sec-fetch-mode": "navigate", "accept-encoding": "gzip, br", "accept-language": c.lang || "en-US,en;q=0.9" };
  if (c.ga) headers.cookie = `_ga=${c.ga}; theme=dark`;
  return { method: "GET", path, host: "app.example", access: "login", ua: c.ua, lang: "en-US", headers, ...extra };
}
// one request, answered: what the guard said, and what the app answered (200 unless stopped)
function visit(g, ip, c, path = "/", extra = {}, status = 200) {
  const info = req(c, path, extra);
  const r = g.gate(ip, info);
  g.after(ip, info, { status: r?.status ?? status });
  return { r, info, e: g.entry(ip, info, { status: r?.status ?? status }) };
}
const browse = (g, ip, clients) => { for (const c of clients) { visit(g, ip, c, "/"); visit(g, ip, c, "/assets/app.js"); } };

test("a school: 300 clients behind one address, one attacks; only that client is banned", () => {
  const { g, sent } = setup();
  const school = "203.0.113.10";
  // half of them the same Chromebook (one model, one browser version), told apart by their own cookies
  const kids = Array.from({ length: 300 }, (_, i) => (i % 2 ? { ua: chromebook(0), ga: `GA1.1.${1000000 + i}.1731990000` } : { ua: chromebook(i) + ` Kid/${i}`, lang: i % 4 ? "en-US" : "es-US" }));
  browse(g, school, kids);
  assert.ok(g.sharedSize(school) >= 100, `the school is seen as shared (${g.sharedSize(school)})`);
  assert.ok(sent.some((m) => m.t === "shared" && m.ip === school), "the app hears of it");
  const bad = kids[7];
  const a = visit(g, school, bad, "/.env");
  assert.equal(a.r.status, 404, "the payload is dropped");
  assert.equal(a.e.scope, "client");
  assert.match(a.e.expl, /dropped a payload.*this client \(not the whole address: over 100 others use it\)/);
  const b = visit(g, school, bad, "/.git/config");
  assert.equal(b.r.status, 403);
  assert.equal(b.e.dec, "ban");
  assert.match(b.e.expl, /^banned this client for 1 hour, not the whole address \(over 100 others use it\)/);
  assert.equal(g.bans.has(school), false, "the school's address is not banned");
  assert.equal(g.clientBans.size, 1);
  assert.ok(sent.some((m) => m.t === "clientban" && m.ip === school && m.b.reason.includes("2 payloads")));
  assert.ok(!sent.some((m) => m.t === "ban"), "no address ban, so no kick for everyone");
  // the attacker stays out; everyone else, the same Chromebook included, goes on
  const again = visit(g, school, bad, "/");
  assert.equal(again.r.status, 403);
  assert.match(again.e.expl, /^blocked this client, not the whole address/);
  for (const k of [kids[8], kids[9], kids[10], kids[299]]) assert.equal(visit(g, school, k, "/dashboard").r, null);
  // a new student with the same Chromebook and no cookie yet is someone else too
  assert.equal(visit(g, school, { ua: chromebook(0), ga: "GA1.1.555.1731990000" }, "/").r, null);
});

test("a home with 3 clients: the one who attacks is banned, the other two aren't", () => {
  const { g, sent } = setup();
  const home = "198.51.100.40";
  const family = [{ ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 Safari/537.36" }, { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Version/18.1 Mobile Safari/604.1" },
                  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0", lang: "ru-RU,ru;q=0.9" }];
  browse(g, home, family);
  assert.equal(g.sharedSize(home), 3);
  visit(g, home, family[2], "/.env");
  const b = visit(g, home, family[2], "/wp-config.php.bak");
  assert.equal(b.e.dec, "ban");
  assert.match(b.e.expl, /not the whole address \(2 others use it\)/);
  assert.equal(g.bans.has(home), false);
  assert.equal(visit(g, home, family[0], "/").r, null);
  assert.equal(visit(g, home, family[1], "/photos").r, null);
  assert.equal(visit(g, home, family[2], "/").r.status, 403);
  assert.ok(!sent.some((m) => m.t === "ban"));
});

test("an address with one client is judged as before: two payloads ban the address for 30 days", () => {
  const { g, sent } = setup();
  const ip = "198.51.100.50", me = { ua: "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0 Safari/537.36" };
  browse(g, ip, [me, me, me]);
  assert.equal(g.sharedSize(ip), 1, "one browser, however many requests");
  const a = visit(g, ip, me, "/.env");
  assert.equal(a.e.scope, "address");
  assert.match(a.e.expl, /this address has 5 of 10 points/);
  const b = visit(g, ip, me, "/.git/config");
  assert.equal(b.r.status, 403);
  const ban = g.bans.get(ip);
  assert.ok(ban && ban.until - ban.at >= 29 * DAY, "30 days, as before");
  assert.match(b.e.expl, /^banned this address for 30 days/);
  assert.ok(sent.some((m) => m.t === "ban" && m.ip === ip));
  assert.equal(g.clientBans.size, 0);
  // a scanner that changes its User-Agent on every request never looks like a crowd
  const scanner = "198.51.100.51";
  for (let i = 0; i < 6; i++) visit(g, scanner, { ua: `Mozilla/5.0 (rotating ${i}) Chrome/${100 + i}.0` }, `/x${i}.html`, {}, 404);
  visit(g, scanner, { ua: "Mozilla/5.0 (rotating a)" }, "/.env");
  visit(g, scanner, { ua: "Mozilla/5.0 (rotating b)" }, "/.aws/credentials");
  assert.equal(g.sharedSize(scanner), 0);
  assert.ok(g.bans.has(scanner), "banned by address, as before");
});

test("a client you signed in with is never banned for the others; nor is your browser without the session", () => {
  const { g } = setup();
  const school = "203.0.113.20";
  const kids = Array.from({ length: 12 }, (_, i) => ({ ua: `Mozilla/5.0 (X11; CrOS x86_64 ${15000 + i}.0.0) Chrome/131.0 Safari/537.36` }));
  const me = { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15" };
  browse(g, school, [...kids, me]);
  assert.equal(visit(g, school, me, "/", { trusted: () => true }).e.auth, true, "signed in");
  // six of the 13 attacking at once is still six clients; the seventh, half of them, is the address: 15 minutes
  for (let i = 0; i < 6; i++) { visit(g, school, kids[i], "/.env"); visit(g, school, kids[i], "/.git/config"); }
  assert.equal(g.bans.has(school), false);
  assert.equal(g.clientBans.size, 6);
  visit(g, school, kids[6], "/.env");
  const ban = g.bans.get(school);
  assert.ok(ban, "many clients attacking at once: the address");
  assert.equal(ban.shared, true);
  assert.ok(ban.until - ban.at <= SHARED_BAN_FOR + 1000, "briefly");
  assert.equal(visit(g, school, kids[11], "/").r.status, 403, "everyone else waits it out");
  // you: with your session, and with the same browser on a tunnel where you have none
  assert.equal(visit(g, school, me, "/", { trusted: () => true }).r, null);
  g.apply({ t: "ban", ip: school, b: ban });                       // (signing in lifted it; the app says it again)
  const mine = visit(g, school, me, "/somewhere-else");
  assert.equal(mine.r, null);
  assert.equal(mine.e.mine, true);
  assert.match(mine.e.expl, /your browser on a shared address/);
  // and your sign-in there vouched for your browser only, not the address
  g.bans.delete(school);
  visit(g, school, kids[11], "/.env");
  assert.equal(visit(g, school, kids[11], "/.git/config").e.dec, "ban", "the others are judged as ever");
});

test("many different clients attacking within minutes: the address is banned, for 15 minutes", () => {
  const { g, sent } = setup();
  const home = "198.51.100.60";
  browse(g, home, [{ ua: "Mozilla/5.0 A" }, { ua: "Mozilla/5.0 B" }, { ua: "Mozilla/5.0 C" }]);
  // a scanner behind it that changes its User-Agent with every payload
  let r = null;
  for (let i = 0; i < 4 && !g.bans.has(home); i++) r = visit(g, home, { ua: `sqlmap-ish/${i}` }, `/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--&n=${i}`);
  const ban = g.bans.get(home);
  assert.ok(ban, "four different attackers out of three regular clients");
  assert.match(ban.reason, /4 different clients behind this shared address attacked within 10 minutes/);
  assert.ok(ban.until - ban.at <= SHARED_BAN_FOR + 1000);
  assert.match(r.e.expl, /^banned the whole shared address for 15 minutes/);
  assert.equal(sent.filter((m) => m.t === "ban").length, 1);
});

test("a flood that hurts the host bans a shared address briefly; one client's flood is its own", () => {
  const { g } = setup();
  const ip = "198.51.100.70";
  const a = { ua: "Mozilla/5.0 A" }, b = { ua: "Mozilla/5.0 B" };
  browse(g, ip, [a, b]);
  let stopped = null;
  for (let i = 0; i < 2500 && !stopped; i++) { const v = visit(g, ip, i % 2 ? a : b, `/p${i % 50}`); if (v.r) stopped = v; }
  assert.ok(stopped, "2400 a minute from one shared address");
  assert.equal(g.bans.get(ip).shared, true);
  assert.match(stopped.e.why, /a flood: over 2400 requests a minute from one shared address/);
});

test("a strong blocklist doesn't ban a shared address on sight: it marks its clients", () => {
  const { g } = setup({ firehol1: "203.0.113.30\n" });
  const ip = "203.0.113.30";
  g.apply({ t: "shared", ip, n: 40, at: Date.now() });               // the app remembers it: a school
  const kid = { ua: "Mozilla/5.0 (X11; CrOS x86_64) Chrome/131.0" }, other = { ua: "Mozilla/5.0 (iPad) Safari" };
  assert.equal(visit(g, ip, kid, "/").r, null, "listed, but shared: through");
  assert.equal(g.bans.has(ip), false);
  const hit = visit(g, ip, kid, "/.env");
  assert.equal(hit.r.status, 403, "a listed shared address: one payload bans the client");
  assert.equal(hit.e.scope, "client");
  assert.match(hit.e.why, /FireHOL/);
  assert.equal(visit(g, ip, other, "/").r, null);
  // the same list on an ordinary address bans it on sight, as before
  const { g: g2 } = setup({ firehol1: "198.51.100.80\n" });
  assert.equal(g2.gate("198.51.100.80", req({ ua: "Mozilla/5.0" })).status, 403);
  assert.equal(g2.bans.get("198.51.100.80").source, "list");
});

test("shared from the first request: a network you marked, a mobile carrier, what the app remembers", () => {
  const { g } = setup();
  g.apply({ t: "settings", settings: { sharedNets: "198.51.100.200/29, 198.51.100.208/28" } });
  g.apply({ t: "verdict", ip: "203.0.113.90", v: { bad: false, benign: false, level: "clean", why: [], dc: false, mobile: true } });
  g.apply({ t: "state", shared: [["203.0.113.91", { n: 25, at: Date.now() }]] });
  for (const [ip, what] of [["198.51.100.203", /a network you marked as shared/], ["203.0.113.90", /a mobile carrier's address/], ["203.0.113.91", /24 others use it/]]) {
    const x = { ua: "Mozilla/5.0 X" };
    visit(g, ip, x, "/.env");
    const b = visit(g, ip, x, "/.git/config");
    assert.equal(b.e.scope, "client", ip);
    assert.match(b.e.expl, what);
    assert.equal(g.bans.has(ip), false, ip);
    assert.equal(visit(g, ip, { ua: "Mozilla/5.0 Y" }, "/").r, null, ip);
  }
  assert.equal(g.sharedSize("198.51.100.199"), 0, "just outside the range");
  // a sign-in lifting a ban on the address leaves its clients' bans; you unbanning it doesn't
  assert.ok([...g.clientBans.keys()].some((k) => k.startsWith("203.0.113.90#")));
  g.apply({ t: "unban", ip: "203.0.113.90" });
  assert.ok([...g.clientBans.keys()].some((k) => k.startsWith("203.0.113.90#")));
  g.apply({ t: "unban", ip: "203.0.113.90", clients: true });
  assert.ok(![...g.clientBans.keys()].some((k) => k.startsWith("203.0.113.90#")));
});

test("fingerprints: one browser is one client however its requests differ; a script posing as it isn't", () => {
  const ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0 Safari/537.36";
  const nav = fingerprint(req({ ua }, "/")), asset = fingerprint({ ...req({ ua }, "/x.js"), headers: { ...req({ ua }).headers, accept: "*/*", "sec-fetch-dest": "script", referer: "https://app.example/" } });
  assert.equal(nav.dev, asset.dev);
  const script = fingerprint({ ua, headers: { "user-agent": ua, "accept-encoding": "gzip, deflate", accept: "*/*", connection: "keep-alive" } });
  assert.notEqual(script.dev, nav.dev, "python-requests with a Chrome User-Agent: Accept-Encoding before Accept, no Sec-Fetch");
  assert.notEqual(fingerprint({ ...req({ ua }), session: "abc" }).id, 0, "a session the host names");
  assert.notEqual(fingerprint(req({ ua, ga: "GA1.1.42.1731990000" })).id, 0, "a long-lived id cookie");
  assert.equal(fingerprint(req({ ua })).id, 0);
});

test("memory stays bounded: addresses, fingerprints, client bans, trusted clients", () => {
  const { g } = setup();
  const crowds = new Crowds();
  const t = Date.now();
  for (let i = 0; i < 30000; i++) { const ip = `198.18.${(i >> 8) & 255}.${i & 255}`; const fp = { dev: i + 1, id: 0 }; crowds.learn(ip, fp, t); crowds.learn(ip, fp, t); }
  assert.ok(crowds.map.size <= 20000, `${crowds.map.size} addresses`);
  for (let i = 0; i < 2000; i++) { crowds.learn("203.0.113.1", { dev: 1e6 + i, id: 0 }, t); crowds.learn("203.0.113.1", { dev: 1e6 + i, id: 7 }, t); }
  const rec = crowds.get("203.0.113.1");
  assert.ok(rec.dev.m.size <= 128 && rec.ids.m.size <= 128);
  for (let i = 0; i < 6000; i++) g.apply({ t: "clientban", ip: "203.0.113.2", key: `203.0.113.2#${i.toString(36)}`, b: { reason: "x", until: Date.now() + HOUR, source: "payload", at: Date.now() } });
  assert.ok(g.clientBans.size <= 5000);
  g.apply({ t: "shared", ip: "203.0.113.3", n: 5 });
  for (let i = 0; i < 3000; i++) visit(g, "203.0.113.3", { ua: `Mozilla/5.0 owner-${i}` }, "/", { trusted: () => true });
  assert.ok(g.clientTrust.size <= 2000);
  for (let i = 0; i < 6000; i++) g.crowds.remember(`198.19.${(i >> 8) & 255}.${i & 255}`, 3, t);
  assert.ok(g.crowds.known.size <= 5000);
});

test("credential stuffing: many addresses, a few passwords each, one page: strict for a while, nobody banned", () => {
  const { g, sent, clock } = setup({ ipsum: "203.0.113.77\t1\n" });
  const login = (ip, extra = {}, status = 401) => visit(g, ip, { ua: `Mozilla/5.0 ${ip}` }, "/login", { method: "POST", ...extra }, status);
  for (let i = 1; i <= 8; i++) for (let k = 0; k < 3; k++) login(`198.51.100.${i}`);
  const camp = sent.find((m) => m.t === "stuffing");
  assert.ok(camp, "the app hears of the campaign");
  assert.equal(camp.path, "/login");
  assert.ok(camp.addresses >= 8 && camp.fails >= 20);
  assert.equal(g.bans.size, 0, "nobody is banned for it");
  // a listed address, a hosting one, one of the stuffers: refused (429)
  const listed = login("203.0.113.77");
  assert.equal(listed.r.status, 429);
  assert.match(listed.e.expl, /^refused a sign-in, nobody banned: \/login on app.example is under a credential-stuffing campaign.*IPsum/);
  g.apply({ t: "verdict", ip: "198.51.100.150", v: { bad: false, benign: false, level: "clean", why: [], dc: true } });
  assert.equal(login("198.51.100.150").r.status, 429, "a hosting network");
  assert.equal(login("198.51.100.3").r.status, 429, "three failures this minute already");
  // nothing known: scanned first; scanned clean: through
  const unknown = login("198.51.100.160");
  assert.equal(unknown.r.status, 403); assert.equal(unknown.r.page, "checking");
  assert.ok(sent.some((m) => m.t === "scan" && m.ip === "198.51.100.160"));
  g.apply({ t: "cleared", ip: "198.51.100.160", at: Date.now() });
  assert.equal(login("198.51.100.160", {}, 200).r, null);
  g.apply({ t: "verdict", ip: "198.51.100.161", v: { bad: false, benign: false, level: "clean", why: [], dc: false } });
  assert.equal(login("198.51.100.161", {}, 200).r, null, "a clean verdict");
  assert.equal(login("198.51.100.162", { trusted: () => true }, 200).r, null, "you");
  // other pages, and reading the page, are untouched
  assert.equal(visit(g, "198.51.100.163", { ua: "Mozilla/5.0 Z" }, "/login").r, null);
  assert.equal(visit(g, "198.51.100.163", { ua: "Mozilla/5.0 Z" }, "/api/login", { method: "POST" }, 200).r, null);
  // half an hour without failures: as before
  clock.move(31 * 60e3);
  assert.equal(login("198.51.100.164", {}, 200).r, null);
  assert.equal(g.bans.size, 0);
});

test("a few people mistyping their passwords is not a campaign; one address hammering is brute force", () => {
  const { g, sent } = setup();
  for (let i = 1; i <= 6; i++) visit(g, `198.51.100.${i}`, { ua: "Mozilla/5.0" }, "/login", { method: "POST" }, 401);
  for (let k = 0; k < 30; k++) visit(g, "198.51.100.99", { ua: "Mozilla/5.0" }, "/login", { method: "POST" }, 401);
  assert.ok(!sent.some((m) => m.t === "stuffing"), "one address doing most of it is brute force, not a campaign");
  assert.ok(g.bans.has("198.51.100.99"));
});

test("every decision says why in plain words; the old log fields stay", () => {
  const { g } = setup({ firehol1: "198.51.100.200\n" });
  const c = { ua: "Mozilla/5.0 (X11; Linux x86_64) Firefox/132.0" };
  g.apply({ t: "ban", ip: "198.51.100.201", b: { reason: "by hand", until: null, source: "manual", at: Date.now() } });
  const cases = [
    ["192.168.1.5", "/", /private address/],
    ["198.51.100.201", "/", /^blocked: this address is banned by you \(by hand\)/],
    ["198.51.100.200", "/", /^banned this address for 7 days: on FireHOL/],
    ["198.51.100.202", "/.env", /^dropped a payload \(.env files, 5 points\)/],
    ["198.51.100.203", "/wp-login.php", /^passed: WordPress logins \(a probe/],
    ["198.51.100.204", "/x?q=%3Cmarquee%3E", null],
  ];
  for (const [ip, path, want] of cases) {
    const { e } = visit(g, ip, c, path);
    for (const k of ["t", "ip", "host", "m", "path", "ua", "st", "dec"]) assert.ok(k in e, `${k} kept`);
    if (want) assert.match(e.expl, want, `${ip} ${path}`);
  }
  assert.equal(visit(g, "198.51.100.205", c, "/").e.expl, undefined, "a plain pass: nothing against it, nothing to say");
  const pub = visit(g, "198.51.100.206", c, "/", { access: "public" });
  assert.match(pub.e.expl, /^held until the address is scanned/);
});

test("the guard on a day's traffic (homes, a school, a carrier, scanners): fast, and bounded", () => {
  const g = new Guard();
  const reqs = traffic(30000);
  for (const { ip, info, st } of reqs.slice(0, 5000)) { const x = { ...info }; g.gate(ip, x); g.after(ip, x, { status: st }); }
  g.stats.us = 0; g.stats.requests = 0;
  for (const { ip, info, st } of reqs.slice(5000)) { const x = { ...info }; g.gate(ip, x); g.after(ip, x, { status: st }); g.entry(ip, x, { status: st }); }
  const us = g.stats.us / g.stats.requests;
  assert.ok(us < 60, `${us.toFixed(1)} µs a request`);
  assert.ok(g.sharedSize("203.0.113.10") >= 100, "the school is seen as shared");
  assert.ok(g.sharedSize("203.0.113.20") >= 50, "and the carrier");
  assert.ok(g.crowds.map.size <= 20000 && g.scores.size <= 20000 && g.behav.size <= 20000);
});
