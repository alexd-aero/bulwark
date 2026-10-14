// The app end to end: a guard connects over the socket, reports a wave like the
// one of 2026-10-14 (seven cloud machines, each /.env then /.git/config), and the
// app logs it, bans, warns, draws it, exports it. No network: lookups are faked.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";

process.env.BULWARK_CONFIG = join(mkdtempSync(join(tmpdir(), "bw-cfg-")), "bulwark.json");
const { startApp } = await import("../server.mjs");

const home = mkdtempSync(join(tmpdir(), "bw-home-"));
// Aegis 2.14's built-in shield, to be imported
const legacy = mkdtempSync(join(tmpdir(), "bw-legacy-"));
mkdirSync(join(legacy, "feeds"));
writeFileSync(join(legacy, "state.json"), JSON.stringify({ bans: { "35.236.186.124": { at: Date.now(), until: null, reason: "129+ .env grabs", source: "manual", hits: 3 } },
                                                          allow: {}, trusted: { "93.184.216.34": Date.now() }, events: [{ t: Date.now() - 1000, ip: "35.236.186.124", act: "banned", why: "x" }] }));
writeFileSync(join(legacy, "feeds", "cins.txt"), "45.148.10.120\n");

const verdicts = { "203.0.113.66": { verdict: { level: "malicious", why: ["GreyNoise: malicious"] }, sources: { greynoise: { result: { classification: "malicious", seen: true } } } } };
const app = startApp({ home, port: 0, key: "k", offline: true, quiet: true,
  remote: async (ip) => verdicts[ip] || { verdict: { level: "clean", why: [] }, sources: {} } });
after(() => { sock?.destroy(); app.close(); });
const base = () => `http://127.0.0.1:${app.server.address().port}`;
const get = (p) => fetch(base() + p, { headers: { "x-bulwark-key": "k" } }).then((r) => r.json());
const post = (p, b = {}) => fetch(base() + p, { method: "POST", headers: { "x-bulwark-key": "k", "Content-Type": "application/json" }, body: JSON.stringify(b) }).then((r) => r.json());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// wait for something the app does in its own time (a fixed sleep is flaky under load)
const until = async (fn, ms = 4000) => { const t = Date.now(); while (!(await fn())) { if (Date.now() - t > ms) return false; await sleep(25); } return true; };
await new Promise((r) => app.server.once("listening", r).listening ? r() : null);
await sleep(100);

// a fake guard
const got = [];
var sock = connect(app.brain.P.socket);
let buf = "";
sock.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { got.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
await new Promise((r) => sock.once("connect", r));
const tell = (m) => sock.write(JSON.stringify(m) + "\n");
tell({ t: "hello", host: "aegis-burrow", legacy });
await sleep(150);

test("a key is needed; the status isn't secret", async () => {
  assert.equal((await fetch(base() + "/api/overview")).status, 401);
  assert.equal((await fetch(base() + "/api/status").then((r) => r.json())).ok, true);
  const r = await fetch(base() + "/?k=k", { redirect: "manual" });
  assert.equal(r.status, 302);
  assert.match(r.headers.get("set-cookie"), /bulwark_k=k/);
});

test("the guard gets the state on hello; Aegis's old shield is imported", async () => {
  const st = got.find((m) => m.t === "state");
  assert.ok(st, "state sent");
  await sleep(50);
  assert.ok(app.brain.state.bans["35.236.186.124"], "the old ban came over");
  assert.ok(app.brain.isTrusted("93.184.216.34"));
  assert.ok(app.brain.feeds.lists.has("cins"), "and its lists");
  assert.ok(got.filter((m) => m.t === "state").length >= 2, "the guard got the merged state");
});

test("a wave: logged in full, banned, a campaign alert, the graph and the export", async () => {
  const t0 = Date.now();
  const cloud = ["136.85.34.52", "104.199.226.84", "104.196.170.201", "136.85.201.228", "136.85.182.102", "136.83.11.229", "34.134.246.137"];
  const list = [];
  for (const [i, ip] of cloud.entries()) {
    list.push({ t: t0 + i * 10, ip, cc: "US", host: "27715.tunnel.example", m: "GET", path: "/.env", ua: "Go-http-client/1.1", dec: "drop", sig: "env-file", sc: 3, st: 404, b: 9 });
    list.push({ t: t0 + i * 10 + 5, ip, cc: "US", host: "27715.tunnel.example", m: "GET", path: "/.git/config", ua: "Go-http-client/1.1", dec: "ban", sig: "vcs", sc: 3, st: 403, b: 8, why: "sent 2 payloads" });
  }
  list.push({ t: t0 + 100, ip: "203.0.113.66", cc: "NL", host: "27715.tunnel.example", m: "GET", path: "/", ua: "Mozilla/5.0", dec: "pass", st: 200, b: 1900 });
  tell({ t: "ev", list });
  for (const ip of cloud) tell({ t: "ban", ip, b: { reason: "sent 2 payloads (/.git/config, /.env)", until: null, source: "payload", at: Date.now() }, info: { host: "27715.tunnel.example", country: "US" } });
  await sleep(300);
  // logs
  const logs = (await get("/api/logs?ip=136.85.34.52")).logs;
  assert.equal(logs.length, 2);
  assert.equal(logs[0].path, "/.git/config", "newest first");
  assert.equal((await get("/api/logs?dec=bad&limit=100")).logs.length, 14);
  assert.equal((await get("/api/logs?q=git%2Fconfig")).logs.length, 7);
  // bans: the guard's, and the lookup's (GreyNoise malicious)
  const bl = (await get("/api/blocklist")).bans.map((b) => b.ip);
  for (const ip of cloud) assert.ok(bl.includes(ip), ip);
  assert.ok(bl.includes("203.0.113.66"), "banned by its lookup");
  assert.ok(got.some((m) => m.t === "ban" && m.ip === "203.0.113.66"), "and the guard was told");
  assert.ok(got.some((m) => m.t === "kick" && m.ip === "203.0.113.66"));
  const ban = app.brain.state.bans["136.85.34.52"];
  assert.deepEqual(ban.lines, ["GET /.env", "GET /.git/config"], "evidence kept for reports");
  // the wave
  const alerts = (await get("/api/alerts")).alerts;
  const camp = alerts.find((a) => a.kind === "campaign");
  assert.ok(camp, "a campaign alert");
  assert.equal(camp.sev, "critical", "seven machines: critical");
  assert.equal(camp.members.length, 7);
  assert.match(camp.detail, /\.env files → Git/);
  assert.ok(alerts.some((a) => a.kind === "network"), "and a network cluster (136.85.x)");
  // strict mode follows a critical wave
  app.brain.tick();
  assert.ok(app.brain.strictUntil > Date.now());
  await sleep(50);
  assert.ok(got.some((m) => m.t === "strict" && m.until > Date.now()));
  // charts and graph
  const s = await get("/api/series?span=1h&points=60");
  const sum = s.points.reduce((a, p) => a + p.req, 0);
  assert.equal(sum, 15);
  assert.equal(s.points.reduce((a, p) => a + p.newIp, 0), 8);
  // the Patterns page: networks -> patterns, counted in addresses, the campaign, who's behind each
  const g = await get("/api/patterns?span=1h");
  const env = g.sigs.find((x) => x.sig === "env-file"), vcs = g.sigs.find((x) => x.sig === "vcs");
  assert.equal(env.ips, 7); assert.equal(vcs.ips, 7); assert.equal(env.name, ".env files");
  assert.equal(g.flow.links.filter((l) => l.b === "sig:env-file").reduce((a, l) => a + l.ips, 0), 7, "every address on a ribbon, once per pattern");
  assert.ok(g.waves.some((w) => w.members === 7 && w.sigs.length), "the campaign, with what it ran");
  assert.equal(g.totals.ips >= 7, true);
  const who = await get("/api/patterns/who?span=1h&id=sig:env-file");
  assert.equal(who.ips.length, 7);
  assert.ok(who.ips.every((x) => x.n === 1), "tries of that pattern, per address");
  // the workflow's last stage: what became of each address, and the connections into it
  const outs = g.flow.outcomes.reduce((a, o) => a + o.ips, 0);
  assert.equal(outs, g.totals.ips, "every attacker ends up in exactly one outcome");
  assert.ok(g.flow.outLinks.some((l) => l.a === "sig:env-file" && l.b.startsWith("out:")));
  assert.ok(g.flow.sigs.find((x) => x.sig === "env-file").examples.some((p) => /\.env/.test(p)), "real requests as examples");
  const link = g.flow.links.find((l) => l.b === "sig:env-file");
  const lw = await get(`/api/patterns/who?span=1h&id=${encodeURIComponent(`${link.a}|${link.b}`)}`);
  assert.equal(lw.ips.length, link.ips, "a connection's addresses");
  const ol = g.flow.outLinks[0], ow = await get(`/api/patterns/who?span=1h&id=${encodeURIComponent(`${ol.a}|${ol.b}`)}`);
  assert.equal(ow.ips.length, ol.ips);
  // overview
  const o = await get("/api/overview?span=1h");
  assert.equal(o.totals.req, 15);
  assert.ok(o.alerts.length >= 2);
  assert.equal(o.tops.sigs[0].n, 7);
  // export
  const txt = await fetch(base() + "/api/blocklist.txt?format=nginx", { headers: { "x-bulwark-key": "k" } }).then((r) => r.text());
  assert.match(txt, /deny 136\.85\.34\.52;/);
});

test("one address in detail: profile, coverage, logs; ban, unban, allow", async () => {
  const v = await get("/api/ip/136.85.34.52");
  // an IPv6 address, as the drawer asks for it (":" encoded): not "not found"
  const v6 = await get(`/api/ip/${encodeURIComponent("2001:db8::7")}`);
  assert.equal(v6.ip, "2001:db8::7");
  assert.equal(v.profile.n, 2);
  assert.deepEqual(v.profile.seq, ["env-file", "vcs"]);
  assert.ok(v.coverage.some((c) => c.vendor === "AbuseIPDB"));
  assert.equal(v.logs.length, 2);
  let r = await post("/api/ip/136.85.34.52/unban");
  assert.equal(r.ban, null);
  assert.ok(got.some((m) => m.t === "unban" && m.ip === "136.85.34.52"));
  r = await post("/api/ip/198.51.100.7/ban", { reason: "testing" });
  assert.equal(r.ban.reason, "testing");
  r = await post("/api/ip/198.51.100.7/allow");
  assert.equal(r.ban, null); assert.ok(r.allowed);
});

test("a sign-in from a guard lifts an automatic ban and makes the address yours", async () => {
  tell({ t: "trust", ip: "104.199.226.84" });
  await sleep(100);
  assert.equal(app.brain.state.bans["104.199.226.84"], undefined);
  assert.ok(app.brain.isTrusted("104.199.226.84"));
});

test("your devices: the host's list comes in, their addresses are trusted as of when used, an automatic ban on one lifts", async () => {
  await post("/api/ip/192.0.2.40/ban", { reason: "x" });
  app.brain.state.bans["192.0.2.40"].source = "payload";                 // as if the guard had banned it
  app.brain.state.bans["192.0.2.40"].at = Date.now() - 60e3;
  const used = Date.now() - 3600e3;
  tell({ t: "devices", list: [{ id: "dev-a", name: "Chrome on Windows", ips: [{ ip: "192.0.2.40", last: Date.now() - 5e3 }, { ip: "192.0.2.41", last: used }], hosts: [], first: used, last: Date.now() }],
         addresses: { "192.0.2.40": { last: Date.now() - 5e3, devices: ["dev-a"] }, "192.0.2.41": { last: used, devices: ["dev-a"] }, "10.0.0.5": { last: Date.now(), devices: ["dev-a"] } } });
  assert.ok(await until(() => app.brain.devices?.list.length === 1));
  assert.equal(app.brain.state.bans["192.0.2.40"], undefined, "lifted: one of your devices uses it");
  assert.equal(app.brain.state.trusted["192.0.2.41"], used, "trusted as of when it was used, not now");
  assert.equal(app.brain.state.trusted["10.0.0.5"], undefined, "private addresses aren't the point");
  const d = await get("/api/devices");
  assert.equal(d.devices[0].name, "Chrome on Windows");
  assert.equal(d.devices[0].ips.length, 2);
  const v = await get("/api/ip/192.0.2.41");
  assert.deepEqual(v.devices.map((x) => x.name), ["Chrome on Windows"]);
  got.length = 0;
  await post("/api/devices/refresh");
  assert.ok(await until(() => got.some((m) => m.t === "devices?")), "the guard is asked again");
});

test("a public tunnel asks for a scan: clean ones are cleared (and stay so), a known attacker is banned", async () => {
  got.length = 0;
  tell({ t: "scan", ip: "192.0.2.60" });
  assert.ok(await until(() => got.some((m) => m.t === "cleared" && m.ip === "192.0.2.60")), "cleared");
  assert.ok(app.brain.state.cleared["192.0.2.60"]);
  tell({ t: "scan", ip: "203.0.113.66" });
  assert.ok(await until(() => app.brain.state.bans["203.0.113.66"]), "GreyNoise has seen it attack: banned");
  assert.equal(got.some((m) => m.t === "cleared" && m.ip === "203.0.113.66"), false);
  got.length = 0;
  tell({ t: "scan", ip: "192.0.2.60" });
  assert.ok(await until(() => got.some((m) => m.t === "cleared" && m.ip === "192.0.2.60")), "asked again: told again, without a new lookup");
  assert.ok(app.brain.snapshot().cleared.some(([ip]) => ip === "192.0.2.60"), "a reconnecting guard gets it");
});

test("settings: the key is never shown; the guards get the switches", async () => {
  const r = await fetch(base() + "/api/settings", { method: "PUT", headers: { "x-bulwark-key": "k", "Content-Type": "application/json" }, body: JSON.stringify({ abuseipdbKey: "secret-abc1234", drop: false }) }).then((x) => x.json());
  assert.equal(r.abuseipdbKey, "••••••••1234");
  assert.equal(r.drop, false);
  await sleep(50);
  assert.ok(got.some((m) => m.t === "settings" && m.settings.drop === false));
});

test("the host's past: Aegis's history comes in once, attackers in it are banned, the dashboard is told", async () => {
  const t0 = Date.now() - 6 * 3600e3;
  const data = {
    tunnels: [{ port: 27715, host: "27715.tunnel.example", clients: [{ ip: "198.51.100.40", country: "DE", agent: "Other", first: t0, last: t0 + 60e3, requests: 31 }],
      recent: [{ t: t0, ip: "198.51.100.40", country: "DE", method: "GET", path: "/.env", status: 200, ms: 2, bytes: 90 },
               { t: t0 + 1000, ip: "198.51.100.40", country: "DE", method: "GET", path: "/.git/config", status: 200, ms: 2, bytes: 90 },
               { t: t0 + 2000, ip: "198.51.100.41", country: "US", method: "GET", path: "/", status: 200, ms: 2, bytes: 900 }] }],
    audit: [{ t: new Date(t0 + 3000).toISOString(), event: "sign-in failed", ip: "198.51.100.42", host: "aegis.example", ua: "curl/8" }],
  };
  got.length = 0;
  tell({ t: "history", host: "aegis-burrow", data });
  await until(() => app.brain.state.history?.last?.rows && got.some((m) => m.t === "notify" && m.key === "history"));
  const b = app.brain.state.bans["198.51.100.40"];
  assert.ok(b, "two payloads in the past: banned now");
  assert.equal(b.source, "history");
  assert.match(b.reason, /Aegis's history: 2 payloads/);
  assert.equal(app.brain.state.bans["198.51.100.41"], undefined, "a plain visit: nothing");
  const rows = (await get("/api/logs?ip=198.51.100.40")).logs;
  assert.equal(rows.length, 2); assert.equal(rows[0].dec, "seen"); assert.equal(rows[0].src, "aegis-burrow");
  assert.ok(app.brain.profiles.get("198.51.100.42"), "a failed sign-in's address is known");
  const n = got.find((m) => m.t === "notify" && m.key === "history");
  assert.ok(n, "the dashboard hears of it"); assert.equal(n.level, "warn"); assert.match(n.title, /found \{n\} \{attacker\|attackers\}/);
  assert.deepEqual([n.items[0].label, n.items[0].cc, n.items[0].tag, n.items[0].link], ["198.51.100.40", "DE", "history", "/__gate/bulwark/#/ip/198.51.100.40"]);
  // the same history again: nothing new
  const at = app.brain.state.history.last.at;
  tell({ t: "history", host: "aegis-burrow", data });
  await until(() => app.brain.state.history.last.at !== at);
  assert.equal((await get("/api/logs?ip=198.51.100.40")).logs.length, 2, "not twice");
  app.brain.logs.flush();                                     // on disk too now: still once (old times, but in memory)
  assert.equal((await get("/api/logs?ip=198.51.100.40")).logs.length, 2, "not twice, after the day file has them");
  assert.equal((await get("/api/history")).last.rows, 0);
  // the setting turns the dashboard warnings off
  await fetch(base() + "/api/settings", { method: "PUT", headers: { "x-bulwark-key": "k", "Content-Type": "application/json" }, body: JSON.stringify({ hostNotices: false }) });
  got.length = 0; app.brain.hostNotice({ level: "warn", title: "x" });
  assert.equal(got.filter((m) => m.t === "notify").length, 0);
  await fetch(base() + "/api/settings", { method: "PUT", headers: { "x-bulwark-key": "k", "Content-Type": "application/json" }, body: JSON.stringify({ hostNotices: true }) });
  // "Pull now" asks the guards
  got.length = 0; await post("/api/history/pull"); await sleep(50);
  assert.ok(got.some((m) => m.t === "pull"));
});

test("access \"host\": only the host's header opens it, never a link or a cookie", async () => {
  const h2 = mkdtempSync(join(tmpdir(), "bw-home2-"));
  const a2 = startApp({ home: h2, port: 0, key: "k2", access: "host", offline: true, quiet: true });
  try {
    await new Promise((r) => (a2.server.listening ? r() : a2.server.once("listening", r)));
    const b2 = `http://127.0.0.1:${a2.server.address().port}`;
    assert.equal((await fetch(b2 + "/?k=k2", { redirect: "manual" })).status, 401, "a key link doesn't");
    assert.equal((await fetch(b2 + "/api/overview", { headers: { cookie: "bulwark_k=k2" } })).status, 401, "nor a cookie");
    assert.equal((await fetch(b2 + "/api/settings", { headers: { "x-bulwark-key": "k2" } })).status, 200, "the host's header does");
  } finally { a2.close(); }
});

test("newer patterns, older lines: the log is read again and what slipped through is caught", async () => {
  const t0 = Date.now();
  // a phishing-kit hunter that came before the patterns knew it: let through then
  tell({ t: "ev", list: ["/js/raif_ch.js", "/js/twint_ch.js", "/bot-connect.js"].map((p, i) => ({ t: t0 + i, ip: "198.51.100.77", cc: "RO", host: "8790.tunnel.example", m: "GET", path: p, ua: "Mozilla/5.0", dec: "pass", st: 302, b: 0 })) });
  await sleep(150);
  assert.equal(app.brain.state.bans["198.51.100.77"], undefined);
  app.brain.state.sigVersion = 1;
  const r = app.brain.rescan();
  assert.ok(r.marked >= 3);
  assert.ok(r.banned.includes("198.51.100.77"));
  assert.match(app.brain.state.bans["198.51.100.77"].reason, /newer patterns.*3 payloads/);
  assert.equal(app.brain.rescan().banned.length, 0, "once is enough");
});

test("a notice row's reason: the sign-in detour undone, trimmed", async () => {
  const { shortReason } = await import("../core/brain.mjs");
  assert.equal(shortReason("18 payloads (/js/raif_ch.js, /__gate/sso?to=8790.tunnel.example&next=%2Fjs%2Ftwint_ch.js)"), "18 payloads (/js/raif_ch.js, /js/twint_ch.js)");
  assert.ok(shortReason("x".repeat(300)).length <= 110);
});
