// Email alerts through selfmail: found only through a fresh mesh entry, sent the
// way selfmail expects, coalesced and rate-limited, and invisible while selfmail
// isn't there. A local HTTP server stands in for selfmail; the mesh is a temp dir.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.BULWARK_CONFIG = join(mkdtempSync(join(tmpdir(), "bw-mcfg-")), "bulwark.json");
process.env.MESH = mkdtempSync(join(tmpdir(), "bw-mesh-never-"));      // never the real one
const { readSelfmail, Mailer, MAIL_DEFAULTS, meshDir, LIMITS } = await import("../core/mail.mjs");
const { renderWave, renderDigest, renderSystem } = await import("../core/mailview.mjs");
const { startApp } = await import("../server.mjs");

const MIN = 60e3;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 3000) => { const t = Date.now(); while (!(await fn())) { if (Date.now() - t > ms) return false; await sleep(10); } return true; };

// ------------------------------------------------------------ a fake selfmail
const got = [];
let reply = () => [200, { ok: true, id: `m${got.length}` }];
const fake = createServer((req, res) => {
  let b = "";
  req.on("data", (d) => { b += d; });
  req.on("end", () => {
    let body = null; try { body = JSON.parse(b); } catch { /* bad */ }
    got.push({ method: req.method, url: req.url, headers: req.headers, body });
    const [status, out] = reply(body);
    res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(out));
  });
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
const port = fake.address().port;
after(() => fake.close());

const keyDir = mkdtempSync(join(tmpdir(), "bw-key-"));
const keyFile = join(keyDir, "host.key");
writeFileSync(keyFile, "  s3cret-key-for-tests \n");
const announce = (dir, { updated = Math.floor(Date.now() / 1000), url = `http://127.0.0.1:${port}/api/notify`, id = "selfmail" } = {}) =>
  writeFileSync(join(dir, "selfmail.json"), JSON.stringify({
    spec: 1, id, name: "selfmail", version: "2.3.0", host: "burrow", url: `http://127.0.0.1:${port}/`, health: `http://127.0.0.1:${port}/health`, port,
    provides: ["mail", "notify"], items: [{ name: "me@example.com" }],
    notify: { url, keyFile, to: "me@example.com", domains: ["example.com"] }, updated,
  }));

// ------------------------------------------------------------ the mesh
test("the mesh: missing, stale, fresh, and entries that aren't usable", () => {
  const dir = mkdtempSync(join(tmpdir(), "bw-mesh-"));
  const now = Date.now();
  assert.equal(readSelfmail({ dir, now }), null, "no entry");
  announce(dir, { updated: Math.floor(now / 1000) - 91 });
  assert.equal(readSelfmail({ dir, now }), null, "older than 90 s is stale");
  announce(dir, { updated: Math.floor(now / 1000) - 60 });
  const sm = readSelfmail({ dir, now });
  assert.ok(sm, "fresh");
  assert.equal(sm.version, "2.3.0");
  assert.equal(sm.notify.to, "me@example.com");
  assert.deepEqual(sm.notify.domains, ["example.com"]);
  assert.equal(sm.notify.url, `http://127.0.0.1:${port}/api/notify`);
  announce(dir, { url: "http://192.0.2.10:8088/api/notify" });
  assert.equal(readSelfmail({ dir, now: Date.now() }), null, "the key never goes over plain http to another machine");
  announce(dir, { url: "https://mail.example.com/api/notify" });
  assert.ok(readSelfmail({ dir, now: Date.now() }), "https is fine");
  announce(dir, { id: "someone-else" });
  assert.equal(readSelfmail({ dir, now: Date.now() }), null, "only selfmail's own entry");
  writeFileSync(join(dir, "selfmail.json"), "{not json");
  assert.equal(readSelfmail({ dir, now }), null, "a half-written file");
  assert.equal(meshDir({ MESH: "/x/mesh" }), "/x/mesh");
  assert.equal(meshDir({ XDG_CONFIG_HOME: "/x/cfg" }), "/x/cfg/weft/mesh");
});

// ------------------------------------------------------------ the mailer, on a fake clock
function rig(settings = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bw-mesh-"));
  const S = { ...MAIL_DEFAULTS, mailOn: true, ...settings };
  const r = { dir, S, clock: Date.now(), contexts: [] };
  announce(dir, { updated: Math.floor(r.clock / 1000) });
  r.mailer = new Mailer({ settings: () => S, dir, now: () => r.clock, gather: 0, version: "9.9.9",
    context: (kind, items) => { r.contexts.push([kind, items.length]); return { rpm: 1240, normalRpm: 35, attacks: 300, normalAttacks: 2, members: 57, banned: 42, nets: [{ name: "Example Cloud", asn: 64500, n: 30, banned: 25 }], patterns: [{ name: ".env grab", n: 812 }], alerts: {} }; } });
  // time passes; selfmail keeps announcing itself
  r.advance = (ms) => { r.clock += ms; announce(dir, { updated: Math.floor(r.clock / 1000) }); };
  return r;
}
const wave = (title, sev = "warn", key = title) => ({ type: "wave", sev, key, title, detail: `${title}: details` });

test("the request selfmail expects: key, headers, body; to only when Settings names someone", async () => {
  got.length = 0;
  const r = rig();
  assert.equal(r.mailer.event(wave("Surge of new addresses")), true);
  assert.ok(await until(() => got.length === 1), "sent after the gather");
  const q = got[0];
  assert.equal(q.method, "POST");
  assert.equal(q.url, "/api/notify");
  assert.equal(q.headers["x-selfmail-key"], "s3cret-key-for-tests", "the key file's contents, trimmed");
  assert.equal(q.headers["x-selfmail"], "1");
  assert.match(q.headers["content-type"], /application\/json/);
  assert.equal(q.body.app, "bulwark");
  assert.equal(q.body.level, "warn");
  assert.ok(!("to" in q.body), "no recipient: selfmail's own notify.to");
  assert.match(q.body.subject, /^Bulwark: Surge of new addresses$/);
  assert.match(q.body.text, /1,240/);
  assert.match(q.body.html, /<table/);
  assert.ok(await until(() => r.mailer.state.lastOk), "and the answer read");
  assert.equal(r.mailer.state.lastOk.id, "m1");
  // a recipient of your own
  r.S.mailTo = "alerts@example.com";
  await r.mailer.test();
  assert.equal(got[1].body.to, "alerts@example.com");
  assert.match(got[1].body.subject, /test/i);
});

test("coalescing: one email at once, then one per window with everything in between", async () => {
  got.length = 0;
  const r = rig();
  r.mailer.event(wave("Wave A"));
  assert.ok(await until(() => got.length === 1));
  r.advance(2 * MIN);
  r.mailer.event(wave("Wave B"));
  r.mailer.event(wave("Wave C"));
  r.mailer.event(wave("Wave B"));                          // the same alert again: one row, updated twice
  await sleep(30);
  r.mailer.tick();
  await sleep(30);
  assert.equal(got.length, 1, "nothing more inside the 15 minutes");
  assert.equal(r.mailer.state.pending.wave.length, 2);
  r.advance(13 * MIN);
  r.mailer.tick();
  assert.ok(await until(() => got.length === 2), "the window is over: the next one");
  const m = got[1].body;
  assert.match(m.subject, /\(\+1 more\)/);
  assert.match(m.text, /Wave B/); assert.match(m.text, /Wave C/);
  assert.match(m.text, /updated 2 times/);
  assert.equal(r.mailer.state.pending.wave.length, 0);
  // a wave turning critical doesn't wait the window, only a minute
  r.advance(30e3);
  r.mailer.event(wave("Wave C", "critical"));
  await sleep(30); r.mailer.tick(); await sleep(30);
  assert.equal(got.length, 2, "not within the first minute");
  r.advance(40e3); r.mailer.tick();
  assert.ok(await until(() => got.length === 3), "escalation goes out");
  assert.match(got[2].body.subject, /^Bulwark CRITICAL: /);
  assert.equal(got[2].body.level, "critical");
  // a second critical waits the window again
  r.advance(2 * MIN);
  r.mailer.event(wave("Wave D", "critical"));
  await sleep(30); r.mailer.tick(); await sleep(30);
  assert.equal(got.length, 3);
});

test("rate limits: 429 pauses 15 minutes and keeps the events; 12 an hour at most", async () => {
  got.length = 0;
  const r = rig();
  reply = () => [429, { error: "rate limited" }];
  r.mailer.event(wave("Wave A"));
  assert.ok(await until(() => got.length === 1));
  await sleep(20);
  assert.equal(r.mailer.state.pending.wave.length, 1, "kept for later");
  assert.match(r.mailer.status().lastError.error, /rate limited/);
  assert.ok(r.mailer.status().pausedUntil > r.clock);
  reply = () => [200, { ok: true, id: "x" }];
  r.advance(10 * MIN); r.mailer.tick(); await sleep(30);
  assert.equal(got.length, 1, "still paused");
  r.advance(6 * MIN); r.mailer.tick();
  assert.ok(await until(() => got.length === 2), "sent after the pause");
  assert.equal(r.mailer.status().lastError, null, "an error older than the last success isn't shown");
  // the hourly cap: tests count too
  const r2 = rig();
  let ok = 0, refused = 0;
  for (let i = 0; i < 14; i++) { r2.advance(LIMITS.testGap); try { await r2.mailer.test(); ok++; } catch (e) { assert.equal(e.status, 429); refused++; } }
  assert.equal(ok, LIMITS.perHour); assert.equal(refused, 14 - LIMITS.perHour);
  // other errors: kept, tried three times at most
  got.length = 0;
  const r3 = rig();
  reply = () => [500, { error: "boom" }];
  r3.mailer.event(wave("Wave Z"));
  for (let i = 0; i < 4; i++) { await until(() => !r3.mailer.busy.wave); await sleep(20); r3.advance(16 * MIN); r3.mailer.tick(); await sleep(30); }
  assert.equal(got.length, 3, "three tries");
  assert.equal(r3.mailer.state.pending.wave.length, 0, "then dropped");
  reply = () => [200, { ok: true, id: "x" }];
});

test("nothing is queued when it's off, an event is turned off, or selfmail is gone", async () => {
  got.length = 0;
  const r = rig({ mailOn: false });
  assert.equal(r.mailer.event(wave("A")), false, "off");
  r.S.mailOn = true; r.S.mailWaves = false;
  assert.equal(r.mailer.event(wave("A")), false, "waves off");
  assert.equal(r.mailer.event({ type: "critical", sev: "critical", key: "guard", title: "The guard is disconnected" }), true, "critical still on");
  r.S.mailCritical = false;
  assert.equal(r.mailer.event({ type: "critical", sev: "critical", key: "faults", title: "x" }), false);
  r.S.mailWaves = true;
  r.advance(100e3);                      // selfmail stopped announcing: stale
  r.clock += 0;
  writeFileSync(join(r.dir, "selfmail.json"), JSON.stringify({ id: "selfmail", updated: Math.floor(r.clock / 1000) - 120, notify: { url: `http://127.0.0.1:${port}/api/notify`, keyFile } }));
  assert.equal(r.mailer.event(wave("B")), false, "selfmail is gone");
  assert.equal(r.mailer.status(), null, "and the status says so");
  rmSync(join(r.dir, "selfmail.json"));
  assert.equal(r.mailer.status(), null);
});

test("the daily digest: once a day, from 8:00, only when asked", async () => {
  got.length = 0;
  const r = rig({ mailDigest: true });
  r.clock = new Date(2026, 9, 27, 7, 30).getTime(); r.advance(0);
  r.mailer.tick(); await sleep(30);
  assert.equal(got.length, 0, "not before 8:00");
  r.advance(40 * MIN); r.mailer.tick();
  assert.ok(await until(() => got.length === 1));
  assert.match(got[0].body.subject, /^Bulwark daily: /);
  r.advance(2 * 3600e3); r.mailer.tick(); await sleep(30);
  assert.equal(got.length, 1, "once a day");
  r.advance(24 * 3600e3); r.mailer.tick();
  assert.ok(await until(() => got.length === 2), "the next day");
  const off = rig();
  off.clock = new Date(2026, 9, 27, 9, 0).getTime(); off.advance(0);
  off.mailer.tick(); await sleep(30);
  assert.equal(got.length, 2, "no digest unless asked");
});

test("the emails: escaped, self-contained, with the numbers, and a plain-text twin", () => {
  const items = [{ type: "wave", sev: "critical", key: "k", title: "<script>alert(1)</script> surge", detail: "1240 a minute", at: Date.now(), first: Date.now(), n: 1 }];
  const m = renderWave(items, { rpm: 1240, normalRpm: 35, attacks: 300, normalAttacks: 2, members: 57, banned: 42, strict: Date.now() + 30 * MIN,
    nets: [{ name: "Example & Co", asn: 64500, n: 30, banned: 25 }], patterns: [{ name: ".env grab", n: 812 }], link: "https://dash.example.com/__gate/bulwark/#/waves", version: "1.8.0" });
  assert.ok(!m.html.includes("<script>"), "escaped");
  assert.match(m.html, /&lt;script&gt;/);
  assert.ok(!/<img|<link|@import|url\(|<style/i.test(m.html), "no images, stylesheets or fonts from elsewhere");
  assert.match(m.html, /Example &amp; Co/);
  assert.match(m.html, /AS64500/);
  assert.match(m.html, /1,240/); assert.match(m.html, /normal 35/);
  assert.match(m.html, /href="https:\/\/dash\.example\.com\/__gate\/bulwark\/#\/waves"/);
  assert.match(m.html, /Strict mode is on/);
  assert.match(m.text, /Requests\/min: 1,240 \(normal 35\)/);
  assert.match(m.text, /Example & Co \(AS64500\): 30 addresses, 25 banned/);
  assert.match(m.text, /\.env grab: 812 requests/);
  assert.equal(m.level, "critical");
  // no dashboard known: no link
  const n = renderWave(items, { rpm: 1, normalRpm: 1 });
  assert.ok(!/href=/.test(n.html) && !/Open the waves/.test(n.text));
  const bad = renderWave(items, { link: "javascript:alert(1)" });
  assert.ok(!/javascript:/.test(bad.html), "only http(s) links");
  const d = renderDigest({ totals: { req: 10000, attacks: 300, bans: 12, newIps: 80 }, waves: [{ title: "Campaign", sev: "warn", first: Date.now(), members: 6 }] });
  assert.match(d.subject, /1 wave and 12 bans/);
  const s = renderSystem([{ type: "critical", sev: "critical", key: "guard", title: "The guard is disconnected", detail: "x", at: Date.now(), n: 1 }], { sensors: 0 });
  assert.match(s.subject, /^Bulwark CRITICAL: The guard is disconnected$/);
});

// ------------------------------------------------------------ the app: hidden without selfmail, then there
test("the API: email is null and no mail settings while selfmail isn't there; then the section, the test, the hooks", async () => {
  got.length = 0;
  const mesh = mkdtempSync(join(tmpdir(), "bw-mesh-app-"));
  const home = mkdtempSync(join(tmpdir(), "bw-mhome-"));
  const app = startApp({ home, port: 0, key: "k", offline: true, quiet: true, mesh, dashboard: "https://dash.example.com/__gate/bulwark/",
                         remote: async () => ({ verdict: { level: "clean", why: [] }, sources: {} }) });
  try {
    await new Promise((r) => (app.server.listening ? r() : app.server.once("listening", r)));
    const base = `http://127.0.0.1:${app.server.address().port}/api/`;
    const H = { "x-bulwark-key": "k", "Content-Type": "application/json" };
    const call = (p, o = {}) => fetch(base + p, { headers: H, ...o }).then(async (r) => ({ status: r.status, j: await r.json() }));
    // absent
    let s = (await call("settings")).j;
    assert.equal(s.email, null);
    assert.ok(!Object.keys(s).some((k) => k.startsWith("mail")), "no mail settings shown");
    assert.ok(!Object.keys((await call("overview")).j.settings).some((k) => k.startsWith("mail")));
    assert.deepEqual((await call("email")).j, { email: null, settings: null });
    assert.equal((await call("email/test", { method: "POST" })).status, 404);
    assert.equal(got.length, 0);
    // selfmail arrives
    announce(mesh);
    s = (await call("settings")).j;
    assert.ok(s.email, "the section's data");
    assert.equal(s.email.selfmail.version, "2.3.0");
    assert.equal(s.email.to, "me@example.com");
    assert.equal(s.mailOn, false, "off until you turn it on");
    assert.equal(s.mailWaves, true);
    assert.equal(s.mailDigest, false);
    assert.equal((await call("settings", { method: "PUT", body: JSON.stringify({ mailTo: "not an address" }) })).status, 400);
    s = (await call("settings", { method: "PUT", body: JSON.stringify({ mailOn: true, mailTo: "alerts@example.com" }) })).j;
    assert.equal(s.mailOn, true); assert.equal(s.email.to, "alerts@example.com");
    const t = await call("email/test", { method: "POST" });
    assert.equal(t.status, 200); assert.equal(t.j.ok, true); assert.equal(t.j.to, "alerts@example.com");
    assert.equal(got.length, 1);
    assert.match(got[0].body.html, /href="https:\/\/dash\.example\.com\/__gate\/bulwark\/"/, "the dashboard link");
    assert.equal(t.j.email.lastSent.kind, "test");
    // a wave in the brain becomes an email
    app.brain.mailer.gather = 5;
    app.brain.alerted({ key: "surge:newIp", kind: "surge", sev: "warn", title: "Surge of new addresses", detail: "120 a minute against a usual 3.0", members: [], open: true }, "new");
    assert.ok(await until(() => got.length === 2), "the wave email");
    assert.equal(got[1].body.level, "warn");
    assert.match(got[1].body.subject, /Surge of new addresses/);
    assert.match(got[1].body.html, /#\/waves/);
    app.brain.alerted({ key: "campaign:x", kind: "campaign", sev: "info", title: "A campaign may be forming", members: [] }, "new");
    assert.equal(app.brain.mailer.state.pending.wave.length, 0, "info isn't emailed");
    // the guard gone for 5 minutes: a critical email (its own stream, no wait behind the wave one)
    app.brain.health.hadGuard = true; app.brain.health.lostAt = Date.now() - 6 * MIN;
    app.brain.checkGuard();
    assert.ok(await until(() => got.length === 3), "the guard email");
    assert.match(got[2].body.subject, /^Bulwark CRITICAL: The guard is disconnected/);
    assert.equal(got[2].body.level, "critical");
    // selfmail gone again: hidden again
    rmSync(join(mesh, "selfmail.json"));
    s = (await call("settings")).j;
    assert.equal(s.email, null);
    assert.ok(!("mailOn" in s));
  } finally { app.close(); }
  assert.ok(!existsSync(join(home, "run", "app.running")), "a clean stop removes the running marker");
});

test("a run that didn't stop cleanly is reported when the app starts again", async () => {
  got.length = 0;
  const mesh = mkdtempSync(join(tmpdir(), "bw-mesh-crash-"));
  const home = mkdtempSync(join(tmpdir(), "bw-chome-"));
  announce(mesh);
  const a1 = startApp({ home, port: 0, key: "k", offline: true, quiet: true, mesh });
  await new Promise((r) => (a1.server.listening ? r() : a1.server.once("listening", r)));
  a1.brain.state.settings.mailOn = true; a1.brain.save(true);
  // a crash: no stop(), the marker stays
  a1.server.close(); a1.sensorSrv.close();
  for (const x of a1.brain.timers) { clearInterval(x); clearTimeout(x); }
  assert.ok(existsSync(join(home, "run", "app.running")));
  const a2 = startApp({ home, port: 0, key: "k", offline: true, quiet: true, mesh });
  try {
    assert.equal(a2.brain.mailer.state.pending.system.length, 1);
    assert.match(a2.brain.mailer.state.pending.system[0].title, /restarted after stopping unexpectedly/);
    assert.ok(await until(() => got.length === 1, 8000), "sent after the gather");
    assert.equal(got[0].body.level, "critical");
  } finally { a2.close(); }
});
