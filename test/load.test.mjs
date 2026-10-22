// A big wave: tens of thousands of addresses. Nothing may grow with it, and
// each request must stay cheap however many came before.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readdirSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Waves } from "../core/waves.mjs";
import { Logs } from "../core/store.mjs";

const ipOf = (i) => `198.${18 + (i >> 16 & 1)}.${(i >> 8) & 255}.${i & 255}`;       // 198.18.0.0/15, the benchmarking range

test("waves: 50 000 attackers from one network stay bounded and fast", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulwark-load-"));
  let alerts = 0;
  const w = new Waves({ file: join(dir, "waves.json"), onAlert: () => alerts++ });
  const t0 = Date.now(), start = performance.now();
  for (let i = 0; i < 50000; i++) {
    const e = { t: t0 + i, ip: ipOf(i), asn: 64500, org: "TEST-NET", sig: "env-file", ua: "Go-http-client/1.1", host: "x.example" };
    w.feed(e, { seq: ["env-file", "vcs"] }, true, false);
  }
  const ms = performance.now() - start;
  assert.ok(ms < 5000, `50k requests took ${Math.round(ms)} ms`);
  for (const m of [...w.nets.values(), ...w.fps.values()]) assert.ok(m.size <= 2000, `a member map holds ${m.size}`);
  for (const a of w.alerts.values()) assert.ok(a.members.length <= 300 && a.known.size <= 300);
  assert.ok(w.alerts.size <= 601, `${w.alerts.size} alerts kept`);
  assert.ok(alerts > 0);
  w.save();
  const saved = JSON.parse(readFileSync(join(dir, "waves.json"), "utf8"));
  assert.ok(!JSON.stringify(saved).includes('"known"'), "the membership index is never saved");
});

test("logs: a full day writes only what did something, and the byte budget drops the oldest day", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulwark-logs-"));
  writeFileSync(join(dir, "2001-01-01.jsonl"), "x".repeat(4000) + "\n");
  const logs = new Logs({ dir, keepDays: 100000, maxBytes: 3000, dayBytes: 2000 });
  clearInterval(logs.timer);
  const t = Date.now();
  for (let i = 0; i < 100; i++) logs.pending.push({ t, id: i, ip: ipOf(i), dec: "pass", path: "/" + "a".repeat(20) });
  logs.flush();
  logs.writing = false;
  for (let i = 0; i < 5; i++) logs.pending.push({ t, id: 100 + i, ip: ipOf(i), dec: "drop", sig: "env-file", path: "/.env" });
  logs.flush();
  assert.ok(logs.skipped > 0, "plain passes past the day's budget are left out");
  logs.prune();
  assert.ok(!readdirSync(dir).includes("2001-01-01.jsonl"), "the oldest day went for the byte budget");
});

test("logs: a restart reads only the tail of a huge day", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulwark-tail-"));
  const day = new Date().toISOString().slice(0, 10), line = JSON.stringify({ t: Date.now(), id: 1, ip: "198.18.0.1", dec: "pass", path: "/" + "p".repeat(900) }) + "\n";
  writeFileSync(join(dir, `${day}.jsonl`), line.repeat(60000));                     // ~55 MB
  assert.ok(statSync(join(dir, `${day}.jsonl`)).size > 48e6);
  const logs = new Logs({ dir, ring: 1000 });
  clearInterval(logs.timer);
  assert.equal(logs.ring.length, 1000);
});
