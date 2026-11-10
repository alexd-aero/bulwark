// Vendor reports (core/report.mjs): nothing is lost before a key is set; each
// vendor hears about an address once a week; the evidence never names your hosts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Reporters, blocklistdeService } from "../core/report.mjs";

function setup(settings = {}) {
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, opts, body: opts.body ? String(opts.body) : "" });
    if (url.includes("abuseipdb.com/api/v2/check")) return { ok: true, status: 200, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }), headers: new Map() };
    if (url.includes("abuseipdb.com/api/v2/report")) return { ok: true, status: 200, json: async () => ({ data: { abuseConfidenceScore: 25 } }) };
    if (url.includes("blocklist.de")) return { ok: true, status: 200, text: async () => "<html>Thank you, the attack was added</html>" };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const s = { report: true, abuseipdbKey: "", blocklistdeEmail: "", blocklistdeKey: "", ...settings };
  const r = new Reporters({ file: join(mkdtempSync(join(tmpdir(), "bw-rep-")), "reports.json"), log: () => {}, settings: () => s, fetchImpl });
  r.gap = 0;
  return { r, s, calls };
}
const ev = { ip: "203.0.113.50", reason: "sent 2 payloads (/.env) on chat.example.dev", source: "payload", sigs: ["env-file", "sqli"], lines: ["GET /.env", "GET /?id=1' OR '1'='1"] };
const settle = () => new Promise((res) => setTimeout(res, 30));

test("without a vendor: it waits, says so, and goes out once a key is added", async () => {
  const { r, s, calls } = setup();
  const a = r.enqueue(ev);
  assert.equal(a.queued, false); assert.equal(a.waiting, true); assert.match(a.why, /no vendor/);
  assert.equal(r.view().waiting, 1);
  assert.equal(calls.length, 0, "nothing was sent anywhere");
  s.abuseipdbKey = "k";
  assert.equal(r.resume([{ ip: "198.51.100.60", reason: "x", source: "payload", lines: ["GET /.git/config"], sigs: ["vcs"], at: Date.now() }, { ip: "198.51.100.61", source: "list", reason: "on a list" }]), 2, "the waiting one and this week's payload ban; never a list ban");
  await settle(); await settle();
  assert.ok(r.state.reported[ev.ip]?.vendors?.abuseipdb);
  const rep = calls.find((c) => c.url.endsWith("/report") && c.body.includes("203.0.113.50"));
  assert.ok(rep, "reported to AbuseIPDB");
  assert.ok(!rep.body.includes("example.dev"), "host names never leave");
  assert.match(decodeURIComponent(rep.body), /categories=15,16,21|categories=16,15,21/);
  assert.equal(r.enqueue(ev).queued, false, "once a week per vendor");
});

test("blocklist.de: reported with a service that fits; both vendors hear about it", async () => {
  const { r, calls } = setup({ abuseipdbKey: "k", blocklistdeEmail: "me@example.org", blocklistdeKey: "b" });
  assert.equal(r.enqueue(ev).queued, true);
  await settle(); await settle();
  const bl = calls.find((c) => c.url.includes("blocklist.de"));
  assert.ok(bl); assert.match(bl.body, /service=sql-injection/); assert.match(bl.body, /server=me%40example.org/);
  assert.deepEqual(Object.keys(r.state.reported[ev.ip].vendors).sort(), ["abuseipdb", "blocklistde"]);
  assert.equal(blocklistdeService(["wordpress"]), "wp-bruteforce");
  assert.equal(blocklistdeService(["cmd-inject"]), "rfi-attack");
  assert.equal(blocklistdeService(["scanner-ua"]), "badbot");
  assert.equal(r.view().vendors.find((v) => v.id === "blocklistde").reported, 1);
});

test("what isn't reported, and why", () => {
  const { r } = setup({ abuseipdbKey: "k" });
  assert.match(r.enqueue({ ...ev, source: "list" }).why, /only addresses banned for what they did/);
  assert.match(r.enqueue({ ...ev, lines: [], sigs: [] }).why, /no evidence/);
  const { r: off } = setup({ abuseipdbKey: "k", report: false });
  assert.match(off.enqueue(ev).why, /reporting is off/);
  assert.equal(off.enqueue({ ...ev, source: "manual-report" }).queued, true, "a report you ask for goes out even with automatic reports off");
});
