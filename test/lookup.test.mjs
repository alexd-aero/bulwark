// A listing elsewhere (DroneBL, GreyNoise) bans on its own only a datacenter
// address; a home or mobile one (shared, carrier NAT) only for what it does here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Brain } from "../core/brain.mjs";

const drone = { verdict: { level: "malicious", why: ["DroneBL: SOCKS proxy"] }, sources: { dnsbl: { result: { dronebl: { listed: true, why: ["SOCKS proxy"] } } } } };

function brain() {
  const home = mkdtempSync(join(tmpdir(), "bulwark-lookup-"));
  const b = new Brain({ home, log: () => {}, offline: true, fetchImpl: async () => { throw new Error("offline"); } });
  b.settings.auto = true;
  const nets = { "172.58.255.194": { asn: 21928, name: "T-MOBILE-AS21928", hosting: false }, "45.9.0.1": { asn: 1, name: "SOME HOSTING", hosting: true } };
  b.asn.lookup = (ip) => nets[ip] || null;
  b.asn.t4 = true;
  return { b, home };
}

test("a phone on a listed carrier address isn't banned for the listing; a datacenter address is", () => {
  const { b, home } = brain();
  try {
    b.judge("172.58.255.194", drone);
    assert.equal(b.state.bans["172.58.255.194"], undefined);
    b.judge("45.9.0.1", drone);
    assert.equal(b.state.bans["45.9.0.1"]?.source, "lookup");
  } finally { b.stop?.(); rmSync(home, { recursive: true, force: true }); }
});

test("bans from before for a listing alone on a home or mobile network are lifted", () => {
  const { b, home } = brain();
  try {
    b.state.bans["172.58.255.194"] = { at: 1, until: Date.now() + 1e9, reason: "DroneBL: SOCKS proxy", source: "lookup", lines: [], sigs: [] };
    b.state.bans["45.9.0.1"] = { at: 1, until: Date.now() + 1e9, reason: "DroneBL: SOCKS proxy", source: "lookup", lines: [], sigs: [] };
    b.state.bans["10.9.9.9"] = { at: 1, reason: "tried /.env", source: "payload", lines: ["GET /.env"], sigs: ["env"] };
    b.liftListedOnly();
    assert.deepEqual(Object.keys(b.state.bans).sort(), ["10.9.9.9", "45.9.0.1"]);
  } finally { b.stop?.(); rmSync(home, { recursive: true, force: true }); }
});
