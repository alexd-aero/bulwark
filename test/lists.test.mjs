// Lists every 5 s: conditional requests, only new addresses added, straight into the guard.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Feeds, FEEDS, RangeSet } from "../core/lists.mjs";
import { Guard } from "../sensor/guard.mjs";

test("a list that changed: only the addresses that weren't there are added, live", async () => {
  let body = "45.148.10.120\n198.51.100.0/24\n", etag = '"v1"', asked = [];
  const fetchImpl = async (url, { headers }) => {
    asked.push(headers["If-None-Match"] || "-");
    if (headers["If-None-Match"] === etag) return { status: 304, ok: false, headers: new Map() };
    return { status: 200, ok: true, headers: new Map([["etag", etag]]), text: async () => body };
  };
  const feeds = new Feeds({ dir: mkdtempSync(join(tmpdir(), "bw-feeds-")), log: () => {}, fetchImpl });
  const cins = FEEDS.find((f) => f.id === "cins");
  // only CINS is "loaded", so only it is polled
  assert.ok(await feeds.refresh(cins));
  const adds = [];
  feeds.onAdd = (id, a) => adds.push([id, a.map(([, e]) => e)]);
  assert.ok(feeds.lookup("45.148.10.120").length);
  // not modified: nothing happens
  feeds.meta.cins.checked = 0;
  assert.equal(await feeds.poll(), 0);
  assert.equal(asked.at(-1), '"v1"', "asked with its ETag");
  // two new addresses (one already there)
  body = "45.148.10.120\n198.51.100.0/24\n203.0.113.9\n2001:db8::7\n"; etag = '"v2"';
  feeds.meta.cins.checked = 0;
  assert.equal(await feeds.poll(), 2);
  assert.deepEqual(adds, [["cins", ["203.0.113.9", "2001:db8::7"]]]);
  assert.equal(feeds.lookup("203.0.113.9")[0].id, "cins", "looked up at once, without a rebuild");
  assert.ok(feeds.lookup("2001:db8::7").length);
  assert.equal(feeds.meta.cins.added, 2);
  // too soon: not asked again
  const n = asked.length;
  await feeds.poll();
  assert.equal(asked.length, n, "a source is asked no more often than it publishes");
});

test("the guard takes new list addresses in place, and they survive a worker hop", () => {
  const g = new Guard();
  g.useLists(new Map([["cins", { strong: RangeSet.empty() }]]));
  assert.equal(g.gate("203.0.113.9", { path: "/" }), null);
  g.apply({ t: "listadd", id: "cins", adds: [["strong", "203.0.113.9", null], ["strong", "192.0.2.0/24", null]] });
  g.apply({ t: "listadd", id: "et", adds: [["strong", "198.51.100.77", null]] });
  assert.equal(g.gate("203.0.113.10", { path: "/" }), null);
  assert.equal(g.gate("203.0.113.9", { path: "/" }).status, 403);
  assert.equal(g.gate("192.0.2.200", { path: "/" }).status, 403, "ranges too");
  assert.equal(g.gate("198.51.100.77", { path: "/" }).status, 403, "a list it didn't have yet");
  const r = RangeSet.unpack(structuredClone(g.lists.get("cins").strong.pack()));
  assert.ok(r.has("192.0.2.5"));
});
