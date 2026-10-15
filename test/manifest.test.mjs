// forge-addon.json as the hosts check it: a card they refuse blocks the update
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const m = JSON.parse(readFileSync(new URL("../forge-addon.json", import.meta.url), "utf8"));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("the update card fits the hosts' limits (Aegis × Burrow's cleanUpdateCard)", () => {
  assert.equal(m.version, pkg.version, "manifest and package agree");
  const c = m.update_card;
  if (!c) return;
  for (const [k, max] of [["badge", 14], ["title", 80], ["tagline", 140], ["button", 24]]) if (c[k] != null) assert.ok(c[k].trim().length <= max, `${k} ≤ ${max}`);
  if (c.highlights != null) {
    assert.ok(Array.isArray(c.highlights) && c.highlights.length <= 5, "up to 5 highlights");
    for (const x of c.highlights) assert.ok(x.trim() && x.trim().length <= 100, `≤ 100 characters: "${x}" (${x.length})`);
  }
});
