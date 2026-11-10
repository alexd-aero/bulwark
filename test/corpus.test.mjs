// The engine against two corpora (test/corpus): the one it was built with, and a
// held-out one written without seeing it. Detection may only go up; ordinary
// traffic must never be dropped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const run = (...args) => execFileSync(process.execPath, [fileURLToPath(new URL("./corpus/run.mjs", import.meta.url)), ...args], { encoding: "utf8" });
const rate = (out) => Number(/attacks caught: \d+\/\d+ \(([\d.]+)%\)/.exec(out)[1]);
const fps = (out) => Number(/payloads \(false positives\): (\d+)/.exec(out)[1]);

test("the built-with corpus: nearly everything caught, nothing ordinary dropped", () => {
  const out = run();
  assert.ok(rate(out) >= 99.5, out);
  assert.equal(fps(out), 0, out);
});
test("the held-out corpus: well caught, nothing ordinary dropped", () => {
  const out = run("--dir", fileURLToPath(new URL("./corpus/holdout", import.meta.url)));
  assert.ok(rate(out) >= 89, out);
  assert.equal(fps(out), 0, out);
});
