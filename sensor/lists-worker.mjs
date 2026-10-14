// Parses the list files off the host's main thread (2 MB of IPsum takes a
// moment on a Pi; the gate must not stall), and hands back the ranges.
import { parentPort, workerData } from "node:worker_threads";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { FEEDS, parseFeed } from "../core/lists.mjs";

const out = [], transfer = [];
for (const f of FEEDS) {
  const file = join(workerData.dir, f.id + ".txt");
  if (!existsSync(file)) continue;
  try {
    const sets = parseFeed(f, readFileSync(file, "utf8"));
    const packed = {};
    for (const [k, s] of Object.entries(sets)) { packed[k] = s.pack(); transfer.push(s.start.buffer, s.end.buffer); }
    out.push([f.id, packed]);
  } catch { /* a broken file: skipped until the app fetches it again */ }
}
parentPort.postMessage(out, transfer);
