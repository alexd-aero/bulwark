// Scores the engine against the corpus: how many attacks it catches (by
// category, plain and with every query value encoded once more) and how much
// ordinary traffic it leaves alone.
//   node test/corpus/run.mjs [--misses] [--fps] [--bench]
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const engArg = process.argv.indexOf("--engine");
const { inspect } = await import(engArg > 0 ? process.argv[engArg + 1] : "../../core/payloads.mjs");

const dirArg = process.argv.indexOf("--dir");
const here = (f) => (dirArg > 0 ? `${process.argv[dirArg + 1]}/${f}` : fileURLToPath(new URL(f, import.meta.url)));
export function load(file) {
  const out = [];
  for (const line of readFileSync(here(file), "utf8").split("\n")) {
    if (!line.trim() || line.startsWith("#")) continue;
    const [want, target, ...extra] = line.split("\t");
    const req = { method: "GET", path: target.replace(/ /g, "%20"), headers: {} };
    for (const x of extra) {
      if (x.startsWith("M=")) req.method = x.slice(2);
      else if (x.startsWith("H:")) { const e = x.indexOf("="); req.headers[x.slice(2, e).toLowerCase()] = x.slice(e + 1); }
    }
    req.ua = req.headers["user-agent"] ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    req.referer = req.headers.referer || "";
    const loose = want.startsWith("~");
    out.push({ line, cats: want.replace(/^~/, "").split("|"), loose, req });
  }
  return out;
}
// every query value percent-encoded once more (what a careful scanner sends)
export function reencode(path) {
  const q = path.indexOf("?");
  if (q < 0) return null;
  return path.slice(0, q + 1) + path.slice(q + 1).split("&").map((p) => {
    const e = p.indexOf("=");
    return e < 0 ? p : p.slice(0, e + 1) + encodeURIComponent(p.slice(e + 1));
  }).join("&");
}
const caught = (v, c) => (c.loose ? !!v.id && !v.label && v.pts > 0 : v.score === 3);
export function score() {
  const res = { attacks: 0, seen: 0, caught: 0, byCat: {}, misses: [], benign: 0, fps: [], flagged: [] };
  for (const c of load("attacks.tsv")) {
    for (const path of [c.req.path, reencode(c.req.path)]) {
      if (!path) continue;
      const v = inspect({ ...c.req, path });
      const ok = caught(v, c);
      const k = c.cats[0];
      const b = (res.byCat[k] ||= { n: 0, ok: 0 });
      b.n++; res.attacks++;
      if (v.id && !v.label && v.pts > 0) res.seen++;
      if (ok) { b.ok++; res.caught++; } else res.misses.push(`${c.line.split("\t").slice(0, 3).join(" ")}${path !== c.req.path ? "  [re-encoded]" : ""}  -> ${v.id || "nothing"} ${v.pts || 0}pts`);
    }
  }
  for (const c of load("benign.tsv")) {
    const v = inspect(c.req);
    res.benign++;
    if (v.score === 3) res.fps.push(`${c.line}  -> ${v.hits.join(",")} ${v.pts}pts ${v.det || ""}`);
    else if (!c.loose && v.id && !v.label && v.pts > 0) res.flagged.push(`${c.line}  -> ${v.hits.join(",")} ${v.pts}pts ${v.det || ""}`);
  }
  return res;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const r = score();
  const pct = (a, b) => `${((100 * a) / b).toFixed(1)}%`;
  console.log(`attacks caught: ${r.caught}/${r.attacks} (${pct(r.caught, r.attacks)}); flagged at all: ${pct(r.seen, r.attacks)}`);
  for (const [k, b] of Object.entries(r.byCat).sort()) console.log(`  ${k.padEnd(10)} ${String(b.ok).padStart(4)}/${String(b.n).padEnd(4)} ${pct(b.ok, b.n)}`);
  console.log(`benign: ${r.benign}, payloads (false positives): ${r.fps.length}, flagged: ${r.flagged.length}`);
  if (process.argv.includes("--misses")) console.log("\nMISSES\n" + r.misses.join("\n"));
  if (process.argv.includes("--fps")) console.log("\nFALSE POSITIVES\n" + r.fps.join("\n") + "\n\nFLAGGED\n" + r.flagged.join("\n"));
}
