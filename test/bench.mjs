// What the guard costs a request, on traffic shaped like a real day: homes
// with a browser or three, a school and a mobile carrier behind one address
// each, scanners walking their lists, URLs never seen before, every header a
// browser sends. Prints the guard's own time (gate) and with the log line and
// the answer it reads afterwards (gate + observe).
//   node test/bench.mjs [--root DIR] [--n 200000]
// --root: another checkout's guard (compare two versions on the same traffic)
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const root = resolve(arg("--root", new URL("..", import.meta.url).pathname));
const N = Number(arg("--n", 200000));
const { Guard } = await import(pathToFileURL(`${root}/sensor/guard.mjs`).href);

export function traffic(n, seed = 7) {
  let s = seed;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const uas = [];
  for (let v = 120; v < 140; v++) {
    uas.push(`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`);
    uas.push(`Mozilla/5.0 (X11; CrOS x86_64 ${15000 + v}.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`);
    uas.push(`Mozilla/5.0 (iPhone; CPU iPhone OS 18_${v % 6} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.${v % 6} Mobile/15E148 Safari/604.1`);
    uas.push(`Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`);
  }
  const langs = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "ru-RU,ru;q=0.9,en;q=0.8", "es-US,es;q=0.9", "en-US"];
  const client = () => ({ ua: pick(uas), lang: pick(langs), ga: `GA1.1.${Math.floor(rnd() * 1e9)}.${1700000000 + Math.floor(rnd() * 1e7)}` });
  const homes = [];
  for (let i = 0; i < 3000; i++) homes.push({ ip: `198.18.${(i >> 8) & 255}.${i & 255}`, clients: Array.from({ length: 1 + Math.floor(rnd() * 3) }, client) });
  const school = { ip: "203.0.113.10", clients: Array.from({ length: 300 }, client) };
  const mobile = { ip: "203.0.113.20", clients: Array.from({ length: 100 }, client) };
  const scanners = Array.from({ length: 200 }, (_, i) => `198.51.100.${i}`);
  const assets = Array.from({ length: 120 }, (_, i) => `/assets/chunk-${(i * 2654435761 >>> 0).toString(36)}.js`);
  const pages = ["/", "/login", "/dashboard", "/settings", "/api/v1/me", "/api/v1/feed?page=2", "/search?q=hello+world", "/favicon.ico", "/manifest.json"];
  const probes = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/?id=1%27%20OR%20%271%27=%271", "/cgi-bin/luci/;stok=/locale", "/xmlrpc.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/admin.php", "/config.json"];
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = rnd();
    let ip, c, path;
    if (r < 0.04) {                                      // a scanner
      ip = pick(scanners);
      out.push({ ip, info: { method: "GET", path: pick(probes), ua: "Mozilla/5.0 zgrab/0.x", referer: "", lang: "", proto: "1.1", host: "x.example", access: "login",
                             headers: { host: "x.example", "user-agent": "Mozilla/5.0 zgrab/0.x", accept: "*/*", "accept-encoding": "gzip" } }, st: 404 });
      continue;
    }
    const where = r < 0.70 ? pick(homes) : r < 0.88 ? school : mobile;
    ip = where.ip; c = pick(where.clients);
    const q = rnd();
    path = q < 0.55 ? pick(assets) : q < 0.93 ? pick(pages) : `/api/v1/items/${Math.floor(rnd() * 1e6)}?sort=name&t=${Date.now() + i}`;
    const headers = { host: "app.example", "sec-ch-ua": '"Chromium";v="130"', "sec-ch-ua-mobile": "?0", "user-agent": c.ua, accept: "text/html,application/xhtml+xml,*/*;q=0.8",
                      "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": c.lang,
                      cookie: `_ga=${c.ga}; theme=dark`, "x-forwarded-for": ip, "cf-ray": "8f1a2b3c4d5e6f70-IAD", "cf-ipcountry": "US" };
    out.push({ ip, info: { method: "GET", path, ua: c.ua, referer: "https://app.example/", lang: c.lang.split(",")[0], proto: "1.1", host: "app.example", access: "login", headers }, st: 200 });
  }
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const reqs = traffic(N);
  const run = () => {
    const g = new Guard();
    let obs = 0;
    for (const { ip, info: proto, st } of reqs) {
      const info = { ...proto, t0: 0 };
      g.gate(ip, info);
      const t0 = process.hrtime.bigint();
      g.after(ip, info, { status: st });
      g.entry(ip, info, { status: st, bytes: 100, ms: 1 });
      obs += Number(process.hrtime.bigint() - t0) / 1000;
    }
    return { gate: g.stats.us / g.stats.requests, observe: obs / g.stats.requests };
  };
  run();                                                // warm up (JIT, the engine's caches)
  // the best of five: on a busy machine the scheduler only ever adds time
  const runs = Array.from({ length: Number(arg("--runs", 5)) }, run).sort((a, b) => a.gate - b.gate);
  const best = runs[0], mid = runs[runs.length >> 1];
  console.log(`${root}: ${N} requests, gate ${best.gate.toFixed(2)} µs (median ${mid.gate.toFixed(2)}), gate + observe ${(best.gate + best.observe).toFixed(2)} µs a request`);
}
