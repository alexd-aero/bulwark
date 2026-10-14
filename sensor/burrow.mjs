// Bulwark inside Aegis × Burrow: the extension the gate loads (forge-addon.json
// "burrow.extension"). It is small on purpose:
//
//   guard(ip, info)          every request, before anything else: the Guard's
//                            answer (null = through), synchronous, microseconds
//   observe(ip, info, res)   when the response is done: one line for the log,
//                            batched to the app every 250 ms (never awaited)
//   signedIn(ip)             a sign-in: that address is yours
//   peek(ip) / lookup(ip)    for the gate's own pages and IP checks
//   mount                    the dashboard under the gate's login (/__gate/bulwark)
//   handle(...)              /__gate/api/x/bulwark/… -> the app's API
//
// The app (server.mjs, its own service) does everything else, and sends the
// guard its state over <home>/run/sensor.sock. While the app is down the guard
// keeps going on the last state it saved (<home>/state/guard.json) and the lists
// on disk; what it saw meanwhile is buffered (up to 5000 lines).

import { connect } from "node:net";
import { readFileSync, existsSync, watch } from "node:fs";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { loadConfig, paths } from "../core/config.mjs";
import { RangeSet, lookupIn } from "../core/lists.mjs";
import { Guard } from "./guard.mjs";

let ctx = null, cfg = null, P = null, guardObj = null, sock = null, buf = "", queue = [], dropped = 0, pending = [];
let flushTimer = null, retryTimer = null, feedsWatch = null, feedsTimer = null, stopped = true, connectedAt = 0;
const MAX_QUEUE = 5000;

function log(...a) { ctx?.log?.(...a); }
function send(msg) {
  if (sock && !sock.destroyed && sock.writable) { sock.write(JSON.stringify(msg) + "\n"); return true; }
  return false;
}
function flush() {
  if (!queue.length) return;
  if (send({ t: "ev", list: queue, dropped })) { queue = []; dropped = 0; }
}

function connectApp() {
  if (stopped) return;
  clearTimeout(retryTimer);
  const s = connect(P.socket);
  s.setNoDelay(true);
  s.on("connect", () => {
    sock = s; connectedAt = Date.now();
    send({ t: "hello", host: "aegis-burrow", hostVersion: ctx?.hostVersion || null, legacy: ctx?.legacyShield || null,
           stats: guardObj.stats });
    for (const m of pending.splice(0)) send(m);
    flush();
  });
  s.on("data", (d) => {
    buf += d.toString("utf8");
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      let m; try { m = JSON.parse(line); } catch { continue; }
      if (m.t === "kick") { try { ctx?.kick?.(m.ip); } catch { /* best effort */ } continue; }
      if (m.t === "feeds") { loadLists(); continue; }
      guardObj.apply(m);
    }
  });
  const again = () => {
    if (sock === s) sock = null;
    buf = "";
    if (!stopped) retryTimer = setTimeout(connectApp, 3000);
  };
  s.on("error", () => {});
  s.on("close", again);
}

// the lists, parsed in a worker thread and swapped in whole
let loadingLists = false;
function loadLists() {
  if (loadingLists || stopped) return;
  loadingLists = true;
  const w = new Worker(fileURLToPath(new URL("./lists-worker.mjs", import.meta.url)), { workerData: { dir: P.feeds } });
  w.once("message", (list) => {
    const m = new Map();
    for (const [id, packed] of list) {
      const sets = {};
      for (const [k, o] of Object.entries(packed)) sets[k] = RangeSet.unpack(o);
      m.set(id, sets);
    }
    if (m.size) guardObj.useLists(m);
  });
  w.once("error", (e) => log("lists:", e.message));
  w.once("exit", () => { loadingLists = false; });
}

export async function start(hostCtx) {
  ctx = hostCtx; stopped = false;
  cfg = loadConfig(); P = paths(cfg.home);
  guardObj = new Guard({ log, emit: (m) => { if (!send(m) && pending.length < 2000) pending.push(m); if (m.t === "ban") { try { ctx?.kick?.(m.ip); } catch { /* best effort */ } } } });
  // the last state the app left, so the guard is right from the first request
  try { if (existsSync(P.snapshot)) guardObj.apply({ t: "state", ...JSON.parse(readFileSync(P.snapshot, "utf8")) }); } catch (e) { log("snapshot:", e.message); }
  loadLists();
  try { feedsWatch = watch(P.feeds, { persistent: false }, () => { clearTimeout(feedsTimer); feedsTimer = setTimeout(loadLists, 5000); }); } catch { /* no folder yet */ }
  flushTimer = setInterval(flush, 250);
  flushTimer.unref?.();
  connectApp();
}
export function stop() {
  stopped = true;
  clearInterval(flushTimer); clearTimeout(retryTimer); clearTimeout(feedsTimer);
  try { feedsWatch?.close(); } catch { /* gone */ }
  flush();
  try { sock?.end(); } catch { /* gone */ }
  sock = null;
}

// ------------------------------------------------------------------ the host's hooks
export function guard(ip, info) {
  if (!guardObj) return null;
  try { return guardObj.gate(ip, info); } catch (e) { log("guard:", e.message); return null; }
}
export function observe(ip, info, res) {
  if (!guardObj) return;
  try {
    const e = guardObj.entry(ip, info, res);
    if (sock) queue.push(e);
    else { queue.push(e); if (queue.length > MAX_QUEUE) { queue.shift(); dropped++; } }
    if (queue.length >= 500) flush();
  } catch { /* never in the way */ }
}
export function signedIn(ip) { guardObj?.trust(ip); }
export function peek(ip) {
  if (!guardObj) return null;
  const b = guardObj.bans.get(ip);
  return { banned: b && (!b.until || b.until > Date.now()) ? b : null, allowed: guardObj.allow.has(ip), trusted: guardObj.isTrusted(ip),
           own: guardObj.own.has(ip), lists: lookupIn(guardObj.lists, ip).map(({ id, name, strength }) => ({ id, name, strength })),
           probes: guardObj.scores.get(ip)?.probes || 0, verdict: guardObj.verdicts.get(ip)?.level || null };
}
export function lookup(ip) { return guardObj ? lookupIn(guardObj.lists, ip) : []; }
const appUrl = () => `http://${!cfg.bind || cfg.bind === "0.0.0.0" || cfg.bind === "::" ? "127.0.0.1" : cfg.bind}:${cfg.port}`;
export function mount() {
  return cfg?.key ? { prefix: "/__gate/bulwark", upstream: appUrl(), headers: { "x-bulwark-key": cfg.key }, name: "Bulwark" } : null;
}

// /__gate/api/x/bulwark/<path>: the app's API, for the Burrow page's panel
export async function handle({ method, path, json }) {
  if (path === "/sensor") {
    return { status: 200, json: { connected: !!sock, since: connectedAt, queue: queue.length, dropped, stats: guardObj?.stats,
                                  lists: guardObj?.lists.size || 0, bans: guardObj?.bans.size || 0 } };
  }
  if (!cfg?.key) return { status: 503, json: { error: "Bulwark isn't set up yet." } };
  const body = method === "GET" ? undefined : JSON.stringify(json ? await json().catch(() => ({})) : {});
  try {
    const r = await fetch(`${appUrl()}/api${path}`, {
      method, body, headers: { "Content-Type": "application/json", "x-bulwark-key": cfg.key }, signal: AbortSignal.timeout(15000),
    });
    return { status: r.status, json: await r.json().catch(() => ({})) };
  } catch (e) { return { status: 503, json: { error: `Bulwark isn't answering (${e.cause?.code || e.message}).` } }; }
}
