// Where Bulwark keeps things, and how its parts find each other.
//   ~/.config/bulwark/bulwark.json   {home, port, bind, key, access}: written once, read by
//                                    the app, the sensor inside a host, the CLI
//   <home>/feeds  lists   <home>/asn  network database   <home>/logs  every request
//   <home>/state  bans, settings, alerts   <home>/run/sensor.sock  sensor <-> app
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { randomBytes, createHash } from "node:crypto";

export const CONFIG_FILE = process.env.BULWARK_CONFIG
  || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "bulwark", "bulwark.json");
export const DEFAULT_PORT = 4370;

export function loadConfig({ create = false } = {}) {
  let c = {};
  try { c = JSON.parse(readFileSync(CONFIG_FILE, "utf8")); } catch { /* none yet */ }
  const out = {
    home: process.env.BULWARK_HOME || c.home || join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "bulwark"),
    port: Number(process.env.BULWARK_PORT || c.port || DEFAULT_PORT),
    bind: process.env.BULWARK_BIND || c.bind || "127.0.0.1",
    key: c.key || null,
    // "key": the key opens it (a link, then a cookie); "host": only a host's header does
    access: c.access === "host" ? "host" : "key",
  };
  if (create && (!c.key || !existsSync(CONFIG_FILE))) {
    out.key = out.key || randomBytes(24).toString("base64url");
    mkdirSync(dirname(CONFIG_FILE), { recursive: true });
    writeFileSync(CONFIG_FILE, JSON.stringify({ home: out.home, port: out.port, bind: out.bind, key: out.key, access: out.access }, null, 2) + "\n", { mode: 0o600 });
  }
  return out;
}
// Change one thing in the config file (the installer: access "host" inside Aegis).
export function setConfig(patch) {
  let c = {};
  try { c = JSON.parse(readFileSync(CONFIG_FILE, "utf8")); } catch { /* none yet */ }
  mkdirSync(dirname(CONFIG_FILE), { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify({ ...c, ...patch }, null, 2) + "\n", { mode: 0o600 });
}
// A Unix socket's path must stay under ~107 bytes. A deep home gets a short one
// under the user's home (hosts may run with a private /tmp and a read-only /run).
function socketPath(home) {
  const p = join(home, "run", "sensor.sock");
  return Buffer.byteLength(p) <= 100 ? p : join(homedir(), `.bulwark-${createHash("sha256").update(home).digest("hex").slice(0, 10)}.sock`);
}
export const paths = (home) => ({
  feeds: join(home, "feeds"), asn: join(home, "asn"), logs: join(home, "logs"), state: join(home, "state"),
  run: join(home, "run"), socket: socketPath(home), snapshot: join(home, "state", "guard.json"),
});
