#!/usr/bin/env node
// Bulwark: the app. Its own process (bulwark.service), its own dashboard.
//
//   http://127.0.0.1:4370/     the dashboard (key: ?k=<key> once, then a cookie;
//                              hosts send x-bulwark-key, e.g. Aegis's /__gate/bulwark)
//   /api/...                   what the dashboard reads and does (below)
//   <home>/run/sensor.sock     the guards inside hosts (sensor/burrow.mjs) connect here
//
// API: GET overview | series?span= | logs?… | stream (SSE) | ip/IP | alerts |
// graph?span= | blocklist | blocklist.txt?format=txt|cidr|nginx|iptables|csv|json |
// lists | vendors | settings | status;  POST ip/IP/{ban,unban,allow,disallow,report} |
// lists/refresh | alerts/close;  PUT settings

import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { readFileSync, existsSync, unlinkSync, chmodSync } from "node:fs";
import { join, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual, createHash } from "node:crypto";
import { loadConfig } from "./core/config.mjs";
import { Brain, DEFAULT_SETTINGS } from "./core/brain.mjs";
import { checkIp } from "./core/intel.mjs";
import { isIP, isPrivate, normIp, netOf } from "./core/net.mjs";
import { signatureById, SIGNATURES } from "./core/payloads.mjs";

const APP = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(APP, "package.json"), "utf8")).version;
const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
const SPANS = { "15m": 15 * MIN, "1h": HOUR, "6h": 6 * HOUR, "24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY, "90d": 90 * DAY };
const log = (...a) => console.log(new Date().toISOString(), ...a);

export function startApp({ home, port, bind = "127.0.0.1", key, offline = false, remote, fetchImpl, quiet = false } = {}) {
  const say = quiet ? () => {} : log;
  const brain = new Brain({ home, log: say, offline, remote, fetchImpl }).start();
  const keyHash = createHash("sha256").update(String(key)).digest();
  const okKey = (k) => !!k && timingSafeEqual(createHash("sha256").update(String(k)).digest(), keyHash);
  const cookie = (req) => /(?:^|;\s*)bulwark_k=([^;]+)/.exec(req.headers.cookie || "")?.[1];

  // ------------------------------------------------------------ sensor socket
  const sockPath = brain.P.socket;
  try { if (existsSync(sockPath)) unlinkSync(sockPath); } catch { /* in use? listen will say */ }
  const sensorSrv = createNetServer((s) => {
    s.setNoDelay(true);
    brain.sensors.add(s);
    let buf = "";
    s.on("data", (d) => {
      buf += d.toString("utf8");
      if (buf.length > 64 * 1024 * 1024) { s.destroy(); return; }
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        try { brain.onSensor(JSON.parse(line), s); } catch { /* a bad line */ }
      }
    });
    s.on("close", () => brain.sensors.delete(s));
    s.on("error", () => {});
  });
  sensorSrv.listen(sockPath, () => { try { chmodSync(sockPath, 0o600); } catch { /* fine */ } });

  // ------------------------------------------------------------ http
  const send = (res, status, body, type = "application/json") => {
    res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'",
                            "Referrer-Policy": "no-referrer" });
    res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  };
  const readJson = (req) => new Promise((resolve) => {
    let b = ""; req.on("data", (d) => { b += d; if (b.length > 1e6) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch { resolve({}); } });
  });
  const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png" };

  const enrich = (e) => e;
  const ipView = async (ip) => {
    const p = brain.profiles.get(ip);
    const intel = await checkIp(ip).catch((e) => ({ error: e.message }));
    const lists = brain.feeds.lookup(ip);
    return {
      ip, profile: p, ban: brain.state.bans[ip] || null, allowed: brain.state.allow[ip] || null, trusted: brain.isTrusted(ip), own: brain.own.has(ip),
      asn: brain.asn.lookup(ip), net24: netOf(ip), net16: netOf(ip, true), lists, intel, verdict: brain.verdicts.get(ip) ? { ...brain.verdicts.get(ip), intel: undefined } : null,
      coverage: brain.reporters.coverage(ip, lists, intel.error ? null : intel),
      alerts: brain.waves.list(300).filter((a) => a.members?.includes(ip)).map(({ id, title, sev, kind, open, first, last }) => ({ id, title, sev, kind, open, first, last })),
      logs: await brain.logs.query({ ip, limit: 300 }),
    };
  };
  // yours (signed in, trusted, allowed, this machine, local) are never "strangers"
  const mine = (p) => p.auth || isPrivate(p.ip) || brain.own.has(p.ip) || brain.isTrusted(p.ip) || !!brain.state.allow[p.ip];
  const tops = (since) => {
    const all = brain.profiles.recent(since, 5000), ips = all.filter((p) => !mine(p));
    const by = (fn) => { const m = new Map(); for (const p of ips) for (const [k, n] of fn(p)) m.set(k, (m.get(k) || 0) + n); return [...m].sort((a, b) => b[1] - a[1]); };
    return {
      ips: ips.filter((p) => !p.auth).sort((a, b) => b.n - a.n).slice(0, 15).map((p) => ({ ip: p.ip, n: p.n, cc: p.cc, org: p.org, dc: p.dc, banned: !!brain.state.bans[p.ip], sigs: Object.keys(p.sigs).length })),
      sigs: by((p) => Object.entries(p.sigs)).slice(0, 12).map(([id, n]) => ({ id, name: signatureById(id)?.name || id, score: signatureById(id)?.score || 0, n })),
      orgs: by((p) => (p.org && !p.auth ? [[`${p.asn}|${p.org}|${p.dc ? 1 : 0}`, p.n]] : [])).slice(0, 10).map(([k, n]) => { const [asn, org, dc] = k.split("|"); return { asn: Number(asn), org, dc: dc === "1", n }; }),
      countries: by((p) => (p.cc && !p.auth ? [[p.cc, 1]] : [])).slice(0, 12).map(([cc, n]) => ({ cc, n })),
      hosts: by((p) => Object.entries(p.hosts)).slice(0, 10).map(([host, n]) => ({ host, n })),
      seen: all.length,
    };
  };
  // the patterns graph: addresses linked to what they asked for and who holds them
  const graph = (since) => {
    const ips = brain.profiles.recent(since, 20000).filter((p) => !mine(p) && (Object.keys(p.sigs).length || brain.state.bans[p.ip]))
      .sort((a, b) => b.n - a.n).slice(0, 160);
    const nodes = new Map(), edges = [];
    const node = (id, x) => { if (!nodes.has(id)) nodes.set(id, { id, ...x, w: 0 }); return nodes.get(id); };
    for (const p of ips) {
      const ban = brain.state.bans[p.ip];
      node(`ip:${p.ip}`, { kind: "ip", label: p.ip, cc: p.cc, org: p.org, banned: !!ban, n: p.n, dc: !!p.dc }).w += p.n;
      for (const [sig, n] of Object.entries(p.sigs)) {
        const s = signatureById(sig);
        node(`sig:${sig}`, { kind: "sig", label: s?.name || sig, score: s?.score || 0 }).w += n;
        edges.push({ a: `ip:${p.ip}`, b: `sig:${sig}`, w: n });
      }
      if (p.asn) { node(`as:${p.asn}`, { kind: "as", label: p.org || `AS${p.asn}`, dc: !!p.dc }).w += 1; edges.push({ a: `ip:${p.ip}`, b: `as:${p.asn}`, w: 1 }); }
    }
    for (const a of brain.waves.list(50).filter((x) => x.kind === "campaign" && x.last >= since)) {
      const id = `wave:${a.key}`;
      node(id, { kind: "wave", label: a.title, sev: a.sev, open: a.open }).w += a.members.length;
      for (const ip of a.members) if (nodes.has(`ip:${ip}`)) edges.push({ a: id, b: `ip:${ip}`, w: 2 });
    }
    return { nodes: [...nodes.values()], edges };
  };
  const exportList = (format) => {
    const bans = brain.bansList();
    switch (format) {
      case "cidr": return bans.map((b) => (isIP(b.ip) === 6 ? `${b.ip}/128` : `${b.ip}/32`)).join("\n") + "\n";
      case "nginx": return bans.map((b) => `deny ${b.ip}; # ${b.reason.replace(/[\r\n#]/g, " ").slice(0, 80)}`).join("\n") + "\n";
      case "iptables": return bans.map((b) => `${isIP(b.ip) === 6 ? "ip6tables" : "iptables"} -A INPUT -s ${b.ip} -j DROP`).join("\n") + "\n";
      case "csv": return "ip,since,until,source,reason,org,country,requests\n" + bans.map((b) => [b.ip, new Date(b.at).toISOString(), b.until ? new Date(b.until).toISOString() : "", b.source, `"${b.reason.replace(/"/g, "'")}"`, `"${(b.org || "").replace(/"/g, "'")}"`, b.country, b.hits || 0].join(",")).join("\n") + "\n";
      case "json": return JSON.stringify(bans, null, 1);
      default: return `# Bulwark blocklist · ${bans.length} addresses · ${new Date().toISOString()}\n` + bans.map((b) => b.ip).join("\n") + "\n";
    }
  };

  async function api(req, res, path, url) {
    const q = Object.fromEntries(url.searchParams);
    const m = req.method;
    if (path === "/status") return send(res, 200, { ok: true, name: "Bulwark", version: VERSION, sensors: brain.sensors.size, bans: brain.bansList().length });
    if (path === "/overview" && m === "GET") {
      const span = SPANS[q.span] || DAY, since = Date.now() - span, sum = brain.series.total(span);
      return send(res, 200, {
        version: VERSION, now: Date.now(), span: q.span || "24h", totals: sum, bans: brain.bansList().length, stats: brain.state.stats,
        alerts: brain.waves.open().map(({ arrivals, ...a }) => a), strictUntil: brain.strictUntil, latency: brain.latency(), queue: brain.queue.length,
        sensors: [...brain.sensors].map((x) => x.info || {}), lists: { total: brain.feeds.total(), loaded: brain.feeds.lists.size, of: brain.feeds.view().length },
        asn: brain.asn.view(), own: [...brain.own], settings: { ...brain.settings, abuseipdbKey: brain.settings.abuseipdbKey ? "set" : "" },
        tops: tops(since), actions: brain.state.actions.slice(0, 40), vendors: brain.reporters.view(),
      });
    }
    if (path === "/series" && m === "GET") return send(res, 200, brain.series.range(SPANS[q.span] || DAY, Math.min(400, Number(q.points) || 180)));
    if (path === "/logs" && m === "GET") {
      const f = { ...q, since: q.since ? Number(q.since) : undefined, until: q.until ? Number(q.until) : undefined, before: q.before ? Number(q.before) : undefined };
      return send(res, 200, { logs: (await brain.logs.query(f)).map(enrich) });
    }
    if (path === "/stream" && m === "GET") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive", "X-Accel-Buffering": "no" });
      res.write(": hi\n\n");
      let n = 0, windowAt = Date.now();
      const offLog = brain.logs.subscribe((e) => {
        if (Date.now() - windowAt > 1000) { windowAt = Date.now(); n = 0; }
        if (++n > 200) return;                                         // a flood: the stream samples, the log keeps all
        res.write(`event: log\ndata: ${JSON.stringify(e)}\n\n`);
      });
      const offAlert = brain.onAlerts((a, change) => res.write(`event: alert\ndata: ${JSON.stringify({ change, alert: { ...a, arrivals: undefined } })}\n\n`));
      const ping = setInterval(() => res.write(": ping\n\n"), 20000);
      req.on("close", () => { offLog(); offAlert(); clearInterval(ping); });
      return;
    }
    const ipm = /^\/ip\/([0-9a-fA-F.:]{3,45})(?:\/(ban|unban|allow|disallow|report))?$/.exec(path);
    if (ipm) {
      const ip = normIp(ipm[1]);
      if (!isIP(ip)) return send(res, 400, { error: "That isn't an IP address." });
      if (!ipm[2] && m === "GET") return send(res, 200, await ipView(ip));
      if (m !== "POST") return send(res, 405, { error: "POST" });
      const b = await readJson(req);
      try {
        if (ipm[2] === "ban") brain.ban(ip, b.reason || "banned by you", { source: "manual" });
        if (ipm[2] === "unban") brain.unban(ip);
        if (ipm[2] === "allow") brain.allow(ip, true, b.note || "");
        if (ipm[2] === "disallow") brain.allow(ip, false);
        if (ipm[2] === "report") {
          const ev = brain.evidence(ip);
          if (!ev.lines.length) return send(res, 400, { error: "Nothing from this address to report: no payloads or probes on record." });
          brain.reporters.enqueue({ ip, reason: brain.state.bans[ip]?.reason || "web attack", source: "manual-report", ...ev, last: Date.now() });
        }
      } catch (e) { return send(res, 400, { error: e.message }); }
      return send(res, 200, await ipView(ip));
    }
    if (path === "/alerts" && m === "GET") return send(res, 200, { alerts: brain.waves.list(200), baseline: brain.waves.baseline(), strictUntil: brain.strictUntil });
    if (path === "/alerts/close" && m === "POST") {
      const b = await readJson(req), a = [...brain.waves.alerts.values()].find((x) => x.id === b.id);
      if (a && a.open) { a.open = false; a.closed = Date.now(); a.dismissed = true; }
      return send(res, 200, { alerts: brain.waves.list(200) });
    }
    if (path === "/graph" && m === "GET") return send(res, 200, graph(Date.now() - (SPANS[q.span] || DAY)));
    if (path === "/blocklist" && m === "GET" && q.since) {
      const since = Number(q.since) || 0;
      return send(res, 200, { bans: brain.bansList().filter((b) => (b.at || 0) > since), total: brain.bansList().length, now: Date.now() });
    }
    if (path === "/blocklist" && m === "GET") return send(res, 200, { now: Date.now(), bans: brain.bansList(), allow: Object.entries(brain.state.allow).map(([ip, a]) => ({ ip, ...a })),
                                                                       trusted: Object.entries(brain.state.trusted).filter(([ip]) => !brain.own.has(ip)).map(([ip, t]) => ({ ip, at: t })).sort((a, b) => b.at - a.at) });
    if (path === "/blocklist.txt" && m === "GET") {
      const fmt = q.format || "txt";
      res.setHeader("Content-Disposition", `inline; filename="bulwark-blocklist.${fmt === "json" ? "json" : fmt === "csv" ? "csv" : "txt"}"`);
      return send(res, 200, exportList(fmt), fmt === "json" ? "application/json" : fmt === "csv" ? "text/csv" : "text/plain; charset=utf-8");
    }
    if (path === "/lists" && m === "GET") return send(res, 200, { adds: brain.listAdds, lists: brain.feeds.view(), total: brain.feeds.total(), asn: brain.asn.view(), signatures: SIGNATURES.map(({ id, name, score }) => ({ id, name, score })) });
    if (path === "/lists/refresh" && m === "POST") { await brain.feeds.refreshDue(true); return send(res, 200, { lists: brain.feeds.view(), total: brain.feeds.total() }); }
    if (path === "/vendors" && m === "GET") return send(res, 200, { ...brain.reporters.view(), abuseipdb: !!brain.settings.abuseipdbKey, report: brain.settings.report });
    if (path === "/settings") {
      if (m === "PUT") {
        const b = await readJson(req);
        for (const [k, def] of Object.entries(DEFAULT_SETTINGS)) {
          if (!(k in b)) continue;
          if (typeof def === "boolean") brain.state.settings[k] = !!b[k];
          else if (typeof def === "number") brain.state.settings[k] = Math.max(1, Math.min(365, Number(b[k]) || def));
          else brain.state.settings[k] = String(b[k] || "").trim().slice(0, 300);
        }
        brain.logs.keepDays = brain.state.settings.keepDays;
        brain.dirty = true; brain.save(true);
        brain.broadcast({ t: "settings", settings: { auto: brain.settings.auto, drop: brain.settings.drop, lookups: brain.settings.lookups } });
      }
      return send(res, 200, { ...brain.settings, abuseipdbKey: brain.settings.abuseipdbKey ? "•".repeat(8) + brain.settings.abuseipdbKey.slice(-4) : "" });
    }
    return send(res, 404, { error: "not found" });
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url || "/", "http://x");
    let path = url.pathname;
    try {
      // the key: a header from a host, a cookie, or ?k= once (then the cookie)
      const k = req.headers["x-bulwark-key"] || url.searchParams.get("k") || cookie(req);      // a fresh ?k= link wins over an old cookie
      if (!okKey(k)) {
        if (path === "/api/status") return send(res, 200, { ok: true, name: "Bulwark", version: VERSION });
        return send(res, 401, path.startsWith("/api/") ? { error: "key required" } : "<!doctype html><title>Bulwark</title><body style='font:15px system-ui;background:#0b0c0e;color:#ddd;display:grid;place-items:center;height:100vh'><p>Open Bulwark from its host (Burrow or Selkies Forge), or with <code>?k=&lt;key&gt;</code> from <code>bulwark key</code>.</p>", path.startsWith("/api/") ? "application/json" : "text/html; charset=utf-8");
      }
      if (url.searchParams.get("k") && !req.headers["x-bulwark-key"]) {
        res.setHeader("Set-Cookie", `bulwark_k=${encodeURIComponent(k)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000`);
        url.searchParams.delete("k");
        res.writeHead(302, { Location: url.pathname + (url.search || "") }); return res.end();
      }
      if (path.startsWith("/api/")) return await api(req, res, path.slice(4), url);
      if (path === "/") path = "/index.html";
      const file = join(APP, "public", path.replace(/\.\.+/g, ""));
      if (!file.startsWith(join(APP, "public")) || !existsSync(file)) return send(res, 404, "not found", "text/plain");
      return send(res, 200, readFileSync(file), TYPES[extname(file)] || "application/octet-stream");
    } catch (e) {
      say("http:", e.message);
      if (!res.headersSent) send(res, 500, { error: "internal error" }); else res.end();
    }
  });
  server.listen(port, bind, () => say(`bulwark ${VERSION} on http://${bind}:${server.address().port} (home ${home})`));
  const close = () => { brain.stop(); server.close(); sensorSrv.close(); try { unlinkSync(sockPath); } catch { /* gone */ } };
  return { brain, server, sensorSrv, close };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cfg = loadConfig({ create: true });
  const app = startApp({ home: cfg.home, port: cfg.port, bind: cfg.bind, key: cfg.key, offline: process.env.BULWARK_OFFLINE === "1" });
  for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { app.close(); process.exit(0); });
}
