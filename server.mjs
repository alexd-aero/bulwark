#!/usr/bin/env node
// Bulwark: the app. Its own process (bulwark.service), its own dashboard.
//
//   http://127.0.0.1:4370/     the dashboard (key: ?k=<key> once, then a cookie;
//                              hosts send x-bulwark-key, e.g. Aegis's /__gate/bulwark).
//                              With access "host" (installed in a host that has a
//                              login: Aegis × Burrow) only the host's header opens
//                              it: no link or cookie does, so the dashboard is
//                              behind that login (post-quantum, in Aegis's case)
//   /api/...                   what the dashboard reads and does (below)
//   <home>/run/sensor.sock     the guards inside hosts (sensor/burrow.mjs) connect here
//
// API: GET overview | series?span= | logs?… | stream (SSE) | ip/IP | alerts |
// graph?span= | blocklist | blocklist.txt?format=txt|cidr|nginx|iptables|csv|json |
// lists | vendors | settings | status | inspect/IP[?fresh=1&wait=ms] | inspect/IP/export |
// email (null while the selfmail addon isn't there);
// POST ip/IP/{ban,unban,allow,disallow,report} |
// lists/refresh | alerts/close | email/test;  PUT settings

import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { readFileSync, existsSync, unlinkSync, chmodSync } from "node:fs";
import { join, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual, createHash } from "node:crypto";
import { loadConfig } from "./core/config.mjs";
import { Brain, DEFAULT_SETTINGS } from "./core/brain.mjs";
import { MAIL_KEYS, validAddress } from "./core/mail.mjs";
import { checkIp } from "./core/intel.mjs";
import { isIP, isPrivate, normIp, netOf } from "./core/net.mjs";
import { signatureById, categoryOf, catalog, classify, matcherStats } from "./core/payloads.mjs";
import { CATEGORIES, categoryById } from "./core/taxonomy.mjs";
import { Inspector, SOURCES as INSPECT_SOURCES } from "./core/inspect.mjs";

const APP = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(APP, "package.json"), "utf8")).version;
const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
const SPANS = { "15m": 15 * MIN, "1h": HOUR, "6h": 6 * HOUR, "24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY, "90d": 90 * DAY };
const log = (...a) => console.log(new Date().toISOString(), ...a);

// dashboard: the dashboard's URL for links in emails (else the host tells it);
// mesh, mailFetch: where selfmail is looked for and how it's reached (tests)
export function startApp({ home, port, bind = "127.0.0.1", key, access = "key", offline = false, remote, fetchImpl, quiet = false, inspectFetch, inspectDns, dashboard, mesh, mailFetch } = {}) {
  const say = quiet ? () => {} : log;
  const brain = new Brain({ home, log: say, offline, remote, fetchImpl, dashboard, mesh, mailFetch, version: VERSION }).start();
  // the IP Inspector: on demand only, from the dashboard
  const inspector = new Inspector({ brain, fetchImpl: inspectFetch || fetchImpl, dns: inspectDns, offline: offline && !inspectFetch });
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
    s.on("close", () => { brain.sensors.delete(s); brain.guardGone(); });
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
  // the settings as the dashboard sees them: the AbuseIPDB key hidden; email only
  // while selfmail is there (else no mail* keys at all, and email: null)
  const settingsView = () => {
    const email = brain.mailer.status(), out = { ...brain.settings, abuseipdbKey: brain.settings.abuseipdbKey ? "•".repeat(8) + brain.settings.abuseipdbKey.slice(-4) : "" };
    if (!email) for (const k of MAIL_KEYS) delete out[k];
    return { ...out, email };
  };
  const emailView = () => {
    const email = brain.mailer.status();
    return { email, settings: email ? Object.fromEntries(MAIL_KEYS.map((k) => [k, brain.settings[k]])) : null };
  };
  const ipView = async (ip) => {
    const p = brain.profiles.get(ip);
    const intel = await checkIp(ip).catch((e) => ({ error: e.message }));
    const lists = brain.feeds.lookup(ip);
    return {
      ip, profile: p, devices: brain.devicesAt(ip), ban: brain.state.bans[ip] || null, allowed: brain.state.allow[ip] || null, trusted: brain.isTrusted(ip), own: brain.own.has(ip),
      asn: brain.asn.lookup(ip), net24: netOf(ip), net16: netOf(ip, true), lists, intel, verdict: brain.verdicts.get(ip) ? { ...brain.verdicts.get(ip), intel: undefined } : null,
      coverage: brain.reporters.coverage(ip, lists, intel.error ? null : intel),
      alerts: brain.waves.list(300).filter((a) => a.members?.includes(ip)).map(({ id, title, sev, kind, open, first, last }) => ({ id, title, sev, kind, open, first, last })),
      logs: await brain.logs.query({ ip, limit: 300 }),
    };
  };
  // an address's attack categories (requests per category), from its patterns
  const catsOf = (p) => { const m = new Map(); for (const [sig, n] of Object.entries(p.sigs || {})) { const c = categoryOf(sig); if (c && signatureById(sig)?.sev !== "info") m.set(c, (m.get(c) || 0) + n); } return [...m]; };
  const sigMeta = (sig) => { const d = signatureById(sig); return { cat: d?.cat || null, sev: d?.sev || null, cve: d?.cve || null }; };
  // yours (signed in, trusted, allowed, this machine, local) are never "strangers"
  const mine = (p) => p.auth || isPrivate(p.ip) || brain.own.has(p.ip) || brain.isTrusted(p.ip) || !!brain.state.allow[p.ip];
  const tops = (since) => {
    const all = brain.profiles.recent(since, 5000), ips = all.filter((p) => !mine(p));
    const by = (fn) => { const m = new Map(); for (const p of ips) for (const [k, n] of fn(p)) m.set(k, (m.get(k) || 0) + n); return [...m].sort((a, b) => b[1] - a[1]); };
    return {
      ips: ips.filter((p) => !p.auth).sort((a, b) => b.n - a.n).slice(0, 15).map((p) => ({ ip: p.ip, n: p.n, cc: p.cc, org: p.org, dc: p.dc, banned: !!brain.state.bans[p.ip], sigs: Object.keys(p.sigs).length })),
      sigs: by((p) => Object.entries(p.sigs)).slice(0, 12).map(([id, n]) => ({ id, name: signatureById(id)?.name || id, score: signatureById(id)?.score || 0, ...sigMeta(id), n })),
      orgs: by((p) => (p.org && !p.auth ? [[`${p.asn}|${p.org}|${p.dc ? 1 : 0}`, p.n]] : [])).slice(0, 10).map(([k, n]) => { const [asn, org, dc] = k.split("|"); return { asn: Number(asn), org, dc: dc === "1", n }; }),
      countries: by((p) => (p.cc && !p.auth ? [[p.cc, 1]] : [])).slice(0, 12).map(([cc, n]) => ({ cc, n })),
      cats: by((p) => catsOf(p)).slice(0, 12).map(([id, n]) => ({ id, n, name: categoryById(id)?.name || id, color: categoryById(id)?.color || null })),
      hosts: by((p) => Object.entries(p.hosts)).slice(0, 10).map(([host, n]) => ({ host, n })),
      seen: all.length,
    };
  };
  // the patterns graph: addresses linked to what they asked for and who holds them
  // The Patterns page: who tried what, organized. Every stranger that attacked in
  // the window, folded into networks (left) and patterns (right); links count
  // distinct addresses. The busiest networks and patterns are named, the rest
  // fold into "other". `who` lists the addresses behind one of them.
  // a stranger that attacked, or that Bulwark stopped (banned, blocked or dropped) without a pattern: on a
  // blocklist, flagged by the lookups, banned by you. Those come through "known bad" in the graph
  const hasSigs = (p) => Object.keys(p.sigs).length > 0;
  const attackers = (since) => brain.profiles.recent(since, 20000).filter((p) => !mine(p) && (hasSigs(p) || brain.state.bans[p.ip] || p.dec?.block || p.dec?.drop || p.dec?.ban));
  const KNOWN = { id: "sig:none", sig: null, score: 0, known: true, name: "Known bad, nothing tried",
                  what: "Never sent an attack pattern here: stopped for who they are (a blocklist, the threat lookups, an earlier ban, or you)." };
  const netKey = (p) => (p.asn ? `as:${p.asn}` : "as:0");
  // what Bulwark did about an address: the last stage of the Patterns graph
  const OUTCOMES = {
    "out:payload": { name: "Banned for payloads", what: "Asked for secrets or a way in, so Bulwark banned it everywhere." },
    "out:lookup": { name: "Banned on reputation", what: "The threat lookups found it bad (a botnet, an abuse list, a probe they agreed on), so Bulwark banned it." },
    "out:list": { name: "Banned: on a blocklist", what: "Already on a list of known attackers, so it was banned on sight." },
    "out:manual": { name: "Banned by you", what: "You banned it." },
    "out:ban": { name: "Banned", what: "Banned for another reason (part of a campaign, say)." },
    "out:dropped": { name: "Stopped, not banned", what: "Its payload requests were dropped; not enough yet to ban it." },
    "out:blocked": { name: "Blocked, not banned", what: "Turned away (the scan flagged it, or it was banned then): not banned now." },
    "out:watched": { name: "Watched", what: "Only probes (asking for software that isn't here): counted, answered normally, not banned." },
  };
  const outcomeOf = (p) => {
    const b = brain.state.bans[p.ip];
    if (b) return b.source === "payload" || b.source === "history" ? "out:payload" : b.source === "lookup" ? "out:lookup" : b.source === "list" ? "out:list" : b.source === "manual" ? "out:manual" : "out:ban";
    if (Object.keys(p.sigs).some((s) => signatureById(s)?.score === 3)) return "out:dropped";
    return p.dec?.block || p.dec?.ban ? "out:blocked" : p.dec?.drop ? "out:dropped" : "out:watched";
  };
  const patterns = (since, { nets: NN = 10, sigs: NS = 14 } = {}) => {
    const ps = attackers(since);
    const sigs = new Map(), nets = new Map(), links = new Map(), outs = new Map();
    const known = { ...KNOWN, ips: 0, banned: 0, requests: 0, last: 0 };
    for (const p of ps) {
      const banned = !!brain.state.bans[p.ip], nk = netKey(p);
      const n = nets.get(nk) || { id: nk, asn: p.asn || 0, org: p.org || (p.asn ? `AS${p.asn}` : "unknown network"), dc: !!p.dc, ips: 0, banned: 0, requests: 0 };
      n.ips++; n.banned += banned; n.requests += p.n || 0; nets.set(nk, n);
      for (const [sig, k] of Object.entries(p.sigs)) {
        const def = signatureById(sig);
        const x = sigs.get(sig) || { id: `sig:${sig}`, sig, name: def?.name || sig, score: def?.score || 0, ...sigMeta(sig), ips: 0, banned: 0, requests: 0, last: 0 };
        x.ips++; x.banned += banned; x.requests += k; x.last = Math.max(x.last, p.last || 0); sigs.set(sig, x);
        const lk = `${nk}|${sig}`, l = links.get(lk) || { a: nk, b: `sig:${sig}`, ips: 0, requests: 0 };
        l.ips++; l.requests += k; links.set(lk, l);
      }
      if (!hasSigs(p)) {
        known.ips++; known.banned += banned; known.requests += p.n || 0; known.last = Math.max(known.last, p.last || 0);
        const lk = `${nk}|sig:none`, l = links.get(lk) || { a: nk, b: "sig:none", ips: 0, requests: 0 };
        l.ips++; l.requests += p.n || 0; links.set(lk, l);
      }
      const oc = outcomeOf(p), o = outs.get(oc) || { id: oc, ...OUTCOMES[oc], ips: 0, requests: 0 };
      o.ips++; o.requests += p.n || 0; outs.set(oc, o);
    }
    // name the busiest; fold the rest (so the flow stays readable at any volume)
    const topNets = [...nets.values()].sort((a, b) => b.ips - a.ips || b.requests - a.requests);
    const keepN = new Set(topNets.slice(0, NN).map((n) => n.id));
    const otherN = topNets.slice(NN), sigList = [...sigs.values()].sort((a, b) => b.ips - a.ips || b.requests - a.requests);
    const keepS = new Set([...sigList.filter((x) => x.score === 3).slice(0, Math.ceil(NS * 0.6)), ...sigList.filter((x) => x.score !== 3).slice(0, Math.floor(NS * 0.4))].map((x) => x.id));
    const otherS = sigList.filter((x) => !keepS.has(x.id));
    const flowLinks = new Map();
    for (const l of links.values()) {
      const s = sigs.get(l.b.slice(4));
      const a = keepN.has(l.a) ? l.a : "as:other", b = l.b === "sig:none" || keepS.has(l.b) ? l.b : (s.score === 3 ? "sig:other-payload" : "sig:other-probe");
      const k = `${a}|${b}`, f = flowLinks.get(k) || { a, b, ips: 0, requests: 0 };
      f.ips += l.ips; f.requests += l.requests; flowLinks.set(k, f);
    }
    // pattern -> outcome: the addresses that tried a pattern, by what became of them
    const sigTo = (sig) => (keepS.has(`sig:${sig}`) ? `sig:${sig}` : signatureById(sig)?.score === 3 ? "sig:other-payload" : "sig:other-probe");
    const outLinks = new Map();
    for (const p of ps) {
      const oc = outcomeOf(p);
      for (const b of hasSigs(p) ? new Set(Object.keys(p.sigs).map(sigTo)) : ["sig:none"]) {
        const k = `${b}|${oc}`, l = outLinks.get(k) || { a: b, b: oc, ips: 0, requests: 0 };
        l.ips++; l.requests += p.n || 0; outLinks.set(k, l);
      }
    }
    const fold = (list, base) => list.reduce((o, x) => { o.ips += x.ips; o.banned += x.banned; o.requests += x.requests; o.count++; return o; }, { ...base, ips: 0, banned: 0, requests: 0, count: 0 });
    const flowNets = topNets.slice(0, NN);
    if (otherN.length) flowNets.push(fold(otherN, { id: "as:other", org: `${otherN.length} other networks`, other: true }));
    // a few real requests for each named pattern (what it looks like)
    const examples = new Map();
    for (const p of ps) for (const path of p.paths || []) {
      const c = classify(path);
      if (!c.id || !keepS.has(`sig:${c.id}`)) continue;
      const ex = examples.get(c.id) || new Set();
      if (ex.size < 4) ex.add(String(path).slice(0, 90));
      examples.set(c.id, ex);
    }
    const flowSigs = sigList.filter((x) => keepS.has(x.id)).map((x) => ({ ...x, examples: [...(examples.get(x.sig) || [])] }));
    for (const [score, id, label] of [[3, "sig:other-payload", "other payloads"], [1, "sig:other-probe", "other probes"]]) {
      const rest = otherS.filter((x) => (x.score === 3) === (score === 3));
      if (!rest.length) continue;
      // an address that tried several of them counts once
      const ids = new Set(rest.map((x) => x.sig)), who = ps.filter((p) => Object.keys(p.sigs).some((k) => ids.has(k)));
      flowSigs.push({ ...fold(rest, { id, score, other: true }), name: `${rest.length} ${label}`, ips: who.length, banned: who.filter((p) => brain.state.bans[p.ip]).length });
    }
    if (known.ips) flowSigs.push(known);
    const waves = brain.waves.list(50).filter((x) => x.kind === "campaign" && x.last >= since).map((w) => {
      const tally = new Map();
      for (const ip of w.members) for (const sig of Object.keys(brain.profiles.get(ip)?.sigs || {})) tally.set(sig, (tally.get(sig) || 0) + 1);
      return { id: `wave:${w.key}`, title: w.title, sev: w.sev, open: w.open, first: w.first, last: w.last, members: w.members.length,
               banned: w.members.filter((ip) => brain.state.bans[ip]).length,
               sigs: [...tally].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([sig]) => signatureById(sig)?.name || sig) };
    });
    // by category: addresses and requests, and how many of them are banned
    const cats = new Map();
    for (const p of ps) for (const [c, n] of catsOf(p)) { const x = cats.get(c) || { id: c, name: categoryById(c)?.name || c, color: categoryById(c)?.color || null, ips: 0, requests: 0, banned: 0, sigs: new Set() }; x.ips++; x.requests += n; x.banned += !!brain.state.bans[p.ip]; cats.set(c, x); }
    for (const x of sigList) cats.get(x.cat)?.sigs.add(x.name);
    const catList = [...cats.values()].sort((a, b) => b.ips - a.ips || b.requests - a.requests).map((x) => ({ ...x, sigs: [...x.sigs].slice(0, 6) }));
    return {
      cats: catList,
      totals: { ips: ps.length, attacked: ps.length - known.ips, known: known.ips, banned: ps.filter((p) => brain.state.bans[p.ip]).length, sigs: sigs.size, nets: nets.size, campaigns: waves.length,
                requests: [...sigs.values()].reduce((a, x) => a + x.requests, 0) },
      flow: { nets: flowNets, sigs: flowSigs, links: [...flowLinks.values()],
              outcomes: Object.keys(OUTCOMES).filter((k) => outs.has(k)).map((k) => outs.get(k)), outLinks: [...outLinks.values()] },
      sigs: sigList, waves,
    };
  };
  // the addresses behind a network, a pattern (or a folded "other"), or a campaign
  const patternWho = (since, id) => {
    const ps = attackers(since), all = patterns(since);
    // a connection in the graph: the addresses on both ends
    if (id.includes("|")) {
      const [a, b] = id.split("|", 2), pa = picker(all, a), pb = picker(all, b);
      const named = (x) => x.startsWith("sig:") && !x.startsWith("sig:other") && x !== "sig:none";
      const sig = named(b) ? b.slice(4) : named(a) && !b.startsWith("out:") ? a.slice(4) : null;
      return listOf(ps.filter((p) => pa(p) && pb(p)), sig);
    }
    const sig = id.startsWith("sig:") && !id.startsWith("sig:other") && id !== "sig:none" ? id.slice(4) : null;
    return listOf(ps.filter(picker(all, id)), sig);
  };
  const listOf = (ps, sig) => ps.map((p) => ({ ip: p.ip, cc: p.cc, org: p.org, dc: !!p.dc, n: sig ? p.sigs[sig] : p.n, banned: !!brain.state.bans[p.ip], last: p.last }))
    .sort((a, b) => b.n - a.n).slice(0, 500);
  const picker = (all, id) => {
    let pick;
    if (id.startsWith("out:")) return (p) => outcomeOf(p) === id;
    if (id.startsWith("cat:")) { const c = id.slice(4); return (p) => catsOf(p).some(([x]) => x === c); }
    if (id.startsWith("wave:")) { const w = brain.waves.list(50).find((x) => `wave:${x.key}` === id); const m = new Set(w?.members || []); pick = (p) => m.has(p.ip); }
    else if (id === "as:other") { const keep = new Set(all.flow.nets.filter((n) => !n.other).map((n) => n.id)); pick = (p) => !keep.has(netKey(p)); }
    else if (id.startsWith("as:")) pick = (p) => netKey(p) === id;
    else if (id === "sig:none") pick = (p) => !hasSigs(p);
    else if (id === "sig:other-payload" || id === "sig:other-probe") {
      const keep = new Set(all.flow.sigs.filter((x) => !x.other).map((x) => x.sig)), pay = id === "sig:other-payload";
      pick = (p) => Object.keys(p.sigs).some((s) => !keep.has(s) && ((signatureById(s)?.score === 3) === pay));
    } else { const sig = id.slice(4); pick = (p) => sig in p.sigs; }
    return pick;
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
        asn: brain.asn.view(), own: [...brain.own], settings: { ...Object.fromEntries(Object.entries(brain.settings).filter(([k]) => !MAIL_KEYS.includes(k))), abuseipdbKey: brain.settings.abuseipdbKey ? "set" : "" },
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
    // the IP Inspector: starts (or reuses) a full scan, answers with what's known so far
    const ins = /^\/inspect\/((?:[0-9a-fA-F.:]|%3[aA]){3,90})(\/export)?$/.exec(path);
    if (ins && m === "GET") {
      const ip = normIp(ins[1].replace(/%3a/gi, ":"));
      if (!isIP(ip)) return send(res, 400, { error: "That isn't an IP address." });
      const job = inspector.inspect(ip, { fresh: q.fresh === "1" && !ins[2] });
      const wait = ins[2] ? 25000 : Math.min(8000, Number(q.wait) || 0);
      if (wait && job.running) { let t; await Promise.race([job.done, new Promise((r) => { t = setTimeout(r, wait); })]); clearTimeout(t); }
      if (!job.local) await job.done.catch(() => {});
      const view = job.view();
      if (ins[2]) {
        res.setHeader("Content-Disposition", `attachment; filename="bulwark-inspect-${ip.replace(/[:]/g, "-")}.json"`);
        return send(res, 200, JSON.stringify({ tool: `Bulwark ${VERSION} IP Inspector`, exported: new Date().toISOString(), ...view }, null, 2));
      }
      return send(res, 200, view);
    }
    if (path === "/inspect" && m === "GET") return send(res, 200, { sources: INSPECT_SOURCES.map(({ id, name, about, key: needsKey }) => ({ id, name, about, needsKey: !!needsKey })), abuseipdb: !!brain.settings.abuseipdbKey,
      recent: [...inspector.jobs.values()].reverse().slice(0, 12).map((j) => { const v = j.view(); return { ip: j.ip, at: j.at, level: v.summary.level, score: v.summary.score, cc: v.summary.country, as: v.summary.asName }; }) });
    // an IPv6 address may come encoded (":" as %3A)
    const ipm = /^\/ip\/((?:[0-9a-fA-F.:]|%3[aA]){3,90})(?:\/(ban|unban|allow|disallow|report))?$/.exec(path);
    if (ipm) {
      const ip = normIp(ipm[1].replace(/%3a/gi, ":"));
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
    // your devices (from the host's device keys), each address with its network
    if (path === "/devices" && m === "GET") {
      const d = brain.devices || { list: [], at: null };
      return send(res, 200, { at: d.at, host: brain.sensors.size > 0, devices: d.list.map((x) => ({ ...x, ips: (x.ips || []).map((a) => { const n = isIP(a.ip) ? brain.asn.lookup(a.ip) : null; return { ...a, cc: n?.cc || "", org: n?.name || "", dc: !!n?.hosting }; }) })) });
    }
    if (path === "/devices/refresh" && m === "POST") { brain.refreshDevices(); return send(res, 200, { ok: true }); }
    if (path === "/alerts/close" && m === "POST") {
      const b = await readJson(req), a = [...brain.waves.alerts.values()].find((x) => x.id === b.id);
      if (a && a.open) { a.open = false; a.closed = Date.now(); a.dismissed = true; }
      return send(res, 200, { alerts: brain.waves.list(200) });
    }
    if (path === "/patterns" && m === "GET") return send(res, 200, patterns(Date.now() - (SPANS[q.span] || DAY)));
    if (path === "/patterns/who" && m === "GET") return send(res, 200, { ips: patternWho(Date.now() - (SPANS[q.span] || DAY), String(q.id || "")) });
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
    if (path === "/lists" && m === "GET") return send(res, 200, { adds: brain.listAdds, lists: brain.feeds.view(), total: brain.feeds.total(), asn: brain.asn.view(), signatures: catalog(), categories: CATEGORIES, engine: matcherStats() });
    if (path === "/lists/refresh" && m === "POST") { await brain.feeds.refreshDue(true); return send(res, 200, { lists: brain.feeds.view(), total: brain.feeds.total() }); }
    if (path === "/vendors" && m === "GET") return send(res, 200, { ...brain.reporters.view(), abuseipdb: !!brain.settings.abuseipdbKey, report: brain.settings.report });
    if (path === "/history" && m === "GET") return send(res, 200, { last: brain.state.history?.last || null, hosts: [...brain.sensors].map((x) => x.info?.host).filter(Boolean) });
    if (path === "/history/pull" && m === "POST") { brain.pullHistory(); return send(res, 200, { ok: true }); }
    if (path === "/email" && m === "GET") return send(res, 200, emailView());
    if (path === "/email/test" && m === "POST") {
      if (!brain.mailer.status()) return send(res, 404, { error: "selfmail isn't running.", email: null });
      try { const r = await brain.mailer.test(); return send(res, 200, { ...r, ...emailView() }); }
      catch (e) { return send(res, e.status === 404 || e.status === 429 ? e.status : 502, { error: e.message, ...emailView() }); }
    }
    if (path === "/settings") {
      if (m === "PUT") {
        const b = await readJson(req);
        if ("mailTo" in b) {
          b.mailTo = String(b.mailTo || "").trim();
          if (b.mailTo && !validAddress(b.mailTo)) return send(res, 400, { error: "That isn't an email address." });
        }
        for (const [k, def] of Object.entries(DEFAULT_SETTINGS)) {
          if (!(k in b)) continue;
          if (typeof def === "boolean") brain.state.settings[k] = !!b[k];
          else if (typeof def === "number") brain.state.settings[k] = Math.max(1, Math.min(365, Number(b[k]) || def));
          else brain.state.settings[k] = String(b[k] || "").trim().slice(0, 300);
        }
        brain.logs.keepDays = brain.state.settings.keepDays;
        brain.dirty = true; brain.save(true);
        brain.broadcast({ t: "settings", settings: { auto: brain.settings.auto, drop: brain.settings.drop, lookups: brain.settings.lookups, scanFirst: brain.settings.scanFirst } });
      }
      return send(res, 200, settingsView());
    }
    return send(res, 404, { error: "not found" });
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url || "/", "http://x");
    let path = url.pathname;
    try {
      // the key: a header from a host, a cookie, or ?k= once (then the cookie)
      const hostOnly = access === "host";
      const k = req.headers["x-bulwark-key"] || (hostOnly ? null : url.searchParams.get("k") || cookie(req));      // a fresh ?k= link wins over an old cookie
      if (!okKey(k)) {
        if (path === "/api/status") return send(res, 200, { ok: true, name: "Bulwark", version: VERSION });
        const how = hostOnly ? "Open Bulwark from your Aegis × Burrow dashboard (it's behind that login)." : "Open Bulwark from its host (Burrow or Selkies Forge), or with <code>?k=&lt;key&gt;</code> from <code>bulwark key</code>.";
        return send(res, 401, path.startsWith("/api/") ? { error: hostOnly ? "open it through your host's dashboard" : "key required" } : `<!doctype html><title>Bulwark</title><body style='font:15px system-ui;background:#0b0c0e;color:#ddd;display:grid;place-items:center;height:100vh'><p>${how}</p>`, path.startsWith("/api/") ? "application/json" : "text/html; charset=utf-8");
      }
      if (!hostOnly && url.searchParams.get("k") && !req.headers["x-bulwark-key"]) {
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
      brain.fault("http", e.message);
      if (!res.headersSent) send(res, 500, { error: "internal error" }); else res.end();
    }
  });
  server.listen(port, bind, () => say(`bulwark ${VERSION} on http://${bind}:${server.address().port} (home ${home})`));
  const close = () => { brain.stop(); server.close(); sensorSrv.close(); try { unlinkSync(sockPath); } catch { /* gone */ } };
  return { brain, server, sensorSrv, close };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cfg = loadConfig({ create: true });
  const app = startApp({ home: cfg.home, port: cfg.port, bind: cfg.bind, key: cfg.key, access: cfg.access, dashboard: cfg.dashboard, offline: process.env.BULWARK_OFFLINE === "1" });
  for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { app.close(); process.exit(0); });
}
