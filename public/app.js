// Bulwark's dashboard. Plain modules, no build step, no inline handlers (strict CSP):
// everything is wired through data-act attributes and one delegated listener.
// All paths are relative, so it works at / and under a host's mount (/__gate/bulwark/).
import { TimeChart, Heatmap, Graph, fmtN } from "./charts.js";

const $ = (s, el = document) => el.querySelector(s);
const app = $("#app");
const h = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ago = (t) => { if (!t) return "never"; const s = Math.max(0, (Date.now() - t) / 1000); return s < 5 ? "now" : s < 60 ? Math.floor(s) + "s ago" : s < 3600 ? Math.floor(s / 60) + "m ago" : s < 86400 ? Math.floor(s / 3600) + "h ago" : Math.floor(s / 86400) + "d ago"; };
const clock = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtB = (b) => { if (!b) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(4, Math.floor(Math.log(b) / Math.log(1024))); return (b / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i]; };
const flag = (cc) => /^[A-Z]{2}$/.test(cc || "") ? `<span class="flag" title="${cc}">${String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0)))}</span>` : "";
const ICONS = {
  back: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>',
  grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
  list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/></svg>',
  wave: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M2 12c2.5-5 5-5 7.5 0s5 5 7.5 0 3.5-3 5-2"/><path d="M2 18c2.5-3 5-3 7.5 0s5 3 7.5 0 3.5-2 5-1" opacity=".5"/></svg>',
  graph: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="7" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7.2 7.2 10.6 16M16.8 8.6 13.4 16M7.5 6.2l9 .7"/></svg>',
  ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>',
  layers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5" opacity=".6"/></svg>',
  send: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M21 3 10 14M21 3l-7 18-4-7-7-4 18-7Z"/></svg>',
  device: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><rect x="2" y="4" width="14" height="10" rx="1.5"/><path d="M6 18h6M9 14v4"/><rect x="17" y="8" width="5" height="12" rx="1.2"/></svg>',
  phone: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><rect x="6.5" y="2.5" width="11" height="19" rx="2.2"/><path d="M10.5 18.5h3"/></svg>',
  laptop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><rect x="4" y="4.5" width="16" height="11" rx="1.5"/><path d="M2 19.5h20"/></svg>',
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>',
};
for (const i of document.querySelectorAll("[data-i]")) i.innerHTML = ICONS[i.dataset.i] || "";

const DEC = { pass: ["pass", "through"], drop: ["drop", "payload dropped"], block: ["block", "blocked"], ban: ["ban", "banned"], seen: ["seen", "from the host's history"], check: ["check", "checked first"] };
const SEVP = { critical: "crit", warn: "warn", info: "info" };
const SPAN_KEYS = ["15m", "1h", "6h", "24h", "7d", "30d", "90d"];
// your devices (the host's device keys): id -> name, for the log and the address drawer
const devName = (id) => S.devices?.find((d) => d.id === id)?.name || "one of your devices";
const S = { devices: null, view: "overview", span: localStore("span") || "24h", gspan: "24h", ov: null, logs: [], logF: { dec: "", sig: "", q: "", ip: "", host: "" }, paused: false,
            open: null, alerts: null, bl: null, lists: null, vendors: null, settings: null, ip: null, live: false, newIds: new Set() };
let charts = {};
function localStore(k, v) { try { if (v === undefined) return localStorage.getItem("bulwark-" + k); localStorage.setItem("bulwark-" + k, v); } catch { return null; } }

async function api(path, opts = {}) {
  const r = await fetch("api/" + path, { headers: { "Content-Type": "application/json" }, ...opts });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
const post = (path, body = {}) => api(path, { method: "POST", body: JSON.stringify(body) });
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("show"), 2600); }
const seg = (act, cur, keys = SPAN_KEYS) => `<div class="seg">${keys.map((k) => `<button data-act="${act}" data-v="${k}" class="${k === cur ? "on" : ""}">${k}</button>`).join("")}</div>`;
const decPill = (d) => `<span class="pill ${DEC[d]?.[0] || ""}">${h(DEC[d]?.[1] || d)}</span>`;
const ipBtn = (ip, cc) => `<a href="#" data-act="ip" data-ip="${h(ip)}" class="mono">${flag(cc)} ${h(ip)}</a>`;
const bars = (rows, label, n, cls = () => "") => { const max = Math.max(1, ...rows.map(n)); return `<div class="bars">${rows.map((r) => `<div class="bar"><span class="lbl">${label(r)}</span><span class="n">${fmtN(n(r))}</span><span class="track"><i class="${cls(r)}" style="width:${(100 * n(r)) / max}%"></i></span></div>`).join("")}</div>`; };

// ------------------------------------------------------------------ overview
async function loadOverview() {
  const [ov, series] = await Promise.all([api(`overview?span=${S.span}`), api(`series?span=${S.span}&points=${Math.max(60, Math.min(240, Math.floor(app.clientWidth / 6)))}`)]);
  S.ov = ov; S.series = series;
  chrome();
}
function alertBanner(alerts) {
  const top = (alerts || []).filter((a) => a.sev !== "info");
  if (!top.length) return "";
  const a = top[0], crit = a.sev === "critical";
  return `<div class="banner ${crit ? "" : "warn"}"><span class="pill ${SEVP[a.sev]}">${crit ? "CRITICAL" : "WARNING"}</span>
    <div class="grow"><b>${h(a.title)}</b> <span class="muted">${h(a.detail)}</span>${a.forecast ? ` <span class="forecast">· ~${a.forecast.nextHour} more expected next hour (${a.forecast.trend})</span>` : ""}</div>
    ${top.length > 1 ? `<span class="faint small">+${top.length - 1} more</span>` : ""}<a class="btn sm" href="#/waves">Open</a></div>`;
}
function renderOverview() {
  const o = S.ov;
  if (!o) { app.innerHTML = '<p class="muted"><span class="spin"></span> Loading…</p>'; return; }
  const T = o.totals || {}, bad = (T.drop || 0) + (T.block || 0) + (T.ban || 0);
  const strict = o.strictUntil > Date.now();
  app.innerHTML = `
    <div class="head"><div><h1>Overview</h1><p>Every request through ${o.sensors.length ? o.sensors.map((s) => h(s.host || "a host")).join(", ") : "your hosts"} is checked in microseconds; what is slow happens here, behind it.</p></div>
      <div class="spacer"></div>${seg("span", S.span)}</div>
    ${alertBanner(o.alerts)}
    ${!o.sensors.length ? `<div class="banner warn"><span class="pill warn">NO SENSOR</span><div class="grow">No host is connected yet. Install Bulwark in Aegis × Burrow (Burrow → Addons) and its guard connects here by itself.</div></div>` : ""}
    <div class="grid g4" style="margin-bottom:14px">
      <div class="card stat"><b>${fmtN(T.req || 0)}</b><span>requests</span><div class="sub">${fmtB(T.bytes || 0)} · ${fmtN(o.tops.seen)} addresses</div></div>
      <div class="card stat ${bad ? "hot" : ""}"><b>${fmtN(bad)}</b><span>stopped</span><div class="sub">${fmtN(T.drop || 0)} payloads · ${fmtN(T.block || 0)} blocked · ${fmtN(T.ban || 0)} bans</div></div>
      <div class="card stat"><b>${fmtN(o.bans)}</b><span>banned now</span><div class="sub">${fmtN(T.newIp || 0)} new addresses · ${fmtN((T.payload || 0) + (T.probe || 0))} attacks</div></div>
      <div class="card stat ${strict ? "warm" : ""}"><b>${o.latency ? fmtN(o.latency.p95) + '<span class="faint" style="font-size:15px"> ms</span>' : "–"}</b><span>to categorize a new address <span class="faint">(p95)</span></span>
        <div class="sub">${o.latency ? `median ${o.latency.p50} ms · ` : ""}${fmtN(o.stats.checked)} looked up${strict ? " · STRICT" : ""}</div></div>
    </div>
    <section class="card" style="margin-bottom:14px"><h3>Traffic <span class="faint">by what happened</span></h3><div id="cTraffic"></div>
      <div class="legend"><span><i style="background:#3d4450"></i>through</span><span><i style="background:#f2b53c"></i>payload dropped</span><span><i style="background:#ff5a52"></i>blocked</span><span><i style="background:#e040fb"></i>banned</span><span><i style="background:#46c2ff"></i>new addresses (right axis)</span></div></section>
    <section class="card" style="margin-bottom:14px"><h3>Attack patterns <span class="faint">over time</span></h3><div id="cHeat"></div></section>
    <div class="grid g3" style="margin-bottom:14px">
      <section class="card"><h3>Patterns</h3>${o.tops.sigs.length ? bars(o.tops.sigs, (r) => h(r.name), (r) => r.n, (r) => "s" + r.score) : '<p class="empty">No attacks in this window.</p>'}</section>
      <section class="card"><h3>Networks <span class="faint">(strangers)</span></h3>${o.tops.orgs.length ? bars(o.tops.orgs, (r) => `${h(r.org)} <span class="faint mono">AS${r.asn}</span>${r.dc ? ' <span class="pill dc">hosting</span>' : ""}`, (r) => r.n, (r) => (r.dc ? "dc" : "")) : '<p class="empty">–</p>'}</section>
      <section class="card"><h3>Countries</h3>${o.tops.countries.length ? bars(o.tops.countries, (r) => `${flag(r.cc)} ${h(r.cc)}`, (r) => r.n) : '<p class="empty">–</p>'}</section>
    </div>
    <div class="grid g21">
      <section class="card"><h3>Busiest strangers</h3>${o.tops.ips.length ? `<div class="scroll"><table><thead><tr><th>Address</th><th>Network</th><th>Requests</th><th>Patterns</th><th></th></tr></thead><tbody>
        ${o.tops.ips.map((p) => `<tr class="click" data-act="ip" data-ip="${h(p.ip)}"><td>${ipBtn(p.ip, p.cc)}</td><td class="why">${h(p.org || "–")}${p.dc ? ' <span class="pill dc">hosting</span>' : ""}</td><td class="mono">${fmtN(p.n)}</td><td class="mono">${p.sigs || ""}</td><td>${p.banned ? '<span class="pill ban">banned</span>' : ""}</td></tr>`).join("")}</tbody></table></div>` : '<p class="empty">Nobody yet.</p>'}</section>
      <section class="card"><h3>What Bulwark did</h3>${o.actions.length ? `<div class="scroll" style="max-height:420px"><table><tbody>${o.actions.slice(0, 30).map((a) => `<tr class="click" data-act="ip" data-ip="${h(a.ip)}"><td class="faint mono">${ago(a.t)}</td><td><span class="pill ${a.act === "banned" ? "ban" : a.act === "lifted" || a.act === "unbanned" || a.act === "trusted" ? "ok" : ""}">${h(a.act)}</span></td><td>${ipBtn(a.ip, a.cc)}</td><td class="why" title="${h(a.why)}">${h(a.why)}</td></tr>`).join("")}</tbody></table></div>` : '<p class="empty">Quiet.</p>'}</section>
    </div>`;
  charts.traffic = new TimeChart($("#cTraffic"), { height: 300,
    series: [{ key: "pass", label: "through", color: "#3d4450" }, { key: "drop", label: "payload dropped", color: "#f2b53c" }, { key: "block", label: "blocked", color: "#ff5a52" }, { key: "ban", label: "banned", color: "#e040fb" }],
    line: { key: "newIp", label: "new addresses", color: "#46c2ff" } });
  charts.traffic.set(S.series);
  const rows = (S.sigRows ||= null);
  drawHeat($("#cHeat"), S.series);
}
function drawHeat(el, series) {
  const seen = new Map();
  for (const p of series.points) for (const [id, n] of Object.entries(p.sig || {})) seen.set(id, (seen.get(id) || 0) + n);
  const sigs = (S.sigs || []).filter((s) => seen.has(s.id)).sort((a, b) => b.score - a.score || seen.get(b.id) - seen.get(a.id));
  if (!sigs.length) { el.innerHTML = '<p class="empty">No attack patterns in this window. When they come, each kind gets a row here.</p>'; return; }
  charts.heat = new Heatmap(el, { height: Math.min(420, 30 + sigs.length * 24) });
  charts.heat.set(series, sigs);
}

// ------------------------------------------------------------------ live log
async function loadLog(more) {
  const f = Object.fromEntries(Object.entries(S.logF).filter(([, v]) => v));
  if (more && S.logs.length) f.before = S.logs[S.logs.length - 1].id;
  const r = await api("logs?" + new URLSearchParams({ ...f, limit: 300 }));
  S.logs = more ? [...S.logs, ...r.logs] : r.logs;
  S.logEnd = r.logs.length < 300;                // nothing older to fetch
  return r.logs;
}
const logMatches = (e) => { const f = S.logF; if (f.dec && (f.dec === "bad" ? e.dec === "pass" : e.dec !== f.dec)) return false; if (f.sig && (f.sig === "any" ? !e.sig : e.sig !== f.sig)) return false; if (f.ip && e.ip !== f.ip) return false; if (f.host && e.host !== f.host) return false; if (f.q && !`${e.ip} ${e.host} ${e.path} ${e.ua} ${e.why || ""} ${e.org || ""}`.toLowerCase().includes(f.q.toLowerCase())) return false; return true; };
function logRow(e) {
  return `<tr class="click d-${h(e.dec)} ${S.newIds.has(e.id) ? "new" : ""}" data-act="logrow" data-id="${e.id}">
    <td class="faint mono">${clock(e.t)}</td><td>${decPill(e.dec)}</td><td>${ipBtn(e.ip, e.cc)}${e.dc ? ' <span class="pill dc">hosting</span>' : ""}${e.dev ? ` <span class="pill ok dev" title="${h(devName(e.dev))}: recognized by its device key">${h(devName(e.dev))}</span>` : e.auth ? ' <span class="pill ok">you</span>' : ""}</td>
    <td class="mono">${h(e.m)}</td><td class="mono path" title="${h(e.path)}"><span class="faint">${h((e.host || "").split(".")[0])}</span>${h(e.path)}</td>
    <td class="mono st${String(e.st || 0)[0]}">${e.st || "–"}</td><td class="mono faint">${e.ms != null ? e.ms + "ms" : ""}</td>
    <td>${e.sig ? `<span class="pill ${e.sc === 3 ? "block" : "drop"}">${h(e.sig)}</span>` : ""}</td><td class="why" title="${h(e.org || "")}">${h(e.org || "")}</td></tr>
    ${S.open === e.id ? `<tr class="logdetail"><td colspan="9">${logDetail(e)}</td></tr>` : ""}`;
}
function logDetail(e) {
  const kv = [["Time", new Date(e.t).toISOString()], ["Address", `${e.ip} ${e.cc ? "· " + e.cc : ""}`], ["Network", e.asn ? `AS${e.asn} ${e.org || ""}${e.dc ? " (hosting)" : ""}` : "–"],
    ["Host", `${e.host || "–"}${e.port ? ` (tunnel ${e.port})` : e.main ? " (dashboard)" : ""}`], ["Request", `${e.m} ${e.path}`], ["Status", `${e.st || "–"} · ${fmtB(e.b || 0)}${e.ms != null ? ` · ${e.ms} ms` : ""}${e.ws ? " · WebSocket" : ""}`],
    ["Decision", `${DEC[e.dec]?.[1] || e.dec}${e.why ? ` · ${e.why}` : ""}`], ["Pattern", e.sig ? `${e.sig} (${e.sc === 3 ? "payload" : "probe"})` : "–"], ["Lists", (e.lists || []).join(", ") || "–"],
    ["User agent", e.ua || "–"], ["Referer", e.ref || "–"], ["Language", e.lang || "–"], ["Came via", `${e.via || "–"}${e.ray ? ` · ray ${e.ray}` : ""}${e.proto ? ` · HTTP/${e.proto}` : ""}`],
    ["Signed in", e.auth === undefined ? "not checked" : e.auth ? "yes" : "no"], ["Device", e.dev ? `${devName(e.dev)} (its device key)` : "not one of yours, or never signed in"], ["Log id", `#${e.id}${e.src ? ` · from ${e.src === "aegis-burrow" ? "Aegis's" : "the host's"} history` : ""}`]];
  return `<dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd class="${k === "Request" || k === "User agent" ? "mono" : ""}">${h(v)}</dd>`).join("")}</dl>
    <div class="row" style="margin-top:10px"><button class="btn sm" data-act="ip" data-ip="${h(e.ip)}">This address</button><button class="btn sm ghost" data-act="logf" data-k="ip" data-v="${h(e.ip)}">Only this address</button>${e.host ? `<button class="btn sm ghost" data-act="logf" data-k="host" data-v="${h(e.host)}">Only ${h(e.host)}</button>` : ""}</div>`;
}
function renderLog() {
  const f = S.logF;
  const keep = document.activeElement?.id === "lq" ? $("#lq").selectionStart : null;
  // where the reader is: kept across the repaint (new lines on top don't push it around)
  const sc = $("#logScroll"), top = sc ? sc.scrollTop : 0, tall = sc ? sc.scrollHeight : 0, winY = window.scrollY;
  app.innerHTML = `
    <div class="head"><div><h1>Live log</h1><p>Every request, in full: who, where from, what for, what Bulwark did and why. Click a row for everything; newest on top.</p></div></div>
    <div class="logbar">
      <input class="input" id="lq" placeholder="search address, path, user agent, network…" value="${h(f.q)}" style="flex:1;min-width:200px">
      <select class="input" data-act="logsel" data-k="dec"><option value="">everything</option>${[["bad", "stopped (any)"], ["drop", "payload dropped"], ["block", "blocked"], ["ban", "banned"], ["pass", "let through"]].map(([v, l]) => `<option value="${v}" ${f.dec === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <select class="input" data-act="logsel" data-k="sig"><option value="">any pattern</option><option value="any" ${f.sig === "any" ? "selected" : ""}>attacks only</option>${(S.sigs || []).map((s) => `<option value="${s.id}" ${f.sig === s.id ? "selected" : ""}>${h(s.name)}</option>`).join("")}</select>
      ${f.ip ? `<span class="pill">ip ${h(f.ip)} <a href="#" data-act="logf" data-k="ip" data-v="">✕</a></span>` : ""}${f.host ? `<span class="pill">host ${h(f.host)} <a href="#" data-act="logf" data-k="host" data-v="">✕</a></span>` : ""}
      <button class="btn sm" data-act="pause">${S.paused ? "▶ Resume" : "❚❚ Pause"}</button>
    </div>
    <section class="card" style="padding:6px 8px">${S.logs.length ? `<div class="scroll" id="logScroll" style="max-height:calc(100vh - 230px)"><table class="logtable"><thead><tr><th>Time</th><th></th><th>Address</th><th>Method</th><th>Path</th><th>Status</th><th>Took</th><th>Pattern</th><th>Network</th></tr></thead>
      <tbody id="logBody">${S.logs.map(logRow).join("")}</tbody></table>
      <div class="row" id="logMore" style="justify-content:center;padding:10px">${logMoreBtn()}</div></div>` : '<p class="empty">Nothing matches yet.</p>'}</section>`;
  if (keep !== null) { const i = $("#lq"); i.focus(); i.setSelectionRange(keep, keep); }
  const sc2 = $("#logScroll");
  if (sc2 && top > 0) sc2.scrollTop = top + (sc2.scrollHeight - tall);       // lines that arrived on top push the view down by as much
  if (winY) window.scrollTo(0, winY);
  S.newIds.clear();
}
const logMoreBtn = () => S.logEnd ? `<span class="faint small">That's everything${S.logF.q || S.logF.ip || S.logF.dec || S.logF.sig || S.logF.host ? " that matches" : " kept"} (${fmtN(S.logs.length)} lines).</span>`
  : `<button class="btn sm" data-act="logmore">Load older</button> <span class="faint small">${fmtN(S.logs.length)} shown</span>`;
// older lines go under the ones on screen: nothing is repainted, the view stays where it is
async function logMore(btn) {
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Loading…';
  const before = S.logs.length;
  const got = await loadLog(true);
  const body = $("#logBody");
  if (!body) return renderLog();
  body.insertAdjacentHTML("beforeend", S.logs.slice(before).map(logRow).join(""));
  $("#logMore").innerHTML = logMoreBtn();
  if (!got.length) toast("Nothing older");
}

// ------------------------------------------------------------------ waves
async function loadWaves() { S.alerts = await api("alerts"); }
function alertCard(a) {
  const fc = a.forecast;
  return `<div class="alert ${h(a.sev)} ${a.open ? "" : "closed"}">
    <div class="top"><span class="pill ${SEVP[a.sev]}">${h(a.sev)}</span><span class="pill">${h(a.kind)}</span><span class="title">${h(a.title)}</span><span class="spacer"></span>
      <span class="faint small">${a.open ? `since ${ago(a.first)} · last ${ago(a.last)}` : `closed ${ago(a.closed || a.last)}`}</span>${a.open ? `<button class="btn sm ghost" data-act="dismiss" data-id="${h(a.id)}">Dismiss</button>` : ""}</div>
    <div class="muted">${h(a.detail)}</div>
    ${fc ? `<div class="forecast">Forecast: <b class="${fc.trend === "rising" ? "up" : fc.trend === "falling" ? "down" : ""}">~${fc.nextHour} more addresses in the next hour</b> · ${fc.perHour}/h · ${fc.trend}</div>` : ""}
    ${a.members?.length ? `<div class="members">${a.members.slice(0, 60).map((ip) => `<button data-act="ip" data-ip="${h(ip)}">${h(ip)}</button>`).join("")}${a.members.length > 60 ? `<span class="faint small">+${a.members.length - 60}</span>` : ""}</div>` : ""}
  </div>`;
}
function renderWaves() {
  const A = S.alerts;
  if (!A) { app.innerHTML = '<p class="muted"><span class="spin"></span> Loading…</p>'; return; }
  const open = A.alerts.filter((a) => a.open), closed = A.alerts.filter((a) => !a.open);
  const b = A.baseline || {};
  app.innerHTML = `
    <div class="head"><div><h1>Waves</h1><p>Many addresses moving together: surges against what's normal here, campaigns running the same attack, clusters from one network, and names suddenly found by scanners. Each open wave forecasts what's coming.</p></div></div>
    <div class="grid g4" style="margin-bottom:14px">
      <div class="card stat ${open.some((a) => a.sev === "critical") ? "hot" : open.length ? "warm" : ""}"><b>${open.length}</b><span>open waves</span><div class="sub">${A.alerts.length} on record</div></div>
      <div class="card stat ${A.strictUntil > Date.now() ? "hot" : ""}"><b>${A.strictUntil > Date.now() ? "ON" : "off"}</b><span>strict mode</span><div class="sub">${A.strictUntil > Date.now() ? `a first payload bans · until ${new Date(A.strictUntil).toLocaleTimeString()}` : "turns on during a critical wave"}</div></div>
      <div class="card stat"><b>${b.newIp ? b.newIp.mean.toFixed(1) : "–"}</b><span>new addresses a minute, usually</span><div class="sub">${b.newIp ? `± ${Math.sqrt(b.newIp.var).toFixed(1)} · learned from ${b.newIp.n} min` : "learning"}</div></div>
      <div class="card stat"><b>${b.attacks ? b.attacks.mean.toFixed(1) : "–"}</b><span>attacks a minute, usually</span><div class="sub">${b.attacks ? `± ${Math.sqrt(b.attacks.var).toFixed(1)} · learned from ${b.attacks.n} min` : "learning"}</div></div>
    </div>
    <div class="stack">${open.length ? open.map(alertCard).join("") : '<div class="card empty">No wave right now. Bulwark is watching: surges (z ≥ 4 against the baseline), 3+ addresses running one attack, 3–4+ probing from one network, names found by strangers.</div>'}</div>
    ${closed.length ? `<h3 style="margin:24px 0 10px;font-size:13px" class="muted">Earlier</h3><div class="stack">${closed.slice(0, 40).map(alertCard).join("")}</div>` : ""}`;
}

// ------------------------------------------------------------------ patterns graph
async function renderPatterns() {
  app.innerHTML = `
    <div class="head"><div><h1>Patterns</h1><p>Every stranger that attacked, linked to what it tried, the network it came from and the waves it joined. Drag to move, scroll to zoom, hover to trace, click to open. The layout is kept between visits.</p></div>
      <div class="spacer"></div>${seg("gspan", S.gspan, ["1h", "6h", "24h", "7d", "30d"])}</div>
    <div class="graphwrap" id="gw"><div class="graph-hud"><button class="btn sm" data-act="gzoom" data-v="1.25">+</button><button class="btn sm" data-act="gzoom" data-v="0.8">−</button><button class="btn sm" data-act="gfit">Fit</button></div>
      <div class="graph-legend"><span><i style="background:#9aa3ae"></i>address</span><span><i style="background:#e040fb"></i>banned</span><span><i style="background:#ff5a52"></i>payload pattern</span><span><i style="background:#f2b53c"></i>probe pattern</span><span><i style="background:#46c2ff;border-radius:2px"></i>network</span><span><i style="background:#a78bfa;border-radius:2px"></i>hosting network</span><span><i style="background:#ff6a3d"></i>campaign</span></div></div>`;
  charts.graph = new Graph($("#gw"), { onPick: (n) => { if (n.kind === "ip") openIp(n.label); else openPop(n); } });
  S.gdata = await api(`graph?span=${S.gspan}`);
  charts.graph.set(S.gdata);
}
// A pattern, a network or a campaign, clicked: who's behind it, right here.
function openPop(n) {
  const g = S.gdata || { nodes: [], edges: [] }, byId = new Map(g.nodes.map((x) => [x.id, x]));
  const w = new Map();
  for (const e of g.edges) {
    const other = e.a === n.id ? e.b : e.b === n.id ? e.a : null;
    if (other?.startsWith("ip:")) w.set(other, (w.get(other) || 0) + (e.w || 1));
  }
  const ips = [...w].map(([id, k]) => ({ ...byId.get(id), k })).filter((x) => x.label).sort((a, b) => b.k - a.k || b.n - a.n);
  const banned = ips.filter((x) => x.banned).length;
  const kind = { sig: n.score === 3 ? "payload pattern" : "probe pattern", as: n.dc ? "hosting network" : "network", wave: "campaign" }[n.kind] || n.kind;
  const logBtn = n.kind === "sig" ? `<button class="btn sm ghost" data-act="poplog" data-k="sig" data-v="${h(n.id.slice(4))}">Show its requests in the live log</button>` : "";
  const pop = $("#pop");
  pop.innerHTML = `<div class="pop-card" role="dialog" aria-modal="true" aria-label="${h(n.label)}">
      <div class="row"><div><div class="faint small">${h(kind)} · ${S.gspan}</div><h2>${h(n.label)}</h2></div><span class="spacer"></span><button class="btn sm ghost" data-act="popclose" aria-label="Close">✕</button></div>
      <p class="muted small">${fmtN(ips.length)} address${ips.length === 1 ? "" : "es"}${banned ? ` · <b class="st4">${fmtN(banned)} banned</b>` : ""}${n.kind === "sig" ? ` · ${fmtN(n.w)} request${n.w === 1 ? "" : "s"}` : ""}. Click one for everything about it.</p>
      <div class="scroll pop-list"><table><thead><tr><th>Address</th><th>Network</th><th>${n.kind === "sig" ? "Tries" : "Requests"}</th><th></th></tr></thead><tbody>
        ${ips.map((x) => `<tr class="click" data-act="popip" data-ip="${h(x.label)}"><td>${ipBtn(x.label, x.cc)}</td><td class="why">${h(x.org || "–")}${x.dc ? ' <span class="pill dc">hosting</span>' : ""}</td>
          <td class="mono">${fmtN(n.kind === "sig" ? x.k : x.n)}</td><td>${x.banned ? '<span class="pill ban">banned</span>' : ""}</td></tr>`).join("") || '<tr><td colspan="4" class="empty">Nobody in this window.</td></tr>'}
      </tbody></table></div>
      <div class="row end">${logBtn}<button class="btn sm" data-act="popclose">Close</button></div></div>`;
  pop.hidden = false;
  requestAnimationFrame(() => pop.classList.add("open"));
}
function closePop() { const p = $("#pop"); if (!p || p.hidden) return; p.classList.remove("open"); p.hidden = true; }

// ------------------------------------------------------------------ blocklist
async function loadBl() { S.bl = await api("blocklist"); S.blAt = S.bl.now; }
const SRC = { list: "blocklist", payload: "payloads", lookup: "lookup", manual: "by you", campaign: "campaign" };
const banRow = (b, fresh) => `<tr class="click ${fresh ? "new" : ""}" data-act="ip" data-ip="${h(b.ip)}"><td>${ipBtn(b.ip, b.country)}</td><td class="why" title="${h(b.reason)}">${h(b.reason)}</td><td><span class="pill">${h(SRC[b.source] || b.source)}</span></td>
        <td class="why">${h(b.org || "–")}${b.dc ? ' <span class="pill dc">hosting</span>' : ""}</td><td class="faint">${ago(b.at)}</td><td class="faint">${b.until ? new Date(b.until).toLocaleDateString() : "for good"}</td><td class="mono">${fmtN(b.hits || 0)}</td>
        <td>${b.reported ? '<span class="pill ok">reported</span>' : b.source === "payload" ? '<span class="pill">queued</span>' : '<span class="faint small">known</span>'}</td>
        <td><button class="btn sm" data-act="unban" data-ip="${h(b.ip)}">Unban</button></td></tr>`;
// every 5 s: only the bans that weren't there, put on top
async function blTick() {
  if (S.view !== "addresses" || !S.bl || document.hidden) return;
  const r = await api(`blocklist?since=${S.blAt || 0}`).catch(() => null);
  if (!r) return;
  S.blAt = r.now;
  const known = new Set(S.bl.bans.map((b) => b.ip)), fresh = r.bans.filter((b) => !known.has(b.ip));
  if (!fresh.length) return;
  S.bl.bans = [...fresh, ...S.bl.bans];
  const body = $("#blBody");
  if (!body) { renderBl(); return; }
  body.insertAdjacentHTML("afterbegin", fresh.map((b) => banRow(b, true)).join(""));
  $("#blCount").textContent = S.bl.bans.length;
  $("#banCount").textContent = fmtN(S.bl.bans.length);
}
setInterval(blTick, 5000);
function renderBl() {
  const B = S.bl;
  if (!B) { app.innerHTML = '<p class="muted"><span class="spin"></span> Loading…</p>'; return; }
  app.innerHTML = `
    <div class="head"><div><h1>Blocklist</h1><p>Every address Bulwark has banned, why, and whether the vendors have it. Bans cover every tunnel and the dashboard.</p></div><div class="spacer"></div>
      <div class="row">${["txt", "cidr", "nginx", "iptables", "csv", "json"].map((f) => `<a class="btn sm ghost" href="api/blocklist.txt?format=${f}" target="_blank" rel="noopener">${f}</a>`).join("")}</div></div>
    <div class="row" style="margin-bottom:12px"><input class="input mono" id="banIp" placeholder="ban an address…" style="width:240px"><input class="input" id="banWhy" placeholder="why (optional)" style="flex:1;min-width:160px"><button class="btn danger" data-act="banit">Ban</button></div>
    <section class="card" style="margin-bottom:14px"><h3>Banned <span class="faint" id="blCount">${B.bans.length}</span> <span class="faint small">· new ones appear here within 5 s</span></h3><div class="scroll tall"><table><thead><tr><th>Address</th><th>Why</th><th>By</th><th>Network</th><th>Since</th><th>Until</th><th>Hits</th><th>Vendors</th><th></th></tr></thead><tbody id="blBody">
      ${B.bans.map((b) => banRow(b)).join("")}</tbody></table>${B.bans.length ? "" : '<p class="empty">Nobody is banned.</p>'}</div></section>
    <div class="grid g2">
      <section class="card"><h3>Always allowed</h3><div class="row" style="margin-bottom:10px"><input class="input mono" id="allowIp" placeholder="an address to always let through" style="flex:1"><button class="btn" data-act="allowit">Allow</button></div>
        ${B.allow.length ? `<table><tbody>${B.allow.map((a) => `<tr><td class="mono">${h(a.ip)}</td><td class="faint">${ago(a.at)}</td><td><button class="btn sm ghost" data-act="disallow" data-ip="${h(a.ip)}">Remove</button></td></tr>`).join("")}</tbody></table>` : '<p class="faint small">Nobody yet.</p>'}</section>
      <section class="card"><h3>Yours <span class="faint">signed in, last 30 days: never banned</span></h3>${B.trusted.length ? `<table><tbody>${B.trusted.slice(0, 30).map((t) => `<tr class="click" data-act="ip" data-ip="${h(t.ip)}"><td class="mono">${h(t.ip)}</td><td class="faint">${ago(t.at)}</td></tr>`).join("")}</tbody></table>` : '<p class="faint small">Addresses you sign in from show up here.</p>'}</section>
    </div>`;
}

// ------------------------------------------------------------------ lists
setInterval(async () => { if (S.view === "lists" && !document.hidden) { try { S.lists = await api("lists"); renderLists(); } catch { /* next time */ } } }, 5000);
async function renderLists() {
  S.lists = S.lists || await api("lists");
  const L = S.lists;
  app.innerHTML = `
    <div class="head"><div><h1>Lists</h1><p>${fmtN(L.total)} addresses from ${L.lists.filter((x) => x.loadedNow).length} public blocklists, refreshed every few hours and looked up locally in microseconds, plus a network database of ${fmtN(L.asn.ranges)} ranges.</p></div><div class="spacer"></div><button class="btn" data-act="refreshlists">Update now</button></div>
    <section class="card" style="margin-bottom:14px"><table><thead><tr><th>List</th><th>What</th><th>Counts as</th><th>Addresses</th><th>Updated</th></tr></thead><tbody>
      ${L.lists.map((f) => `<tr><td><b>${h(f.name)}</b><div class="faint small">${h(f.vendor)}</div></td><td class="muted small">${h(f.about)}</td><td><span class="pill ${f.strength === "strong" ? "block" : f.strength === "weak" ? "drop" : ""}">${f.strength === "strong" ? "a ban" : f.strength === "weak" ? "a mark" : "shown"}</span></td>
        <td class="mono">${f.loadedNow ? fmtN(f.count) : "–"}${f.added ? ` <span class="pill ok" title="added since the last full read">+${fmtN(f.added)}</span>` : ""}</td>
        <td class="small ${f.error ? "st5" : "faint"}">${f.error ? h(f.error) : `${f.checked ? `checked ${ago(f.checked)}` : f.at ? ago(f.at) : f.loadedNow ? "from disk" : "downloading…"}${f.addedAt ? ` · new ${ago(f.addedAt)}` : ""}<div class="faint">asked every ${f.poll >= 60e3 ? Math.round(f.poll / 60e3) + " min" : Math.round(f.poll / 1e3) + " s"}</div>`}</td></tr>`).join("")}
      <tr><td><b>iptoasn</b><div class="faint small">networks</div></td><td class="muted small">who holds each address (AS number, name, country), for grouping waves</td><td><span class="pill">info</span></td><td class="mono">${fmtN(L.asn.ranges)}</td><td class="small faint">${L.asn.error ? h(L.asn.error) : L.asn.at ? ago(L.asn.at) : "loading"}</td></tr>
    </tbody></table></section>
    <section class="card" style="margin-bottom:14px"><h3>Just added <span class="faint">checked every 5 s · only addresses that weren't on the list yet</span></h3>${L.adds?.length ? `<table><tbody>${L.adds.slice(0, 20).map((a) => `<tr><td class="faint mono">${ago(a.t)}</td><td>${h((L.lists.find((f) => f.id === a.id) || {}).name || a.id)}</td><td class="mono">+${fmtN(a.n)}</td><td class="mono faint small">${a.sample.map(h).join(", ")}${a.n > a.sample.length ? "…" : ""}</td></tr>`).join("")}</tbody></table>` : '<p class="faint small" style="margin:0">Nothing new since Bulwark started; each source is asked whether it changed as often as it publishes.</p>'}</section>
    <section class="card"><h3>Payload patterns <span class="faint">what Bulwark recognises in a request</span></h3><div class="row">${L.signatures.map((s) => `<span class="pill ${s.score === 3 ? "block" : "drop"}">${h(s.name)}</span>`).join("")}</div>
      <p class="faint small" style="margin:10px 0 0">Red: a payload (looking for secrets or a way in), dropped with a 404 and scored. Amber: a probe for software that isn't here, a mark against the address.</p></section>`;
}

// ------------------------------------------------------------------ vendors
async function renderVendors() {
  const [v, s] = await Promise.all([api("vendors"), api("settings")]);
  app.innerHTML = `
    <div class="head"><div><h1>Vendors</h1><p>Addresses banned for what they did here are checked against every vendor Bulwark can see, and reported to those that missed them, with the requests as evidence (never your host names).</p></div></div>
    <div class="grid g2" style="margin-bottom:14px">
      <section class="card"><h3>AbuseIPDB <span class="faint">reports</span></h3>
        <label class="field"><span>API key (free at abuseipdb.com → Account → API)</span><input class="input mono" id="abKey" placeholder="${s.abuseipdbKey ? h(s.abuseipdbKey) : "paste your key"}" autocomplete="off"></label>
        <div class="row"><button class="btn primary" data-act="savekey">Save</button>${s.abuseipdbKey ? '<button class="btn ghost" data-act="clearkey">Remove</button>' : ""}<span class="spacer"></span>
          <label class="row small muted"><span class="switch"><input type="checkbox" data-act="setting" data-k="report" ${s.report ? "checked" : ""}><i></i></span> report automatically</label></div>
        <p class="faint small" style="margin:10px 0 0">Today: ${v.used?.check || 0} checks, ${v.used?.report || 0} reports (kept under 900 each). ${v.reported} addresses reported in the last 30 days. ${v.queue ? v.queue + " waiting." : ""}</p></section>
      <section class="card"><h3>Who else sees an address</h3><p class="muted small" style="margin-top:0">For every banned address, Bulwark shows which vendors know it: FireHOL, blocklist.de, CINS, Emerging Threats, GreenSnow, IPsum and elsnet (their lists), Spamhaus and DroneBL (DNS), GreyNoise and StopForumSpam (their APIs), and AbuseIPDB. Open any address to see its coverage.</p>
        <p class="faint small">blocklist.de, Spamhaus, GreyNoise and the others don't take reports from a program like this: they collect from their own sensors and partners. AbuseIPDB does, and the lists above read it.</p></section>
    </div>
    <section class="card"><h3>Reports <span class="faint">newest first</span></h3>${v.log?.length ? `<div class="scroll tall"><table><tbody>${v.log.map((x) => `<tr class="click" data-act="ip" data-ip="${h(x.ip)}"><td class="faint mono">${ago(x.at)}</td><td>${ipBtn(x.ip)}</td><td>${h(x.vendor)}</td><td><span class="pill ${x.ok ? (x.skipped ? "" : "ok") : "block"}">${x.ok ? (x.skipped ? "skipped" : "reported") : "failed"}</span></td><td class="why">${h(x.why)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="empty">${s.abuseipdbKey ? "Nothing reported yet." : "Add an AbuseIPDB key to start reporting."}</p>`}</section>`;
}

// ------------------------------------------------------------------ settings
async function renderSettings() {
  const [s, hist] = await Promise.all([api("settings"), api("history").catch(() => null)]);
  const hl = hist?.last;
  const sw = (k, title, sub) => `<div class="switchrow"><div class="grow"><b>${title}</b><span class="muted small">${sub}</span></div><span class="switch"><input type="checkbox" data-act="setting" data-k="${k}" ${s[k] ? "checked" : ""}><i></i></span></div>`;
  app.innerHTML = `
    <div class="head"><div><h1>Settings</h1><p>Bulwark is on by default and stays out of the way: the guard in each host decides in microseconds; nothing here slows a request.</p></div></div>
    <div class="grid g2">
      <section class="card"><h3>Protection</h3>
        ${sw("auto", "Ban automatically", "Strong blocklists, known attackers, two payloads, or a probe from an address with any mark against it.")}
        ${sw("drop", "Drop payloads", "/.env, /.git, ../../etc/passwd, phpunit, ${jndi:…} get a 404 and never reach the app.")}
        ${sw("lookups", "Look up every new address", "Behind the request, never in its way: Spamhaus, DroneBL, StopForumSpam, GreyNoise for probes. Known services (search engines, scrapers) are left alone.")}
        ${sw("strict", "Strict mode during critical waves", "While a critical wave is on, a first payload bans.")}
        ${sw("scanFirst", "Scan before public tunnels", "Someone new gets a \"checking your connection\" page until their address is scanned (about a second; it reloads by itself), and only then the tunnel. With your VPS in front, they never reach this machine before that. Yours (signed in, your devices) pass at once.")}</section>
      <section class="card"><h3>Alerts &amp; logs</h3>
        <label class="field"><span>ntfy topic URL (push to your phone: ntfy.sh/your-secret-topic)</span><input class="input mono" id="sNtfy" value="${h(s.ntfy)}" placeholder="https://ntfy.sh/…"></label>
        <label class="field"><span>Webhook (JSON POST for every wave)</span><input class="input mono" id="sHook" value="${h(s.webhook)}" placeholder="https://…"></label>
        <label class="field"><span>Keep the full request log for (days)</span><input class="input mono" id="sKeep" type="number" min="1" max="365" value="${s.keepDays}" style="width:120px"></label>
        <button class="btn primary" data-act="savealerts">Save</button></section>
      <section class="card"><h3>Your host</h3>
        ${sw("hostNotices", "Warnings on your Aegis dashboard", "Waves and bans show up under the bell on Aegis × Burrow's dashboard (a critical wave as a banner too). One notice a minute at most for bans.")}
        <div class="switchrow"><div class="grow"><b>What the host remembers</b><span class="muted small">Every tunnel's clients and recent requests and the sign-in log, from before Bulwark was there: pulled in when Bulwark connects. Attackers in it are banned by the same rules.${hl ? `<br>Last: ${ago(hl.at)} · ${fmtN(hl.rows)} new lines · ${fmtN(hl.ips)} addresses${hl.banned?.length ? ` · banned ${hl.banned.map(h).join(", ")}` : ""}` : "<br>Not pulled yet."}</span></div>
          <button class="btn sm" data-act="pullhistory">Pull now</button></div></section>
    </div>`;
}

// ------------------------------------------------------------------ your devices
// Every browser that signed in to the host, recognized by its device key (sealed
// by the host, never guessed). Rename and forget go to the host itself.
const underHost = location.pathname.startsWith("/__gate/");
async function loadDevices(quiet) {
  const r = await api("devices");
  S.devices = r.devices; S.devAt = r.at; S.devHost = r.host;
  if (underHost) { try { const g = await (await fetch("/__gate/api/devices")).json(); S.devThis = g.devices?.find((d) => d.this)?.id || null; } catch { /* not signed in here */ } }
  const c = $("#devCount"); if (c) c.textContent = S.devices.length ? S.devices.length : "";
  if (!quiet && S.view === "log") renderLog();
}
const devKind = (d) => /iPhone|Android phone|Android tablet|iPad/.test(d.auto || d.name) ? "phone" : "laptop";
function devCard(d) {
  const ips = d.ips || [];
  return `<section class="card dev-card${d.id === S.devThis ? " this" : ""}">
    <div class="dev-top"><span class="dev-ic">${ICONS[devKind(d)]}</span>
      <div class="grow"><b>${h(d.name)}</b>${d.named ? `<span class="faint small"> · ${h(d.auto)}</span>` : ""}
        <div class="faint small">${d.id === S.devThis ? '<span class="pill ok">this device</span> ' : ""}last seen ${ago(d.last)} · signed in first ${new Date(d.first).toLocaleDateString()}</div></div>
      ${underHost ? `<div class="row"><button class="btn sm ghost" data-act="devname" data-id="${h(d.id)}">Rename</button><button class="btn sm ghost" data-act="devforget" data-id="${h(d.id)}">Forget</button></div>` : ""}</div>
    <div class="dev-ips">${ips.slice(0, 6).map((a) => `<div class="dev-ip">${ipBtn(a.ip, a.cc)}<span class="faint small">${h(a.org || "")}${a.dc ? ' <span class="pill dc">hosting</span>' : ""}</span><span class="faint small mono">${ago(a.last)}</span></div>`).join("")}
      ${ips.length > 6 ? `<div class="faint small">and ${ips.length - 6} more</div>` : ""}</div>
    ${d.hosts?.length ? `<div class="faint small dev-hosts">Opened ${d.hosts.slice(0, 4).map((x) => `<span class="mono">${h(x.host.split(".")[0])}</span>`).join(", ")}${d.hosts.length > 4 ? ` and ${d.hosts.length - 4} more` : ""}</div>` : ""}
  </section>`;
}
function renderDevices() {
  const list = S.devices || [];
  app.innerHTML = `
    <div class="head"><div><h1>Your devices</h1><p>Every browser that signed in to your host, from any address, signed in right now or not.</p></div></div>
    <section class="card dev-how"><div class="dev-how-in">
      <div><b>Recognized for sure</b><span class="muted small">A sign-in gives the browser a device key, sealed by your host. It can't be guessed or copied into another key, and it follows the browser onto your tunnels. Requests carrying it are yours: never dropped, never banned, marked in the live log.</span></div>
      <div><b>The rest is never guessed</b><span class="muted small">A device that never signed in (a phone on your Wi-Fi opening a public tunnel) carries nothing to recognize. No address or browser trick tells it apart for certain, so Bulwark doesn't pretend: the addresses your devices used lately are trusted instead, so nothing on them is banned automatically.</span></div>
    </div></section>
    ${!S.devHost ? '<div class="card muted">No host is connected right now: this is the last list it sent.</div>' : ""}
    ${list.length ? `<div class="grid g2">${list.map(devCard).join("")}</div>` : '<div class="card muted">No device has signed in since your host learned device keys. Sign in once on each device (or sign out and in again) and it shows up here.</div>'}`;
}
async function hostDevices(method, id, body) {
  const r = await fetch(`/__gate/api/devices/${encodeURIComponent(id)}`, { method, headers: { "Content-Type": "application/json", "X-Gate": "1" }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  await post("devices/refresh").catch(() => {});
  await new Promise((res) => setTimeout(res, 600));
  await loadDevices(true); renderDevices();
}

// ------------------------------------------------------------------ one address
async function openIp(ip) {
  const d = $("#drawer"), inn = $("#drawerIn");
  d.classList.add("open"); d.setAttribute("aria-hidden", "false");
  inn.innerHTML = `<h2>${h(ip)}</h2><p class="muted"><span class="spin"></span> Asking everyone about it…</p>`;
  try { S.ip = await api("ip/" + encodeURIComponent(ip)); drawIp(); } catch (e) { inn.innerHTML = `<h2>${h(ip)}</h2><p class="st5">${h(e.message)}</p>`; }
}
function drawIp() {
  const v = S.ip, p = v.profile, a = v.asn, i = v.intel || {}, o = i.owner || {};
  const verdict = i.verdict ? `<span class="pill ${i.verdict.level === "malicious" ? "block" : i.verdict.level === "suspicious" ? "drop" : i.verdict.level === "clean" ? "ok" : ""}">${h(i.verdict.level)}</span>` : "";
  $("#drawerIn").innerHTML = `
    <div class="row"><h2>${flag(p?.cc || a?.cc)} ${h(v.ip)}</h2>${verdict}${v.ban ? '<span class="pill ban">banned</span>' : ""}${v.devices?.length ? '<span class="pill ok">your device</span>' : v.trusted ? '<span class="pill ok">yours</span>' : ""}${v.own ? '<span class="pill drop">this machine</span>' : ""}${v.allowed ? '<span class="pill ok">allowed</span>' : ""}<span class="spacer"></span><button class="btn sm ghost" data-act="closedrawer">✕</button></div>
    <div class="muted">${h([a ? `AS${a.asn} ${a.name}` : o.org, o.city, a?.cc || o.country].filter(Boolean).join(" · "))}${a?.hosting ? ' <span class="pill dc">hosting</span>' : ""}${o.hostname ? ` <span class="mono faint">${h(o.hostname)}</span>` : ""}</div>
    ${i.verdict?.why?.length ? `<div class="row">${i.verdict.why.map((w) => `<span class="pill">${h(w)}</span>`).join("")}</div>` : ""}
    <div class="row">${v.ban ? `<button class="btn" data-act="unban" data-ip="${h(v.ip)}">Unban</button>` : `<button class="btn danger" data-act="ban" data-ip="${h(v.ip)}">Ban</button>`}
      ${v.allowed ? `<button class="btn ghost" data-act="disallow" data-ip="${h(v.ip)}">Stop allowing</button>` : `<button class="btn ghost" data-act="allow" data-ip="${h(v.ip)}">Always allow</button>`}
      <button class="btn ghost" data-act="report" data-ip="${h(v.ip)}">Report to vendors</button><button class="btn ghost" data-act="logf" data-k="ip" data-v="${h(v.ip)}">Its log</button></div>
    ${v.devices?.length ? `<section class="card"><h3>Your devices on it</h3>${v.devices.map((d) => `<div class="row"><a href="#/devices" class="dev-link">${ICONS.device}${h(d.name)}</a><span class="faint small">${ago(d.last)}</span></div>`).join("")}<p class="faint small" style="margin:8px 0 0">Recognized by their device keys, so this address is trusted and never banned automatically.</p></section>` : ""}
    ${v.ban ? `<section class="card"><h3>Banned</h3><dl class="kv"><dt>Why</dt><dd>${h(v.ban.reason)}</dd><dt>By</dt><dd>${h(v.ban.source)}</dd><dt>Since</dt><dd>${new Date(v.ban.at).toLocaleString()}</dd><dt>Until</dt><dd>${v.ban.until ? new Date(v.ban.until).toLocaleString() : "for good"}</dd><dt>Turned away</dt><dd>${fmtN(v.ban.hits || 0)} requests since</dd>${v.ban.lines?.length ? `<dt>Evidence</dt><dd class="mono">${v.ban.lines.map(h).join("<br>")}</dd>` : ""}</dl></section>` : ""}
    <section class="card"><h3>Who knows it <span class="faint">vendors</span></h3><div class="cov">${v.coverage.map((c) => `<div class="${c.knows ? "k" : v.ban ? "miss" : ""}"><span>${h(c.vendor)}</span><span class="pill ${c.knows ? "ok" : ""}" title="${h(c.how)}">${c.knows ? "knows" : "missed"}</span></div>`).join("")}</div></section>
    ${p ? `<section class="card"><h3>Here</h3><dl class="kv"><dt>First seen</dt><dd>${new Date(p.first).toLocaleString()}</dd><dt>Last seen</dt><dd>${ago(p.last)}</dd><dt>Requests</dt><dd>${fmtN(p.n)} · ${fmtB(p.bytes)}</dd>
      <dt>What happened</dt><dd>${Object.entries(p.dec).map(([d, n]) => `${decPill(d)} ${n}`).join(" ")}</dd><dt>Patterns</dt><dd>${Object.entries(p.sigs).map(([s, n]) => `<span class="pill">${h(s)} ×${n}</span>`).join(" ") || "none"}</dd>
      ${p.seq?.length ? `<dt>In order</dt><dd class="mono">${p.seq.map(h).join(" → ")}</dd>` : ""}<dt>Hosts</dt><dd>${Object.entries(p.hosts).map(([x, n]) => `${h(x)} ×${n}`).join(", ") || "–"}</dd>
      <dt>User agents</dt><dd class="mono small">${p.uas.map(h).join("<br>") || "–"}</dd></dl></section>` : '<section class="card muted">Never seen here.</section>'}
    ${v.alerts.length ? `<section class="card"><h3>Waves</h3>${v.alerts.map((x) => `<div class="row"><span class="pill ${SEVP[x.sev]}">${h(x.sev)}</span>${h(x.title)} <span class="faint small">${ago(x.last)}</span></div>`).join("")}</section>` : ""}
    <section class="card"><h3>Lists &amp; lookups</h3><dl class="kv">
      <dt>Blocklists</dt><dd>${v.lists.length ? v.lists.map((l) => `<span class="pill ${l.strength === "strong" ? "block" : l.strength === "weak" ? "drop" : ""}">${h(l.name)}</span>`).join(" ") : "on none"}</dd>
      ${line("GreyNoise", i.sources?.greynoise, (g) => !g?.seen ? "never seen scanning" : [g.classification, g.scanner && "mass scanner", g.benign && "known service", g.name].filter(Boolean).join(", "))}
      ${line("DNS lists", i.sources?.dnsbl, (d) => d?.skipped || Object.entries(d || {}).map(([k, x]) => `${k}: ${x.listed ? "LISTED " + x.why.join("/") : x.error || "clean"}`).join(" · "))}
      ${line("StopForumSpam", i.sources?.sfs, (x) => x?.reports ? `${x.reports} reports` : "no reports")}
      ${line("Shodan", i.sources?.shodan, (x) => !x?.seen ? "nothing indexed" : `ports ${x.ports.join(", ") || "–"}${x.vulns ? ` · ${x.vulns} vulns` : ""}${x.tags.length ? ` · ${x.tags.join(", ")}` : ""}`)}
      ${line("Tor", i.sources?.tor, (x) => x?.skipped || (x?.exit ? "exit node" : "not an exit"))}
      <dt>Networks</dt><dd class="mono">${h(v.net24)} · ${h(v.net16)}</dd></dl></section>
    <section class="card"><h3>Its requests <span class="faint">${v.logs.length}</span></h3>${v.logs.length ? `<div class="scroll" style="max-height:420px"><table class="logtable"><tbody>${v.logs.map((e) => `<tr class="d-${h(e.dec)}"><td class="faint mono">${new Date(e.t).toLocaleString()}</td><td>${decPill(e.dec)}</td><td class="mono path" title="${h(e.path)}">${h(e.m)} ${h(e.path)}</td><td class="mono st${String(e.st || 0)[0]}">${e.st || ""}</td></tr>`).join("")}</tbody></table></div>` : '<p class="faint small">None on record.</p>'}</section>`;
}
const line = (name, x, fmt) => `<dt>${name}</dt><dd>${x?.error ? `<span class="faint">couldn't ask: ${h(x.error)}</span>` : h(fmt(x?.result))}</dd>`;
function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); S.ip = null; }

// ------------------------------------------------------------------ chrome, routing, live
function chrome() {
  const o = S.ov;
  if (!o) return;
  const crit = o.alerts.filter((a) => a.sev === "critical").length, warn = o.alerts.filter((a) => a.sev === "warn").length;
  const wb = $("#waveBadge"); wb.hidden = !(crit + warn); wb.textContent = crit + warn; wb.className = "badge" + (crit ? "" : " warn");
  $("#banCount").textContent = o.bans ? fmtN(o.bans) : "";
  $("#railFoot").innerHTML = `<div><b>${o.sensors.length}</b> ${o.sensors.length === 1 ? "host" : "hosts"} guarded</div><div><b>${fmtN(o.lists.total)}</b> on ${o.lists.loaded} lists</div><div class="faint">v${h(o.version)}</div>`;
}
const VIEWS = { overview: [loadOverview, renderOverview], log: [loadLog, renderLog], waves: [loadWaves, renderWaves], patterns: [null, renderPatterns],
                devices: [loadDevices, renderDevices], addresses: [loadBl, renderBl], lists: [null, renderLists], vendors: [null, renderVendors], settings: [null, renderSettings] };
async function show(view) {
  S.view = VIEWS[view] ? view : "overview";
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("on", a.dataset.v === S.view);
  const [load, render] = VIEWS[S.view];
  charts = {};
  try { if (load) { if (S.view !== "overview" || !S.ov) app.innerHTML = '<p class="muted"><span class="spin"></span> Loading…</p>'; await load(); } await render(); }
  catch (e) { app.innerHTML = `<div class="card"><b class="st5">Couldn't load this.</b> <span class="muted">${h(e.message)}</span></div>`; }
}
// the way back to the host's dashboard, when Bulwark is opened through one (Aegis: /__gate/bulwark/)
if (location.pathname.startsWith("/__gate/")) { const b = $("#backHost"); if (b) b.hidden = false; }
function route() {
  closePop();
  // #/ip/<address> (a notice on the host's dashboard links here): the address, over the overview
  const ip = /^#\/ip\/(.+)$/.exec(location.hash)?.[1];
  if (ip) { if (S.view !== "overview" || !S.ov) show("overview"); openIp(decodeURIComponent(ip)); return; }
  show((location.hash.replace(/^#\/?/, "") || "overview").split("?")[0]);
}
window.addEventListener("hashchange", route);
loadDevices(true).catch(() => {});
setInterval(() => { if (!document.hidden) loadDevices(true).catch(() => {}); }, 60e3);

// refresh what's on screen (not the log: that one is live)
setInterval(async () => {
  if (document.hidden || S.view === "log" || S.view === "patterns" || S.view === "settings" || S.view === "vendors") return;
  try {
    if (S.view === "overview") { await loadOverview(); renderOverview(); }
    else { const o = await api("overview?span=1h"); S.ov = S.ov ? { ...S.ov, alerts: o.alerts, bans: o.bans, sensors: o.sensors, lists: o.lists, version: o.version } : o; chrome();
           if (S.view === "waves") { await loadWaves(); renderWaves(); } }
  } catch { /* the next one */ }
}, 15000);

function live() {
  const es = new EventSource("api/stream");
  es.onopen = () => { S.live = true; $("#liveDot").classList.add("on"); };
  es.onerror = () => { S.live = false; $("#liveDot").classList.remove("on"); };
  let pending = false;
  es.addEventListener("log", (m) => {
    const e = JSON.parse(m.data);
    if (S.view !== "log" || S.paused || !logMatches(e)) return;
    S.logs.unshift(e); S.newIds.add(e.id);
    if (S.logs.length > 6000) S.logs.length = 6000;
    if (!pending) { pending = true; requestAnimationFrame(() => { pending = false; if (S.view === "log" && document.activeElement?.tagName !== "SELECT") renderLog(); }); }
  });
  es.addEventListener("alert", (m) => {
    const { change, alert } = JSON.parse(m.data);
    if (change !== "closed" && alert.sev !== "info") toast(`${alert.sev === "critical" ? "CRITICAL" : "Warning"}: ${alert.title}`);
    if (S.ov) { S.ov.alerts = [alert, ...(S.ov.alerts || []).filter((a) => a.key !== alert.key)].filter((a) => a.open); chrome(); }
  });
}

// ------------------------------------------------------------------ events
document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) {
    if (S.ip && !e.target.closest("#drawer")) closeDrawer();
    else if (e.target.id === "pop") closePop();
    return;
  }
  const act = el.dataset.act, ip = el.dataset.ip;
  if (el.tagName === "A") e.preventDefault();
  try {
    if (act === "span") { S.span = el.dataset.v; localStore("span", S.span); await loadOverview(); renderOverview(); }
    else if (act === "gspan") { S.gspan = el.dataset.v; renderPatterns(); }
    else if (act === "gzoom") charts.graph?.zoom(Number(el.dataset.v));
    else if (act === "gfit") { charts.graph?.fit(); charts.graph?.draw(); }
    else if (act === "ip") { e.stopPropagation(); openIp(ip); }
    else if (act === "closedrawer") closeDrawer();
    else if (act === "devname") {
      const d = S.devices.find((x) => x.id === el.dataset.id), name = prompt("A name for this device (empty: its browser and system)", d?.named ? d.name : "");
      if (name !== null) { await hostDevices("PATCH", el.dataset.id, { name }); toast("Renamed"); }
    }
    else if (act === "devforget") {
      const d = S.devices.find((x) => x.id === el.dataset.id);
      if (confirm(`Forget ${d?.name || "this device"}? Its device key stops working; it's recognized again once it signs in.`)) { await hostDevices("DELETE", el.dataset.id); toast("Forgotten"); }
    }
    else if (act === "logrow") { if (e.target.closest("a")) return; const id = Number(el.dataset.id); S.open = S.open === id ? null : id; renderLog(); }
    else if (act === "logf") { S.logF[el.dataset.k] = el.dataset.v; closeDrawer(); if (location.hash !== "#/log") location.hash = "#/log"; else { await loadLog(); renderLog(); } }
    else if (act === "logmore") await logMore(el);
    else if (act === "popclose") closePop();
    else if (act === "popip") { e.stopPropagation(); openIp(ip); }
    else if (act === "poplog") { const k = el.dataset.k, v = el.dataset.v; closePop(); S.logF = { ...S.logF, [k]: v }; location.hash = "#/log"; }
    else if (act === "pullhistory") { el.disabled = true; el.innerHTML = '<span class="spin"></span> Asking…'; await post("history/pull"); setTimeout(async () => { S.hist = await api("history"); renderSettings(); toast("Pulled"); }, 2500); }
    else if (act === "pause") { S.paused = !S.paused; if (!S.paused) await loadLog(); renderLog(); }
    else if (act === "dismiss") { S.alerts = { ...S.alerts, ...(await post("alerts/close", { id: el.dataset.id })) }; renderWaves(); }
    else if (act === "ban") { await post(`ip/${ip}/ban`, {}); toast(`${ip} banned everywhere`); refreshAfter(ip); }
    else if (act === "unban") { e.stopPropagation(); await post(`ip/${ip}/unban`); toast(`${ip} unbanned`); refreshAfter(ip); }
    else if (act === "allow") { await post(`ip/${ip}/allow`); toast(`${ip} is always let through`); refreshAfter(ip); }
    else if (act === "disallow") { await post(`ip/${ip}/disallow`); toast("Removed"); refreshAfter(ip); }
    else if (act === "report") { await post(`ip/${ip}/report`); toast("Queued for the vendors"); }
    else if (act === "banit") { const x = $("#banIp").value.trim(); if (!x) return; await post(`ip/${encodeURIComponent(x)}/ban`, { reason: $("#banWhy").value.trim() || undefined }); toast(`${x} banned`); await loadBl(); renderBl(); }
    else if (act === "allowit") { const x = $("#allowIp").value.trim(); if (!x) return; await post(`ip/${encodeURIComponent(x)}/allow`); toast(`${x} allowed`); await loadBl(); renderBl(); }
    else if (act === "refreshlists") { el.disabled = true; el.innerHTML = '<span class="spin"></span> Updating…'; S.lists = await post("lists/refresh"); S.lists = await api("lists"); renderLists(); }
    else if (act === "savekey") { await api("settings", { method: "PUT", body: JSON.stringify({ abuseipdbKey: $("#abKey").value.trim() }) }); toast("Saved"); renderVendors(); }
    else if (act === "clearkey") { await api("settings", { method: "PUT", body: JSON.stringify({ abuseipdbKey: "" }) }); toast("Removed"); renderVendors(); }
    else if (act === "savealerts") { await api("settings", { method: "PUT", body: JSON.stringify({ ntfy: $("#sNtfy").value, webhook: $("#sHook").value, keepDays: Number($("#sKeep").value) }) }); toast("Saved"); }
  } catch (ex) { toast(ex.message); }
});
async function refreshAfter(ip) {
  if (S.ip?.ip === ip) { S.ip = await api("ip/" + encodeURIComponent(ip)); drawIp(); }
  if (S.view === "addresses") { await loadBl(); renderBl(); }
}
document.addEventListener("change", async (e) => {
  const el = e.target;
  if (el.dataset.act === "setting") {
    try { await api("settings", { method: "PUT", body: JSON.stringify({ [el.dataset.k]: el.checked }) }); toast("Saved"); } catch (ex) { el.checked = !el.checked; toast(ex.message); }
  } else if (el.dataset.act === "logsel") { S.logF[el.dataset.k] = el.value; await loadLog(); renderLog(); }
});
let qTimer;
document.addEventListener("input", (e) => {
  if (e.target.id !== "lq") return;
  clearTimeout(qTimer); qTimer = setTimeout(async () => { S.logF.q = e.target.value.trim(); await loadLog(); renderLog(); }, 300);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { if (S.ip) closeDrawer(); else closePop(); }
  if (e.key === "Enter" && e.target.id === "banIp") $('[data-act="banit"]').click();
  if (e.key === "Enter" && e.target.id === "allowIp") $('[data-act="allowit"]').click();
});

api("lists").then((l) => { S.sigs = l.signatures; S.lists = l; if (S.view === "overview" && S.series) drawHeat($("#cHeat"), S.series); }).catch(() => {});
live();
route();
