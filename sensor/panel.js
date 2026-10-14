// Bulwark's panel on the Burrow page. The host calls card(ctx) on every paint
// (synchronous, from what was last fetched) and wire(el, ctx) after it.
// ctx.api talks to /__gate/api/x/bulwark/…, which the extension proxies to the app.

const S = { ov: null, sensor: null, at: 0, loading: false, error: null };
const LOGO = '<svg viewBox="0 0 64 64" fill="none"><defs><linearGradient id="bwg" x1="10" y1="6" x2="54" y2="58" gradientUnits="userSpaceOnUse"><stop stop-color="#ff7a45"/><stop offset="1" stop-color="#e5384f"/></linearGradient></defs><path d="M32 4 9 12v17c0 14.6 9.7 26.6 23 31 13.3-4.4 23-16.4 23-31V12L32 4Z" fill="url(#bwg)"/><path d="M20 22v8c0 8 5 14.6 12 17.4 7-2.8 12-9.4 12-17.4v-8M20 22h5v4h4.7v-4h4.6v4H39v-4h5" stroke="#16080a" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" opacity=".88"/></svg>';

const style = document.createElement("style");
style.textContent = `
.bw { padding:0; overflow:hidden; border-color:rgba(255,106,61,.25); background:radial-gradient(120% 140% at 0% 0%, rgba(255,106,61,.07), transparent 55%), var(--card,#0f1012); margin-bottom:14px; }
.bw-head { display:flex; align-items:center; gap:13px; padding:16px 18px; }
.bw-logo { width:34px; height:34px; flex:none; }
.bw-head .grow { flex:1; min-width:0; }
.bw-name { font-weight:650; letter-spacing:-.01em; display:flex; gap:8px; align-items:center; }
.bw-sub { color:var(--muted); font-size:12.5px; }
.bw-stats { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line); border-top:1px solid var(--line); }
.bw-stat { background:var(--card,#0f1012); padding:11px 16px; }
.bw-stat b { font-size:17px; font-weight:700; display:block; letter-spacing:-.02em; }
.bw-stat b.hot { color:#ff5a52; }
.bw-stat span { font-size:11px; color:var(--faint); text-transform:uppercase; letter-spacing:.05em; }
.bw-alert { display:flex; gap:10px; align-items:center; padding:10px 18px; border-top:1px solid rgba(255,90,82,.3); background:rgba(255,90,82,.07); font-size:13px; }
.bw-alert.warn { border-color:rgba(242,181,60,.3); background:rgba(242,181,60,.06); }
@media (max-width:700px){ .bw-stats{grid-template-columns:repeat(2,1fr);} }`;
document.head.appendChild(style);

const fmt = (n) => (n == null ? "–" : n >= 1e4 ? (n / 1e3).toFixed(1) + "k" : Math.round(n).toLocaleString());

function load(ctx) {
  if (S.loading || Date.now() - S.at < 15000) return;
  S.loading = true;
  Promise.all([ctx.api("/overview").catch((e) => ({ error: e.message })), ctx.api("/sensor").catch(() => null)])
    .then(([ov, sensor]) => { S.ov = ov.error ? null : ov; S.error = ov.error || null; S.sensor = sensor; S.at = Date.now(); })
    .finally(() => { S.loading = false; ctx.render(); });
}

export function card(ctx) {
  load(ctx);
  const o = S.ov, s = S.sensor, h = ctx.h;
  const t = o?.totals || {}, stopped = (t.drop || 0) + (t.block || 0) + (t.ban || 0);
  const alert = (o?.alerts || []).find((a) => a.sev !== "info");
  const sub = S.error ? `The app isn't answering (${h(S.error)}). The guard inside Burrow keeps enforcing bans and blocklists.`
    : !o ? "Starting…"
    : `Every request checked in ${s?.stats?.requests ? (s.stats.us / s.stats.requests).toFixed(1) : "–"} µs · ${fmt(o.lists.total)} addresses on ${o.lists.loaded} lists${s && !s.connected ? " · guard reconnecting" : ""}`;
  return `<section class="card bw">
    <div class="bw-head"><div class="bw-logo">${LOGO}</div>
      <div class="grow"><div class="bw-name">Bulwark ${o ? `<span class="pill">v${h(o.version)}</span>` : ""}${o?.strictUntil > Date.now() ? '<span class="pill err">strict</span>' : ""}</div><div class="bw-sub">${sub}</div></div>
      <a class="btn sm primary" href="/__gate/bulwark/" target="_blank" rel="noopener">Open Bulwark</a></div>
    ${alert ? `<div class="bw-alert ${alert.sev === "critical" ? "" : "warn"}"><span class="pill ${alert.sev === "critical" ? "err" : "warn"}">${h(alert.sev)}</span><b>${h(alert.title)}</b><span class="faint">${h(alert.detail)}</span></div>` : ""}
    ${o ? `<div class="bw-stats">
      <div class="bw-stat"><b>${fmt(t.req || 0)}</b><span>requests · 24 h</span></div>
      <div class="bw-stat"><b class="${stopped ? "hot" : ""}">${fmt(stopped)}</b><span>stopped</span></div>
      <div class="bw-stat"><b>${fmt(o.bans)}</b><span>banned now</span></div>
      <div class="bw-stat"><b class="${(o.alerts || []).some((a) => a.sev === "critical") ? "hot" : ""}">${(o.alerts || []).length}</b><span>open waves</span></div>
    </div>` : ""}
  </section>`;
}
export function wire() { /* links only */ }
