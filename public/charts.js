// Charts on canvas, no libraries. Every chart keeps its scale and layout from
// one refresh to the next (a "stable" picture: nothing jumps when data arrives).

const DPR = () => Math.min(2, window.devicePixelRatio || 1);
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
export const fmtN = (n) => (n == null ? "–" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e4 ? (n / 1e3).toFixed(1) + "k" : Math.round(n).toLocaleString());
const niceMax = (v) => { if (v <= 5) return 5; const p = 10 ** Math.floor(Math.log10(v)); for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p; return 10 * p; };
function fit(canvas, h) {
  const w = canvas.parentElement.clientWidth, d = DPR();
  if (canvas.width !== Math.round(w * d) || canvas.height !== Math.round(h * d)) { canvas.width = Math.round(w * d); canvas.height = Math.round(h * d); canvas.style.height = h + "px"; }
  const ctx = canvas.getContext("2d"); ctx.setTransform(d, 0, 0, d, 0, 0);
  return { ctx, w, h };
}
const timeLabel = (t, step) => {
  const d = new Date(t);
  return step >= 86400e3 ? d.toLocaleDateString([], { month: "short", day: "numeric" })
    : step >= 3600e3 ? d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" })
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

// ------------------------------------------------------------------ the big time chart
// series: [{key, label, color}] stacked as bars; line: {key, label, color} drawn over (own axis)
export class TimeChart {
  constructor(el, { height = 300, series, line }) {
    this.el = el; this.height = height; this.series = series; this.line = line;
    el.classList.add("chart");
    el.innerHTML = '<canvas></canvas><div class="tip"></div>';
    this.canvas = el.querySelector("canvas"); this.tip = el.querySelector(".tip");
    this.hover = -1; this.max = 0; this.lmax = 0;
    this.canvas.addEventListener("mousemove", (e) => { const r = this.canvas.getBoundingClientRect(); this.pick(e.clientX - r.left); });
    this.canvas.addEventListener("mouseleave", () => { this.hover = -1; this.tip.style.display = "none"; this.draw(); });
    new ResizeObserver(() => this.draw()).observe(el);
  }
  set(data) {
    this.data = data;
    const peak = Math.max(1, ...data.points.map((p) => this.series.reduce((a, s) => a + (p[s.key] || 0), 0)));
    const lpeak = this.line ? Math.max(1, ...data.points.map((p) => p[this.line.key] || 0)) : 1;
    // the scale only grows quickly, and shrinks slowly: steady from one refresh to the next
    this.max = niceMax(peak > this.max || peak < this.max * 0.4 ? peak : this.max);
    this.lmax = niceMax(lpeak > this.lmax || lpeak < this.lmax * 0.4 ? lpeak : this.lmax);
    this.draw();
  }
  geom() { const { w } = { w: this.canvas.parentElement.clientWidth }; return { L: 44, R: this.line ? 44 : 12, T: 10, B: 26, w }; }
  pick(x) {
    if (!this.data) return;
    const { L, R, w } = this.geom(), n = this.data.points.length, bw = (w - L - R) / n;
    const i = Math.floor((x - L) / bw);
    this.hover = i >= 0 && i < n ? i : -1;
    this.draw();
    if (this.hover < 0) { this.tip.style.display = "none"; return; }
    const p = this.data.points[i];
    this.tip.innerHTML = `<div class="t">${new Date(p.t).toLocaleString()}</div>` +
      [...this.series].reverse().map((s) => `<div class="r"><span><i style="background:${s.color}"></i>${s.label}</span><b>${fmtN(p[s.key] || 0)}</b></div>`).join("") +
      (this.line ? `<div class="r"><span><i style="background:${this.line.color}"></i>${this.line.label}</span><b>${fmtN(p[this.line.key] || 0)}</b></div>` : "");
    this.tip.style.display = "block";
    const tx = L + (i + 0.5) * bw;
    this.tip.style.left = Math.min(w - this.tip.offsetWidth - 4, Math.max(4, tx + 12)) + "px";
    this.tip.style.top = "8px";
  }
  draw() {
    if (!this.data) return;
    const { ctx, w, h } = fit(this.canvas, this.height);
    const { L, R, T, B } = this.geom(), pts = this.data.points, n = pts.length;
    const ih = h - T - B, iw = w - L - R, bw = iw / n;
    ctx.clearRect(0, 0, w, h);
    ctx.font = "11px ui-monospace, Menlo, monospace"; ctx.textBaseline = "middle";
    // grid
    for (let g = 0; g <= 4; g++) {
      const y = T + ih - (ih * g) / 4;
      ctx.strokeStyle = g ? "rgba(255,255,255,.05)" : "rgba(255,255,255,.12)"; ctx.beginPath(); ctx.moveTo(L, y + 0.5); ctx.lineTo(w - R, y + 0.5); ctx.stroke();
      ctx.fillStyle = "#5b616a"; ctx.textAlign = "right"; ctx.fillText(fmtN((this.max * g) / 4), L - 8, y);
      if (this.line) { ctx.textAlign = "left"; ctx.fillStyle = this.line.color + "aa"; ctx.fillText(fmtN((this.lmax * g) / 4), w - R + 8, y); }
    }
    // hover column
    if (this.hover >= 0) { ctx.fillStyle = "rgba(255,255,255,.05)"; ctx.fillRect(L + this.hover * bw, T, bw, ih); }
    // stacked bars
    const gap = bw > 6 ? 1 : 0;
    for (let i = 0; i < n; i++) {
      let y = T + ih;
      for (const s of this.series) {
        const v = pts[i][s.key] || 0;
        if (!v) continue;
        const hh = (v / this.max) * ih;
        ctx.fillStyle = s.color;
        ctx.fillRect(L + i * bw + gap / 2, y - hh, Math.max(1, bw - gap), hh);
        y -= hh;
      }
    }
    // the line
    if (this.line) {
      ctx.strokeStyle = this.line.color; ctx.lineWidth = 1.8; ctx.lineJoin = "round"; ctx.beginPath();
      pts.forEach((p, i) => { const x = L + (i + 0.5) * bw, y = T + ih - ((p[this.line.key] || 0) / this.lmax) * ih; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.stroke(); ctx.lineWidth = 1;
      const grad = ctx.createLinearGradient(0, T, 0, T + ih); grad.addColorStop(0, this.line.color + "33"); grad.addColorStop(1, this.line.color + "00");
      ctx.lineTo(L + (n - 0.5) * bw, T + ih); ctx.lineTo(L + 0.5 * bw, T + ih); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
    }
    // time axis
    ctx.fillStyle = "#5b616a"; ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 90))));
    for (let i = 0; i < n; i += every) ctx.fillText(timeLabel(pts[i].t, this.data.step), L + (i + 0.5) * bw, h - 8);
  }
}

// ------------------------------------------------------------------ patterns over time (heatmap)
export class Heatmap {
  constructor(el, { height = 260, onPick } = {}) {
    this.el = el; this.height = height; this.onPick = onPick;
    el.classList.add("chart");
    el.innerHTML = '<canvas></canvas><div class="tip"></div>';
    this.canvas = el.querySelector("canvas"); this.tip = el.querySelector(".tip");
    this.canvas.addEventListener("mousemove", (e) => this.move(e));
    this.canvas.addEventListener("mouseleave", () => { this.tip.style.display = "none"; });
    new ResizeObserver(() => this.draw()).observe(el);
  }
  // data: {step, points}, rows: [{id, name, score}]
  set(data, rows) { this.data = data; this.rows = rows; this.draw(); }
  layout() { const w = this.canvas.parentElement.clientWidth, rows = this.rows.length || 1; return { L: Math.min(210, w * 0.32), T: 4, w, rh: Math.max(16, Math.min(26, (this.height - 30) / rows)) }; }
  draw() {
    if (!this.data || !this.rows) return;
    const g = this.layout(), h = Math.max(80, g.rh * this.rows.length + 30);
    const { ctx, w } = fit(this.canvas, h);
    ctx.clearRect(0, 0, w, h);
    const pts = this.data.points, n = pts.length, cw = (w - g.L - 6) / n;
    let max = 1;
    for (const p of pts) for (const r of this.rows) max = Math.max(max, p.sig[r.id] || 0);
    ctx.font = "12px Inter, system-ui, sans-serif"; ctx.textBaseline = "middle";
    this.rows.forEach((r, j) => {
      const y = g.T + j * g.rh;
      ctx.fillStyle = r.score === 3 ? "#ff8a84" : "#f2c46b"; ctx.textAlign = "right";
      ctx.fillText(r.name.length > 30 ? r.name.slice(0, 29) + "…" : r.name, g.L - 10, y + g.rh / 2);
      for (let i = 0; i < n; i++) {
        const v = pts[i].sig[r.id] || 0;
        ctx.fillStyle = v ? (r.score === 3 ? `rgba(255,90,82,${0.18 + 0.82 * Math.sqrt(v / max)})` : `rgba(242,181,60,${0.15 + 0.85 * Math.sqrt(v / max)})`) : "rgba(255,255,255,.025)";
        ctx.fillRect(g.L + i * cw + 0.5, y + 1.5, Math.max(1, cw - 1), g.rh - 3);
      }
    });
    ctx.fillStyle = "#5b616a"; ctx.textAlign = "center"; ctx.font = "11px ui-monospace, Menlo, monospace";
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((w - g.L) / 90))));
    for (let i = 0; i < n; i += every) ctx.fillText(timeLabel(pts[i].t, this.data.step), g.L + (i + 0.5) * cw, h - 10);
  }
  move(e) {
    if (!this.data) return;
    const r = this.canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top, g = this.layout();
    const n = this.data.points.length, cw = (g.w - g.L - 6) / n, i = Math.floor((x - g.L) / cw), j = Math.floor((y - g.T) / g.rh);
    const row = this.rows[j], p = this.data.points[i];
    if (!row || !p) { this.tip.style.display = "none"; return; }
    this.tip.innerHTML = `<div class="t">${new Date(p.t).toLocaleString()}</div><div class="r"><span>${row.name}</span><b>${fmtN(p.sig[row.id] || 0)}</b></div>`;
    this.tip.style.display = "block";
    this.tip.style.left = Math.min(g.w - this.tip.offsetWidth - 4, x + 14) + "px"; this.tip.style.top = Math.max(4, y - 10) + "px";
  }
}

// ------------------------------------------------------------------ the flow (Patterns)
// Who tried what, as a flow: networks on the left, patterns on the right
// (payloads, then probes, each a labeled group), and a ribbon for every
// network → pattern pair, as thick as the addresses behind it. A fixed layout:
// nothing moves, nothing overlaps, every node is labeled with its count.
// Hover a node or a ribbon to trace it; click a node to see its addresses.
// data: {nets: [{id, org, dc, ips, banned, other?}], sigs: [{id, name, score, ips, banned, other?}], links: [{a, b, ips, requests}]}
const NS = "http://www.w3.org/2000/svg";
const PAY = "#ff5a52", PROBE = "#f2b53c", NET = "#9aa3ae";
const kindColor = (n) => (n.score === 3 ? PAY : PROBE);
// "TECHTIES-AS - TechTies Inc." -> "TechTies Inc."; "GOOGLE-CLOUD-PLATFORM" stays
export const netName = (org) => { const m = /^[A-Z0-9_.-]+ - (.+)$/.exec(String(org || "")); return (m ? m[1] : String(org || "")).trim() || "unknown network"; };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export class Flow {
  constructor(el, { onPick } = {}) {
    this.el = el; this.onPick = onPick;
    el.classList.add("flow");
    el.innerHTML = '<svg role="img"></svg><div class="tip"></div>';
    this.svg = el.querySelector("svg"); this.tip = el.querySelector(".tip");
    this.ro = new ResizeObserver(() => { if (this.data && Math.abs(this.el.clientWidth - (this.w || 0)) > 2) this.draw(); });
    this.ro.observe(el);
    this.svg.addEventListener("mousemove", (e) => this.hover(e));
    this.svg.addEventListener("mouseleave", () => this.focus(null));
    this.svg.addEventListener("click", (e) => { const n = e.target.closest("[data-node]"); if (n) this.onPick?.(this.byId.get(n.dataset.node)); });
    this.svg.addEventListener("keydown", (e) => { const n = e.target.closest("[data-node]"); if (n && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); this.onPick?.(this.byId.get(n.dataset.node)); } });
    this.svg.addEventListener("focusin", (e) => { const n = e.target.closest("[data-node]"); if (n) this.focus({ node: n.dataset.node }); });
  }
  set(data) { this.data = data; this.draw(); }
  destroy() { this.ro.disconnect(); }
  draw() {
    const d = this.data;
    this.focused = null; this.svg.classList.remove("dim"); this.tip.style.opacity = 0;
    const W = this.w = this.el.clientWidth, narrow = W < 640;
    // only what has ribbons (an address banned without a pattern has no pattern to point at)
    const used = new Set(d.links.flatMap((l) => [l.a, l.b]));
    const nets = d.nets.filter((n) => used.has(n.id)), pays = d.sigs.filter((x) => used.has(x.id) && x.score === 3), probes = d.sigs.filter((x) => used.has(x.id) && x.score !== 3);
    this.byId = new Map([...nets, ...pays, ...probes].map((n) => [n.id, n]));
    const out = new Map(), inn = new Map();
    for (const l of d.links) { out.set(l.a, (out.get(l.a) || 0) + l.ips); inn.set(l.b, (inn.get(l.b) || 0) + l.ips); }
    if (!nets.length) { this.svg.setAttribute("viewBox", `0 0 ${W} 120`); this.svg.style.height = "120px"; this.svg.innerHTML = `<text x="${W / 2}" y="64" text-anchor="middle" class="fl-empty">No attacks in this window.</text>`; return; }
    // geometry: a column of bars each side, labels outside them
    const labW = narrow ? Math.min(132, W * 0.34) : Math.min(250, W * 0.27), barW = 10, top = 34, gap = narrow ? 14 : 12, groupGap = 44, minH = 4;
    const xL = labW, xR = W - labW - barW;
    const total = d.links.reduce((a, l) => a + l.ips, 0);
    const rowsL = nets.length, rowsR = pays.length + probes.length;
    const avail = Math.max(260, Math.min(560, Math.max(rowsL, rowsR) * 34));
    const k = Math.max(0.5, (avail - Math.max(rowsL, rowsR) * gap) / Math.max(1, total));
    const place = (list, size, y0, slot = 30) => {
      let y = y0;
      for (const n of list) { n._h = Math.max(minH, size(n) * k); n._y = y; y += Math.max(n._h, slot) + gap; }
      return y;
    };
    let endL = place(nets, (n) => out.get(n.id) || 0, top);
    let y = place(pays, (n) => inn.get(n.id) || 0, top);
    const probeTop = pays.length ? y + groupGap - gap : top;
    let endR = place(probes, (n) => inn.get(n.id) || 0, probeTop);
    // the shorter column sits in the middle of the taller one
    const shift = (list, dy) => { for (const n of list) n._y += dy; };
    if (endL < endR) { const dy = (endR - endL) / 2; shift(nets, dy); endL += dy; }
    else if (endR < endL) { const dy = (endL - endR) / 2; shift(pays, dy); shift(probes, dy); endR += dy; this._probeShift = dy; }
    const H = Math.max(endL, endR) + 6;
    for (const n of nets) n._x = xL;
    for (const n of [...pays, ...probes]) n._x = xR;
    // ribbons, stacked on each bar in the order of the other end (fewer crossings)
    const links = d.links.filter((l) => this.byId.has(l.a) && this.byId.has(l.b)).map((l) => ({ ...l, A: this.byId.get(l.a), B: this.byId.get(l.b), t: l.ips * k }));
    const offA = new Map(), offB = new Map();
    for (const l of [...links].sort((p, q) => p.B._y - q.B._y)) { const o = offA.get(l.a) || 0; l.ya = l.A._y + o; offA.set(l.a, o + l.t); }
    for (const l of [...links].sort((p, q) => p.A._y - q.A._y)) { const o = offB.get(l.b) || 0; l.yb = l.B._y + o; offB.set(l.b, o + l.t); }
    // a node shorter than its ribbons (the 4px floor) stretches them: center them on it instead
    for (const n of this.byId.values()) {
      const sum = (n._x === xL ? out.get(n.id) : inn.get(n.id)) * k;
      if (n._h > sum) { const pad = (n._h - sum) / 2; for (const l of links) { if (l.A === n) l.ya += pad; if (l.B === n) l.yb += pad; } }
    }
    const x0 = xL + barW, x1 = xR, mx = (x0 + x1) / 2;
    const ribbon = (l) => { const t = Math.max(1, l.t); return `M${x0},${l.ya}C${mx},${l.ya} ${mx},${l.yb} ${x1},${l.yb}L${x1},${l.yb + t}C${mx},${l.yb + t} ${mx},${l.ya + t} ${x0},${l.ya + t}Z`; };
    this.links = links;
    const fit = (s, px) => { const max = Math.floor(px / 6.6); return s.length > max ? s.slice(0, Math.max(4, max - 1)) + "…" : s; };
    const label = (n, side) => {
      const cy = n._y + Math.max(n._h, 14) / 2, name = n.org ? (n.other ? n.org : netName(n.org)) : n.name;
      const count = `${fmtN(n.ips)}${narrow ? "" : n.ips === 1 ? " address" : " addresses"}${n.banned && !narrow ? ` · ${fmtN(n.banned)} banned` : ""}`;
      const tx = side === "L" ? xL - 10 : xR + barW + 10, anchor = side === "L" ? "end" : "start";
      const tag = n.dc && !narrow ? '<tspan class="fl-tag" dx="6">hosting</tspan>' : "";
      return `<text x="${tx}" y="${cy - 2}" text-anchor="${anchor}" class="fl-name${n.other ? " other" : ""}" data-max="${labW - 16 - (tag ? 52 : 0)}" data-full="${esc(name)}">${esc(fit(name, labW - 16))}${tag}</text>
        <text x="${tx}" y="${cy + 12}" text-anchor="${anchor}" class="fl-count">${count}</text>`;
    };
    const bar = (n, color) => `<g class="fl-node" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc((n.org || n.name) + ": " + n.ips + " addresses")}">
        <rect class="fl-hit" x="${n._x === xL ? 0 : xR - 6}" y="${n._y - 4}" width="${labW + barW + 6}" height="${Math.max(n._h, 26) + 8}"></rect>
        <rect class="fl-bar${n.other ? " other" : ""}" x="${n._x}" y="${n._y}" width="${barW}" height="${n._h}" rx="3" fill="${color}"></rect>
        ${label(n, n._x === xL ? "L" : "R")}</g>`;
    const head = (x, yy, text, anchor) => `<text x="${x}" y="${yy}" text-anchor="${anchor}" class="fl-head">${text}</text>`;
    this.svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    this.svg.style.height = H + "px";
    this.svg.setAttribute("aria-label", `Who tried what: ${nets.length} networks, ${pays.length + probes.length} patterns`);
    this.svg.innerHTML = `
      ${head(xL + barW, 14, "NETWORKS", "end")}
      ${pays.length ? head(xR, (pays[0]?._y ?? top) - 20, "PAYLOADS", "start") : ""}${probes.length ? head(xR, probes[0]._y - 14, "PROBES", "start") : ""}
      <g class="fl-links">${links.map((l, i) => `<path d="${ribbon(l)}" fill="${kindColor(l.B)}" data-link="${i}" class="fl-link"></path>`).join("")}</g>
      ${nets.map((n) => bar(n, NET)).join("")}
      ${pays.map((n) => bar(n, PAY)).join("")}${probes.map((n) => bar(n, PROBE)).join("")}`;
    // names cut to the room they have, measured (the estimate above is only a first guess)
    for (const t of this.svg.querySelectorAll(".fl-name")) {
      const max = Number(t.dataset.max), first = t.firstChild;
      if (!first || first.nodeType !== 3 || !(max > 0)) continue;
      let txt = t.dataset.full;
      first.textContent = txt;
      const width = () => (t.querySelector(".fl-tag") ? t.getComputedTextLength() - t.querySelector(".fl-tag").getComputedTextLength() : t.getComputedTextLength());
      while (txt.length > 4 && width() > max) { txt = txt.slice(0, -1); first.textContent = txt.trimEnd() + "…"; }
    }
  }
  // light up one node (and everything it touches) or one ribbon; dim the rest
  focus(f) {
    const key = f ? (f.node || `l${f.link}`) : null;
    if (key === this.focused) return;
    this.focused = key;
    this.svg.classList.toggle("dim", !!f);
    const hot = new Set();
    for (const [i, l] of (this.links || []).entries()) {
      const on = f && (f.link === i || l.a === f.node || l.b === f.node);
      this.svg.querySelector(`[data-link="${i}"]`)?.classList.toggle("on", !!on);
      if (on) { hot.add(l.a); hot.add(l.b); }
    }
    for (const g of this.svg.querySelectorAll("[data-node]")) g.classList.toggle("on", hot.has(g.dataset.node) || g.dataset.node === f?.node);
    if (!f) this.tip.style.opacity = 0;
  }
  hover(e) {
    const r = this.el.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    const nodeEl = e.target.closest("[data-node]"), linkEl = e.target.closest("[data-link]");
    let html = null;
    if (nodeEl) {
      const n = this.byId.get(nodeEl.dataset.node);
      this.focus({ node: n.id });
      const kind = n.score === undefined ? (n.other ? "networks" : n.dc ? "hosting network" : "network") : n.score === 3 ? "payload pattern" : "probe pattern";
      html = `<b>${esc(n.org || n.name)}</b><span>${kind}${n.asn ? ` · AS${n.asn}` : ""}</span><span>${fmtN(n.ips)} addresses · ${fmtN(n.banned || 0)} banned · ${fmtN(n.requests)} requests</span><em>Click for the addresses</em>`;
    } else if (linkEl) {
      const l = this.links[Number(linkEl.dataset.link)];
      this.focus({ link: Number(linkEl.dataset.link) });
      html = `<b>${esc(l.A.other ? l.A.org : netName(l.A.org))} → ${esc(l.B.name)}</b><span>${fmtN(l.ips)} address${l.ips === 1 ? "" : "es"} · ${fmtN(l.requests)} request${l.requests === 1 ? "" : "s"}</span>`;
    } else this.focus(null);
    if (!html) return;
    this.tip.innerHTML = html;
    this.tip.style.opacity = 1;
    const tw = this.tip.offsetWidth, th = this.tip.offsetHeight;
    this.tip.style.left = Math.max(4, Math.min(r.width - tw - 4, x + 14)) + "px";
    this.tip.style.top = Math.max(4, y - th - 10) + "px";
  }
}
