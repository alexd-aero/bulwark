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

// ------------------------------------------------------------------ the patterns graph
// Addresses linked to the patterns they used, the networks they come from and
// the waves they belong to. Positions are kept (here and in localStorage), so a
// refresh only places what is new, next to what it is linked to: the picture stays.
const COLORS = { ip: "#9aa3ae", ipBan: "#e040fb", sig3: "#ff5a52", sig1: "#f2b53c", as: "#46c2ff", asDc: "#a78bfa", wave: "#ff6a3d" };
const hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967295; };
export class Graph {
  constructor(el, { onPick } = {}) {
    this.el = el; this.onPick = onPick;
    this.canvas = document.createElement("canvas"); el.appendChild(this.canvas);
    this.pos = new Map();
    try { for (const [k, v] of JSON.parse(localStorage.getItem("bulwark-graph") || "[]")) this.pos.set(k, v); } catch { /* fresh */ }
    this.view = { x: 0, y: 0, k: 1 }; this.hover = null; this.nodes = []; this.edges = [];
    this.wire();
    new ResizeObserver(() => this.draw()).observe(el);
  }
  color(n) { return n.kind === "ip" ? (n.banned ? COLORS.ipBan : COLORS.ip) : n.kind === "sig" ? (n.score === 3 ? COLORS.sig3 : COLORS.sig1) : n.kind === "as" ? (n.dc ? COLORS.asDc : COLORS.as) : COLORS.wave; }
  radius(n) { const base = n.kind === "ip" ? 3.5 : n.kind === "sig" ? 8 : n.kind === "wave" ? 10 : 6; return base + Math.min(n.kind === "ip" ? 6 : 16, Math.sqrt(n.w || 1) * (n.kind === "ip" ? 0.5 : 1.2)); }
  set({ nodes, edges }) {
    this.nodes = nodes; this.edges = edges;
    const byId = new Map(nodes.map((n) => [n.id, n]));
    // place new nodes: next to a placed neighbour, else on a ring by kind (deterministic)
    const nb = new Map();
    for (const e of edges) { (nb.get(e.a) || nb.set(e.a, []).get(e.a)).push(e.b); (nb.get(e.b) || nb.set(e.b, []).get(e.b)).push(e.a); }
    const ring = { sig: 160, wave: 60, as: 330, ip: 250 };
    for (const n of nodes) {
      if (this.pos.has(n.id)) continue;
      const near = (nb.get(n.id) || []).map((id) => this.pos.get(id)).find(Boolean);
      const a = hash(n.id) * Math.PI * 2, r = ring[n.kind] || 200;
      this.pos.set(n.id, near ? { x: near.x + Math.cos(a) * 40, y: near.y + Math.sin(a) * 40 } : { x: Math.cos(a) * r, y: Math.sin(a) * r });
    }
    // settle: a fixed number of steps from where things were (same input, same picture)
    const P = (id) => this.pos.get(id);
    for (let it = 0; it < 220; it++) {
      const cool = 1 - it / 220;
      const f = new Map(nodes.map((n) => [n.id, { x: 0, y: 0 }]));
      for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
        const a = P(nodes[i].id), b = P(nodes[j].id);
        let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01;
        if (d2 > 90000) continue;
        const rep = 900 / d2, fa = f.get(nodes[i].id), fb = f.get(nodes[j].id);
        fa.x += dx * rep; fa.y += dy * rep; fb.x -= dx * rep; fb.y -= dy * rep;
      }
      for (const e of edges) {
        const a = P(e.a), b = P(e.b);
        if (!a || !b) continue;
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01;
        const want = byId.get(e.a)?.kind === "ip" && byId.get(e.b)?.kind === "as" ? 55 : 80;
        const k = (d - want) * 0.012 * Math.min(3, 1 + Math.log1p(e.w || 1) * 0.3);
        const fa = f.get(e.a), fb = f.get(e.b);
        if (fa) { fa.x += (dx / d) * k * d * 0.05; fa.y += (dy / d) * k * d * 0.05; }
        if (fb) { fb.x -= (dx / d) * k * d * 0.05; fb.y -= (dy / d) * k * d * 0.05; }
      }
      for (const n of nodes) {
        const p = P(n.id), v = f.get(n.id);
        v.x -= p.x * 0.002; v.y -= p.y * 0.002;                       // a gentle pull to the middle
        const m = Math.sqrt(v.x * v.x + v.y * v.y), cap = 8 * cool + 0.4;
        if (m > cap) { v.x *= cap / m; v.y *= cap / m; }
        p.x += v.x; p.y += v.y;
      }
    }
    try { localStorage.setItem("bulwark-graph", JSON.stringify([...this.pos].filter(([k]) => byId.has(k)).slice(-1500))); } catch { /* full */ }
    if (!this.fitted) this.fit();
    this.draw();
  }
  fit() {
    const xs = this.nodes.map((n) => this.pos.get(n.id)?.x || 0), ys = this.nodes.map((n) => this.pos.get(n.id)?.y || 0);
    if (!xs.length) return;
    const w = this.el.clientWidth, h = this.el.clientHeight;
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    const k = Math.min(2.2, 0.86 * Math.min(w / Math.max(80, maxX - minX), h / Math.max(80, maxY - minY)));
    this.view = { k, x: w / 2 - ((minX + maxX) / 2) * k, y: h / 2 - ((minY + maxY) / 2) * k };
    this.fitted = true;
  }
  toScreen(p) { return { x: p.x * this.view.k + this.view.x, y: p.y * this.view.k + this.view.y }; }
  at(sx, sy) {
    let best = null, bd = 1e9;
    for (const n of this.nodes) {
      const s = this.toScreen(this.pos.get(n.id)), r = this.radius(n) * Math.max(0.6, this.view.k) + 4;
      const d = (s.x - sx) ** 2 + (s.y - sy) ** 2;
      if (d < r * r && d < bd) { bd = d; best = n; }
    }
    return best;
  }
  wire() {
    let drag = null;
    const c = this.canvas;
    c.addEventListener("mousedown", (e) => { drag = { x: e.clientX, y: e.clientY, vx: this.view.x, vy: this.view.y, moved: false }; c.classList.add("drag"); });
    window.addEventListener("mouseup", (e) => {
      if (drag && !drag.moved) { const r = c.getBoundingClientRect(); const n = this.at(e.clientX - r.left, e.clientY - r.top); if (n) this.onPick?.(n); }
      drag = null; c.classList.remove("drag");
    });
    c.addEventListener("mousemove", (e) => {
      const r = c.getBoundingClientRect();
      if (drag) {
        const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
        this.view.x = drag.vx + dx; this.view.y = drag.vy + dy; this.draw(); return;
      }
      const n = this.at(e.clientX - r.left, e.clientY - r.top);
      if (n !== this.hover) { this.hover = n; this.draw(); }
    });
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const r = c.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
      const k2 = Math.max(0.2, Math.min(6, this.view.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
      this.view.x = mx - ((mx - this.view.x) * k2) / this.view.k; this.view.y = my - ((my - this.view.y) * k2) / this.view.k; this.view.k = k2;
      this.draw();
    }, { passive: false });
  }
  zoom(f) { const w = this.el.clientWidth / 2, h = this.el.clientHeight / 2, k2 = Math.max(0.2, Math.min(6, this.view.k * f)); this.view.x = w - ((w - this.view.x) * k2) / this.view.k; this.view.y = h - ((h - this.view.y) * k2) / this.view.k; this.view.k = k2; this.draw(); }
  draw() {
    const w = this.el.clientWidth, h = this.el.clientHeight;
    if (!w || !h) return;
    const d = DPR();
    if (this.canvas.width !== Math.round(w * d) || this.canvas.height !== Math.round(h * d)) { this.canvas.width = Math.round(w * d); this.canvas.height = Math.round(h * d); }
    const ctx = this.canvas.getContext("2d"); ctx.setTransform(d, 0, 0, d, 0, 0); ctx.clearRect(0, 0, w, h);
    const hv = this.hover, linked = new Set();
    if (hv) { linked.add(hv.id); for (const e of this.edges) { if (e.a === hv.id) linked.add(e.b); if (e.b === hv.id) linked.add(e.a); } }
    for (const e of this.edges) {
      const a = this.pos.get(e.a), b = this.pos.get(e.b);
      if (!a || !b) continue;
      const sa = this.toScreen(a), sb = this.toScreen(b), on = hv && linked.has(e.a) && linked.has(e.b);
      ctx.strokeStyle = on ? "rgba(255,170,140,.75)" : hv ? "rgba(255,255,255,.03)" : `rgba(255,255,255,${Math.min(0.22, 0.05 + Math.log1p(e.w || 1) * 0.04)})`;
      ctx.lineWidth = on ? 1.6 : 1;
      ctx.beginPath(); ctx.moveTo(sa.x, sa.y); ctx.lineTo(sb.x, sb.y); ctx.stroke();
    }
    ctx.lineWidth = 1;
    const labels = [];
    for (const n of this.nodes) {
      const s = this.toScreen(this.pos.get(n.id)), r = this.radius(n) * Math.max(0.6, Math.min(1.6, this.view.k));
      const dim = hv && !linked.has(n.id);
      ctx.globalAlpha = dim ? 0.18 : 1;
      ctx.fillStyle = this.color(n);
      if (n.kind === "sig" || n.kind === "wave") { ctx.shadowColor = this.color(n); ctx.shadowBlur = 14; }
      ctx.beginPath();
      if (n.kind === "as") { ctx.rect(s.x - r, s.y - r, r * 2, r * 2); } else if (n.kind === "wave") { ctx.moveTo(s.x, s.y - r * 1.2); ctx.lineTo(s.x + r * 1.1, s.y + r * 0.8); ctx.lineTo(s.x - r * 1.1, s.y + r * 0.8); ctx.closePath(); }
      else ctx.arc(s.x, s.y, r, 0, Math.PI * 2);
      ctx.fill(); ctx.shadowBlur = 0;
      if (n.kind === "ip" && n.banned) { ctx.strokeStyle = "rgba(224,64,251,.5)"; ctx.beginPath(); ctx.arc(s.x, s.y, r + 2.5, 0, Math.PI * 2); ctx.stroke(); }
      if (!dim && (n.kind !== "ip" || this.view.k > 1.6 || n === hv)) labels.push([n, s, r]);
    }
    ctx.globalAlpha = 1;
    ctx.font = "12px Inter, system-ui, sans-serif"; ctx.textBaseline = "middle";
    for (const [n, s, r] of labels) {
      const t = n.kind === "ip" ? n.label : n.label.length > 34 ? n.label.slice(0, 33) + "…" : n.label;
      ctx.fillStyle = "rgba(8,9,11,.75)"; const tw = ctx.measureText(t).width;
      ctx.fillRect(s.x + r + 4, s.y - 8, tw + 8, 16);
      ctx.fillStyle = n.kind === "ip" ? "#cfd4da" : "#f1f3f5"; ctx.fillText(t, s.x + r + 8, s.y);
    }
    if (hv) {
      const t = hv.kind === "ip" ? `${hv.label}${hv.org ? " · " + hv.org : ""}${hv.cc ? " · " + hv.cc : ""} · ${hv.n} requests${hv.banned ? " · banned" : ""}` : `${hv.label}`;
      ctx.font = "12px ui-monospace, Menlo, monospace"; const tw = ctx.measureText(t).width;
      ctx.fillStyle = "rgba(13,15,18,.95)"; ctx.fillRect(12, 12, tw + 20, 26); ctx.strokeStyle = "#2a2f37"; ctx.strokeRect(12.5, 12.5, tw + 19, 25);
      ctx.fillStyle = "#e9ebee"; ctx.fillText(t, 22, 25);
    }
  }
}
