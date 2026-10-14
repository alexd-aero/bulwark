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

// "TECHTIES-AS - TechTies Inc." -> "TechTies Inc."; "GOOGLE-CLOUD-PLATFORM" stays
export const netName = (org) => { const m = /^[A-Z0-9_.-]+ - (.+)$/.exec(String(org || "")); return (m ? m[1] : String(org || "")).trim() || "unknown network"; };
