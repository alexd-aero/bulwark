// The Patterns workflow: who attacked, what they tried, what Bulwark did about
// it, drawn the way a workflow editor draws one (n8n, Node-RED): cards on a
// canvas, joined by connections, read left to right.
//
//   Where from (networks)  ->  What they tried (patterns)  ->  What Bulwark did
//
// A connection's width is how many addresses travelled it. Hover anything to
// trace it; click a card or a connection and the panel beside the canvas tells
// everything about it, down to each address (click one for its drawer). Drag
// the canvas to move around, drag a card to move it, scroll (or pinch) to
// zoom; "Fit" brings everything back into view, "Tidy up" lays it out again.

const NODE_W = 250, NODE_H = 56, COL_GAP = 150, ROW_GAP = 10, GROUP_GAP = 34;
const COLORS = { net: "var(--pass-hi)", payload: "var(--block)", probe: "var(--drop)", known: "var(--known)", "out:blocked": "var(--block)",
  "out:payload": "var(--ban)", "out:lookup": "var(--ban)", "out:list": "var(--ban)", "out:manual": "var(--ban)", "out:ban": "var(--ban)", "out:dropped": "var(--drop)", "out:watched": "var(--pass-hi)" };
const svgI = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const ICON = {
  server: svgI('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'),
  globe: svgI('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>'),
  stack: svgI('<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>'),
  key: svgI('<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14 9l2 2"/>'),
  search: svgI('<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>'),
  ban: svgI('<circle cx="12" cy="12" r="9"/><path d="m5.7 5.7 12.6 12.6"/>'),
  hand: svgI('<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>'),
  eye: svgI('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>'),
  list: svgI('<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4 6h.01M4 12h.01M4 18h.01"/>'),
  user: svgI('<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>'),
  plus: svgI('<path d="M12 5v14M5 12h14"/>'), minus: svgI('<path d="M5 12h14"/>'),
  fit: svgI('<rect x="3" y="5" width="18" height="14" rx="2.5"/><circle cx="12" cy="12" r="2.5"/>'),
  full: svgI('<path d="M15 3h6v6M21 3l-7 7M9 21H3v-6M3 21l7-7"/>'), unfull: svgI('<path d="M14 10l7-7M20 10h-6V4M10 14l-7 7M4 14h6v6"/>'), tidy: svgI('<rect x="3" y="4" width="7" height="6" rx="1.5"/><rect x="14" y="4" width="7" height="6" rx="1.5"/><rect x="14" y="14" width="7" height="6" rx="1.5"/><path d="M10 7h4M17.5 10v4"/>'),
  close: svgI('<path d="M6 6l12 12M18 6 6 18"/>'), arrow: svgI('<path d="M5 12h14M13 6l6 6-6 6"/>'),
};
const OUT_ICON = { "out:payload": ICON.ban, "out:lookup": ICON.ban, "out:list": ICON.list, "out:manual": ICON.user, "out:ban": ICON.ban, "out:dropped": ICON.hand, "out:watched": ICON.eye, "out:blocked": ICON.hand };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => (n >= 1e4 ? (n / 1e3).toFixed(1) + "k" : Math.round(n || 0).toLocaleString());
const plural = (n, w, ws = w + "s") => `${fmt(n)} ${n === 1 ? w : ws}`;
export const netLabel = (org) => { const m = /^[A-Z0-9_.-]+ - (.+)$/.exec(String(org || "")); return (m ? m[1] : String(org || "")).trim() || "unknown network"; };
const flagOf = (cc) => (/^[A-Z]{2}$/.test(cc || "") ? String.fromCodePoint(...[...cc].map((c) => 127397 + c.charCodeAt(0))) : "");
const GROUP_LABEL = { payload: "payloads · dropped on sight", probe: "probes · counted, not dropped", known: "known bad · stopped for who they are" };
const STAGES = [["Where they come from", "networks"], ["What they tried", "attack patterns"], ["What Bulwark did", "the outcome"]];

export class Workflow {
  constructor(el, { who, onIp, onLog, span = "", cat = () => null } = {}) {
    this.el = el; this.who = who; this.onIp = onIp; this.onLog = onLog; this.span = span; this.cat = cat;
    this.view = { x: 0, y: 0, k: 1 };
    this.sel = null;                     // {node: id} | {edge: key}
    this.moved = new Map();              // cards you dragged: id -> {x, y}
    el.classList.add("wf");
    el.innerHTML = `
      <div class="wf-canvas" tabindex="0" aria-label="Attack workflow. Drag to move around, scroll to zoom.">
        <div class="wf-world"><svg class="wf-edges" width="10" height="10" aria-hidden="true"></svg><div class="wf-labels"></div><div class="wf-nodes"></div></div>
        <div class="wf-controls" role="toolbar" aria-label="Canvas">
          <button type="button" data-wf="in" title="Zoom in" aria-label="Zoom in">${ICON.plus}</button>
          <button type="button" data-wf="out" title="Zoom out" aria-label="Zoom out">${ICON.minus}</button>
          <button type="button" data-wf="fit" title="Fit to view" aria-label="Fit to view">${ICON.fit}</button>
          <button type="button" data-wf="tidy" title="Tidy up" aria-label="Tidy up">${ICON.tidy}</button>
          <button type="button" data-wf="full" title="Full screen (F)" aria-label="Full screen" aria-pressed="false">${ICON.full}</button>
          <span class="wf-zoom">100%</span>
        </div>
        <div class="wf-hint">drag to move · scroll to zoom · <kbd>F</kbd> full screen · click a card or a line</div>
        <div class="wf-tip" hidden></div>
      </div>
      <aside class="wf-panel" aria-live="polite"></aside>`;
    this.canvas = el.querySelector(".wf-canvas"); this.world = el.querySelector(".wf-world");
    this.svg = el.querySelector(".wf-edges"); this.nodesEl = el.querySelector(".wf-nodes"); this.labelsEl = el.querySelector(".wf-labels");
    this.panel = el.querySelector(".wf-panel"); this.tip = el.querySelector(".wf-tip"); this.zoomEl = el.querySelector(".wf-zoom");
    this.wire();
    this.ro = new ResizeObserver(() => {
      if (!this.fitted || Math.abs(this.canvas.clientWidth - this.cw) <= 40) return;
      if (!this.moved.size) { this.layout(); this.render(); }
      this.fit();
    });
    this.ro.observe(this.canvas);
  }
  destroy() {
    this.ro.disconnect();
    document.removeEventListener("fullscreenchange", this.onFsChange);
    document.removeEventListener("keydown", this.onKey);
    if (this.isFull()) { if (document.fullscreenElement === this.el) document.exitFullscreen().catch(() => {}); document.documentElement.classList.remove("wf-noscroll"); }
  }

  // ------------------------------------------------------------ data
  set(flow, { span } = {}) {
    if (span) this.span = span;
    const used = new Set([...flow.links, ...(flow.outLinks || [])].flatMap((l) => [l.a, l.b]));
    const nodes = [];
    for (const n of flow.nets) if (used.has(n.id)) nodes.push({ ...n, col: 0, type: "net", title: n.other ? n.org : netLabel(n.org) });
    // payloads first, then probes, then "known bad" (stopped without trying anything); the busiest on top, "other" last in each
    const typeOf = (x) => (x.known ? "known" : x.score === 3 ? "payload" : "probe"), RANK = { payload: 0, probe: 1, known: 2 };
    const sigs = flow.sigs.filter((x) => used.has(x.id)).sort((a, b) => RANK[typeOf(a)] - RANK[typeOf(b)] || (a.other ? 1 : 0) - (b.other ? 1 : 0) || b.ips - a.ips || b.requests - a.requests);
    for (const s of sigs) nodes.push({ ...s, col: 1, type: typeOf(s), title: s.name });
    for (const o of flow.outcomes || []) if (used.has(o.id)) nodes.push({ ...o, col: 2, type: "out", title: o.name });
    this.nodes = nodes; this.byId = new Map(nodes.map((n) => [n.id, n]));
    this.edges = [...flow.links, ...(flow.outLinks || [])].filter((l) => this.byId.has(l.a) && this.byId.has(l.b))
      .map((l) => ({ ...l, key: `${l.a}|${l.b}`, stage: this.byId.get(l.b).col }));
    this.maxIps = Math.max(1, ...this.edges.map((e) => e.ips));
    this.sel = null;
    this.layout();
    this.render();
    requestAnimationFrame(() => this.fit());
  }

  layout() {
    // wider canvases spread the stages apart (the cards keep their size)
    const cw = this.canvas.clientWidth || 900;
    this.colGap = Math.round(Math.max(COL_GAP, Math.min(380, (cw / 0.9 - 3 * NODE_W - 120) / 2)));
    const cols = [[], [], []];
    for (const n of this.nodes) cols[n.col].push(n);
    // the middle column: payloads, probes, known bad, each a group of its own
    const heights = cols.map((c, i) => c.length * (NODE_H + ROW_GAP) - ROW_GAP + (i === 1 ? (new Set(c.map((n) => n.type)).size - 1) * GROUP_GAP : 0));
    const H = Math.max(...heights);
    this.groups = [];
    cols.forEach((c, i) => {
      let y = (H - heights[i]) / 2, prev = null;
      for (const n of c) {
        if (i === 1 && prev && prev !== n.type) y += GROUP_GAP;
        if (i === 1 && prev !== n.type) this.groups.push({ type: n.type, y });
        const m = this.moved.get(n.id);
        n.x = m ? m.x : i * (NODE_W + this.colGap); n.y = m ? m.y : y;
        y += NODE_H + ROW_GAP; prev = n.type;
      }
    });
    this.height = H;
  }

  // ------------------------------------------------------------ drawing
  render() {
    this.nodesEl.innerHTML = this.nodes.map((n) => this.card(n)).join("");
    this.labelsEl.innerHTML = STAGES.map(([t, s], i) => `<div class="wf-stage" style="left:${i * (NODE_W + this.colGap)}px;top:-58px;width:${NODE_W}px"><b>${i + 1}</b><span>${t}<em>${s}</em></span></div>`).join("")
      + (this.groups.length > 1 ? this.groups.map((g) => `<div class="wf-group ${g.type}" style="left:${NODE_W + this.colGap}px;top:${g.y - 18}px">${GROUP_LABEL[g.type]}</div>`).join("") : "")
      + '<div class="wf-elabel" hidden></div>';
    this.elabel = this.labelsEl.querySelector(".wf-elabel");
    this.drawEdges();
    this.paintPanel();
  }
  card(n) {
    const k = n.type, other = n.other ? " other" : "";
    const icon = k === "net" ? (n.other ? ICON.stack : n.dc ? ICON.server : ICON.globe) : k === "payload" ? ICON.key : k === "probe" ? ICON.search : k === "known" ? ICON.list : OUT_ICON[n.id] || ICON.ban;
    const ban = k !== "out" && n.ips ? n.banned / n.ips : null;
    const stats = k === "out" ? `<span><b>${fmt(n.ips)}</b> ${n.ips === 1 ? "address" : "addresses"}</span>`
      : k === "net" ? `<span><b>${fmt(n.ips)}</b> addr</span>${n.banned ? `<span class="wf-banned"><b>${fmt(n.banned)}</b> banned</span>` : ""}${n.other ? `<span>${fmt(n.count)} nets</span>` : n.dc ? '<span class="wf-tag">hosting</span>' : ""}`
      : `${n.cat && this.cat(n.cat) ? `<span class="wf-cat" style="--k:${esc(this.cat(n.cat).color)}">${esc(this.cat(n.cat).short)}</span>` : ""}<span><b>${fmt(n.ips)}</b> addr</span>${n.requests && !(n.cat && this.cat(n.cat)) ? `<span><b>${fmt(n.requests)}</b> ${k === "known" ? "req" : "tries"}</span>` : ""}${n.banned ? `<span class="wf-banned"><b>${fmt(n.banned)}</b> banned</span>` : ""}`;
    return `<div class="wf-node ${k}${other}" data-id="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(n.title)}: ${n.ips} addresses" style="left:${n.x}px;top:${n.y}px;--c:${COLORS[k === "out" ? n.id : k]}">
      ${n.col > 0 ? '<i class="wf-port in"></i>' : ""}${n.col < 2 ? '<i class="wf-port out"></i>' : ""}
      <span class="wf-ic">${icon}</span>
      <span class="wf-body"><b class="wf-title" title="${esc(n.org || n.title)}">${esc(n.title)}</b><span class="wf-stats">${stats}</span></span>
      ${ban !== null ? `<i class="wf-ratio" title="${Math.round(ban * 100)}% banned"><i style="width:${(ban * 100).toFixed(1)}%"></i></i>` : ""}
    </div>`;
  }
  path(e) {
    const a = this.byId.get(e.a), b = this.byId.get(e.b);
    const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
    const dx = Math.max(60, Math.abs(x2 - x1) * 0.5);
    e.mid = { x: (x1 + 3 * (x1 + dx) + 3 * (x2 - dx) + x2) / 8, y: (y1 + y2) / 2 };
    return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
  }
  edgeColor(e) {
    const b = this.byId.get(e.b);
    return b.col === 1 ? COLORS[b.type] : COLORS[b.id] || COLORS.net;
  }
  drawEdges() {
    // the thin ones first, so the thick ones sit on top
    const list = [...this.edges].sort((a, b) => a.ips - b.ips);
    this.svg.innerHTML = list.map((e) => {
      const d = this.path(e), w = (1.4 + 5.6 * Math.sqrt(e.ips / this.maxIps)).toFixed(2);
      return `<g class="wf-edge" data-key="${esc(e.key)}" style="--c:${this.edgeColor(e)};--w:${w}px"><path class="wf-line" d="${d}"/><path class="wf-flow" d="${d}"/><path class="wf-hit" d="${d}"/></g>`;
    }).join("");
    this.applySel();
  }
  moveEdges(id) {
    for (const e of this.edges) if (e.a === id || e.b === id) {
      const d = this.path(e);
      this.svg.querySelectorAll(`[data-key="${CSS.escape(e.key)}"] path`).forEach((p) => p.setAttribute("d", d));
    }
  }

  // ------------------------------------------------------------ focus
  // what lights up: a card and its connections (and the cards at their ends),
  // or a connection and its two cards; everything else steps back
  lit(target) {
    if (!target) return null;
    const nodes = new Set(), edges = new Set();
    if (target.node) {
      nodes.add(target.node);
      for (const e of this.edges) if (e.a === target.node || e.b === target.node) { edges.add(e.key); nodes.add(e.a); nodes.add(e.b); }
    } else if (target.edge) {
      const e = this.edges.find((x) => x.key === target.edge);
      if (e) { edges.add(e.key); nodes.add(e.a); nodes.add(e.b); }
    }
    return { nodes, edges };
  }
  applySel(hover = null) {
    const L = this.lit(hover || this.sel);
    this.canvas.classList.toggle("dim", !!L);
    for (const el of this.nodesEl.children) {
      el.classList.toggle("lit", !!L && L.nodes.has(el.dataset.id));
      el.classList.toggle("sel", !!this.sel?.node && this.sel.node === el.dataset.id);
    }
    for (const g of this.svg.children) {
      const on = !!L && L.edges.has(g.dataset.key);
      g.classList.toggle("lit", on);
      g.classList.toggle("sel", this.sel?.edge === g.dataset.key);
      if (on) g.parentNode.appendChild(g);                 // drawn on top
    }
    // the count on the connection in focus
    const ek = hover?.edge || (!hover && this.sel?.edge);
    const e = ek && this.edges.find((x) => x.key === ek);
    if (e) {
      this.elabel.hidden = false;
      this.elabel.style.left = `${e.mid.x}px`; this.elabel.style.top = `${e.mid.y}px`;
      const tries = this.byId.get(e.b).col === 1;
      this.elabel.innerHTML = `${plural(e.ips, "address", "addresses")}${e.requests ? ` · ${tries ? plural(e.requests, "try", "tries") : plural(e.requests, "request")}` : ""}`;
    } else this.elabel.hidden = true;
  }
  has(id) { return !!this.byId?.has(id); }
  select(target, { toggle = true } = {}) {
    const same = toggle && target && this.sel && ((target.node && target.node === this.sel.node) || (target.edge && target.edge === this.sel.edge));
    this.sel = same ? null : target;
    this.applySel();
    this.paintPanel();
  }

  // ------------------------------------------------------------ the panel
  paintPanel() {
    const P = this.panel;
    if (!this.sel) {
      const by = (c) => this.nodes.filter((n) => n.col === c);
      const outs = by(2), banned = outs.filter((o) => o.id.startsWith("out:") && !["out:dropped", "out:watched"].includes(o.id)).reduce((a, o) => a + o.ips, 0);
      const all = outs.reduce((a, o) => a + o.ips, 0);
      P.innerHTML = `<div class="wf-p-head"><span class="wf-p-kind">How to read it</span><h3>Left to right, like a workflow</h3></div>
        <ol class="wf-steps">
          <li><b>Where they come from.</b> Each card is a network (the company that owns the addresses). Hosting means a data centre: rented servers, rarely a person.</li>
          <li><b>What they tried.</b> <span class="wf-k payload">Payloads</span> go after secrets or a way in and are dropped on sight; <span class="wf-k probe">probes</span> ask for software that isn't here; <span class="wf-k known">known bad</span> tried nothing: Bulwark knew them already (a blocklist, the lookups, you).</li>
          <li><b>What Bulwark did.</b> Banned (everywhere, for days), stopped without a ban yet, or only watched.</li>
        </ol>
        <p class="wf-p-note">A line's width is how many addresses took that path. Click a card or a line for the addresses behind it.</p>
        ${all ? `<div class="wf-p-sum"><div><b>${fmt(by(0).reduce((a, n) => a + n.ips, 0))}</b><span>hostile addresses</span></div><div><b>${fmt(banned)}</b><span>banned (${Math.round((100 * banned) / all)}%)</span></div></div>` : ""}`;
      return;
    }
    if (this.sel.node) return this.nodePanel(this.byId.get(this.sel.node));
    return this.edgePanel(this.edges.find((x) => x.key === this.sel.edge));
  }
  conns(list, side) {
    if (!list.length) return "";
    const max = Math.max(...list.map((e) => e.ips));
    return list.sort((a, b) => b.ips - a.ips).map((e) => {
      const o = this.byId.get(side === "out" ? e.b : e.a);
      return `<button type="button" class="wf-conn" data-wfedge="${esc(e.key)}" style="--c:${this.edgeColor(e)}">
        <span class="wf-conn-t">${esc(o.title)}</span><span class="wf-conn-n">${fmt(e.ips)}</span>
        <i class="wf-conn-bar"><i style="width:${(100 * e.ips) / max}%"></i></i></button>`;
    }).join("");
  }
  nodePanel(n) {
    if (!n) return;
    const ins = this.edges.filter((e) => e.b === n.id), outs = this.edges.filter((e) => e.a === n.id);
    const kind = n.type === "net" ? (n.other ? "Networks" : n.dc ? "Hosting network" : "Network") : n.type === "payload" ? "Payload pattern" : n.type === "probe" ? "Probe pattern" : n.type === "known" ? "No pattern" : "Outcome";
    const what = n.type === "payload" ? "Requests after secrets or a way in. Nobody needs these, so every one is dropped, and an address that sends them is banned."
      : n.type === "probe" ? "Requests for software that isn't here (an admin page, a CMS). Counted and answered normally; with bad reputation they lead to a ban."
      : n.type === "out" || n.type === "known" ? n.what : n.other ? "The quieter networks, folded into one card so the busy ones stay readable." : `The addresses below belong to ${esc(n.org)}${n.asn ? ` (AS${n.asn})` : ""}.${n.dc ? " A hosting network: rented servers, rarely a person at home." : ""}`;
    const c = n.cat ? this.cat(n.cat) : null;
    const tax = c ? `<div class="wf-p-tax"><span class="wf-cat" style="--k:${esc(c.color)}">${esc(c.name)}</span>${n.sev ? `<span class="sev sev-${esc(n.sev)}">${esc(n.sev)}</span>` : ""}${n.cve ? `<a class="cve" href="https://nvd.nist.gov/vuln/detail/${esc(n.cve)}" target="_blank" rel="noopener noreferrer">${esc(n.cve)}</a>` : ""}
      ${c.mitre?.length ? `<span class="faint small">ATT&amp;CK ${c.mitre.map(esc).join(", ")}${c.owasp ? ` · OWASP ${esc(c.owasp)}` : ""}</span>` : ""}</div>` : "";
    const ex = (n.examples || []).length ? `<div class="wf-p-sec"><h4>What it looks like</h4><div class="wf-ex">${n.examples.map((p) => `<code>${esc(p)}</code>`).join("")}</div></div>` : "";
    const sections = [
      ins.length ? `<div class="wf-p-sec"><h4>${n.type === "out" ? "After trying" : "Came from"}</h4>${this.conns(ins, "in")}</div>` : "",
      outs.length ? `<div class="wf-p-sec"><h4>${n.type === "net" ? "Tried" : "Then"}</h4>${this.conns(outs, "out")}</div>` : "",
    ].join("");
    const log = (n.type === "payload" || n.type === "probe") && !n.other && n.sig ? `<button type="button" class="btn sm ghost" data-wflog="${esc(n.sig)}">Its requests in the live log</button>` : "";
    this.panel.innerHTML = `<div class="wf-p-head" style="--c:${COLORS[n.type === "out" ? n.id : n.type]}"><span class="wf-p-kind">${kind}</span>
        <button type="button" class="wf-p-x" data-wfclose aria-label="Close">${ICON.close}</button><h3>${esc(n.title)}</h3></div>
      <div class="wf-p-stats"><div><b>${fmt(n.ips)}</b><span>addresses</span></div>${n.type !== "out" ? `<div><b>${fmt(n.banned || 0)}</b><span>banned</span></div>` : ""}<div><b>${fmt(n.requests || 0)}</b><span>${n.type === "payload" || n.type === "probe" ? "tries" : "requests"}</span></div></div>
      ${tax}<p class="wf-p-note">${what}${c?.about ? ` <span class="faint">${esc(c.about)}</span>` : ""}</p>${ex}${sections}
      <div class="wf-p-sec"><h4>Addresses <span class="wf-p-span">${esc(this.span)}</span></h4><div class="wf-ips"><p class="muted small"><span class="spin"></span> Finding them…</p></div>${log}</div>`;
    this.loadIps(n.id);
  }
  edgePanel(e) {
    if (!e) return;
    const a = this.byId.get(e.a), b = this.byId.get(e.b);
    const did = b.id === "out:watched" ? "were only watched" : b.id === "out:dropped" ? "were stopped but not banned yet" : `ended up ${esc(b.title.toLowerCase())}`;
    const sentence = b.type === "known" ? `${plural(e.ips, "address", "addresses")} from ${esc(a.title)} were stopped without trying any attack${e.requests ? ` (${plural(e.requests, "request")})` : ""}.`
      : b.col === 1 ? `${plural(e.ips, "address", "addresses")} from ${esc(a.title)} tried ${esc(b.title)}${e.requests ? `, ${plural(e.requests, "time")} in all` : ""}.`
      : a.type === "known" ? `${plural(e.ips, "address", "addresses")} known bad already ${did}.`
      : `${plural(e.ips, "address", "addresses")} that tried ${esc(a.title)} ${did}.`;
    this.panel.innerHTML = `<div class="wf-p-head" style="--c:${this.edgeColor(e)}"><span class="wf-p-kind">Connection</span>
        <button type="button" class="wf-p-x" data-wfclose aria-label="Close">${ICON.close}</button>
        <h3 class="wf-p-path"><button type="button" data-wfnode="${esc(a.id)}">${esc(a.title)}</button>${ICON.arrow}<button type="button" data-wfnode="${esc(b.id)}">${esc(b.title)}</button></h3></div>
      <div class="wf-p-stats"><div><b>${fmt(e.ips)}</b><span>addresses</span></div><div><b>${fmt(e.requests || 0)}</b><span>${b.col === 1 && b.type !== "known" ? "tries" : "requests"}</span></div></div>
      <p class="wf-p-note">${sentence}</p>
      <div class="wf-p-sec"><h4>Addresses <span class="wf-p-span">${esc(this.span)}</span></h4><div class="wf-ips"><p class="muted small"><span class="spin"></span> Finding them…</p></div></div>`;
    this.loadIps(e.key);
  }
  async loadIps(id) {
    const want = JSON.stringify(this.sel);
    let ips;
    try { ips = await this.who(id); } catch (err) { ips = null; var msg = err.message; }
    if (JSON.stringify(this.sel) !== want) return;
    const box = this.panel.querySelector(".wf-ips");
    if (!box) return;
    if (!ips) { box.innerHTML = `<p class="st5 small">${esc(msg || "Could not load them.")}</p>`; return; }
    if (!ips.length) { box.innerHTML = '<p class="muted small">Nobody in this window.</p>'; return; }
    box.innerHTML = `<ul class="wf-ip-list">${ips.slice(0, 200).map((x) => `<li><button type="button" class="wf-ip" data-wfip="${esc(x.ip)}">
        <span class="wf-ip-a">${flagOf(x.cc)} <span class="mono">${esc(x.ip)}</span></span>
        <span class="wf-ip-m">${x.banned ? '<span class="pill ban">banned</span>' : ""}<span class="mono faint">${fmt(x.n)}</span></span>
        ${x.org ? `<span class="wf-ip-o">${esc(netLabel(x.org))}${x.dc ? " · hosting" : ""}</span>` : ""}</button></li>`).join("")}</ul>
      ${ips.length > 200 ? `<p class="muted small">and ${fmt(ips.length - 200)} more</p>` : ""}`;
  }

  // ------------------------------------------------------------ the canvas
  setView(v) {
    this.view = v;
    this.world.style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.k})`;
    const g = 22 * v.k;
    this.canvas.style.backgroundSize = `${g}px ${g}px`;
    this.canvas.style.backgroundPosition = `${v.x}px ${v.y}px`;
    this.zoomEl.textContent = `${Math.round(v.k * 100)}%`;
  }
  bounds() {
    const xs = this.nodes.map((n) => n.x), ys = this.nodes.map((n) => n.y);
    return { x0: Math.min(...xs), y0: Math.min(...ys) - 64, x1: Math.max(...xs) + NODE_W, y1: Math.max(...ys) + NODE_H };
  }
  fit() {
    if (!this.nodes?.length) return;
    const W = this.cw = this.canvas.clientWidth, H = this.canvas.clientHeight, b = this.bounds(), pad = 36;
    const MIN = W < 640 ? 0.5 : 0.62;              // below this the cards can't be read: start at the top and let you move
    const fitK = Math.min(1.1, (W - pad * 2) / (b.x1 - b.x0), (H - pad * 2 - 30) / (b.y1 - b.y0)), k = Math.max(MIN, fitK);
    const x = (b.x1 - b.x0) * k <= W - pad ? (W - (b.x1 - b.x0) * k) / 2 - b.x0 * k : pad - b.x0 * k;
    const y = (b.y1 - b.y0) * k <= H - 30 ? (H - 30 - (b.y1 - b.y0) * k) / 2 - b.y0 * k : pad - b.y0 * k;
    this.setView({ k, x, y });
    this.fitted = true;
  }
  zoomAt(f, cx, cy) {
    const v = this.view, k = Math.max(0.25, Math.min(2.2, v.k * f));
    if (cx === undefined) { cx = this.canvas.clientWidth / 2; cy = this.canvas.clientHeight / 2; }
    this.setView({ k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k });
  }
  wire() {
    const c = this.canvas;
    const local = (e) => { const r = c.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
    const ptrs = new Map();
    let drag = null;          // {kind: "pan"|"node", ...}
    c.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || e.target.closest(".wf-controls")) return;
      ptrs.set(e.pointerId, local(e));
      if (ptrs.size === 2) {     // pinch
        const [p, q] = [...ptrs.values()];
        drag = { kind: "pinch", d: Math.hypot(p.x - q.x, p.y - q.y), v: { ...this.view }, mid: { x: (p.x + q.x) / 2, y: (p.y + q.y) / 2 } };
        return;
      }
      const node = e.target.closest(".wf-node"), p = local(e);
      drag = node ? { kind: "node", id: node.dataset.id, el: node, sx: p.x, sy: p.y, nx: this.byId.get(node.dataset.id).x, ny: this.byId.get(node.dataset.id).y, moved: false }
        : { kind: "pan", sx: p.x, sy: p.y, vx: this.view.x, vy: this.view.y, moved: false, target: e.target };
      c.setPointerCapture(e.pointerId);
    });
    c.addEventListener("pointermove", (e) => {
      if (ptrs.has(e.pointerId)) ptrs.set(e.pointerId, local(e));
      if (!drag) return this.hover(e);
      if (drag.kind === "pinch") {
        if (ptrs.size < 2) return;
        const [p, q] = [...ptrs.values()], d = Math.hypot(p.x - q.x, p.y - q.y), v = drag.v;
        const k = Math.max(0.25, Math.min(2.2, v.k * (d / drag.d))), m = drag.mid;
        this.setView({ k, x: m.x - ((m.x - v.x) * k) / v.k, y: m.y - ((m.y - v.y) * k) / v.k });
        return;
      }
      const p = local(e), dx = p.x - drag.sx, dy = p.y - drag.sy;
      if (!drag.moved && Math.hypot(dx, dy) < 4) return;
      drag.moved = true; this.tip.hidden = true;
      if (drag.kind === "pan") { c.classList.add("panning"); this.setView({ ...this.view, x: drag.vx + dx, y: drag.vy + dy }); }
      else {
        const n = this.byId.get(drag.id);
        n.x = drag.nx + dx / this.view.k; n.y = drag.ny + dy / this.view.k;
        drag.el.style.left = `${n.x}px`; drag.el.style.top = `${n.y}px`; drag.el.classList.add("dragging");
        this.moved.set(n.id, { x: n.x, y: n.y });
        this.moveEdges(n.id);
        this.applySel();
      }
    });
    const end = (e) => {
      ptrs.delete(e.pointerId);
      if (!drag) return;
      const d = drag; drag = null;
      c.classList.remove("panning");
      if (d.kind === "node") d.el.classList.remove("dragging");
      if (d.kind === "pinch" || d.moved) return;
      // a click
      if (d.kind === "node") return this.select({ node: d.id });
      const g = d.target.closest?.(".wf-edge");
      if (g) return this.select({ edge: g.dataset.key });
      if (this.sel) this.select(null);
    };
    c.addEventListener("pointerup", end);
    c.addEventListener("pointercancel", (e) => { ptrs.delete(e.pointerId); drag = null; c.classList.remove("panning"); });
    c.addEventListener("pointerleave", () => { if (!drag) { this.tip.hidden = true; this.applySel(); } });
    // the scroll wheel zooms in and out where the pointer is (a trackpad's pinch too);
    // the page still scrolls with the pointer anywhere outside the canvas
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const p = local(e), dy = e.deltaMode === 1 ? e.deltaY * 33 : e.deltaMode === 2 ? e.deltaY * 400 : e.deltaY;
      this.zoomAt(Math.exp(-Math.max(-160, Math.min(160, dy)) * (e.ctrlKey ? 0.008 : 0.0016)), p.x, p.y);
    }, { passive: false });
    c.addEventListener("keydown", (e) => {
      const node = e.target.closest?.(".wf-node");
      if (node && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); this.select({ node: node.dataset.id }); }
      else if (e.key === "Escape" && this.sel) { e.stopPropagation(); this.select(null); }
      else if (e.key === "+" || e.key === "=") this.zoomAt(1.2);
      else if (e.key === "-") this.zoomAt(1 / 1.2);
      else if ((e.key === "f" || e.key === "F") && !e.ctrlKey && !e.metaKey && !e.altKey) this.toggleFull();
    });
    c.addEventListener("focusin", (e) => { const n = e.target.closest?.(".wf-node"); if (n) this.applySel({ node: n.dataset.id }); });
    this.el.querySelector(".wf-controls").addEventListener("click", (e) => {
      const b = e.target.closest("[data-wf]");
      if (!b) return;
      const a = b.dataset.wf;
      if (a === "in") this.zoomAt(1.2); else if (a === "out") this.zoomAt(1 / 1.2); else if (a === "fit") this.fit();
      else if (a === "tidy") { this.moved.clear(); this.layout(); this.render(); this.fit(); }
      else if (a === "full") this.toggleFull();
    });
    this.panel.addEventListener("click", (e) => {
      const t = e.target.closest("[data-wfedge],[data-wfnode],[data-wfip],[data-wfclose],[data-wflog]");
      if (!t) return;
      e.stopPropagation();
      if (t.dataset.wfedge) this.select({ edge: t.dataset.wfedge });
      else if (t.dataset.wfnode) this.select({ node: t.dataset.wfnode });
      else if (t.dataset.wfip) {
        // the browser's full screen shows only the graph: step down to the window-filling one, so the drawer shows over it
        if (document.fullscreenElement === this.el) { this.keepFull = true; document.exitFullscreen().catch(() => {}); }
        this.onIp?.(t.dataset.wfip);
      }
      else if (t.dataset.wflog) this.onLog?.(t.dataset.wflog);
      else this.select(null);
    });
    this.onFsChange = () => { if (!document.fullscreenElement && this.isFull()) { if (this.keepFull) this.keepFull = false; else this.setFull(false); } };
    document.addEventListener("fullscreenchange", this.onFsChange);
    this.onKey = (e) => { if (e.key === "Escape" && this.isFull() && !document.fullscreenElement && !this.sel) this.setFull(false); };
    document.addEventListener("keydown", this.onKey);
    this.panel.addEventListener("mouseover", (e) => { const t = e.target.closest("[data-wfedge]"); if (t) this.applySel({ edge: t.dataset.wfedge }); });
    this.panel.addEventListener("mouseout", (e) => { if (e.target.closest("[data-wfedge]")) this.applySel(); });
  }
  // Full screen: the browser's own when it allows it (it may not inside a
  // frame, or on an iPhone), else the graph fills the window; either way the
  // canvas and its panel get the whole screen and the view is fitted again.
  isFull() { return this.el.classList.contains("full"); }
  async toggleFull() {
    if (this.isFull()) {
      if (document.fullscreenElement === this.el) { try { await document.exitFullscreen(); } catch { this.setFull(false); } }
      else this.setFull(false);
      return;
    }
    this.setFull(true);
    try { if (this.el.requestFullscreen && document.fullscreenEnabled) await this.el.requestFullscreen({ navigationUI: "hide" }); }
    catch { /* the window-filling version stays */ }
  }
  setFull(on) {
    this.el.classList.toggle("full", on);
    document.documentElement.classList.toggle("wf-noscroll", on);
    const b = this.el.querySelector('[data-wf="full"]');
    b.innerHTML = on ? ICON.unfull : ICON.full;
    b.title = on ? "Leave full screen (F or Esc)" : "Full screen (F)";
    b.setAttribute("aria-pressed", String(on));
    requestAnimationFrame(() => { if (!this.moved.size) { this.layout(); this.render(); } this.fit(); this.canvas.focus({ preventScroll: true }); });
  }
  hover(e) {
    const node = e.target.closest(".wf-node"), g = !node && e.target.closest(".wf-edge");
    const target = node ? { node: node.dataset.id } : g ? { edge: g.dataset.key } : null;
    const key = JSON.stringify(target);
    if (key !== this.hoverKey) { this.hoverKey = key; this.applySel(target); }
    if (!g) { this.tip.hidden = true; return; }
    const ed = this.edges.find((x) => x.key === g.dataset.key), a = this.byId.get(ed.a), b = this.byId.get(ed.b);
    const r = this.canvas.getBoundingClientRect();
    this.tip.innerHTML = `<b>${esc(a.title)} → ${esc(b.title)}</b><span>${plural(ed.ips, "address", "addresses")}${ed.requests ? ` · ${plural(ed.requests, b.col === 1 ? "try" : "request", b.col === 1 ? "tries" : "requests")}` : ""}</span><em>click for the addresses</em>`;
    this.tip.hidden = false;
    const x = e.clientX - r.left, y = e.clientY - r.top;
    this.tip.style.left = `${Math.min(r.width - this.tip.offsetWidth - 8, x + 14)}px`;
    this.tip.style.top = `${Math.max(8, y - this.tip.offsetHeight - 10)}px`;
  }
}
