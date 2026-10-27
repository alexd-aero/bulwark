// What Bulwark's emails look like: HTML any mail client shows the same (tables,
// inline styles, no images, no web fonts, nothing loaded from elsewhere), and a
// plain-text twin. Everything shown is escaped. Used by mail.mjs.
//
//   renderWave(items, ctx)     waves, campaigns, strict mode (one email for a burst)
//   renderSystem(items, ctx)   the guard gone (or back), the app crashing or failing
//   renderDigest(ctx)          the last 24 hours
//   renderTest(ctx)            "it works", with what you'll get
//   -> {subject, text, html, level}

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace";
const C = { ink: "#111317", text: "#30343b", muted: "#6b7079", faint: "#8b9099", line: "#e6e8eb", soft: "#f5f6f8", page: "#eceef1", head: "#101113",
            critical: "#e5384f", warn: "#f2a33a", info: "#3b8fe0", ok: "#22b07d", accent: "#ff6a3d" };
const LABEL = { critical: "CRITICAL", warn: "WARNING", info: "NOTICE", ok: "ALL GOOD" };
const SEVN = { info: 0, warn: 1, critical: 2 };

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const n = (x) => Math.round(Number(x) || 0).toLocaleString("en-US");
const hm = (t) => new Date(t).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
const rate = (x) => { const v = Number(x) || 0; return v > 0 && v < 10 ? String(Math.round(v * 10) / 10) : n(v); };
const plural = (k, one, many = one + "s") => `${n(k)} ${Number(k) === 1 ? one : many}`;
const worstOf = (items) => items.reduce((w, x) => (SEVN[x.sev] > SEVN[w] ? x.sev : w), "info");
const oneLine = (s, max = 160) => { const t = String(s ?? "").replace(/\s+/g, " ").trim(); return t.length > max ? t.slice(0, max - 1) + "…" : t; };
const safeLink = (u) => (typeof u === "string" && /^https?:\/\/[^\s"'<>]+$/.test(u) ? u : null);

// ------------------------------------------------------------------ pieces
function pill(level) {
  const c = C[level] || C.info;
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td bgcolor="${c}" style="background:${c};border-radius:99px;padding:4px 11px;font-family:${FONT};font-size:11px;font-weight:700;letter-spacing:.8px;color:#ffffff;white-space:nowrap;">${LABEL[level] || "NOTICE"}</td></tr></table>`;
}
function heading(t) {
  return `<div style="margin:22px 0 8px;font-family:${FONT};font-size:12px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:${C.muted};">${esc(t)}</div>`;
}
// up to three numbers in boxes; tiles: [{label, value, sub, hot}]
function tiles(list) {
  const cells = list.slice(0, 3).map((x, i, a) => `<td width="${Math.floor(100 / a.length)}%" valign="top" style="padding:0 ${i < a.length - 1 ? 8 : 0}px 0 0;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td bgcolor="${C.soft}" style="background:${C.soft};border:1px solid ${C.line};border-radius:10px;padding:12px 12px 11px;font-family:${FONT};">
        <div style="font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:${C.muted};">${esc(x.label)}</div>
        <div style="font-size:24px;line-height:1.2;font-weight:700;color:${x.hot ? C.critical : C.ink};margin-top:3px;">${esc(x.value)}</div>
        ${x.sub ? `<div style="font-size:12px;color:${C.muted};margin-top:2px;">${x.sub}</div>` : ""}
      </td></tr></table></td>`).join("");
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 6px;"><tr>${cells}</tr></table>`;
}
// a plain table: cols [{label, align}], rows of cell HTML
function table(cols, rows) {
  const th = cols.map((c) => `<th align="${c.align || "left"}" style="padding:0 0 7px;border-bottom:1px solid ${C.line};font-family:${FONT};font-size:12px;font-weight:600;color:${C.faint};text-align:${c.align || "left"};">${esc(c.label)}</th>`).join("");
  const tr = rows.map((r) => `<tr>${r.map((cell, i) => `<td align="${cols[i].align || "left"}" valign="top" style="padding:8px ${i < r.length - 1 ? 10 : 0}px 8px 0;border-bottom:1px solid #f0f1f3;font-family:${FONT};font-size:14px;color:${C.text};text-align:${cols[i].align || "left"};">${cell}</td>`).join("")}</tr>`).join("");
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;margin:0 0 4px;"><tr>${th}</tr>${tr}</table>`;
}
function alertRows(list) {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">${list.map((a) => `<tr>
    <td width="18" valign="top" style="width:18px;padding:14px 0 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="8" height="8" bgcolor="${C[a.sev] || C.info}" style="width:8px;height:8px;background:${C[a.sev] || C.info};border-radius:4px;font-size:0;line-height:0;">&nbsp;</td></tr></table></td>
    <td valign="top" style="padding:9px 10px 9px 0;border-bottom:1px solid #f0f1f3;font-family:${FONT};">
      <div style="font-size:14px;font-weight:600;color:${C.ink};">${esc(a.title)}</div>
      ${a.detail ? `<div style="font-size:13px;line-height:1.45;color:${C.text};margin-top:2px;">${esc(oneLine(a.detail, 260))}</div>` : ""}
      ${a.extra ? `<div style="font-size:12px;color:${C.muted};margin-top:3px;">${esc(a.extra)}</div>` : ""}</td>
    <td align="right" valign="top" style="padding:10px 0 9px;border-bottom:1px solid #f0f1f3;font-family:${MONO};font-size:12px;color:${C.faint};white-space:nowrap;">${esc(a.time || "")}</td></tr>`).join("")}</table>`;
}
function button(link, label) {
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 6px;"><tr><td bgcolor="${C.accent}" style="background:${C.accent};border-radius:8px;">
    <a href="${esc(link)}" target="_blank" style="display:inline-block;padding:12px 22px;font-family:${FONT};font-size:14px;font-weight:700;color:#1b0903;text-decoration:none;border-radius:8px;">${esc(label)} &rarr;</a></td></tr></table>`;
}
const para = (html, style = "") => `<p style="margin:0 0 14px;font-family:${FONT};font-size:14px;line-height:1.55;color:${C.text};${style}">${html}</p>`;

// the frame: dark header with the name, a coloured rule, the body, a quiet footer
function layout({ level, kicker, title, intro, body, link, linkLabel, footer, preheader }) {
  const accent = C[level] || C.info;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="x-apple-disable-message-reformatting"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${esc(title)}</title></head>
<body style="margin:0;padding:0;background:${C.page};-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
<div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px;color:${C.page};">${esc(oneLine(preheader || intro || "", 140))}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${C.page}" style="background:${C.page};"><tr><td align="center" style="padding:28px 10px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">
  <tr><td bgcolor="${C.head}" style="background:${C.head};border-radius:14px 14px 0 0;padding:20px 24px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="38" valign="middle" style="width:38px;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="36" height="36" align="center" valign="middle" bgcolor="${C.critical}" style="width:36px;height:36px;background:${C.critical};border-radius:10px;font-family:${FONT};font-size:19px;line-height:36px;font-weight:800;color:#ffffff;text-align:center;">B</td></tr></table></td>
      <td valign="middle" style="padding:0 0 0 12px;font-family:${FONT};"><div style="font-size:18px;line-height:1.2;font-weight:700;color:#ffffff;letter-spacing:.2px;">Bulwark</div><div style="font-size:12px;line-height:1.4;color:#8b9099;">${esc(kicker)}</div></td>
      <td align="right" valign="middle">${pill(level)}</td>
    </tr></table></td></tr>
  <tr><td height="4" bgcolor="${accent}" style="height:4px;background:${accent};font-size:0;line-height:0;">&nbsp;</td></tr>
  <tr><td bgcolor="#ffffff" style="background:#ffffff;padding:24px 24px 22px;border-left:1px solid ${C.line};border-right:1px solid ${C.line};">
    <h1 style="margin:0 0 8px;font-family:${FONT};font-size:21px;line-height:1.3;font-weight:700;color:${C.ink};">${esc(title)}</h1>
    ${intro ? para(intro, `color:${C.muted};`) : ""}
    ${body}
    ${link ? button(link, linkLabel || "Open the dashboard") : ""}
  </td></tr>
  <tr><td bgcolor="${C.soft}" style="background:${C.soft};border:1px solid ${C.line};border-top:0;border-radius:0 0 14px 14px;padding:14px 24px;font-family:${FONT};font-size:12px;line-height:1.5;color:${C.faint};">${footer}</td></tr>
</table></td></tr></table></body></html>`;
}
const footerText = (ctx, why) => [`Bulwark${ctx.version ? " " + ctx.version : ""} sent this through selfmail.`, why, "Choose what you get in Bulwark → Settings → Email alerts."].filter(Boolean).join(" ");
const footerHtml = (ctx, why) => esc(footerText(ctx, why));
const textBlock = (title, lines) => (lines.length ? `\n${title.toUpperCase()}\n${lines.map((l) => `  ${l}`).join("\n")}\n` : "");

// ------------------------------------------------------------------ waves
// items: [{type, sev, key, title, detail, at, first, n, alertKey}]
// ctx: {link, rpm, normalRpm, attacks, normalAttacks, members, banned, bansHour, strict,
//       nets: [{name, asn, n, banned}], patterns: [{name, n}], alerts: {key: {title, detail, sev, forecast, members}},
//       held, window, version}
export function renderWave(items, ctx = {}) {
  const level = worstOf(items), live = (x) => (x.alertKey && ctx.alerts?.[x.alertKey]) || null;
  const rows = [...items].sort((a, b) => SEVN[b.sev] - SEVN[a.sev] || b.at - a.at).map((x) => {
    const a = live(x), f = a?.forecast;
    const extra = [a?.members ? plural(a.members, "address", "addresses") : "", f?.nextHour ? `~${n(f.nextHour)} more expected next hour (${f.trend})` : "", x.n > 1 ? `updated ${x.n} times` : ""].filter(Boolean).join(" · ");
    return { sev: a?.sev && SEVN[a.sev] > SEVN[x.sev] ? a.sev : x.sev, title: a?.title || x.title, detail: a?.detail || x.detail, extra, time: hm(x.at) };
  });
  const top = rows[0];
  const more = rows.length - 1 + (ctx.held || 0);
  const subject = `Bulwark${level === "critical" ? " CRITICAL" : ""}: ${oneLine(top.title, 90)}${more ? ` (+${more} more)` : ""}`;
  const ratio = ctx.normalRpm > 0 ? ctx.rpm / ctx.normalRpm : null;
  const t = [
    { label: "Requests / min", value: n(ctx.rpm), sub: `normal ${rate(ctx.normalRpm)}${ratio && ratio >= 1.5 ? ` · <b style="color:${C.critical};">${ratio >= 10 ? n(ratio) : ratio.toFixed(1)}×</b>` : ""}`, hot: ratio >= 3 },
    { label: "Attacks / min", value: n(ctx.attacks), sub: `normal ${rate(ctx.normalAttacks)}`, hot: ctx.attacks > Math.max(10, 3 * (ctx.normalAttacks || 0)) },
    { label: "Banned", value: n(ctx.banned), sub: ctx.members ? `of ${plural(ctx.members, "address", "addresses")} in it` : `${n(ctx.bansHour)} in the last hour` },
  ];
  const nets = (ctx.nets || []).slice(0, 5), pats = (ctx.patterns || []).slice(0, 5);
  const intro = rows.length > 1
    ? `${plural(rows.length, "warning")} since ${hm(Math.min(...items.map((x) => x.first || x.at)))}${ctx.held ? `, and ${n(ctx.held)} more counted` : ""}. The worst first.`
    : oneLine(top.detail, 300);
  const strict = ctx.strict ? `<b style="color:${C.critical};">Strict mode is on</b> until ${hm(ctx.strict)}: a first payload bans.` : "";
  const body = [
    tiles(t),
    strict ? para(strict, "margin:12px 0 0;") : "",
    heading(rows.length > 1 ? "What happened" : "The warning"), alertRows(rows.slice(0, 12)),
    rows.length > 12 ? para(`…and ${n(rows.length - 12)} more on the dashboard.`, `color:${C.muted};margin-top:8px;`) : "",
    nets.length ? heading("Top networks") + table([{ label: "Network" }, { label: "Addresses", align: "right" }, { label: "Banned", align: "right" }],
      nets.map((x) => [`${esc(x.name)}${x.asn ? ` <span style="font-family:${MONO};font-size:12px;color:${C.faint};">AS${esc(x.asn)}</span>` : ""}`, n(x.n), n(x.banned)])) : "",
    pats.length ? heading("Top patterns") + table([{ label: "Pattern" }, { label: "Requests", align: "right" }], pats.map((x) => [esc(x.name), n(x.n)])) : "",
  ].join("");
  const why = `Wave emails come at most every ${Math.round((ctx.window || 15 * 60e3) / 60e3)} minutes; what happens in between is summed up in the next one.`;
  const html = layout({ level, kicker: "Wave warning", title: top.title, intro, body, link: safeLink(ctx.link), linkLabel: "Open the waves", footer: footerHtml(ctx, why), preheader: `${n(ctx.rpm)} requests a minute (normal ${rate(ctx.normalRpm)}). ${top.detail || ""}` });
  const text = [
    `${LABEL[level]}: ${top.title}`, "", intro, "",
    `Requests/min: ${n(ctx.rpm)} (normal ${rate(ctx.normalRpm)})`, `Attacks/min:  ${n(ctx.attacks)} (normal ${rate(ctx.normalAttacks)})`,
    `Banned:       ${n(ctx.banned)}${ctx.members ? ` of ${plural(ctx.members, "address", "addresses")}` : ` (${n(ctx.bansHour)} in the last hour)`}`,
    ctx.strict ? `Strict mode is on until ${hm(ctx.strict)}: a first payload bans.` : "",
    textBlock("What happened", rows.slice(0, 12).map((r) => `[${r.sev}] ${r.time} ${r.title}${r.detail ? ` - ${oneLine(r.detail, 200)}` : ""}${r.extra ? ` (${r.extra})` : ""}`)),
    textBlock("Top networks", nets.map((x) => `${x.name}${x.asn ? ` (AS${x.asn})` : ""}: ${plural(x.n, "address", "addresses")}, ${n(x.banned)} banned`)),
    textBlock("Top patterns", pats.map((x) => `${x.name}: ${plural(x.n, "request")}`)),
    safeLink(ctx.link) ? `\nOpen the waves: ${ctx.link}\n` : "",
    "--", footerText(ctx, why),
  ].join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { subject, text, html, level };
}

// ------------------------------------------------------------------ the guard, the app
// ctx: {link, sensors, hosts, held, window, version}
export function renderSystem(items, ctx = {}) {
  const level = worstOf(items), rows = [...items].sort((a, b) => SEVN[b.sev] - SEVN[a.sev] || b.at - a.at).map((x) => ({ ...x, time: hm(x.at), extra: x.n > 1 ? `${x.n} times` : "" }));
  const top = rows[0], allClear = level === "info";
  const shown = allClear ? "ok" : level;
  const subject = `Bulwark${level === "critical" ? " CRITICAL" : ""}: ${oneLine(top.title, 90)}${rows.length > 1 ? ` (+${rows.length - 1} more)` : ""}`;
  const state = ctx.sensors ? `The guard is connected now (${esc((ctx.hosts || []).join(", ") || plural(ctx.sensors, "host"))}).` : `No guard is connected right now: the gate is down, or running without Bulwark's guard (and then nothing checks its requests).`;
  const body = [para(state, `color:${C.muted};`), heading(rows.length > 1 ? "What happened" : "The event"), alertRows(rows.slice(0, 10))].join("");
  const why = `These come at most every ${Math.round((ctx.window || 30 * 60e3) / 60e3)} minutes.`;
  const html = layout({ level: shown, kicker: "Health", title: top.title, intro: oneLine(top.detail, 300), body, link: safeLink(ctx.link), footer: footerHtml(ctx, why) });
  const text = [`${LABEL[shown]}: ${top.title}`, "", oneLine(top.detail, 300), "", state.replace(/<[^>]+>/g, ""),
    textBlock("What happened", rows.map((r) => `[${r.sev}] ${r.time} ${r.title}${r.detail ? ` - ${oneLine(r.detail, 200)}` : ""}${r.extra ? ` (${r.extra})` : ""}`)),
    safeLink(ctx.link) ? `\nOpen the dashboard: ${ctx.link}\n` : "", "--", footerText(ctx, why)].join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { subject, text, html, level };
}

// ------------------------------------------------------------------ the day
// ctx: {link, totals: {req, attacks, bans, newIps}, waves: [{title, sev, first, members}], nets, patterns, version}
export function renderDigest(ctx = {}) {
  const T = ctx.totals || {}, waves = (ctx.waves || []).slice(0, 8), nets = (ctx.nets || []).slice(0, 5), pats = (ctx.patterns || []).slice(0, 5);
  const level = waves.some((w) => w.sev === "critical") ? "warn" : "ok";
  const title = waves.length ? `${plural(waves.length, "wave")} and ${plural(T.bans, "ban")} in the last 24 hours` : `A quiet day: ${plural(T.bans, "ban")}, no waves`;
  const subject = `Bulwark daily: ${title}`;
  const body = [
    tiles([{ label: "Requests", value: n(T.req), sub: `${n(T.newIps)} new addresses` }, { label: "Attacks", value: n(T.attacks), sub: "payloads and probes" }, { label: "Banned", value: n(T.bans), sub: "new bans" }]),
    waves.length ? heading("Waves") + alertRows(waves.map((w) => ({ sev: w.sev, title: w.title, detail: "", extra: w.members ? plural(w.members, "address", "addresses") : "", time: hm(w.first) }))) : "",
    nets.length ? heading("Top networks") + table([{ label: "Network" }, { label: "Addresses", align: "right" }, { label: "Banned", align: "right" }],
      nets.map((x) => [`${esc(x.name)}${x.asn ? ` <span style="font-family:${MONO};font-size:12px;color:${C.faint};">AS${esc(x.asn)}</span>` : ""}`, n(x.n), n(x.banned)])) : "",
    pats.length ? heading("Top patterns") + table([{ label: "Pattern" }, { label: "Requests", align: "right" }], pats.map((x) => [esc(x.name), n(x.n)])) : "",
  ].join("");
  const why = "The digest comes once a day.";
  const html = layout({ level, kicker: "Daily digest", title, intro: "What Bulwark saw and did since this time yesterday.", body, link: safeLink(ctx.link), footer: footerHtml(ctx, why) });
  const text = [`BULWARK DAILY: ${title}`, "", `Requests: ${n(T.req)} (${n(T.newIps)} new addresses)`, `Attacks:  ${n(T.attacks)}`, `Banned:   ${n(T.bans)}`,
    textBlock("Waves", waves.map((w) => `[${w.sev}] ${hm(w.first)} ${w.title}`)),
    textBlock("Top networks", nets.map((x) => `${x.name}${x.asn ? ` (AS${x.asn})` : ""}: ${plural(x.n, "address", "addresses")}, ${n(x.banned)} banned`)),
    textBlock("Top patterns", pats.map((x) => `${x.name}: ${plural(x.n, "request")}`)),
    safeLink(ctx.link) ? `\nOpen the dashboard: ${ctx.link}\n` : "", "--", footerText(ctx, why)].join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { subject, text, html, level: level === "ok" ? "info" : level };
}

// ------------------------------------------------------------------ a test
// ctx: {link, settings, selfmail, version}
export function renderTest(ctx = {}) {
  const s = ctx.settings || {}, on = !!s.mailOn;
  const what = [
    ["Waves and surges", s.mailWaves], ["New campaigns and strict mode", s.mailCampaigns], ["Critical: the guard gone, the app failing", s.mailCritical], ["A daily digest at 8:00", s.mailDigest],
  ];
  const title = "Email alerts work";
  const intro = on ? "This is a test. When something happens you'll get emails like this one." : "This is a test. Email alerts are still off: turn them on in Settings to get them.";
  const body = [
    heading("What you'll get"),
    table([{ label: "Event" }, { label: "Email", align: "right" }], what.map(([k, v]) => [esc(k), v && on ? `<b style="color:${C.ok};">on</b>` : `<span style="color:${C.faint};">off</span>`])),
    para(`At most one email every 15 minutes about waves, with everything in between summed up; at most 12 an hour in all.`, `color:${C.muted};margin-top:14px;`),
  ].join("");
  const html = layout({ level: "ok", kicker: "Test email", title, intro, body, link: safeLink(ctx.link), footer: footerHtml(ctx, ctx.selfmail?.version ? `(selfmail ${ctx.selfmail.version})` : "") });
  const text = [`BULWARK: ${title}`, "", intro, textBlock("What you'll get", what.map(([k, v]) => `${k}: ${v && on ? "on" : "off"}`)),
    safeLink(ctx.link) ? `Open the dashboard: ${ctx.link}\n` : "", "--", footerText(ctx, "")].join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { subject: "Bulwark: a test email", text, html, level: "info" };
}
