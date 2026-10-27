// Email alerts, through selfmail (the mail-server addon), only while it is there.
//
//   finding it   selfmail announces itself in the Weft mesh: <mesh>/selfmail.json
//                (~/.config/weft/mesh, or $MESH), refreshed every 30 s at most. An
//                entry older than 90 s is stale: selfmail isn't running, and then
//                nothing about email shows anywhere (the API says email: null)
//   sending      POST its notify.url with the key in notify.keyFile (x-selfmail-key);
//                selfmail sends it from "Bulwark" <bulwark@its domain>, to notify.to
//                unless Settings names someone else. Plain http only to this machine
//   how often    a wave (or a campaign, strict mode) goes out after a few seconds (a
//                burst becomes one email), then at most one every 15 minutes: what
//                comes meanwhile is summed up in the next one. A wave turning
//                critical doesn't wait the 15 minutes, only one. Critical events (the
//                guard gone, the app crashing or failing) at most every 30 minutes.
//                A digest at 8:00 if asked. 12 an hour in all, whatever happens
//                (selfmail allows about 30); a 429 waits 15 minutes
//   never        throws into its caller: event() only queues, sending is on its own,
//                with a timeout
//
// Off until you turn it on (Settings → Email alerts).

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { renderWave, renderSystem, renderDigest, renderTest } from "./mailview.mjs";

const MIN = 60e3, HOUR = 60 * MIN;
export const STALE_S = 90;
export const MAIL_DEFAULTS = { mailOn: false, mailTo: "", mailWaves: true, mailCampaigns: true, mailCritical: true, mailDigest: false };
export const MAIL_KEYS = Object.keys(MAIL_DEFAULTS);
export const LIMITS = { wave: 15 * MIN, system: 30 * MIN, perHour: 12, gather: 5000, escalate: MIN, backoff429: 15 * MIN, backoffError: 5 * MIN, digestHour: 8, testGap: 15e3 };
const SEV = { info: 0, warn: 1, critical: 2 };
const MAX_PENDING = 40;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

export const validAddress = (a) => typeof a === "string" && a.length <= 254 && /^[^\s@<>()",;:\\]+@[^\s@<>()",;:\\]+\.[^\s@<>()",;:\\.]{2,}$/.test(a);
// the same place Weft's tools use (weft/lib.sh)
export function meshDir(env = process.env) {
  return env.MESH || env.WEFT_MESH || join(env.XDG_CONFIG_HOME || join(homedir(), ".config"), "weft", "mesh");
}

// selfmail's mesh entry, if it is fresh and usable; null otherwise (missing, stale, odd)
export function readSelfmail({ dir = meshDir(), now = Date.now() } = {}) {
  let m;
  try { m = JSON.parse(readFileSync(join(dir, "selfmail.json"), "utf8")); } catch { return null; }
  if (!m || typeof m !== "object" || m.id !== "selfmail") return null;
  const updated = Number(m.updated), age = now / 1000 - updated;
  if (!Number.isFinite(updated) || age > STALE_S || age < -STALE_S) return null;
  const n = m.notify;
  if (!n || typeof n !== "object" || typeof n.url !== "string" || typeof n.keyFile !== "string" || !n.keyFile) return null;
  let u;
  try { u = new URL(n.url); } catch { return null; }
  // the key goes with every request: plain http only to this machine
  if (!(u.protocol === "https:" || (u.protocol === "http:" && LOOPBACK.has(u.hostname)))) return null;
  return {
    name: String(m.name || "selfmail").slice(0, 60), version: String(m.version || "").slice(0, 30), updated: updated * 1000,
    notify: { url: u.href, keyFile: n.keyFile, to: validAddress(n.to) ? n.to : "",
              domains: Array.isArray(n.domains) ? n.domains.filter((d) => typeof d === "string").slice(0, 10) : [] },
  };
}

const blankState = () => ({ last: { wave: 0, system: 0 }, lastSev: { wave: "", system: "" }, pending: { wave: [], system: [] }, held: { wave: 0, system: 0 },
                            hour: { at: 0, n: 0 }, backoff: 0, digestDay: "", log: [], lastOk: null, lastError: null, testAt: 0 });
const localDay = (t) => { const d = new Date(t); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };

export class Mailer {
  // settings: () => the settings (mail* keys); context: (kind, items) => what the email says
  // (mailview.mjs), from the brain; dir: the mesh (tests); now: the clock (tests)
  constructor({ file, settings, context, log, fetchImpl, now, dir, version = "", gather = LIMITS.gather } = {}) {
    this.file = file; this.settings = settings || (() => ({ ...MAIL_DEFAULTS }));
    this.context = context || (() => ({})); this.log = log || (() => {});
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.now = now || (() => Date.now()); this.dir = dir; this.version = version; this.gather = gather;
    this.state = blankState();
    if (file) {
      try {
        const s = JSON.parse(readFileSync(file, "utf8")), b = blankState();
        this.state = { ...b, ...s, last: { ...b.last, ...s.last }, lastSev: { ...b.lastSev, ...s.lastSev }, held: { ...b.held, ...s.held },
                       pending: { wave: Array.isArray(s.pending?.wave) ? s.pending.wave : [], system: Array.isArray(s.pending?.system) ? s.pending.system : [] },
                       hour: { ...b.hour, ...s.hour }, log: Array.isArray(s.log) ? s.log : [] };
      } catch { /* first run */ }
    }
    this.busy = { wave: false, system: false, digest: false };
    this.timers = { wave: null, system: null };
  }
  save() {
    if (!this.file || !this.dirty) return;
    this.state.log = this.state.log.slice(0, 50);
    try { writeFileSync(this.file + ".tmp", JSON.stringify(this.state)); renameSync(this.file + ".tmp", this.file); this.dirty = false; } catch { /* next time */ }
  }
  stop() { for (const k of Object.keys(this.timers)) { clearTimeout(this.timers[k]); this.timers[k] = null; } this.save(); }
  selfmail() { return readSelfmail({ dir: this.dir || meshDir(), now: this.now() }); }
  // for event(): a huge wave raises thousands of alerts, the mesh is read once every 5 s at most
  present() {
    const now = this.now();
    if (!this.seen || now - this.seen.at > 5000 || now < this.seen.at) this.seen = { at: now, ok: !!this.selfmail() };
    return this.seen.ok;
  }

  // ------------------------------------------------------------ events
  // ev: {type: "wave"|"campaign"|"strict"|"critical", sev, key, title, detail, alertKey?}
  // -> true if it was queued. Cheap, never throws.
  event(ev) {
    try {
      const s = this.settings();
      if (!s.mailOn) return false;
      const want = { wave: s.mailWaves, campaign: s.mailCampaigns, strict: s.mailCampaigns, critical: s.mailCritical }[ev.type];
      if (!want || !this.present()) return false;
      const stream = ev.type === "critical" ? "system" : "wave", at = this.now(), q = this.state.pending[stream];
      const item = { type: ev.type, sev: SEV[ev.sev] != null ? ev.sev : "warn", key: String(ev.key || `${ev.type}:${at}`).slice(0, 300),
                     title: String(ev.title || "").slice(0, 200), detail: String(ev.detail || "").slice(0, 600), at, first: at, n: 1 };
      if (ev.alertKey) item.alertKey = String(ev.alertKey).slice(0, 300);
      const old = q.find((x) => x.key === item.key);
      if (old) { old.n++; old.at = at; old.title = item.title || old.title; old.detail = item.detail || old.detail; if (SEV[item.sev] > SEV[old.sev]) old.sev = item.sev; }
      else if (q.length < MAX_PENDING) q.push(item);
      else this.state.held[stream]++;
      this.dirty = true;
      // a burst (a wave raises one alert per network) becomes one email
      if (!this.timers[stream]) {
        this.timers[stream] = setTimeout(() => { this.timers[stream] = null; this.pump(stream); }, this.gather);
        this.timers[stream].unref?.();
      }
      return true;
    } catch (e) { this.log("mail:", e.message); return false; }
  }
  // the hourly allowance: take one, or just ask
  budget(now, take) {
    const h = this.state.hour;
    if (now - h.at >= HOUR) { h.at = now; h.n = 0; }
    if (h.n >= LIMITS.perHour) return false;
    if (take) { h.n++; this.dirty = true; }
    return true;
  }
  // may this stream send now?
  ready(stream, now = this.now()) {
    const st = this.state;
    if (!st.pending[stream].length || this.busy[stream] || now < st.backoff || !this.budget(now, false)) return false;
    const since = now - (st.last[stream] || 0);
    if (since >= LIMITS[stream]) return true;
    // a wave turning critical: a minute after the last one, not the whole window
    return since >= LIMITS.escalate && (SEV[st.lastSev[stream]] ?? -1) < SEV.critical && st.pending[stream].some((x) => x.sev === "critical");
  }
  pump(stream) { if (this.ready(stream)) this.flush(stream).catch((e) => this.log("mail:", e.message)); }
  // every 30 s (the brain's tick): what waited for its window, and the digest
  tick() {
    try {
      for (const stream of ["wave", "system"]) if (!this.timers[stream]) this.pump(stream);
      this.digestDue();
    } catch (e) { this.log("mail:", e.message); }
  }
  // send what waits on a stream as one email (ready() said so, or a test)
  async flush(stream) {
    const st = this.state, now = this.now();
    const items = st.pending[stream].splice(0), held = st.held[stream];
    if (!items.length) return null;
    st.held[stream] = 0; this.dirty = true;
    const prevLast = st.last[stream];
    this.busy[stream] = true; st.last[stream] = now; this.budget(now, true);
    const worst = items.reduce((w, x) => (SEV[x.sev] > SEV[w] ? x.sev : w), "info");
    try {
      const ctx = { ...(await this.context(stream, items)), version: this.version, held, window: LIMITS[stream] };
      const msg = stream === "system" ? renderSystem(items, ctx) : renderWave(items, ctx);
      const r = await this.deliver(msg, stream);
      st.lastSev[stream] = worst;
      return r;
    } catch (e) {
      // kept for the next try (three at most), after a pause
      const again = items.filter((x) => (x.tries = (x.tries || 0) + 1) < 3);
      st.pending[stream].unshift(...again);
      st.pending[stream].splice(MAX_PENDING);
      st.held[stream] += held;
      st.last[stream] = prevLast;
      st.backoff = now + (e.rate ? LIMITS.backoff429 : LIMITS.backoffError);
      if (!e.recorded) { this.state.lastError = { at: now, kind: stream, error: String(e.message).slice(0, 200) }; this.log("mail:", e.message); }
      return null;
    } finally { this.busy[stream] = false; }
  }
  digestDue() {
    const s = this.settings(), now = this.now(), st = this.state;
    if (!s.mailOn || !s.mailDigest || this.busy.digest) return;
    const day = localDay(now);
    if (st.digestDay === day || new Date(now).getHours() < LIMITS.digestHour || now < st.backoff || !this.budget(now, false) || !this.selfmail()) return;
    const prev = st.digestDay;
    st.digestDay = day; this.busy.digest = true; this.budget(now, true); this.dirty = true;
    (async () => this.deliver(renderDigest({ ...(await this.context("digest", [])), version: this.version }), "digest"))()
      .catch((e) => { st.digestDay = prev; st.backoff = now + (e.rate ? LIMITS.backoff429 : LIMITS.backoffError); })
      .finally(() => { this.busy.digest = false; });
  }
  // a test, from Settings (on or off): selfmail must be there
  async test() {
    const now = this.now(), sm = this.selfmail();
    if (!sm) throw Object.assign(new Error("selfmail isn't running."), { status: 404 });
    if (now - this.state.testAt < LIMITS.testGap) throw Object.assign(new Error("A test went out a moment ago: give it a few seconds."), { status: 429 });
    if (!this.budget(now, true)) throw Object.assign(new Error(`${LIMITS.perHour} emails in the last hour already: try again later.`), { status: 429 });
    this.state.testAt = now; this.dirty = true;
    return this.deliver(renderTest({ ...(await this.context("test", [])), version: this.version, settings: this.settings(), selfmail: sm }), "test");
  }

  // ------------------------------------------------------------ the request
  async deliver({ subject, text, html, level }, kind) {
    const now = this.now();
    const fail = (msg, extra = {}) => {
      this.state.lastError = { at: now, kind, subject, error: msg };
      this.note({ kind, subject, ok: false, error: msg });
      this.log(`mail (${kind}): ${msg}`);
      this.save();
      return Object.assign(new Error(msg), { recorded: true }, extra);
    };
    const sm = this.selfmail();
    if (!sm) throw fail("selfmail isn't running", { status: 404 });
    let key;
    try { key = readFileSync(sm.notify.keyFile, "utf8").trim(); } catch (e) { throw fail(`can't read selfmail's key (${e.code || e.message})`); }
    if (!key) throw fail("selfmail's key file is empty");
    const s = this.settings(), to = validAddress(s.mailTo) ? s.mailTo : undefined;
    let r, j = {};
    try {
      r = await this.fetch(sm.notify.url, {
        method: "POST", headers: { "Content-Type": "application/json", "x-selfmail-key": key, "X-Selfmail": "1" },
        body: JSON.stringify({ app: "bulwark", ...(to ? { to } : {}), subject, text, html, level }), signal: AbortSignal.timeout(15000),
      });
      j = await r.json().catch(() => ({}));
    } catch (e) { throw fail(e.name === "TimeoutError" || e.name === "AbortError" ? "selfmail didn't answer within 15 s" : `couldn't reach selfmail (${e.cause?.code || e.cause?.errors?.[0]?.code || e.message})`); }
    if (r.status === 429) throw fail(String(j.error || "selfmail's limit for Bulwark is reached (about 30 an hour)").slice(0, 200), { rate: true, status: 429 });
    if (!r.ok || j.ok !== true) throw fail(String(j.error || `selfmail answered HTTP ${r.status}`).slice(0, 200), { status: 502 });
    const sentTo = to || sm.notify.to || "";
    this.state.lastOk = { at: now, kind, subject, id: j.id ?? null, to: sentTo };
    this.note({ kind, subject, ok: true, id: j.id ?? null, to: sentTo });
    this.save();               // at once: a crash loop must not forget it just sent one
    return { ok: true, id: j.id ?? null, to: sentTo };
  }
  note(x) { this.state.log.unshift({ at: this.now(), ...x }); this.state.log.length = Math.min(this.state.log.length, 50); this.dirty = true; }

  // ------------------------------------------------------------ the dashboard's view
  // null when selfmail isn't there: nothing about email shows anywhere
  status() {
    const sm = this.selfmail();
    if (!sm) return null;
    const st = this.state, s = this.settings();
    const nextAt = (stream) => (st.pending[stream].length ? Math.max(st.backoff, (st.last[stream] || 0) + LIMITS[stream]) : null);
    return {
      selfmail: { name: sm.name, version: sm.version, to: sm.notify.to, domains: sm.notify.domains, seen: sm.updated },
      to: validAddress(s.mailTo) ? s.mailTo : sm.notify.to, defaultTo: sm.notify.to,
      lastSent: st.lastOk, lastError: st.lastError && (!st.lastOk || st.lastError.at > st.lastOk.at) ? st.lastError : null,
      pending: st.pending.wave.length + st.pending.system.length, nextAt: [nextAt("wave"), nextAt("system")].filter(Boolean).sort((a, b) => a - b)[0] || null,
      pausedUntil: st.backoff > this.now() ? st.backoff : null, sentThisHour: this.now() - st.hour.at < HOUR ? st.hour.n : 0,
      log: st.log.slice(0, 8), limits: { waveMinutes: LIMITS.wave / MIN, systemMinutes: LIMITS.system / MIN, perHour: LIMITS.perHour, digestHour: LIMITS.digestHour },
    };
  }
}
