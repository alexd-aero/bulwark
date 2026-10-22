// Seeing through encodings: a request's path and query, the way the app
// behind will understand them, before anything is matched. Evasion that
// pattern matchers miss and this catches:
//
//   multi-pass URL decoding   %252e%252e%252f -> %2e%2e%2f -> ../ (up to 3 passes)
//   %uXXXX                    IIS-style unicode escapes
//   overlong UTF-8            %c0%af -> /, %c0%ae -> ., %e0%80%af -> /
//   invalid bytes             kept as Latin-1 characters, never dropped
//   best-fit and look-alikes  fullwidth ．／＼, ∕, the soft hyphen (CVE-2024-4577)
//   null bytes, backslashes   dropped / turned into slashes
//   HTML entities             &lt; &#x3c; &#60 &colon; …
//   + in the query            a space
//   dot segments              /a/./b/../../c -> /c (Tomcat's ..; too)
//
// What it had to undo is reported (flags), because a hit that was hidden
// is worth more than one that wasn't.

const HEX = (c) => (c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1);

// one pass of percent-decoding, byte sequences as UTF-8 (overlong forms decoded and flagged)
export function decodeOnce(s, flags) {
  if (s.indexOf("%") < 0) return s;
  let out = "", i = 0;
  const n = s.length;
  while (i < n) {
    const ch = s.charCodeAt(i);
    if (ch !== 37) { out += s[i++]; continue; }
    // %uXXXX
    if ((s[i + 1] === "u" || s[i + 1] === "U") && i + 5 < n) {
      const a = HEX(s.charCodeAt(i + 2)), b = HEX(s.charCodeAt(i + 3)), c = HEX(s.charCodeAt(i + 4)), d = HEX(s.charCodeAt(i + 5));
      if (a >= 0 && b >= 0 && c >= 0 && d >= 0) { out += String.fromCharCode((a << 12) | (b << 8) | (c << 4) | d); flags.unicode = true; i += 6; continue; }
    }
    // a run of %XX bytes
    const bytes = [];
    while (i + 2 < n && s.charCodeAt(i) === 37) {
      const h = HEX(s.charCodeAt(i + 1)), l = HEX(s.charCodeAt(i + 2));
      if (h < 0 || l < 0) break;
      bytes.push((h << 4) | l); i += 3;
    }
    if (!bytes.length) { out += "%"; i++; continue; }
    out += utf8Loose(bytes, flags);
  }
  return out;
}
function utf8Loose(b, flags) {
  let out = "";
  for (let i = 0; i < b.length;) {
    const x = b[i], c1 = b[i + 1], c2 = b[i + 2], c3 = b[i + 3];
    const cont = (y) => y !== undefined && (y & 0xc0) === 0x80;
    if (x < 0x80) { out += String.fromCharCode(x); i++; continue; }
    if (x >= 0xc0 && x <= 0xdf && cont(c1)) {
      const cp = ((x & 0x1f) << 6) | (c1 & 0x3f);
      if (x < 0xc2) flags.overlong = true;
      out += String.fromCharCode(cp); i += 2; continue;
    }
    if (x >= 0xe0 && x <= 0xef && cont(c1) && cont(c2)) {
      const cp = ((x & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f);
      if (cp < 0x800) flags.overlong = true;
      out += String.fromCharCode(cp); i += 3; continue;
    }
    if (x >= 0xf0 && x <= 0xf4 && cont(c1) && cont(c2) && cont(c3)) {
      const cp = ((x & 0x07) << 18) | ((c1 & 0x3f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f);
      if (cp < 0x10000) flags.overlong = true;
      out += String.fromCodePoint(Math.min(cp, 0x10ffff)); i += 4; continue;
    }
    out += String.fromCharCode(x); i++;                 // not UTF-8 (Latin-1 filenames): as it is
  }
  return out;
}

// look-alikes that some servers fold to ASCII ("best fit"): flagged, folded
const FOLD = { "­": "-", "‐": "-", "‑": "-", "−": "-", "∕": "/", "⁄": "/", "⧸": "/", "∖": "\\", "⧹": "\\",
               "․": ".", "‥": "..", "…": "...", "﹒": ".", "。": ".", "ʼ": "'", "‘": "'", "’": "'", "“": '"', "”": '"',
               "‹": "<", "›": ">", "˂": "<", "˃": ">", "〈": "<", "〉": ">", "＜": "<", "＞": ">" };
const FOLD_RE = /[­‐‑−∕⁄⧸∖⧹․‥…﹒。ʼ‘’“”‹›˂˃〈〉！-～]/g;
export function fold(s, flags) {
  if (!/[^\x00-\x7f]/.test(s)) return s;
  return s.replace(FOLD_RE, (c) => {
    flags.fold = true;
    const code = c.charCodeAt(0);
    if (code >= 0xff01 && code <= 0xff5e) return String.fromCharCode(code - 0xfee0);      // fullwidth
    return FOLD[c] ?? c;
  });
}

const NAMED = { lt: "<", gt: ">", quot: '"', apos: "'", amp: "&", colon: ":", lpar: "(", rpar: ")", sol: "/", bsol: "\\", tab: "\t", newline: "\n", nbsp: " ",
                semi: ";", equals: "=", period: ".", comma: ",", excl: "!", num: "#", dollar: "$", lsqb: "[", rsqb: "]", lcub: "{", rcub: "}", grave: "`", hat: "^",
                ast: "*", plus: "+", percnt: "%", quest: "?", vert: "|", lowbar: "_", hyphen: "-", dash: "-" };
const ENT_RE = /&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});?/gi;
export function entities(s, flags) {
  if (s.indexOf("&") < 0) return s;
  return s.replace(ENT_RE, (m, e) => {
    let r;
    if (e[0] === "#") { const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); r = cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : null; }
    else r = NAMED[e.toLowerCase()] ?? null;
    if (r === null) return m;
    flags.entity = true;
    return r;
  });
}

// up to three passes; more than one is double encoding
export function decodeDeep(s, flags) {
  let cur = s;
  for (let pass = 0; pass < 3; pass++) {
    if (cur.indexOf("%") < 0) break;
    const next = decodeOnce(cur, flags);
    if (next === cur) break;
    if (pass > 0) flags.double = true;
    cur = next;
  }
  return cur;
}

// a path's dot segments resolved, the way a server would (Tomcat's "..;" too)
export function collapse(path) {
  if (!/\/\.|\/\/|;/.test(path)) return path;
  const out = [];
  for (let seg of path.split("/")) {
    const semi = seg.indexOf(";");
    if (semi >= 0) seg = seg.slice(0, semi);
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { out.pop(); continue; }
    out.push(seg);
  }
  return "/" + out.join("/") + (/\/$/.test(path) && out.length ? "/" : "");
}

const NEEDS = /[%&\\\u0000-\u001f\u007f-￿]|\/\.|\/\//;
// A request target (path?query) -> what the app will see.
//   path      the path, decoded (dot segments kept: they're evidence)
//   collapsed the path with dot segments resolved
//   query     the query string, decoded value by value (& kept as the separator)
//   params    [[name, value]] decoded (at most 64)
//   nparams   how many there were
//   flags     what had to be undone: double, unicode, overlong, nul, backslash, entity, fold
export function normalize(target) {
  const raw = String(target || "");
  const q = raw.indexOf("?");
  const rawPath = q < 0 ? raw : raw.slice(0, q), rawQuery = q < 0 ? "" : raw.slice(q + 1);
  const flags = {};
  let path = rawPath;
  if (NEEDS.test(rawPath)) {
    path = fold(decodeDeep(rawPath, flags), flags);
    if (path.indexOf("\u0000") >= 0) { flags.nul = true; path = path.replace(/\u0000/g, ""); }
    if (path.indexOf("\\") >= 0) { flags.backslash = true; path = path.replace(/\\/g, "/"); }
  }
  const out = { raw, rawPath, rawQuery, path, collapsed: collapse(path), query: "", params: [], nparams: 0, flags };
  if (!rawQuery) return out;
  const parts = rawQuery.split("&");
  out.nparams = parts.length;
  const vals = [];
  for (let i = 0; i < parts.length && i < 64; i++) {
    const p = parts[i];
    if (!p) continue;
    const eq = p.indexOf("=");
    const name = value(eq < 0 ? p : p.slice(0, eq), flags), val = eq < 0 ? "" : value(p.slice(eq + 1), flags);
    out.params.push([name, val]);
    vals.push(eq < 0 ? name : `${name}=${val}`);
  }
  out.query = vals.join("&");
  return out;
}
function value(v, flags) {
  if (!v) return v;
  if (v.indexOf("+") >= 0) v = v.replace(/\+/g, " ");
  if (!NEEDS.test(v)) return v;
  v = entities(fold(decodeDeep(v, flags), flags), flags);
  if (v.indexOf("\u0000") >= 0) { flags.nul = true; v = v.replace(/\u0000/g, ""); }
  return v;
}
