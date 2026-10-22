// SQL injection and cross-site scripting, judged by shape rather than by
// keyword. A keyword list flags "select a file from the menu" and misses
// "1'/**/UnIoN/**/sElEcT/**/1,2--"; a tokenizer sees the second for what it
// is: a string closed early, a UNION, a SELECT, a list, a comment that cuts
// the rest off. The idea is libinjection's: tokenize the value as SQL (as it
// is, and as if it were inside '…' and "…"), fold the tokens to a fingerprint
// ("s&sos" is ' OR '1'='1) and look for the shapes injections take.
//
// sqli(value) / xss(value) -> null | {sev, why}

// ------------------------------------------------------------------ SQL
const STMT = new Set(["select", "insert", "update", "delete", "drop", "create", "alter", "exec", "execute", "declare", "truncate", "shutdown", "merge", "call"]);
const LOGIC = new Set(["and", "or", "xor"]);
const OPW = new Set(["like", "rlike", "regexp", "between", "is", "in", "div", "mod", "sounds", "not"]);
const KW = new Set(["from", "where", "having", "group", "order", "by", "limit", "offset", "into", "values", "table", "database", "schema", "case", "when", "then",
                    "else", "end", "null", "true", "false", "all", "distinct", "as", "join", "procedure", "outfile", "dumpfile", "information_schema", "sysobjects",
                    "syscolumns", "waitfor", "delay", "top", "char", "nchar", "varchar", "convert", "cast", "concat", "ascii", "substring", "mid", "count", "if"]);
// functions that only an injection calls (time-based, error-based, file access)
const DANGER = new Set(["sleep", "pg_sleep", "benchmark", "extractvalue", "updatexml", "load_file", "sys_eval", "sys_exec", "xp_cmdshell", "xp_dirtree",
                        "randomblob", "dbms_pipe", "utl_inaddr", "utl_http", "make_set", "elt", "exp", "geometrycollection", "multipoint", "polygon", "gtid_subset"]);
const INFO = new Set(["information_schema", "sysobjects", "syscolumns", "pg_catalog", "mysql", "sqlite_master", "all_tables", "user_tables"]);

function tokens(s, max = 24) {
  const out = [];
  let i = 0;
  const n = s.length;
  const word = /[A-Za-z_$][\w$]*/y, num = /(0x[0-9a-f]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?|\.\d+)/iy;
  while (i < n && out.length < max) {
    const c = s[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v" || c === " ") { i++; continue; }
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      for (; j < n; j++) { if (s[j] === "\\") { j++; continue; } if (s[j] === c) { if (s[j + 1] === c) { j++; continue; } break; } }
      out.push({ t: "s" }); i = j + 1; continue;
    }
    if (c === "-" && s[i + 1] === "-") { out.push({ t: "c" }); break; }
    if (c === "#") { out.push({ t: "c" }); break; }
    if (c === "/" && s[i + 1] === "*") {
      if (s[i + 2] === "!") { i += 3; while (i < n && /\d/.test(s[i])) i++; continue; }    // MySQL's executable comment: its inside is code
      const e = s.indexOf("*/", i + 2);
      if (e < 0) { out.push({ t: "c" }); break; }
      i = e + 2; continue;                                                                 // an inline comment is whitespace
    }
    if (c === "*" && s[i + 1] === "/") { i += 2; continue; }
    if (c === "@") { let j = i + 1; if (s[j] === "@") j++; word.lastIndex = j; const m = word.exec(s); out.push({ t: "v" }); i = m ? word.lastIndex : j; continue; }
    if (c >= "0" && c <= "9" || (c === "." && s[i + 1] >= "0" && s[i + 1] <= "9")) { num.lastIndex = i; const m = num.exec(s); i = m ? num.lastIndex : i + 1; out.push({ t: "n" }); continue; }
    word.lastIndex = i;
    const w = word.exec(s);
    if (w) {
      i = word.lastIndex;
      const lw = w[0].toLowerCase();
      let k = i; while (k < n && (s[k] === " " || s[k] === "\t")) k++;
      const call = s[k] === "(";
      if (lw === "union") out.push({ t: "U" });
      else if (STMT.has(lw)) out.push({ t: "E" });
      else if (LOGIC.has(lw)) out.push({ t: "&" });
      else if (OPW.has(lw)) out.push({ t: "o" });
      else if (DANGER.has(lw) && call) out.push({ t: "F", w: lw });
      else if (INFO.has(lw)) out.push({ t: "k", w: lw, info: true });
      else if (call) out.push({ t: "f", w: lw });
      else if (KW.has(lw)) out.push({ t: "k", w: lw });
      else out.push({ t: "b", w: lw });
      continue;
    }
    if (c === "|" && s[i + 1] === "|" || c === "&" && s[i + 1] === "&") { out.push({ t: "&" }); i += 2; continue; }
    if ("=<>!^~+-*/%:|&".includes(c)) { let j = i + 1; while (j < n && "=<>!|&".includes(s[j])) j++; if (out[out.length - 1]?.t !== "o") out.push({ t: "o" }); i = j; continue; }
    if (c === "(" || c === ")" || c === "," || c === ";") { out.push({ t: c }); i++; continue; }
    i++;
  }
  return out;
}
const fp = (ts) => ts.map((x) => x.t).join("");

// the shapes of an injection, over a fingerprint
const CRIT = [
  [/^[sn]\)*&\(*[sn]\)*o\(*[sn]/, "a tautology after a closed string (' OR '1'='1)"],
  [/^s\)*&\(*[sn]\)*(c|$)/, "a closed string and a condition, the rest commented out"],
  [/^s\)*o?c/, "a string closed early, the rest commented out (admin'--)"],
  [/^[sn]\)*;\(*E/, "a second statement after a closed string ('; DROP …)"],
  [/^o?[sn]?\)*Uk?\(*E/, "UNION SELECT after a value"],
  [/Uk?\(*E\(*[nfFkvso,(]/, "UNION SELECT"],
  [/^[sn]\)*&\(*F/, "a time- or error-based function after a value (' AND SLEEP(5))"],
  [/^[sn]\)*o\(*F/, "a function call glued to a value (1'+sleep(5))"],
  [/^[sn]\)*kk?n\)*(c|$)/, "ORDER BY / GROUP BY column probing"],
];
const HIGH = [
  [/^[sn]\)*&\(*[snbv]\)*o\(*[snbv]/, "a condition after a value (1 OR a=a)"],
  [/^[sn]\)*&\(*[sn]$/, "a boolean condition after a closed string"],
];

export function sqli(v) {
  if (!v || v.length < 2) return null;
  const low = v.toLowerCase();
  // a cheap gate: nothing an injection needs, no tokenizing
  if (!/['"`]|\b(or|and|xor|union|select|sleep|benchmark|waitfor|order|group|having|exec|drop|insert|update|delete|extractvalue|updatexml|information_schema|load_file)\b|--|#|\/\*|;|@@|\|\||&&/.test(low)) return null;
  if (/\bwaitfor\s+delay\s+['"]\d/.test(low)) return { sev: "critical", why: "WAITFOR DELAY (time-based blind)" };
  if (/\binto\s+(out|dump)file\b/.test(low) && /\bselect\b/.test(low)) return { sev: "critical", why: "SELECT … INTO OUTFILE (writing a file)" };
  if (/\bxp_cmdshell\b/.test(low)) return { sev: "critical", why: "xp_cmdshell (commands through SQL Server)" };
  let best = null;
  const consider = (ts, quoted) => {
    const f = fp(ts);
    for (const [re, why] of CRIT) if (re.test(f)) return { sev: "critical", why, fp: f };
    if (ts.some((x) => x.t === "F" && ["extractvalue", "updatexml", "load_file", "sys_eval", "sys_exec", "gtid_subset"].includes(x.w))) return { sev: "critical", why: "an error-based or file-reading SQL function", fp: f };
    if (ts.some((x) => x.t === "E") && ts.some((x) => x.info)) return { sev: "critical", why: "reading the database's catalog (information_schema)", fp: f };
    for (const [re, why] of HIGH) if (re.test(f)) return { sev: quoted ? "critical" : "high", why, fp: f };
    if (ts.some((x) => x.t === "F")) return { sev: "high", why: "a time-based SQL function (sleep, benchmark)", fp: f };
    if (ts.some((x) => x.info) || ts.some((x) => x.t === "v") && /@@(version|datadir|hostname|basedir)/.test(low)) return { sev: "high", why: "database fingerprinting (@@version, information_schema)", fp: f };
    return null;
  };
  const rank = { critical: 3, high: 2, medium: 1 };
  for (const [prefix, cond] of [["", true], ["'", v.includes("'")], ['"', v.includes('"')]]) {
    if (!cond) continue;
    const r = consider(tokens(prefix + v), !!prefix);
    if (r && (!best || rank[r.sev] > rank[best.sev])) best = r;
    if (best?.sev === "critical") break;
  }
  return best;
}

// ------------------------------------------------------------------ XSS
const BAD_TAGS = /^(script|iframe|frame|frameset|object|embed|applet|base|meta|svg|math|xss|isindex|marquee|template|portal|noscript|style|link|form|xmp|plaintext|listing)$/;
const EVENT = /(^|[\s"'\/`;])on[a-z]{3,30}\s*=/;
const JSURI = /^\s*(java|vb|live)script\s*:|^\s*data\s*:\s*text\/(html|javascript)|^\s*data\s*:[^,]*;base64,(PHNjcmlwd|PHN2Zy|PGltZy|PGlmcmFtZ)/i;
const SINK = /\b(alert|prompt|confirm|eval|setTimeout|setInterval|Function|fetch|import|atob)\s*(\(|`)|document\s*\.\s*(cookie|domain|write|location)|window\s*\.\s*(location|name|open)|\blocation\s*(\.\s*href)?\s*=|String\.fromCharCode|top\s*\[|\.innerHTML\s*=/i;

export function xss(v) {
  if (!v || v.length < 4) return null;
  // control characters and spaces split keywords for browsers' parsers ("java\tscript:"): squeezed out
  let s = v;
  if (/[\x00-\x1f]/.test(s)) s = s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "");
  if (!/[<>"'`:]|\bon[a-z]+\s*=|\(/i.test(s)) return null;
  const low = s.toLowerCase();
  if (JSURI.test(low.replace(/[\t\n\r]/g, ""))) return { sev: "critical", why: "a javascript: (or HTML data:) URL" };
  if (/<\s*\/\s*script/.test(low)) return { sev: "critical", why: "</script>: breaking out of a script block" };
  // tags, the way a browser's tokenizer finds them: < then a letter
  const TAG = /<\s*(\/?)([a-z][a-z0-9:-]*)([^<>]*)(>|$)/gi;
  let m, worst = null;
  const up = (sev, why) => { const r = { critical: 3, high: 2, medium: 1 }; if (!worst || r[sev] > r[worst.sev]) worst = { sev, why }; };
  let count = 0;
  while ((m = TAG.exec(low)) && count++ < 20) {
    const [, close, name, attrs] = m;
    if (close) continue;
    const a = attrs.replace(/[\t\n\r]/g, " ");
    if (name === "script") { up("critical", "a <script> tag"); continue; }
    if (EVENT.test(" " + a)) { up("critical", `<${name}> with an event handler (on…=)`); continue; }
    if (/(href|src|action|formaction|data|xlink:href|srcdoc|background|dynsrc|lowsrc|poster|code|codebase)\s*=\s*["'`]?\s*(java|vb|live)script\s*:/.test(a)) { up("critical", `<${name}> with a javascript: URL`); continue; }
    if (/srcdoc\s*=/.test(a)) { up("critical", `<${name} srcdoc>`); continue; }
    if (/expression\s*\(|-moz-binding|behavior\s*:/.test(a)) { up("high", "a CSS expression"); continue; }
    if (BAD_TAGS.test(name)) { up(name === "svg" || name === "math" || name === "style" || name === "form" ? "medium" : "high", `a <${name}> tag`); continue; }
    if (/^(img|image|video|audio|source|input|body|details|select|textarea|keygen|button|a|div|x|iframe)$/.test(name) && /\b(src|href)\s*=/.test(a) && SINK.test(a)) up("high", `<${name}> carrying script`);
  }
  if (worst?.sev === "critical") return worst;
  // breaking out of an attribute: a quote, then an event handler
  if (/["'`][\s\/]*on[a-z]{3,30}\s*=/.test(low) && SINK.test(s)) up("critical", "an attribute broken out of, with an event handler");
  // breaking out of a JavaScript string: a quote, an operator, a sink
  else if (/["'`]\s*[;)+\-*\/|&,]+\s*(\(|\b)/.test(low) && SINK.test(s) && /["'`]\s*[;)+\-*\/|&,]+\s*[a-z(\[]*\s*(alert|prompt|confirm|eval|fetch|import|document|window|top|self|location|settimeout|function|string\.fromcharcode)/i.test(s)) up("critical", "a JavaScript string broken out of (';alert(1)//)");
  else if (/\b(alert|prompt|confirm)\s*(\(|`)\s*(document\s*\.|\d+\s*[)`]|['"`][^'"`]{0,20}['"`]\s*\))/.test(low)) up("high", "an alert(…) proof of concept");
  return worst;
}
