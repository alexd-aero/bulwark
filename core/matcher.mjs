// Many patterns, one pass. Every signature regex is read once, at load, for a
// literal it cannot match without ("eval-stdin.php", ".env", "/etc/"): the
// regex is asked only when that literal is in the string. The literals of all
// regexes go into one Aho-Corasick automaton (a table: one array lookup per
// character), so a request that contains none of them (nearly all traffic)
// costs one pass over its characters instead of a few hundred regex calls.
// This is what ModSecurity's @pm does, with the literals found by itself.
//
// requiredLiterals(regex) -> [strings] (any one must appear, lowercased) | null
// new Matcher([{id, res}]).candidates(str) -> Set of regex indexes worth asking

// ------------------------------------------------------------------ reading a regex
// A small parser for the subset signatures use: literals, escapes, classes,
// groups, alternation, quantifiers, anchors, lookarounds.
function parse(src) {
  let i = 0;
  const alt = () => {
    const branches = [seq()];
    while (src[i] === "|") { i++; branches.push(seq()); }
    return { alt: branches };
  };
  const seq = () => {
    const items = [];
    while (i < src.length && src[i] !== "|" && src[i] !== ")") {
      let it = atom();
      // quantifier
      const c = src[i];
      if (c === "?" || c === "*" || c === "+" || (c === "{" && /^\{\d+(,\d*)?\}/.test(src.slice(i)))) {
        let min = 1, rep = true;
        if (c === "?") { min = 0; i++; } else if (c === "*") { min = 0; i++; } else if (c === "+") { min = 1; i++; }
        else { const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i)); min = Number(m[1]); rep = m[2] !== undefined || Number(m[1]) > 1; i += m[0].length; }
        if (src[i] === "?") i++;                                   // lazy
        it = { ...it, min, rep };
      }
      items.push(it);
    }
    return { seq: items };
  };
  const atom = () => {
    const c = src[i];
    if (c === "(") {
      i++;
      let look = false;
      if (src[i] === "?") {
        if (src[i + 1] === ":") i += 2;
        else if (src[i + 1] === "=" || src[i + 1] === "!") { look = true; i += 2; }
        else if (src[i + 1] === "<" && (src[i + 2] === "=" || src[i + 2] === "!")) { look = true; i += 3; }
        else if (src[i + 1] === "<") { const e = src.indexOf(">", i); i = e + 1; }
      }
      const inner = alt();
      if (src[i] === ")") i++;
      return look ? { zero: true } : { group: inner };
    }
    if (c === "[") {
      let j = i + 1;
      if (src[j] === "^") j++;
      if (src[j] === "]") j++;
      for (; j < src.length && src[j] !== "]"; j++) if (src[j] === "\\") j++;
      i = j + 1;
      return { any: true };
    }
    if (c === "\\") {
      const d = src[i + 1];
      i += 2;
      if (/[dDwWsS]/.test(d)) return { any: true };
      if (d === "b" || d === "B") return { zero: true };
      if (/\d/.test(d)) return { any: true };                     // a backreference
      if (d === "n") return { ch: "\n" };
      if (d === "r") return { ch: "\r" };
      if (d === "t") return { ch: "\t" };
      if (d === "x") { const h = src.slice(i, i + 2); i += 2; return { ch: String.fromCharCode(parseInt(h, 16)) }; }
      if (d === "u") { const h = src.slice(i, i + 4); i += 4; return { ch: String.fromCharCode(parseInt(h, 16)) }; }
      return { ch: d };
    }
    i++;
    if (c === "^" || c === "$") return { zero: true };
    if (c === ".") return { any: true };
    return { ch: c };
  };
  const tree = alt();
  if (i < src.length) throw new Error(`unparsed at ${i}`);
  return tree;
}

// the best requirement of a node: a set of literals, one of which must appear
const quality = (set) => (set ? Math.min(...set.map((s) => s.replace(/[/._\-]/g, "").length * 2 + s.length)) : -1);
function need(node) {
  if (node.alt) {
    const sets = node.alt.map(need);
    if (sets.some((s) => !s)) return null;
    return [...new Set(sets.flat())];
  }
  if (node.seq) {
    let best = null, run = "";
    const take = (set) => { if (set && quality(set) > quality(best)) best = set; };
    const flush = () => { if (run) take([run]); run = ""; };
    for (const it of node.seq) {
      const min = it.min ?? 1;
      if (it.zero) { flush(); continue; }
      if (it.ch !== undefined && min >= 1) {
        run += it.ch.toLowerCase();
        if (it.rep) flush();
        continue;
      }
      flush();
      if (it.group && min >= 1) take(need(it.group));
    }
    flush();
    return best;
  }
  if (node.group) return need(node.group);
  return null;
}
export function requiredLiterals(re) {
  try {
    const set = need(parse(re.source));
    if (!set || !set.length || set.some((s) => !s)) return null;
    // non-ASCII literals can't be looked up in the table: no requirement then
    if (set.some((s) => /[^\x00-\x7f]/.test(s))) return null;
    return set;
  } catch { return null; }
}

// ------------------------------------------------------------------ Aho-Corasick
export class Matcher {
  // items: [{res: [RegExp]}] -> each regex gets an index (in order)
  constructor(regexes) {
    this.regexes = regexes;
    this.always = [];                                   // regexes without a literal: always asked
    const lits = new Map();                             // literal -> [regex index]
    regexes.forEach((re, k) => {
      const set = requiredLiterals(re);
      if (!set) { this.always.push(k); return; }
      for (const s of set) { if (!lits.has(s)) lits.set(s, []); lits.get(s).push(k); }
    });
    // the trie
    const next = [new Int32Array(128).fill(-1)], out = [[]], fail = [0];
    for (const [s, ks] of lits) {
      let st = 0;
      for (const ch of s) {
        const c = ch.charCodeAt(0);
        if (next[st][c] < 0) { next[st][c] = next.length; next.push(new Int32Array(128).fill(-1)); out.push([]); fail.push(0); }
        st = next[st][c];
      }
      out[st].push(...ks);
    }
    // failure links, breadth first, and the full transition table (a DFA)
    const q = [];
    for (let c = 0; c < 128; c++) { const s = next[0][c]; if (s < 0) next[0][c] = 0; else { fail[s] = 0; q.push(s); } }
    while (q.length) {
      const r = q.shift();
      if (out[fail[r]].length) out[r] = [...out[r], ...out[fail[r]]];
      for (let c = 0; c < 128; c++) {
        const s = next[r][c];
        if (s < 0) next[r][c] = next[fail[r]][c];
        else { fail[s] = next[fail[r]][c]; q.push(s); }
      }
    }
    this.states = next.length;
    this.table = new Int32Array(next.length * 128);
    next.forEach((row, s) => this.table.set(row, s * 128));
    this.out = out.map((o) => (o.length ? Int32Array.from(new Set(o)) : null));
    this.literals = lits.size;
  }
  // the regexes worth asking about str (lowercase ASCII walk; other characters reset)
  candidates(str, into = new Set()) {
    const T = this.table, O = this.out;
    let st = 0;
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c >= 65 && c <= 90) c += 32;
      else if (c > 127) { st = 0; continue; }
      st = T[st * 128 + c];
      const o = O[st];
      if (o !== null) for (let k = 0; k < o.length; k++) into.add(o[k]);
    }
    for (const k of this.always) into.add(k);
    return into;
  }
}
