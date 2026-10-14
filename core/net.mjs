// Addresses: which are private, one spelling for each, and the numbers behind them.
import { isIP } from "node:net";

export { isIP };
export const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.)/.test(ip)
  || /^(::1?$|f[cd]|fe[89ab])/i.test(ip);
export const normIp = (ip) => String(ip || "").trim().replace(/^::ffff:(?=\d+\.)/i, "").toLowerCase();
export const v4int = (ip) => { const p = ip.split("."); return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3]; };
export function v6big(ip) {
  const [head, tail] = ip.includes("::") ? ip.split("::") : [ip, null];
  const hp = head ? head.split(":") : [], tp = tail ? tail.split(":") : [];
  const groups = tail === null ? hp : [...hp, ...Array(8 - hp.length - tp.length).fill("0"), ...tp];
  let n = 0n;
  for (const g of groups) n = (n << 16n) + BigInt(parseInt(g || "0", 16));
  return n;
}
// the network an address sits in, for grouping: /24 and /16 for IPv4, /48 and /32 for IPv6
export function netOf(ip, wide = false) {
  if (isIP(ip) === 4) { const p = ip.split("."); return wide ? `${p[0]}.${p[1]}.0.0/16` : `${p[0]}.${p[1]}.${p[2]}.0/24`; }
  if (isIP(ip) === 6) {
    const n = v6big(ip), bits = wide ? 32 : 48;
    const pre = (n >> BigInt(128 - bits)) << BigInt(128 - bits);
    const hex = pre.toString(16).padStart(32, "0").match(/.{4}/g).slice(0, bits / 16).map((g) => g.replace(/^0+(?=.)/, ""));
    return `${hex.join(":")}::/${bits}`;
  }
  return null;
}
