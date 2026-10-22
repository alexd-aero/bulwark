// What kind of attack a request is: Bulwark's taxonomy. Every signature (and
// every behaviour the guard watches for) belongs to one category, and has a
// severity. The category says what the attacker is after, with the matching
// references: MITRE ATT&CK techniques, the OWASP Top 10 (2021) and the
// ModSecurity Core Rule Set's rule family, and the AbuseIPDB report
// categories it maps to (abuseipdb.com/categories).
//
// Severity is worth anomaly points, as in the Core Rule Set: the points of
// everything a request matched are added up, and 5 or more is a payload
// (dropped on the spot, and counted against the address). One critical match
// is enough; weaker ones have to agree.

export const SEVERITY = {
  critical: { points: 5, rank: 4, name: "critical" },
  high: { points: 4, rank: 3, name: "high" },
  medium: { points: 3, rank: 2, name: "medium" },
  low: { points: 2, rank: 1, name: "low" },
  info: { points: 0, rank: 0, name: "info" },
};
export const DROP_AT = 5;                      // a request's anomaly score that makes it a payload

// AbuseIPDB categories used below
const AB = { ddos: 4, proxy: 9, phishing: 7, scan: 14, hacking: 15, sqli: 16, brute: 18, bot: 19, exploited: 20, webapp: 21, iot: 23 };

const C = (id, name, short, color, { mitre = [], owasp = null, crs = null, abuse = [AB.webapp], about = "" } = {}) =>
  ({ id, name, short, color, mitre, owasp, crs, abuse, about });

export const CATEGORIES = [
  C("recon", "Recon & scanning", "recon", "#9aa3ae", { mitre: ["T1595", "T1595.002", "T1595.003"], crs: "913 scanner detection", abuse: [AB.scan, AB.webapp],
    about: "Asking for software that isn't here, wordlist and content discovery, vulnerability scanners and their tools." }),
  C("secrets", "Secret & config hunting", "secrets", "#ffb02e", { mitre: ["T1552.001", "T1083"], owasp: "A05", crs: "930 restricted files", abuse: [AB.hacking, AB.webapp],
    about: ".env files, Git metadata, cloud and SSH keys, backups, dumps, debug pages: anything that hands over secrets." }),
  C("traversal", "Path traversal / LFI", "traversal", "#ff8a3d", { mitre: ["T1190", "T1083"], owasp: "A01", crs: "930 LFI", abuse: [AB.hacking, AB.webapp],
    about: "Climbing out of the web root (../, encoded or not) to read files such as /etc/passwd, or including local files." }),
  C("rce", "Remote code / command injection", "RCE", "#ff4d4d", { mitre: ["T1190", "T1059", "T1059.004"], owasp: "A03", crs: "932 RCE / 933 PHP", abuse: [AB.hacking, AB.webapp],
    about: "Shell commands, PHP code and expression-language payloads meant to run on your machine." }),
  C("sqli", "SQL injection", "SQLi", "#ff5fa2", { mitre: ["T1190"], owasp: "A03", crs: "942 SQLi", abuse: [AB.sqli, AB.webapp],
    about: "Breaking out of a query: tautologies, UNION SELECT, stacked queries, time and error based blind injection." }),
  C("xss", "Cross-site scripting", "XSS", "#d66bff", { mitre: ["T1189", "T1059.007"], owasp: "A03", crs: "941 XSS", abuse: [AB.webapp],
    about: "Script tags, event handlers and javascript: URLs meant to run in someone's browser." }),
  C("ssrf", "Server-side request forgery", "SSRF", "#4fc3f7", { mitre: ["T1190", "T1552.005"], owasp: "A10", crs: "934 / 931 RFI", abuse: [AB.hacking, AB.webapp],
    about: "Making the server fetch internal addresses, cloud metadata (169.254.169.254) or odd schemes (gopher://, file://)." }),
  C("xxe", "XML external entities", "XXE", "#26c6da", { mitre: ["T1190"], owasp: "A05", crs: "XML / 944", abuse: [AB.hacking, AB.webapp],
    about: "DOCTYPE and ENTITY declarations that read files or reach the network through an XML parser." }),
  C("ssti", "Template injection", "SSTI", "#ab7bff", { mitre: ["T1190", "T1059"], owasp: "A03", crs: "934 generic", abuse: [AB.hacking, AB.webapp],
    about: "{{7*7}}, ${…}, <%= %> and template gadgets (Jinja, Twig, Freemarker, Velocity, Thymeleaf) that reach code." }),
  C("deser", "Insecure deserialization", "deserial.", "#7e9cff", { mitre: ["T1190"], owasp: "A08", crs: "944 Java", abuse: [AB.hacking, AB.webapp],
    about: "Serialized Java, PHP, .NET and Python objects (ysoserial gadget chains) sent to be unpacked." }),
  C("log4shell", "Log4Shell / JNDI", "JNDI", "#ff3d71", { mitre: ["T1190", "T1203"], owasp: "A06", crs: "944150", abuse: [AB.hacking, AB.webapp],
    about: "${jndi:ldap://…} lookups, obfuscated or not, in the URL or the User-Agent (CVE-2021-44228)." }),
  C("cve", "Known CVE exploits", "CVE", "#ff2e63", { mitre: ["T1190"], owasp: "A06", crs: "various", abuse: [AB.hacking, AB.webapp],
    about: "Requests shaped like a published exploit for a specific product (each tagged with its CVE)." }),
  C("webshell", "Web shells & backdoors", "web shell", "#e040fb", { mitre: ["T1505.003"], owasp: "A08", crs: "955 web shells", abuse: [AB.hacking, AB.exploited, AB.webapp],
    about: "Looking for shells someone else planted (alfa, wso, c99, b374k…) or talking to one." }),
  C("bruteforce", "Brute force & credential stuffing", "brute force", "#f2b53c", { mitre: ["T1110", "T1110.001", "T1110.004"], owasp: "A07", crs: "—", abuse: [AB.brute, AB.webapp],
    about: "Admin panels and CMS logins asked for, and login endpoints hammered with guesses." }),
  C("protocol", "Protocol abuse & smuggling", "protocol", "#8bc34a", { mitre: ["T1190", "T1090"], owasp: "A05", crs: "920 / 921", abuse: [AB.hacking, AB.webapp],
    about: "Malformed or odd requests: CRLF and header injection, absolute-URI and CONNECT proxy probes, TRACE, unknown methods, encoding evasion." }),
  C("phishing", "Phishing kits", "phishing", "#ffd54f", { mitre: ["T1583.001", "T1566"], owasp: null, crs: "—", abuse: [AB.webapp],
    about: "Looking for phishing kits planted on other servers (to reuse them), or their control files." }),
  C("infra", "Cloud & container APIs", "cloud APIs", "#40c4aa", { mitre: ["T1552.005", "T1610", "T1613"], owasp: "A05", crs: "—", abuse: [AB.hacking, AB.webapp],
    about: "Docker and Kubernetes APIs, cloud metadata, Elasticsearch, debug endpoints: infrastructure left open." }),
  C("iot", "IoT & botnets", "IoT botnet", "#ff7043", { mitre: ["T1190", "T1584.005"], owasp: null, crs: "—", abuse: [AB.iot, AB.hacking],
    about: "Router, camera and DVR exploits and the Mirai / Mozi style droppers (wget … ; chmod 777 …; ./x.arm7)." }),
  C("miner", "Crypto-miner droppers", "miner", "#cddc39", { mitre: ["T1496"], owasp: null, crs: "—", abuse: [AB.hacking, AB.webapp],
    about: "Payloads that fetch and start a miner: xmrig, kinsing, kdevtmpfsi, stratum+tcp:// pools." }),
  C("bot", "Bots & scrapers", "bot", "#90a4ae", { mitre: ["T1595"], owasp: null, crs: "913", abuse: [AB.bot],
    about: "Clients that announce a scanner or a scraping library, or none at all. A label, never a ban by itself." }),
  C("dos", "DoS & floods", "flood", "#ef5350", { mitre: ["T1498", "T1499", "T1499.002"], owasp: null, crs: "912 DoS", abuse: [AB.ddos],
    about: "Floods from one address, oversized URLs and parameter bombs." }),
];
const BY = new Map(CATEGORIES.map((c) => [c.id, c]));
export const categoryById = (id) => BY.get(id) || null;
export const sevPoints = (s) => SEVERITY[s]?.points ?? 0;
export const sevRank = (s) => SEVERITY[s]?.rank ?? -1;
// AbuseIPDB categories for what an address did (category ids), web attack always
export function abuseCategories(cats) {
  const out = new Set([AB.webapp]);
  for (const c of cats) for (const n of categoryById(c)?.abuse || []) out.add(n);
  return [...out].sort((a, b) => a - b);
}
