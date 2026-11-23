// Value-level detectors: what a single parameter, path segment or header value
// is trying to do, judged by what it means rather than by one keyword. Each
// returns null or {id, sev, why} (id: a signature in payloads.mjs's DYNAMIC
// list, or one of its static signatures when it confirms one).
//
//   ssrf(value, name)      a URL to somewhere only the server can reach: every
//                          way to spell 127.0.0.1 or 169.254.169.254 (octal, hex,
//                          one big number, IPv6-mapped, nip.io, ①②⑦), internal
//                          names (kubernetes.default.svc, *.internal), odd schemes
//   redirect(value, name)  a URL that sends a visitor elsewhere (//evil, /\evil, https:evil)
//   nosql / ldap / xpath   query languages other than SQL
//   code(value)            PHP, Node, Java, Python and Ruby code
//   shell(value, name)     shell commands, also when spelled c'a't, ${IFS}, /???/c?t
//   deser(value)           serialized objects: YAML gadgets, pickle, node-serialize, PHP in base64
//   ssti(value)            template injection beyond {{7*7}}
//   oast(str)              out-of-band callback domains (Burp Collaborator, interactsh…)
//   jwt(token)             a forged or tampered token: alg none, a kid that is a path,
//                          a query or a command, a key fetched from elsewhere (jku,
//                          x5u) or carried inside (jwk), an ECDSA signature of zeros
//   graphql(query)         GraphQL built to exhaust a server: nested too deep, a
//                          field asked a hundred times under aliases, directives piled up
//   headers(h, ctx)        every request header that can carry an attack, and how
//                          the request is framed (smuggling: a body on a GET, a
//                          Transfer-Encoding on HTTP/1.0, Connection: Content-Length)

// ------------------------------------------------------------------ addresses
const V4META = new Set([0xa9fea9fe, 0xa9feaa02, 0x646464c8, 0xc00000c0]);   // 169.254.169.254, 169.254.170.2, 100.100.100.200, 192.0.0.192
function v4num(host) {
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4 || parts.some((p) => p === "")) return null;
  const nums = [];
  for (const p of parts) {
    let n;
    if (/^0x[0-9a-f]*$/i.test(p)) n = p.length > 2 ? parseInt(p.slice(2), 16) : 0;
    else if (/^0[0-7]+$/.test(p)) n = parseInt(p, 8);
    else if (/^\d+$/.test(p)) n = Number(p);
    else return null;
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }
  const last = nums.pop();
  if (nums.some((n) => n > 255) || last >= 2 ** (8 * (4 - nums.length))) return null;
  let v = 0;
  for (const n of nums) v = v * 256 + n;
  return v * 2 ** (8 * (4 - nums.length)) + last;
}
function v4kind(n) {
  if (V4META.has(n)) return "meta";
  const a = Math.floor(n / 2 ** 24), b = Math.floor(n / 2 ** 16) % 256;
  if (a === 127 || a === 0) return "loop";
  if (a === 10 || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b < 128)) return "priv";
  return null;
}
function v6kind(h) {
  let s = h.toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const m4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m4) { const n = v4num(m4[2]); if (n === null) return null; s = m4[1] + (Math.floor(n / 65536)).toString(16) + ":" + (n % 65536).toString(16); }
  if (!/^[0-9a-f:]+$/.test(s) || s.split("::").length > 2) return null;
  const [a, b] = s.split("::");
  const A = a ? a.split(":") : [], B = b !== undefined && b ? b.split(":") : [];
  const groups = b === undefined ? A : [...A, ...Array(8 - A.length - B.length).fill("0"), ...B];
  if (groups.length !== 8) return null;
  const g = groups.map((x) => parseInt(x || "0", 16));
  if (g.slice(0, 7).every((x) => x === 0) && (g[7] === 1 || g[7] === 0)) return "loop";
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) return v4kind(g[6] * 65536 + g[7]) || (g[5] ? "mapped" : null);
  if (g[0] === 0xfd00 && g[1] === 0xec2 && g[7] === 0x254) return "meta";
  if ((g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xffc0) === 0xfe80) return "priv";
  return null;
}
// what a URL's host is: meta (cloud metadata), loop (this machine), priv (a LAN
// address), internal (a name only the inside resolves), or null (the internet)
export function hostKind(raw) {
  let h = String(raw || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h) return null;
  if (h[0] === "[") return v6kind(h);
  if (h.includes(":") && /^[0-9a-f:.]+$/.test(h)) return v6kind(h);
  if (/^[0-9a-fx.]+$/.test(h)) { const n = v4num(h); if (n !== null) return v4kind(n); }
  // names that point back in: localhost, *.localtest.me, 127.0.0.1.nip.io
  if (h === "localhost" || h.endsWith(".localhost") || h === "localtest.me" || h.endsWith(".localtest.me") || h === "lvh.me" || h.endsWith(".lvh.me")) return "loop";
  const wild = /^(?:[\w-]+[.-])*?((?:\d{1,3}[.-]){3}\d{1,3})\.(?:nip\.io|sslip\.io|xip\.io|nip\.direct|traefik\.me)$/.exec(h);
  if (wild) { const n = v4num(wild[1].replace(/-/g, ".")); return n === null ? null : v4kind(n) || null; }
  if (/^(metadata\.google\.internal|metadata\.azure\.com|metadata|instance-data(\.ec2\.internal)?|metadata\.tencentyun\.com|metadata\.platformequinix\.com)$/.test(h)) return "meta";
  if (/^kubernetes(\.default)?(\.svc)?(\.cluster\.local)?$/.test(h) || /\.(svc\.cluster\.local|cluster\.local|internal|intranet|corp|lan|home\.arpa)$/.test(h) || /^(consul|vault|etcd|redis|memcached|elasticsearch|mongo|mysql|postgres|docker|rabbitmq)(\.service)?(\.consul)?$/.test(h)) return "internal";
  return null;
}

// parameters that legitimately carry a URL to send someone back to (OAuth, sign-in)
const RETURNISH = /^(redirect(_?(uri|url|to))?|return(_?(to|url|uri|path))?|returnurl|returnto|next|continue|callback(_?url)?|origin|success_?url|cancel_?url|failure_?url|back(_?url)?|post_logout_redirect_uri|login_?redirect|state|dest(ination)?|goto|go|target|to|r|u|url|link|out|forward(_?url)?|redir|rurl|jump|view|ref|referer|referrer|location|page)$/i;
const OAUTHISH = /^(redirect_uri|post_logout_redirect_uri|callback|callback_url|return_to|returnto|next|continue|state|origin)$/i;
const DANGER_SCHEMES = /^(gopher|dict|file|ldaps?|tftp|jar|netdoc|sftp|smb|telnet|rmi|iiop|ssh2(\.\w+)?|expect|phar|ogg|rar|zip|glob|compress\.\w+|fd|sqlite|mysql|postgres(ql)?|redis|mongodb|memcached?)$/;
export function ssrf(v, name = "") {
  if (v.length < 4 || (v.indexOf(":") < 0 && v.indexOf("//") < 0)) return null;
  const m = /^\s*(?:([a-z][a-z0-9+.-]{1,15}):\s*)?(\/\/|\\\\)?(?:([^@\/?#\s\\]*)@)?(\[[^\]]{2,60}\]|[^\/:?#\s\\@]{1,255})/i.exec(v);
  if (!m || (!m[1] && !m[2])) return null;
  const scheme = (m[1] || "").toLowerCase(), slashes = !!m[2], user = m[3] || "", host = m[4];
  if (scheme && DANGER_SCHEMES.test(scheme)) {
    if (scheme === "file" && !slashes && !/^\/|^[a-z]:/i.test(host)) return null;           // "file:" in a sentence
    if (/^(zip|rar|glob|phar|expect|ogg|compress\.\w+)$/.test(scheme)) return null;            // PHP wrappers: the LFI signature names them
    if (!slashes && !/^(jar|netdoc|file)$/.test(scheme)) return null;
    return { id: "ssrf", sev: "critical", why: `a ${scheme}: URL in a parameter` };
  }
  if (scheme && !/^(https?|ftp|ws|wss)$/.test(scheme)) return null;
  if (!scheme && !slashes) return null;
  let k = hostKind(host) || (user && hostKind(user.replace(/[%#].*$/, "")) ? "confused" : null);
  // http://evil.example#@169.254.169.254/: parsers disagree on which host it is
  if (!k && v.indexOf("@") > 0) for (const x of v.matchAll(/@(\[[^\]]+\]|[^\/:?#\s@\\]+)/g)) if (hostKind(x[1])) { k = "confused"; break; }
  if (!k) return null;
  const back = OAUTHISH.test(name);                           // a sign-in that returns to http://localhost:8080 (a CLI) is fine
  if (k === "meta") return { id: "ssrf", sev: "critical", why: `the cloud metadata service (${host})` };
  if (k === "confused") return { id: "ssrf", sev: "critical", why: `a URL that parsers read two ways (${v.slice(0, 60)})` };
  if (back) return null;
  if (k === "loop") return { id: "ssrf", sev: "critical", why: `the server itself (${host})` };
  if (k === "internal") return { id: "ssrf", sev: "critical", why: `an internal service name (${host})` };
  if (k === "mapped") return { id: "ssrf", sev: "high", why: `an IPv4-mapped address (${host})` };
  return { id: "ssrf", sev: "high", why: `an internal address (${host})` };
}

// ------------------------------------------------------------------ remote file inclusion
const INCLUDEISH = /^(page|file|filename|include|inc|path|template|tpl|module|mod|load|view|doc|document|folder|dir|lang|language|conf|config|theme|skin|layout|content|cat|show|site|pg|p|style|pdf|main|dest|feed|data|class|prefix|base|root|plugin|abspath|basepath|mosconfig_absolute_path|gallery|src)$/i;
export function rfi(v, name = "") {
  if (/^\s*[\\/]{2,}[\w.-]+[\\/]+[\w$.-]+[\\/]+/.test(v) && (INCLUDEISH.test(name) || /\.(php\d?|phtml|inc|txt)$/i.test(v))) return { id: "lfi", sev: "critical", why: `remote file inclusion over a network share (${v.slice(0, 60)})` };
  const m = /^\s*(https?|ftps?|smb):\/\/([^\/?#\s]+)(\/[^?#\s]*)?(\?)?\s*$/i.exec(v);
  if (!m) return null;
  const file = m[3] || "", trail = !!m[4];
  const script = /\.(txt|php\d?|phtml|inc|sh|pl|py|jpg|gif|png|cgi)$/i.test(file);
  if (trail && script) return { id: "lfi", sev: "critical", why: `remote file inclusion (${v.slice(0, 60)})` };
  if (INCLUDEISH.test(name) && (script || /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(m[2]) || m[1].toLowerCase() !== "http" && m[1].toLowerCase() !== "https")) return { id: "lfi", sev: "critical", why: `remote file inclusion in ?${name}= (${v.slice(0, 60)})` };
  return null;
}

// ------------------------------------------------------------------ open redirects
export function redirect(v, name = "") {
  const c = v.charCodeAt(0);
  if (c !== 47 && c !== 92 && c !== 104 && c !== 72 && c !== 32 && c !== 9) return null;    // / \ h H
  const named = RETURNISH.test(name);
  // //evil.example, /\evil.example, \\evil, /\t/evil, ////evil
  const m = /^\s*[\/\\][\t\n\r ]*[\/\\]+\s*([\w-]+(\.[\w-]+)+|\[[0-9a-f:]+\])/i.exec(v);
  if (m && (named || /\.[a-z]{2,}$/i.test(m[1]))) return { id: "open-redirect", sev: "high", why: `a scheme-relative URL (${v.slice(0, 40)})` };
  if (!named) return null;
  if (/^\s*https?:(?!\/\/)[\\\/]?[\w-]+\.[\w.-]+/i.test(v)) return { id: "open-redirect", sev: "high", why: "a URL without slashes (https:evil…), read as absolute by browsers" };
  if (/^\s*https?:\/\/[^\/?#@]*\.[^\/?#@]*@[\w-]+\.[\w.-]+/i.test(v)) return { id: "open-redirect", sev: "high", why: "a URL that hides its real host after an @" };
  return null;
}

// ------------------------------------------------------------------ NoSQL, LDAP, XPath
const MONGO = "ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|expr|function|accumulator|or|and|nor|not|elemMatch|size|type|mod|all|text|jsonSchema|lookup|options";
const MONGO_KEY = new RegExp(`\\[\\s*\\$(${MONGO})\\s*\\]|^\\$(${MONGO})$`, "i");
const MONGO_VAL = new RegExp(`["']\\$(${MONGO})["']\\s*:|\\{\\s*\\$(${MONGO})\\s*:`, "i");
export function nosql(name, v) {
  if (name && name.indexOf("$") >= 0 && MONGO_KEY.test(name)) return { id: "nosqli", sev: "critical", why: `a MongoDB operator in a parameter name (${name.slice(0, 40)})` };
  if (v.indexOf("$") >= 0 && MONGO_VAL.test(v)) return { id: "nosqli", sev: "critical", why: "MongoDB operators in a value ({\"$ne\": …})" };
  const where = /\$where/i.test(name) || /\$where/i.test(v);
  if ((/['"]\s*;\s*return\s+(true|1|this\b)|['"]\s*\|\|\s*['"]?\w+['"]?\s*={2,3}\s*['"]?\w/i.test(v) || where && /function\s*\(\s*\)\s*\{|\bthis\.\w+\s*={2,3}|\bsleep\s*\(\s*\d{3,}\s*\)|\breturn\s+(true|1)\b/i.test(v)) && /['"(]/.test(v))
    return { id: "nosqli", sev: "critical", why: "JavaScript for a $where clause (' ; return true)" };
  return null;
}
export function ldap(v) {
  if (v.indexOf(")") < 0 || v.indexOf("(") < 0) return null;
  if (/\*\s*\)\s*\(\s*[|&!]?\s*\(?\s*[\w-]+\s*[~<>]?=|\)\s*\(\s*[|&!]\s*[()]|\w\s*\)\s*\(\s*[&|]\s*\)|\)\s*\(.*\bobjectclass\s*=\s*\*/i.test(v))
    return { id: "ldapi", sev: "critical", why: "an LDAP filter broken out of (*)(uid=*))" };
  return null;
}
export function xpath(v) {
  if (/\b(count|string-length|name|substring|position)\s*\(\s*(\/|\.\.|name\s*\(|\))[^)]*\)\s*(=|>|<)|['"]\s*\]\s*\|\s*\/\/|\/\/\*\[\s*(contains|starts-with)\s*\(|['"]\s*or\s+(name|local-name)\s*\(\s*\)/i.test(v))
    return { id: "xpathi", sev: "critical", why: "an XPath expression broken out of (' or count(/*)=1)" };
  return null;
}

// ------------------------------------------------------------------ code
const PHP_FN = /\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval|assert|phpinfo|file_put_contents|file_get_contents|fwrite|fputs|preg_replace|create_function|call_user_func(_array)?|base64_decode|gzinflate|gzuncompress|str_rot13|unserialize|move_uploaded_file|show_source|highlight_file|readfile|ini_set|putenv|array_map|array_filter|usort|assert_options|include(_once)?|require(_once)?)\s*\(\s*(['"`$]|\$_|@|\w+\s*\(|\)\s*;|[\w./\\-]{1,40}\s*\)\s*;|['"]?\/[\w.]+\/e['"]?)/i;
const CODE = [
  [/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\s*\[/, "PHP reading the request ($_GET[…])"],
  [/\$\{\s*@?\s*(system|eval|exec|passthru|phpinfo|shell_exec|assert)\b/i, "PHP code in a ${…} string"],
  [/\bphpinfo\s*\(\s*\)/i, "phpinfo()"],
  [/\brequire\s*\(\s*['"`](child_process|fs|net|vm|os|http|dgram|cluster|worker_threads)['"`]\s*\)|\bchild_process\b|\.\s*(execSync|spawnSync|execFileSync)\s*\(|\bprocess\s*\.\s*(mainModule|binding)\b|\bglobal\s*\.\s*process\b/i, "Node.js reaching the shell (child_process)"],
  [/\bconstructor\s*(\.|\[\s*['"`])\s*constructor\b/i, "JavaScript's constructor.constructor (code from a string)"],
  [/java\s*\.\s*lang\s*\.\s*(Runtime|ProcessBuilder|System|Class|reflect|Thread)\b|\bRuntime\s*\.\s*getRuntime\s*\(|\bnew\s+ProcessBuilder\b|\bClass\s*\.\s*forName\s*\(|\.getClass\s*\(\s*\)\s*\.\s*forName|javax\s*\.\s*script\s*\.\s*ScriptEngineManager|\bgetDeclaredMethod\s*\(/, "Java reaching the runtime (Runtime.getRuntime())"],
  [/\b__import__\s*\(|\bos\s*\.\s*(system|popen|exec\w*|spawn\w*)\s*\(|\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(|\b(exec|eval|compile)\s*\(\s*['"]\s*(import|__import__|os\.|open\s*\()|__builtins__|__globals__|\bpty\s*\.\s*spawn\s*\(/, "Python reaching the shell (os.system, __import__)"],
  [/\b(Kernel|IO|Open3|Process|PTY)\s*\.\s*(exec|system|popen\d?|spawn|capture\d\w*|open)\s*\(|%x\(|\bsyscall\s*\(/, "Ruby reaching the shell (Kernel.exec)"],
];
export function code(v) {
  if (v.length < 6 || v.indexOf("(") < 0 && v.indexOf("[") < 0 && v.indexOf("{") < 0 && v.indexOf(".") < 0) return null;
  for (const [re, why] of CODE) if (re.test(v)) return { id: "code-inject", sev: "critical", why };
  const p = PHP_FN.exec(v);
  if (p) return { id: "code-inject", sev: "critical", why: `PHP code (${p[1]}(…))` };
  return null;
}

// ------------------------------------------------------------------ shell
// Commands that are only ever commands (id, whoami, uname…), and those that are
// also English words (cat, sleep, ping…) and count only with the arguments a
// command takes. Separators: ; | || & && newline ` $( and a subshell's (.
const SEP = String.raw`(?:[;|&\n\r\x60]|\$\(|[;|&]\s*\()\s*(?:(?:\/usr)?(?:\/local)?\/s?bin\/|\/bin\/)?`;
const ONLY = String.raw`(?:id|whoami|uname|ifconfig|ipconfig|hostname|pwd|ls|dir|env|printenv|getent|ps|netstat|nslookup|systeminfo|tasklist|uptime|lsb_release|groups|lscpu|lspci|nproc|arp|route|quser|qwinsta)`;
const ARGS = String.raw`(?:(?:cat|tac|nl|head|tail|more|less|od|xxd|strings|base64|grep)\s+[-\/~.$]|(?:cat|tac|base64|sh|bash)\s*<|(?:wget|curl|fetch|tftp|ftpget|lwp-download)\s+\S|(?:nc|ncat|netcat|socat|telnet)\s+\S|(?:bash|sh|zsh|ksh|dash|ash|csh|tcsh)(?:\s+-[a-z]*[ci]|\s*$|\s+\/|\s*[;|&])|(?:python[23]?|perl|ruby|php|node|lua|jrunscript)\s+-[cer]\b|(?:echo|printf)\s+\S|(?:chmod|chown)\s+[-+\d]|rm\s+-[rf]|mkfifo\s|mknod\s|sleep\s+\d|ping\s+(?:-[cnwt]\s*\d|\d)|(?:dig|host)\s+\S+\.\S|(?:powershell|pwsh)(?:\.exe)?\b|cmd(?:\.exe)?\s*\/[ck]|(?:certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|cscript|wscript)(?:\.exe)?\b|net\s+(?:user|localgroup|view|share|group)\b|type\s+(?:[a-z]:\\|\S+\.(?:ini|txt|config|conf|xml))|find\s+\/|awk\s+['"]?(?:BEGIN|\{)|xterm\s+-display|openssl\s+s_client|busybox\s+\w|crontab\s+-|sudo\s+\S|useradd\s|kill\s+-\d|export\s+\w+=|\$0\s+-c\b)`;
const SHELL = new RegExp(`${SEP}(?:${ONLY}(?=$|[\\s;|&\\x60)#<>])|${ARGS})`, "i");
const PROSE = /^(code|snippet|gist|source|src|content|body|text|script|markdown|md|paste|example|answer|solution)$/i;
const CMD_NAMES = /^(cmd|exec|execute|command|cmdline|shell|run|system|passthru|ping|query|code|do|func|function|arg|option|process|payload|daemon|c|e|x)$/i;
export function shell(v, name = "") {
  if (v.length < 2) return null;
  const hasSep = /[;|&\n\r`]|\$\(/.test(v);
  if (!hasSep && !(name && CMD_NAMES.test(name))) {
    if (/\/[?*]{1,4}\/[\w?*]*[?*]/.test(v)) return { id: "cmd-inject", sev: "critical", why: "shell wildcards spelling a path (/???/c?t)" };
    return null;
  }
  // quotes, backslashes and ${IFS} that a shell removes: c'a't, w\hoami, cat${IFS}/etc
  let s = v;
  if (/['"\\]|\$\{?IFS|\$@|\$\{\w*\}/.test(s)) s = s.replace(/\$\{IFS\}|\$IFS\$\d|\$IFS\b/g, " ").replace(/\$@|\$\{\w{0,3}\}/g, "").replace(/(\w)['"\\]+(?=\w)/g, "$1");
  const m = SHELL.exec(s);
  // a field that holds code people paste (?code=, ?snippet=) may hold a command for real: worth points, not a drop alone
  if (m) return { id: "cmd-inject", sev: PROSE.test(name) ? "high" : "critical", why: `a shell command (${m[0].trim().slice(0, 40)})` };
  // a whole value that is a command, in a parameter named for one (?cmd=id)
  if (name && CMD_NAMES.test(name) && new RegExp(`^\\s*(?:${ONLY}(?=$|\\s)|${ARGS})`, "i").test(s)) return { id: "cmd-inject", sev: "critical", why: `a shell command in ?${name}=` };
  if (/\{\s*(cat|ls|id|wget|curl|nc|bash|sh|echo|whoami|uname|ping)\s*,/i.test(s)) return { id: "cmd-inject", sev: "critical", why: "bash brace expansion ({cat,/etc/passwd})" };
  if (/\/[?*]{1,4}\/[\w?*]*[?*]/.test(v)) return { id: "cmd-inject", sev: "critical", why: "shell wildcards spelling a path (/???/c?t)" };
  return null;
}

// ------------------------------------------------------------------ serialized objects
const b64 = (s) => { try { return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("latin1"); } catch { return ""; } };
const PHP_SER = /(^|[;{])[OC]:\d{1,3}:"[a-z_\\][\w\\]{0,80}":\d{1,3}:\{|^a:\d{1,4}:\{(i|s):/i;
export function deser(v) {
  if (v.length < 8) return null;
  if (/!!(python\/(object|name|module)|javax?\.|com\.sun\.|org\.(apache|springframework)\.|java\.net\.|ruby\/(object|hash|struct))/i.test(v)) return { id: "deser", sev: "critical", why: "a YAML gadget (!!python/object, !!javax…)" };
  if (/_\$\$ND_FUNC\$\$_/.test(v)) return { id: "deser", sev: "critical", why: "a node-serialize function (_$$ND_FUNC$$_)" };
  if (/\bc(os|posix|nt|subprocess|builtins|__builtin__|commands|pty|webbrowser)\s*\n\s*(system|popen|exec\w*|eval|call|check_output|spawn\w*|getoutput|open)\b/.test(v)) return { id: "deser", sev: "critical", why: "a Python pickle that runs a command" };
  if (PHP_SER.test(v)) return { id: "deser", sev: "critical", why: "a PHP serialized object" };
  // base64: pickle, PHP and Java objects inside
  if (v.length >= 12 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(v)) {
    const head = v.slice(0, 4);
    if (/^(gASV|gAR|gAN|gAJ|KGRw|Y3Bv|Y29z|Y19f|Y3N1|Y2J1|Y250)/.test(head)) {
      const d = b64(v);
      if (/(posix|\bnt\b|\bos\b|subprocess|builtins|__builtin__|commands)[\s\S]{0,40}(system|popen|exec|eval|check_output|getoutput|spawn)/.test(d)) return { id: "deser", sev: "critical", why: "a base64 Python pickle that runs a command" };
    } else if (/^(Tz|YT|Qz)/.test(head)) {
      if (PHP_SER.test(b64(v))) return { id: "deser", sev: "critical", why: "a base64 PHP serialized object" };
    }
  }
  return null;
}

// ------------------------------------------------------------------ templates
const SSTI = [
  [/\{\{\s*-?\d+\s*[*+\-/%]\s*['"]?-?\d+['"]?\s*\}\}|\$\{\{?\s*\d+\s*[*+]\s*\d+\s*\}?\}|<%=?\s*\d+\s*[*+]\s*\d+\s*%>|[#*@~]\{\s*\d+\s*[*+]\s*\d+\s*\}|@\(\s*\d+\s*[*+]\s*\d+\s*\)|\{\{=\s*\d+\s*[*+]\s*\d+\s*\}\}|\[\[\s*\$\{\s*\d+\s*[*+]\s*\d+\s*\}\s*\]\]/, "a template expression probe ({{7*7}})"],
  [/\{\{\s*(config|self|request|settings|_self|dump|cycler|joiner|namespace|lipsum|url_for|get_flashed_messages|range|session|''|""|\[\]|\(\))\b|\{\{\s*app\s*\.\s*(request|session|user)\b|\{\{\s*['"]\S*['"]\s*\|\s*(attr|filter|map|sort|reduce)\b/, "Jinja / Twig objects in a template ({{config}}, {{self…}})"],
  [/\{%\s*(import|include|extends|set|debug|load|raw|php|exec|from|macro|call)\b/i, "template tags ({% import os %})"],
  [/\{\s*(php|system|exec|passthru|shell_exec|fetch|math\s+equation)[\s(}]|\{\$smarty\.|\{\{#with\s|\{\{\s*#each\s+\(|<#(assign|include|import)\b|#set\s*\(\s*\$/i, "Smarty, Handlebars, Freemarker or Velocity tags"],
  [/[$#]\{[^}]{0,120}(getclass|classloader|forname|\.class\b|getruntime|processbuilder|java\.lang|T\s*\(\s*java)/i, "an expression reaching Java classes (${…getClass()})"],
  [/<%\s*(import|!|@\s*page)|\$\{\s*self\s*\.\s*module|__\$\{[^}]{1,200}\}__/i, "Mako / Thymeleaf preprocessing"],
];
export function ssti(v) {
  if (v.length < 5 || !/[{}%#@[]/.test(v)) return null;
  for (const [re, why] of SSTI) if (re.test(v)) return { id: "ssti", sev: "critical", why };
  return null;
}

// ------------------------------------------------------------------ out-of-band callbacks
const OAST = /(^|[^\w-])[\w.-]*\.?(burpcollaborator\.net|oastify\.com|interact\.sh|interactsh\.com|oast\.(fun|live|pro|site|online|me)|dnslog\.(cn|link)|ceye\.io|requestrepo\.com|bxss\.me|xss\.ht|xss\.report|canarytokens\.(com|org)|dnsbin\.zhack\.ca|eyes\.sh|r87\.me|digimg\.store|psc4fuel\.com|burpcollaborator\.(com|org))(?![\w-])/i;
const OAST_GATE = /burpcollab|oastify|interact\.?sh|\.oast\.|dnslog\.|ceye\.io|requestrepo|bxss\.me|xss\.(ht|report)|canarytokens|dnsbin|eyes\.sh|r87\.me|digimg|psc4fuel/i;
export function oast(s) {
  if (!OAST_GATE.test(s)) return null;
  const m = OAST.exec(s);
  return m ? { id: "oast", sev: "critical", why: `an out-of-band callback domain (${m[2]})` } : null;
}

// ------------------------------------------------------------------ tokens (JWT)
// Only the token's header is read (it says how to check the signature), never
// trusted: nothing here verifies anything. A JWE (five parts) is left alone.
const B64URL = /^[A-Za-z0-9_-]+={0,2}$/;
function b64json(s) {
  if (s.length > 4096 || !B64URL.test(s)) return null;
  try { const o = JSON.parse(Buffer.from(s, "base64url").toString("utf8")); return o && typeof o === "object" && !Array.isArray(o) ? o : null; } catch { return null; }
}
// the site a name belongs to, roughly (its last two labels): app.example and keys.app.example are one
const siteOf = (h) => String(h || "").toLowerCase().replace(/^\[|\]$/g, "").replace(/:\d*$/, "").split(".").slice(-2).join(".");
export function jwt(v, where = "", host = "") {
  const t = String(v).trim();
  if (t.charCodeAt(0) !== 101 || t.charCodeAt(1) !== 121 || t.charCodeAt(2) !== 74) return null;            // "eyJ": a JSON object, base64url
  const d1 = t.indexOf("."), d2 = d1 < 0 ? -1 : t.indexOf(".", d1 + 1);
  if (d1 < 10 || d2 < 0 || t.indexOf(".", d2 + 1) >= 0) return null;
  const head = b64json(t.slice(0, d1));
  if (!head) return null;
  const w = where ? ` ${where}` : "";
  const alg = typeof head.alg === "string" ? head.alg.trim() : "";
  if (/^none$/i.test(alg)) return { id: "jwt-attack", sev: "critical", why: `a token with "alg": "${alg.slice(0, 8)}" (no signature to check)${w}`, cve: "CVE-2015-9235" };
  if (/^ES(256|384|512)$/i.test(alg)) {
    const sig = t.slice(d2 + 1);
    if (sig === "MAYCAQACAQA" || (sig.length >= 40 && /^A+=*$/.test(sig))) return { id: "jwt-attack", sev: "critical", why: `an ECDSA signature of zeros (a psychic signature)${w}`, cve: "CVE-2022-21449" };
  }
  if (head.kid !== undefined && head.kid !== null) {
    const kid = String(head.kid);
    // ids are names, hashes, dates, URLs, "auth0|key-2"; not a climb out of a folder, a system file, SQL or a command
    if (/\.\.[\/\\]|^[\/\\](dev|proc|etc|sys|tmp|var|usr|bin|boot|root|home)\b|^[a-z]:[\/\\]/i.test(kid)) return { id: "jwt-attack", sev: "critical", why: `a token whose kid is a file path (${kid.slice(0, 40)})${w}` };
    if (/['"]\s*(union|select|or|and)\b|['"]\s*(--|#|\/\*)|;\s*(select|drop|insert|update|delete)\b/i.test(kid)) return { id: "jwt-attack", sev: "critical", why: `a token whose kid is SQL (${kid.slice(0, 40)})${w}` };
    if (shell(kid)) return { id: "jwt-attack", sev: "critical", why: `a token whose kid is a command (${kid.slice(0, 40)})${w}` };
  }
  // where to fetch the key from: a token that names its own key server is asking to be believed
  for (const k of ["jku", "x5u"]) {
    if (head[k] === undefined) continue;
    const u = String(head[k]);
    const m = /^([a-z][a-z0-9+.-]*):\/\/([^\/?#]*)/i.exec(u);
    if (!m || m[1].toLowerCase() !== "https") return { id: "jwt-attack", sev: "critical", why: `a token that fetches its key over ${m ? m[1] : "a non-URL"} (${k}: ${u.slice(0, 60)})${w}` };
    const auth = m[2];
    if (auth.indexOf("@") >= 0 || oast(u)) return { id: "jwt-attack", sev: "critical", why: `a token that fetches its key from ${auth.slice(0, 60)} (${k})${w}` };
    const h = auth[0] === "[" ? auth.slice(0, auth.indexOf("]") + 1) : auth.replace(/:\d*$/, "");
    if (hostKind(h) || /^[\d.]+$/.test(h) || h[0] === "[") return { id: "jwt-attack", sev: "critical", why: `a token that fetches its key from an address (${k}: ${h.slice(0, 40)})${w}` };
    if (!host || siteOf(h) !== siteOf(host)) return { id: "jwt-attack", sev: "high", why: `a token that fetches its key from another site (${k}: ${h.slice(0, 50)})${w}` };
  }
  if (head.jwk && typeof head.jwk === "object") return { id: "jwt-attack", sev: "high", why: `a token that carries its own key (jwk)${w}`, cve: "CVE-2018-0114" };
  return null;
}

// ------------------------------------------------------------------ GraphQL
// One pass over the query (strings skipped): how deep it nests, how many
// aliases it uses and how often one field is asked under them, how many
// directives. Real queries nest about ten deep (connections: edges, node) and
// alias a field a few times; attacks go far past both.
const IDENT = /[_A-Za-z]\w*/y;
export function graphql(v) {
  if (v.length < 12 || v.indexOf("{") < 0) return null;
  let depth = 0, max = 0, paren = 0, aliases = 0, dirs = 0, top = 0, field = null;
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c === 34) { for (i++; i < v.length && v.charCodeAt(i) !== 34; i++) if (v.charCodeAt(i) === 92) i++; continue; }   // "a string"
    if (c === 123) { if (++depth > max) max = depth; }
    else if (c === 125) depth--;
    else if (c === 40) paren++;
    else if (c === 41) paren--;
    else if (c === 64) dirs++;
    else if (c === 58 && paren <= 0 && depth > 0) {                      // alias: field
      let j = i + 1;
      while (v.charCodeAt(j) === 32) j++;
      IDENT.lastIndex = j;
      const m = IDENT.exec(v);
      if (m) {
        aliases++;
        const n = ((field ||= new Map()).get(m[0]) || 0) + 1;
        field.set(m[0], n);
        if (n > top) top = n;
      }
    }
  }
  const intro = v.indexOf("__schema") >= 0 || /__type\b/.test(v);
  if (intro && max >= 8) return { id: "graphql-abuse", sev: "critical", why: `GraphQL introspection nested ${max} deep (a schema-cycle denial of service)` };
  if (max > 25) return { id: "graphql-abuse", sev: "critical", why: `a GraphQL query nested ${max} deep` };
  if (top >= 20) return { id: "graphql-abuse", sev: "critical", why: `the same GraphQL field asked ${top} times under aliases (batching past rate limits)` };
  if (aliases >= 100) return { id: "graphql-abuse", sev: "critical", why: `${aliases} aliases in one GraphQL query` };
  if (dirs >= 50) return { id: "graphql-abuse", sev: "critical", why: `${dirs} directives in one GraphQL query (directive overloading)` };
  if (max > 15) return { id: "graphql-abuse", sev: "high", why: `a GraphQL query nested ${max} deep` };
  if (aliases >= 40) return { id: "graphql-abuse", sev: "high", why: `${aliases} aliases in one GraphQL query` };
  return null;
}

// prototype pollution as JSON keys ({"__proto__": …}, {"constructor": {"prototype": …}})
export const PROTO_JSON = /["']__proto__["']\s*:|["']constructor["']\s*:\s*\{\s*["']prototype["']\s*:/i;

// ------------------------------------------------------------------ headers
// headers no attack hides in, or that the engine reads elsewhere (User-Agent, Referer)
const SKIP_H = new Set(["host", "user-agent", "referer", "accept", "accept-encoding", "accept-language", "connection", "cache-control", "pragma", "upgrade-insecure-requests",
                        "dnt", "priority", "te", "upgrade", "keep-alive", "purpose", "save-data", "viewport-width", "dpr", "device-memory", "rtt", "downlink", "ect",
                        "x-requested-with", "x-forwarded-proto", "x-forwarded-port", "x-forwarded-host", "cdn-loop", "cf-ray", "cf-ipcountry", "cf-visitor", "cf-connecting-ip",
                        "cf-ew-via", "cf-worker", "x-real-ip-verified", "content-encoding", "accept-charset", "origin-agent-cluster", "x-aegis-front-host",
                        "dpop"]);       // a DPoP proof carries its public key (jwk) by design
const IPISH = new Set(["x-forwarded-for", "x-real-ip", "x-client-ip", "true-client-ip", "x-originating-ip", "x-remote-ip", "x-remote-addr", "client-ip", "x-cluster-client-ip", "forwarded", "x-host", "x-forwarded-server"]);
// headers that name the host a request is for: anything but a host name there is an injection
// (password-reset links and cached pages built from it point elsewhere)
const HOSTISH = new Set(["host", "x-forwarded-host", "x-host", "x-original-host", "x-forwarded-server", "x-http-host-override", "x-backend-host"]);
const HOSTNAME = /^(?:\[[0-9a-f:.]+\]|[a-z0-9_][a-z0-9_.-]{0,252})(?::\d{1,5})?$/i;
const SCHEMEISH = new Set(["x-forwarded-proto", "x-forwarded-scheme", "x-forwarded-protocol", "x-url-scheme"]);
const PREFIXISH = new Set(["x-forwarded-prefix", "x-forwarded-path"]);
const DEFAULT_CREDS = new Set(["admin:admin", "admin:password", "admin:", "admin:1234", "admin:12345", "admin:123456", "root:root", "root:toor", "root:", "root:admin", "tomcat:tomcat", "tomcat:s3cret", "admin:tomcat",
                               "manager:manager", "user:user", "guest:guest", "test:test", "administrator:administrator", "admin:admin123", "ubnt:ubnt", "pi:raspberry", "support:support", "weblogic:weblogic1",
                               "admin:changeme", "elastic:changeme", "kibana:changeme", "grafana:admin", "nagiosadmin:nagiosadmin", "cisco:cisco", "oracle:oracle", "postgres:postgres", "sa:", "sa:sa"]);
const GATE = /\$\{|%\{|\(\)\s*\{|<[a-z?!%\/]|['"`;|]|\.\.[\/\\]|\$\(|rO0AB|jndi|\{\{|\.oast|oastify|interact|burpcollab|dnslog|!!|_\$\$ND/i;
// Connection: names the headers a proxy must drop; asking it to drop these is how
// a front end's framing or its view of the client is taken apart (hop-by-hop abuse)
const HOP = /(?:^|,)\s*(?:content-length|transfer-encoding|host|x-forwarded-[\w-]+|x-real-ip|forwarded|authorization|cookie|cf-connecting-ip|true-client-ip|x-client-ip)\s*(?:,|$)/i;
const STATIC = /\.(?:css|m?js|png|jpe?g|gif|ico|svg|webp|avif|woff2?|ttf|txt|xml|map)$/i;
const NEXT_ACTION = /^[0-9a-f]{40,64}$/i;           // a Server Action's id: a hash
const H = (id, sev, why, cve) => (cve ? { id, sev, why, cve } : { id, sev, why });
const NOHITS = Object.freeze([]);
// What a value means (code, a command, SQL, markup) is the costly part, and a
// browser sends the same cookie on every request: kept per header value (bounded).
const hcache = new Map();
// h: {name: value} with lowercased names (Node's req.headers), ctx: {method, proto, path, host}
// -> [{id, sev, why, cve?}]
export function headers(h, look, ctx = {}) {
  const out = [];
  if (!h || typeof h !== "object") return out;
  let te = null, cl = null, conn = null;
  for (const name in h) {
    let v = h[name];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string") v = Array.isArray(v) ? v.join(", ") : String(v);
    if (name === "transfer-encoding") { te = v; continue; }
    if (name === "content-length") { cl = v; continue; }
    if (name === "connection") { conn = v; continue; }
    // a line break inside a value: a folded header (obs-fold), or one smuggled in
    if (v.indexOf("\n") >= 0 || v.indexOf("\r") >= 0) { out.push(H("smuggling", "high", `a line break inside the ${name} header (obs-fold)`)); continue; }
    if (HOSTISH.has(name)) {
      const o = oast(v);
      if (o) { out.push({ ...o, why: `${o.why} in the ${name} header` }); continue; }
      const parts = name === "host" ? [v] : v.split(",");                          // X-Forwarded-Host may list every hop
      if (parts.some((p) => !HOSTNAME.test(p.trim()))) {
        if (/<\s*\/?\s*[a-z]|javascript\s*:|["'`]\s*>/i.test(v)) out.push(H("header-attack", "critical", `markup in the ${name} header`));
        else out.push(H("host-header", "high", `${name}: ${v.slice(0, 60)} (not a host name: host-header injection, cache poisoning)`));
        continue;
      }
      if (name === "host" || name === "x-forwarded-host") continue;
    } else if (SCHEMEISH.has(name)) {
      if (!/^\s*(https?|wss?)\s*(,|$)/i.test(v)) out.push(H("host-header", "high", `${name}: ${v.slice(0, 30)} (cache poisoning)`));
      continue;
    } else if (PREFIXISH.has(name)) {
      if (!/^\/(?![\/\\])[\w\-.~%\/]*$/.test(v.trim())) out.push(H("host-header", "high", `${name}: ${v.slice(0, 40)} (cache poisoning)`));
      continue;
    } else if (name === "forwarded") {
      for (const m of v.matchAll(/(?:^|[;,])\s*host\s*=\s*("[^"]*"|[^;,]*)/gi)) {
        const x = m[1].replace(/^"|"$/g, "").trim();
        if (!HOSTNAME.test(x)) { out.push(H("host-header", "high", `Forwarded: host=${x.slice(0, 40)} (not a host name)`)); break; }
      }
    }
    if (SKIP_H.has(name) || name.startsWith("sec-") || name.startsWith("if-") || name.startsWith("x-aegis") || name.startsWith("x-burrow") || name === "x-gate") continue;
    if (name === "x-middleware-subrequest") { out.push(H("nextjs-middleware", "critical", `x-middleware-subrequest: ${v.slice(0, 60)}`)); continue; }
    // Next.js's own internal headers, from outside
    if (name === "x-now-route-matches") { out.push(H("nextjs-cache-poison", "critical", `x-now-route-matches: ${v.slice(0, 40)} (only Next.js itself sends it)`)); continue; }
    if (name === "next-action") { if (!NEXT_ACTION.test(v.trim())) out.push(H("nextjs-rsc", "high", `Next-Action: ${v.slice(0, 30)} (not a Server Action id: a React Server Components exploit probe)`)); continue; }
    // a Location header in a request: Next.js middleware that passes the request's headers on follows it
    if (name === "location") {
      const m = /^\s*[a-z][\w+.-]*:\/\/(?:[^@\/?#]*@)?(\[[^\]]+\]|[^\/:?#\s]+)/i.exec(v);
      const k = m ? hostKind(m[1]) : null;
      out.push(H("nextjs-ssrf", k ? "critical" : "high", `a Location header in a request (${v.slice(0, 60)})${k ? `: ${k === "meta" ? "the cloud metadata service" : "an internal address"}` : ""}`));
      continue;
    }
    if (name === "spring.cloud.function.routing-expression") { out.push(H("spring-function", "critical", "a SpEL routing expression header")); continue; }
    if (name === "x-original-url" || name === "x-rewrite-url" || name === "x-override-url") { out.push(H("access-bypass", "medium", `${name}: ${v.slice(0, 60)}`)); continue; }
    if (name === "x-http-method-override" || name === "x-http-method" || name === "x-method-override") { if (/^(trace|track|debug|connect)$/i.test(v.trim())) out.push(H("trace-method", "medium", `${name}: ${v.slice(0, 20)}`)); continue; }
    if (name === "range") { if (/bytes\s*=\s*\d*-\s*18446744073709551615/i.test(v)) out.push(H("httpsys-range", "critical", "an HTTP.sys integer overflow (MS15-034)")); continue; }
    if (name === "authorization" && /^basic\s/i.test(v)) {
      let up = ""; try { up = Buffer.from(v.trim().slice(6).trim(), "base64").toString("latin1"); } catch { /* not base64 */ }
      if (DEFAULT_CREDS.has(up.toLowerCase())) out.push(H("default-creds", "high", `default credentials (${up.split(":")[0]}:…)`));
      continue;
    }
    if (IPISH.has(name) && /^[\d.:,\s\[\]a-f]*$/i.test(v) && v.split(",").some((x) => { const k = hostKind(x.trim().replace(/^\[|\]$/g, "")); return k === "loop" || k === "meta"; })) { out.push(H("ip-spoof", "medium", `${name}: ${v.slice(0, 60)} (posing as this machine)`)); continue; }
    // tokens: a JWT needs none of the characters the gate below waits for
    if (v.indexOf("eyJ") >= 0) {
      const where = `in the ${name} header`;
      let j = null;
      if (name === "cookie") { for (const crumb of v.split(";")) { const e = crumb.indexOf("="); const cv = crumb.slice(e + 1).trim(); if (cv.startsWith("eyJ") && (j = jwt(cv, `in a cookie`, ctx.host || h.host))) break; } }
      else if (name === "authorization") { const m = /^\s*(?:bearer|jwt|token|dpop)\s+(eyJ\S+)/i.exec(v); if (m) j = jwt(m[1], where, ctx.host || h.host); }
      else if (v.startsWith("eyJ")) j = jwt(v, where, ctx.host || h.host);
      if (j) out.push(j);
    }
    // (a cookie may hold its JSON percent-encoded: %7B%22…)
    if (v.length < 3 || !(GATE.test(v) || name === "cookie" && /%(2[247]|3[cC]|60|7[bBcC])/.test(v))) continue;
    const key = name + "\u0001" + v;
    let r = hcache.get(key);
    if (r === undefined) {
      r = meaning(name, v, look);
      if (hcache.size >= 2048) hcache.clear();
      if (key.length < 4096) hcache.set(key, r);
    }
    for (const x of r) out.push(x);
  }
  // request smuggling: both lengths, or a Transfer-Encoding only some servers understand
  const m = String(ctx.method || "GET").toUpperCase();
  if (te !== null) {
    const t = te.trim().toLowerCase();
    if (t !== "chunked" && !/^((gzip|deflate|br|compress|identity)\s*,\s*)+chunked$/.test(t)) out.push(H("smuggling", "high", `an obfuscated Transfer-Encoding (${JSON.stringify(te.slice(0, 30))})`));
    else if (cl !== null) out.push(H("smuggling", "high", "both Content-Length and Transfer-Encoding (request smuggling)"));
    // a body where none belongs: a front end that ignores it leaves it for the back end as the next request
    else if (m === "GET" || m === "HEAD" || m === "OPTIONS") out.push(H("smuggling", "high", `a chunked body on a ${m} (request smuggling)`));
    else if (ctx.proto === "1.0") out.push(H("smuggling", "high", "Transfer-Encoding on HTTP/1.0, which has none (request smuggling)"));
  }
  if (cl !== null) {
    if (!/^\s*\d{1,15}\s*$/.test(cl)) out.push(H("smuggling", "high", `a malformed Content-Length (${JSON.stringify(cl.slice(0, 30))})`));
    else if ((m === "GET" || m === "HEAD") && Number(cl) > 0) {
      const p = String(ctx.path || ""), q = p.indexOf("?");
      if (STATIC.test(q < 0 ? p : p.slice(0, q))) out.push(H("smuggling", "high", `a ${cl.trim()}-byte body on a ${m} for a static file (CL.0 request smuggling)`));
    }
  }
  if (conn !== null && HOP.test(conn)) out.push(H("smuggling", "high", `Connection: ${conn.slice(0, 50)} (asks a proxy to drop a header it relies on)`));
  return out;
}
// one header value that got past the gate: what it means
function meaning(name, v, look) {
  const out = [];
  const where = `in the ${name} header`;
  const add = (r) => { if (r) out.push({ ...r, why: `${r.why} ${where}` }); return !!r; };
  if (name === "content-type" && /%\{|\$\{|#_memberaccess|@ognl|ognlcontext/i.test(v)) { out.push(H("struts-ognl", "critical", "an OGNL expression in Content-Type (S2-045)")); return out; }
  if (/\(\)\s*\{\s*[:_a-z]*\s*;?\s*\}\s*;/i.test(v)) { out.push(H("shellshock", "critical", `a function definition ${where}`)); return out; }
  const j = look.jndi(v, where);
  if (j) { out.push(j); return out; }
  if (/%\{\s*\(#|\$\{\s*\(#|#_memberaccess|@ognl\.ognlcontext/i.test(v)) { out.push(H("struts-ognl", "critical", `an OGNL expression ${where}`)); return out; }
  if (add(oast(v))) return out;
  if (PROTO_JSON.test(v)) { out.push(H("proto-pollution", "critical", `prototype pollution (a __proto__ key) ${where}`)); return out; }
  if (name === "cookie") {
    for (const crumb of v.split(";")) {
      const e = crumb.indexOf("=");
      let cv = (e < 0 ? crumb : crumb.slice(e + 1)).trim();
      if (cv.length < 4) continue;
      if (cv.indexOf("%") >= 0) { try { cv = decodeURIComponent(cv); } catch { /* as it is */ } }
      if (!/['"`;|<$(\\.!]|rO0AB|^(Tz|YT|gAS)/.test(cv)) continue;
      if (add(deser(cv))) break;
      if (/^rO0AB[A-Za-z0-9+/]{8}/.test(cv)) { out.push(H("deser", "critical", `a Java serialized object ${where}`)); break; }
      if (/(\.\.[\/\\]){2,}|\.\.[\/\\].*(etc\/passwd|win\.ini|\.env)/i.test(cv)) { out.push(H("traversal", "critical", `../ ${where}`)); break; }
      if (PROTO_JSON.test(cv)) { out.push(H("proto-pollution", "critical", `prototype pollution (a __proto__ key) ${where}`)); break; }
      if (add(shell(cv)) || add(code(cv))) break;
      if (/<\s*(script|svg|img|iframe)\b|\bon(error|load)\s*=|javascript\s*:/i.test(cv)) { out.push(H("xss", "critical", `markup ${where}`)); break; }
      if (cv.indexOf("'") >= 0) { const q = look.sqli(cv); if (q?.sev === "critical") { out.push(H("sqli", "critical", `${q.why} ${where}`)); break; } }
    }
    return out.length ? out : NOHITS;
  }
  if (name === "authorization") {
    if (/^bearer\s/i.test(v) && v.indexOf("'") >= 0) { const q = look.sqli(v.slice(7)); if (q) out.push(H("sqli", "critical", `${q.why} ${where}`)); }
    return out.length ? out : NOHITS;
  }
  if (IPISH.has(name) && (/^[\w.:,\s\[\]-]*$/.test(v) || name === "forwarded" && /^(\s*(for|by|proto|host)=("[^"]*"|[^;,"]*)\s*[;,]?)+$/i.test(v))) return NOHITS;     // an address list, or Forwarded: for=…;proto=…
  // anything else: a header is never code, a command, SQL or markup
  if (add(shell(v)) || add(code(v)) || add(ssti(v))) return out;
  if (/<\s*(script|svg|img|iframe|body)\b|<\?php|\bon(error|load)\s*=|javascript\s*:/i.test(v)) { out.push(H("header-attack", "critical", `markup or PHP ${where}`)); return out; }
  if (/['"]/.test(v) || /\b(union|select|sleep|benchmark|waitfor)\b/i.test(v)) { const q = look.sqli(v); if (q && (q.sev === "critical" || IPISH.has(name))) { out.push(H("sqli", "critical", `${q.why} ${where}`)); return out; } }
  return out.length ? out : NOHITS;
}
