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
//   headers(h)             every request header that can carry an attack

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

// ------------------------------------------------------------------ headers
// headers no attack hides in, or that the engine reads elsewhere (User-Agent, Referer)
const SKIP_H = new Set(["host", "user-agent", "referer", "accept", "accept-encoding", "accept-language", "connection", "cache-control", "pragma", "upgrade-insecure-requests",
                        "dnt", "priority", "te", "upgrade", "keep-alive", "purpose", "save-data", "viewport-width", "dpr", "device-memory", "rtt", "downlink", "ect",
                        "x-requested-with", "x-forwarded-proto", "x-forwarded-port", "x-forwarded-host", "cdn-loop", "cf-ray", "cf-ipcountry", "cf-visitor", "cf-connecting-ip",
                        "cf-ew-via", "cf-worker", "x-real-ip-verified", "content-encoding", "accept-charset", "origin-agent-cluster", "x-aegis-front-host"]);
const IPISH = new Set(["x-forwarded-for", "x-real-ip", "x-client-ip", "true-client-ip", "x-originating-ip", "x-remote-ip", "x-remote-addr", "client-ip", "x-cluster-client-ip", "forwarded", "x-host", "x-forwarded-server"]);
const DEFAULT_CREDS = new Set(["admin:admin", "admin:password", "admin:", "admin:1234", "admin:12345", "admin:123456", "root:root", "root:toor", "root:", "root:admin", "tomcat:tomcat", "tomcat:s3cret", "admin:tomcat",
                               "manager:manager", "user:user", "guest:guest", "test:test", "administrator:administrator", "admin:admin123", "ubnt:ubnt", "pi:raspberry", "support:support", "weblogic:weblogic1",
                               "admin:changeme", "elastic:changeme", "kibana:changeme", "grafana:admin", "nagiosadmin:nagiosadmin", "cisco:cisco", "oracle:oracle", "postgres:postgres", "sa:", "sa:sa"]);
const GATE = /\$\{|%\{|\(\)\s*\{|<[a-z?!%\/]|['"`;|]|\.\.[\/\\]|\$\(|rO0AB|jndi|\{\{|\.oast|oastify|interact|burpcollab|dnslog|!!|_\$\$ND/i;
const H = (id, sev, why) => ({ id, sev, why });
// h: {name: value} with lowercased names (Node's req.headers) -> [{id, sev, why}]
export function headers(h, look) {
  const out = [];
  if (!h || typeof h !== "object") return out;
  let te = null, cl = null;
  for (const name in h) {
    let v = h[name];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string") v = Array.isArray(v) ? v.join(", ") : String(v);
    if (name === "transfer-encoding") { te = v; continue; }
    if (name === "content-length") { cl = v; continue; }
    if (SKIP_H.has(name) || name.startsWith("sec-") || name.startsWith("if-") || name.startsWith("x-aegis") || name.startsWith("x-burrow") || name === "x-gate") continue;
    if (name === "x-middleware-subrequest") { out.push(H("nextjs-middleware", "critical", `x-middleware-subrequest: ${v.slice(0, 60)}`)); continue; }
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
    if (v.length < 3 || !GATE.test(v)) continue;
    const where = `in the ${name} header`;
    const add = (r) => { if (r) out.push({ ...r, why: `${r.why} ${where}` }); return !!r; };
    if (name === "content-type" && /%\{|\$\{|#_memberaccess|@ognl|ognlcontext/i.test(v)) { out.push(H("struts-ognl", "critical", "an OGNL expression in Content-Type (S2-045)")); continue; }
    if (/\(\)\s*\{\s*[:_a-z]*\s*;?\s*\}\s*;/i.test(v)) { out.push(H("shellshock", "critical", `a function definition ${where}`)); continue; }
    const j = look.jndi(v, where);
    if (j) { out.push(j); continue; }
    if (/%\{\s*\(#|\$\{\s*\(#|#_memberaccess|@ognl\.ognlcontext/i.test(v)) { out.push(H("struts-ognl", "critical", `an OGNL expression ${where}`)); continue; }
    if (add(oast(v))) continue;
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
        if (add(shell(cv)) || add(code(cv))) break;
        if (/<\s*(script|svg|img|iframe)\b|\bon(error|load)\s*=|javascript\s*:/i.test(cv)) { out.push(H("xss", "critical", `markup ${where}`)); break; }
        if (cv.indexOf("'") >= 0) { const q = look.sqli(cv); if (q?.sev === "critical") { out.push(H("sqli", "critical", `${q.why} ${where}`)); break; } }
      }
      continue;
    }
    if (name === "authorization") {
      if (/^bearer\s/i.test(v) && v.indexOf("'") >= 0) { const q = look.sqli(v.slice(7)); if (q) out.push(H("sqli", "critical", `${q.why} ${where}`)); }
      continue;
    }
    if (IPISH.has(name) && (/^[\w.:,\s\[\]-]*$/.test(v) || name === "forwarded" && /^(\s*(for|by|proto|host)=("[^"]*"|[^;,"]*)\s*[;,]?)+$/i.test(v))) continue;     // an address list, or Forwarded: for=…;proto=…
    // anything else: a header is never code, a command, SQL or markup
    if (add(shell(v)) || add(code(v)) || add(ssti(v))) continue;
    if (/<\s*(script|svg|img|iframe|body)\b|<\?php|\bon(error|load)\s*=|javascript\s*:/i.test(v)) { out.push(H("header-attack", "critical", `markup or PHP ${where}`)); continue; }
    if (/['"]/.test(v) || /\b(union|select|sleep|benchmark|waitfor)\b/i.test(v)) { const q = look.sqli(v); if (q && (q.sev === "critical" || IPISH.has(name))) { out.push(H("sqli", "critical", `${q.why} ${where}`)); continue; } }
  }
  // request smuggling: both lengths, or a Transfer-Encoding only some servers understand
  if (te !== null) {
    const t = te.trim().toLowerCase();
    if (t !== "chunked" && !/^((gzip|deflate|br|compress|identity)\s*,\s*)+chunked$/.test(t)) out.push(H("smuggling", "high", `an obfuscated Transfer-Encoding (${JSON.stringify(te.slice(0, 30))})`));
    else if (cl !== null) out.push(H("smuggling", "high", "both Content-Length and Transfer-Encoding (request smuggling)"));
  }
  if (cl !== null && !/^\s*\d{1,15}\s*$/.test(cl)) out.push(H("smuggling", "high", `a malformed Content-Length (${JSON.stringify(cl.slice(0, 30))})`));
  return out;
}
