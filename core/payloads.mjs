// What a request is after. Each signature has a name, so the dashboard can
// group attacks into patterns ("env-file", "git", "traversal"...).
//   score 3: a payload: looking for secrets or a way in, never a page anybody needs (dropped)
//   score 1: a probe: asking for software that isn't here (a mark, not dropped)

const S = (id, name, score, ...res) => ({ id, name, score, res });
// Raised whenever the signatures learn something: the app then reads its log
// again with them (Brain.rescan), so what slipped past before is caught now.
export const SIGNATURES_VERSION = 2;
export const SIGNATURES = [
  S("env-file", ".env files", 3, /(^|\/)\.env(\.[\w.-]*)?$/i),
  S("vcs", "Git / SVN metadata", 3, /(^|\/)\.(git|svn|hg|bzr)(\/|$)/i, /(^|\/)\.git-credentials$/i),
  S("cloud-creds", "cloud & SSH credentials", 3, /(^|\/)\.(aws|ssh|docker|kube|azure|gnupg)(\/|$)/i, /(^|\/)(id_rsa|id_ed25519|id_ecdsa)(\.pub)?$/i,
    /\/(aws|amazon|s3|gcp|firebase|stripe|twilio|sendgrid|mailgun)[-_.]?(credentials|config|keys?)\.(json|ya?ml|txt|env)/i),
  S("dotfiles", "dotfiles & editor configs", 3, /(^|\/)\.(npmrc|pypirc|netrc|htpasswd|htaccess|bash_history|zsh_history|ds_store|dockercfg|s3cfg)$/i,
    /(^|\/)\.vscode\/sftp\.json$/i, /(^|\/)sftp-config\.json$/i),
  S("config-leak", "config & secret files", 3, /wp-config\.php/i, /(^|\/)(config|settings|database|secrets?|credentials)\.(ya?ml|ini|bak|old|sql|php\.bak|php~)$/i),
  S("backup", "backups & dumps", 3, /(^|\/)[\w.-]*\.(sql|sql\.gz|sqlite3?|bak|old|swp)$/i, /(^|\/)(backup|dump|db|database|site|www)\.(zip|tar|tar\.gz|tgz|rar|7z)$/i),
  S("traversal", "path traversal", 3, /\.\.[\/\\]/, /%2e%2e/i, /%252e/i, /\/etc\/(passwd|shadow|hosts)/i, /\/proc\/self\//i, /win\.ini/i, /boot\.ini/i),
  S("php-rce", "PHP code execution", 3, /phpunit/i, /eval-stdin\.php/i, /php:\/\/(input|filter)/i, /allow_url_include/i, /auto_prepend_file/i),
  S("log4shell", "Log4Shell / JNDI", 3, /\$\{jndi:/i, /\$\{(::-|env:|lower:|upper:)/i),
  S("xss", "script injection", 3, /<script/i),
  S("sqli", "SQL injection", 3, /union(\s|%20|\+|\/\*.*\*\/)+select/i),
  S("cmd-inject", "command injection", 3, /(;|%3b|\||%7c)\s*(wget|curl|sh|bash|nc|busybox|chmod)(\s|%20|\+)/i, /\$\((wget|curl|sh|echo|id)/i, /`(wget|curl|id)/i),
  S("router", "router & IoT exploits", 3, /\/(boaform|GponForm|HNAP1|setup\.cgi|shell\?|tmUnblock\.cgi|hndUnblock\.cgi)/i, /\/cgi-bin\/.*(\.sh|bash|luci|;)/i,
    /\/goform\//i, /\/SDK\/webLanguage/i, /\/(cgi-bin\/)?luci\/;stok=/i, /\/picsdesc\.xml/i, /\/(ctrlt|UD)\/DeviceUpgrade/i, /\/apply\.cgi/i),
  S("rce", "remote code execution", 3, /[?&](cmd|exec|command|execute|ping|query)=[^&]*(\b(wget|curl|id|uname|whoami|cat|echo)\b|[;|`$])/i, /base64_decode\(|die\(md5\(|print\(md5\(|<\?php/i,
    /invokefunction|call_user_func_array/i, /class\.module\.classLoader/i, /%\{\(#|\$\{\(#|ognl/i, /\/bin\/(ba)?sh\b/i, /XDEBUG_SESSION_START/i, /\/vendor\/phpunit/i, /think\\app/i),
  S("edge-exploit", "VPN & firewall exploits", 3, /\/remote\/fgt_lang/i, /\/\+CSCOE\+\//i, /\/mifs\//i, /\/webui\/logoutconfirm/i, /\/api\/v2\/cmdb\//i,
    /\/(owa\/auth\/x\.js|autodiscover\/autodiscover\.json\?.*powershell)/i, /\/(vpn|dana-na|dana-cached)\/.*\.\./i, /\/(ssl-vpn|sslvpn)\/.*(\.\.|%2e)/i),
  S("infra-api", "Docker, Kubernetes & cluster APIs", 3, /\/(containers\/json|v1\.\d+\/containers|images\/json)/i, /\/api\/v1\/(namespaces|pods|secrets|nodes)/i, /\/v2\/_catalog/i,
    /\/(_cat\/indices|_all\/_search|_cluster\/health|_nodes)/i, /\/debug\/(pprof|vars)/i, /\/(metrics\/v1|v1\/metadata|computeMetadata|latest\/meta-data)/i),
  S("info-leak", "debug pages & build files", 3, /(^|\/)(phpinfo|info|pi|test|i)\.php$/i, /\/(server-info|_profiler|_debugbar|elmah\.axd|trace\.axd)(\/|$)/i,
    /\/storage\/logs\/laravel\.log/i, /(^|\/)(web\.config|appsettings(\.\w+)?\.json|docker-compose\.ya?ml|\.gitlab-ci\.yml|\.travis\.yml|\.circleci\/config\.yml|secrets\.json|credentials\.json|service-account\.json|firebase\.json|\.git-credentials|terraform\.tfstate)$/i, /(^|\/)\.terraform(\/|$)/i),
  S("phish-kit", "phishing kits (looked for, or planted)", 3, /(^|\/)[a-z]{2,10}_(ch|de|at|fr|it|es|uk|nl|pl|us)\.js$/i, /(^|\/)(qrcode_twint|twint|antibot(-client)?|bot-connect|licensor|anti_?bot|blocker|visitor_log|telegram_?bot)\.(js|php)$/i,
    /\/(sys_files|style\/protect|static\/style\/protect|prevents|antibots?)\//i, /\/(webscr|signin\.ebay|paypal\.com\.|appleid\.apple\.com\.)/i),
  S("java-admin", "Java / Spring admin endpoints", 3, /\/(actuator\/(env|heapdump|gateway)|_ignition\/execute-solution|telescope\/requests)/i,
    /\/(solr\/admin|jmx-console|invoker\/JMXInvokerServlet|vendor\/laravel-filemanager|server-status)/i),
  S("wordpress", "WordPress logins", 1, /(^|\/)(wp-login|wp-admin|xmlrpc)/i),
  S("db-admin", "database admin panels", 1, /(^|\/)(phpmyadmin|pma|myadmin|mysql|adminer)(\/|$)/i),
  S("vpn-panel", "VPN, mail & admin panels", 1, /(^|\/)(manager\/html|owa|ecp|autodiscover|remote\/login|dana-na|global-protect|vpn|geoserver|druid|console|nacos|jenkins)(\/|$)/i),
  S("device", "device & legacy paths", 1, /(^|\/)(cgi-bin|scripts|webdav|HNAP1|portal|sdk|onvif|ReportServer|api\/jsonws|level\/15|mgmt)(\/|$)/i),
  S("php-probe", "PHP / ASP / CGI scripts", 1, /\.(php\d?|phtml|asp|aspx|jsp|cgi|pl|do|action)(\?|$)/i),
];
// Tools that announce themselves in the User-Agent. Attack tools are payloads
// whatever they ask for; mass scanners only mark.
export const UA_SIGNATURES = [
  S("attack-tool", "attack tools", 3, /\b(sqlmap|nikto|nuclei|wpscan|gobuster|dirbuster|dirsearch|ffuf|feroxbuster|wfuzz|hydra|commix|joomscan|whatweb|acunetix|netsparker|nessus|openvas|jaeles|xray\/|fuzz faster)\b/i),
  S("scanner-ua", "mass scanners", 1, /\b(zgrab|masscan|l9explore|l9tcpid|nmap scripting engine|censysinspect|expanse|internet-measurement|odin|zmap|httpx|fasthttp|go-http-client\/1\.1$|python-requests|aiohttp|libwww-perl)\b/i, /^Mozilla\/5\.0 \(compatible; ?\)$/, /^Hello,? World/i),
];
export const signatureById = (id) => SIGNATURES.find((s) => s.id === id) || UA_SIGNATURES.find((s) => s.id === id);
export function classifyUa(ua) {
  const u = String(ua || "");
  if (!u) return NONE;
  for (const s of UA_SIGNATURES) for (const re of s.res) if (re.test(u)) return s;
  return NONE;
}
// The path, then the User-Agent: whichever says more.
export function classifyRequest(path, ua) {
  const p = classify(path);
  if (p.score === 3) return p;
  const u = classifyUa(ua);
  return u.score > p.score ? { ...u, ua: true } : p;
}

const NONE = { score: 0, id: null, name: null };
// path: the request's path and query, as sent -> {score, id, name}
export function classify(path) {
  const p = String(path || "");
  if (p === "/" || p.length < 3) return NONE;
  let d = p;
  if (p.includes("%")) { try { d = decodeURIComponent(p); } catch { /* bad escapes: test it as it is */ } }
  const q = d.indexOf("?"), bare = q < 0 ? d : d.slice(0, q);
  const full = q >= 0, raw = p !== d;
  for (const s of SIGNATURES) {
    for (const re of s.res) {
      if (re.test(bare) || (s.score === 3 && ((full && re.test(d)) || (raw && re.test(p))))) return s;
    }
  }
  return NONE;
}
