// What a request is after. Each signature has a name, so the dashboard can
// group attacks into patterns ("env-file", "git", "traversal"...).
//   score 3: a payload: looking for secrets or a way in, never a page anybody needs (dropped)
//   score 1: a probe: asking for software that isn't here (a mark, not dropped)

const S = (id, name, score, ...res) => ({ id, name, score, res });
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
  S("router", "router & IoT exploits", 3, /\/(boaform|GponForm|HNAP1|setup\.cgi|shell\?|tmUnblock\.cgi|hndUnblock\.cgi)/i, /\/cgi-bin\/.*(\.sh|bash|luci|;)/i),
  S("java-admin", "Java / Spring admin endpoints", 3, /\/(actuator\/(env|heapdump|gateway)|_ignition\/execute-solution|telescope\/requests)/i,
    /\/(solr\/admin|jmx-console|invoker\/JMXInvokerServlet|vendor\/laravel-filemanager|server-status)/i),
  S("wordpress", "WordPress logins", 1, /(^|\/)(wp-login|wp-admin|xmlrpc)/i),
  S("db-admin", "database admin panels", 1, /(^|\/)(phpmyadmin|pma|myadmin|mysql|adminer)(\/|$)/i),
  S("vpn-panel", "VPN, mail & admin panels", 1, /(^|\/)(manager\/html|owa|ecp|autodiscover|remote\/login|dana-na|global-protect|vpn|geoserver|druid|console|nacos|jenkins)(\/|$)/i),
  S("device", "device & legacy paths", 1, /(^|\/)(cgi-bin|scripts|webdav|HNAP1|portal|sdk|onvif|ReportServer|api\/jsonws|level\/15|mgmt)(\/|$)/i),
  S("php-probe", "PHP / ASP / CGI scripts", 1, /\.(php\d?|phtml|asp|aspx|jsp|cgi|pl|do|action)(\?|$)/i),
];
export const signatureById = (id) => SIGNATURES.find((s) => s.id === id);

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
