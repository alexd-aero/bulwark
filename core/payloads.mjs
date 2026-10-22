// What a request is after. The detection engine, in four steps:
//
//   1. normalize   the path and every query value decoded the way the app will
//                  see them (normalize.mjs: multi-pass URL decoding, %u, overlong
//                  UTF-8, look-alike folding, entities, null bytes, dot segments)
//   2. match       signatures, each with a category (taxonomy.mjs), a severity
//                  and, for a published exploit, its CVE; run on the path, the
//                  query and the User-Agent / Referer where they belong
//   3. lexers      SQL injection and XSS judged by shape, value by value
//                  (lexers.mjs), plus SSRF, Log4Shell lookups, deserialization
//                  and protocol anomalies (methods, proxy probes, CRLF, sizes)
//   4. score       CRS-style anomaly scoring: every distinct hit adds its
//                  severity's points; 5 or more is a payload (dropped). Evasion
//                  that hid a hit adds to it
//
// inspect({method, path, ua, referer, lang}) -> {score, id, name, cat, sev, pts,
// hits, cve, det, label}. score keeps the old meaning: 3 a payload, 1 a probe or a
// label, 0 nothing. label: only informational hits (a scanner's name), which
// never count against an address. Results are cached per path and per
// User-Agent (bounded), so the common request costs a map lookup.

import { normalize } from "./normalize.mjs";
import { sqli, xss } from "./lexers.mjs";
import { Matcher } from "./matcher.mjs";
import { SEVERITY, DROP_AT, categoryById, sevPoints, sevRank } from "./taxonomy.mjs";

// Raised whenever the signatures learn something: the app then reads its log
// again with them (Brain.rescan), so what slipped past before is caught now.
export const SIGNATURES_VERSION = 3;

// in: where it is looked for. path: the path only (decoded, collapsed and as
// sent); url: the path and the query; query: the query values only.
// probe: asking for software that may simply not be here; it counts against an
// address only when the answer says it isn't (4xx), never when the app served it.
const S = (id, name, cat, sev, opts, ...res) => {
  if (!opts || opts instanceof RegExp) { if (opts) res.unshift(opts); opts = {}; }
  return { id, name, cat, sev, score: sev === "critical" ? 3 : 1, in: opts.in || "url", cve: opts.cve || null, probe: !!opts.probe, res };
};
const P = { in: "path" }, Q = { in: "query" };

export const SIGNATURES = [
  // ---- known CVE exploits (most specific first) ------------------------------------------------
  S("phpunit-rce", "PHPUnit eval-stdin RCE", "cve", "critical", { cve: "CVE-2017-9841" }, /eval-stdin\.php/i, /\/phpunit\/(phpunit\/)?(src\/)?util\//i, /(^|\/)vendor\/phpunit(\/|$)/i),
  S("thinkphp-rce", "ThinkPHP invokefunction RCE", "cve", "critical", { cve: "CVE-2018-20062" }, /invokefunction|call_user_func_array/i, /think\\+(app|request|template|container)/i, /\bs=\/?index\/\\?think/i),
  S("spring4shell", "Spring4Shell class loader", "cve", "critical", { cve: "CVE-2022-22965" }, /class\.module\.classloader/i, /class\[module\]\[classloader\]/i),
  S("struts-ognl", "Apache Struts OGNL injection", "cve", "critical", { cve: "CVE-2017-5638" }, /%\{\s*\(#|\$\{\s*\(#|\(#_memberaccess|@ognl\.ognlcontext|#context\[["']xwork/i, /\/(struts2?-?showcase|struts\/[^/]*\.action)\b.*\$\{/i),
  S("confluence-rce", "Confluence OGNL / setup bypass", "cve", "critical", { cve: "CVE-2022-26134" }, /\$\{[^}]{0,200}(@java\.lang\.runtime|getruntime\(|javax\.script|ognl\.)/i,
    /\/pages\/createpage-entervariables\.action/i, /\/server-info\.action\?.*bootstrapstatusprovider/i, /\/setup\/setupadministrator\.action/i),
  S("fortinet-traversal", "FortiOS SSL-VPN path traversal", "cve", "critical", { cve: "CVE-2018-13379" }, /\/remote\/fgt_lang\?lang=.*\.\./i, /\/api\/v2\/cmdb\/system\/admin/i),
  S("cisco-asa-traversal", "Cisco ASA path traversal", "cve", "critical", { cve: "CVE-2020-3452" }, /\/\+CSCOT\+\/(translation-table|oem-customization)\?/i),
  S("citrix-traversal", "Citrix ADC path traversal", "cve", "critical", { cve: "CVE-2019-19781" }, /\/vpns?\/\.\.\/vpns\//i, /\/vpns\/(portal\/scripts|cfg\/smb\.conf)/i),
  S("pulse-traversal", "Pulse Secure file read", "cve", "critical", { cve: "CVE-2019-11510" }, /\/dana-na\/.*\.\.\/.*dana\/html5acc/i, /\/dana-na\/\.\.\//i),
  S("f5-bigip-rce", "F5 BIG-IP TMUI / iControl RCE", "cve", "critical", { cve: "CVE-2020-5902" }, /\/tmui\/login\.jsp\/\.\.;\//i, /\/mgmt\/tm\/util\/bash/i, /\/tmui\/locallb\/workspace\//i),
  S("exchange-proxyshell", "Exchange ProxyShell / ProxyNotShell", "cve", "critical", { cve: "CVE-2021-34473" }, /autodiscover\/autodiscover\.json\?@/i, /autodiscover\.json.{0,80}(powershell|mapi\/nspi)/i),
  S("exchange-proxylogon", "Exchange ProxyLogon", "cve", "critical", { cve: "CVE-2021-26855" }, /\/owa\/auth\/x\.js/i, /\/ecp\/(y|x|[a-z])\.js$/i),
  S("apache-traversal", "Apache 2.4.49/50 path traversal", "cve", "critical", { cve: "CVE-2021-41773", in: "path" }, /\/(cgi-bin|icons)\/(\.%2e|%2e\.|%2e%2e|\.%%32%65|%%32%65)/i),
  S("ignition-rce", "Laravel Ignition RCE", "cve", "critical", { cve: "CVE-2021-3129" }, /_ignition\/execute-solution/i),
  S("drupalgeddon2", "Drupalgeddon 2", "cve", "critical", { cve: "CVE-2018-7600" }, /element_parents=.*#value/i, /\[#(markup|post_render|pre_render|lazy_builder)\]/i, /_triggering_element_name=/i),
  S("vbulletin-rce", "vBulletin widget RCE", "cve", "critical", { cve: "CVE-2019-16759" }, /routestring=ajax\/render\/widget_(php|tabbedcontainer_tab_panel)/i),
  S("vmware-rce", "VMware vCenter / Workspace ONE RCE", "cve", "critical", { cve: "CVE-2021-21972" }, /\/ui\/vropspluginui\/rest\/services\/(uploadova|getstatus)/i,
    /\/catalog-portal\/ui\/oauth\/verify\?.*\$\{/i, /\/ui\/h5-vsan\/rest\/proxy\/service\//i),
  S("ivanti-rce", "Ivanti Connect Secure / EPMM bypass", "cve", "critical", { cve: "CVE-2023-46805" }, /\/api\/v1\/(totp\/user-backup-code|cav\/client\/status)\/\.\.\//i, /\/api\/v1\/license\/keys-status\/;/i,
    /\/mifs\/aad\/api\/v2\/authorized\/users/i, /\/mifs\/\.;\/services/i),
  S("ofbiz-rce", "Apache OFBiz auth bypass RCE", "cve", "critical", { cve: "CVE-2023-51467" }, /\/webtools\/control\/(forgotpassword\/)?(programexport|xmlrpc)\b.*(requirepasswordchange|;|\?)/i, /requirepasswordchange=y/i),
  S("teamcity-bypass", "TeamCity auth bypass", "cve", "critical", { cve: "CVE-2023-42793" }, /\/app\/rest\/users\/id:\d+\/tokens\/rpc2/i, /\/hax\?jsp=\/app\/rest/i),
  S("geoserver-rce", "GeoServer property-name RCE", "cve", "critical", { cve: "CVE-2024-36401" }, /\/geoserver\/.{0,200}(exec\(java\.lang\.runtime|valuereference=exec|propertyname=exec)/i),
  S("solr-rce", "Apache Solr Velocity / DataImport RCE", "cve", "critical", { cve: "CVE-2019-17558" }, /\/solr\/.{0,80}(velocity\.params\.resource\.loader|wt=velocity|dataimport\?.*command=full-import.*(script|dataconfig))/i),
  S("weblogic-rce", "Oracle WebLogic console / wls-wsat RCE", "cve", "critical", { cve: "CVE-2020-14882" }, /\/console\/(css|images)\/(\.\.|%2e%2e)\/console\.portal/i, /\/wls-wsat\/coordinatorporttype/i, /\/_async\/asyncresponseservice/i),
  S("jboss-deser", "JBoss invoker deserialization", "cve", "critical", { cve: "CVE-2015-7501" }, /\/invoker\/(jmxinvokerservlet|ejbinvokerservlet|readonly)/i),
  S("liferay-rce", "Liferay JSON-WS RCE", "cve", "critical", { cve: "CVE-2020-7961" }, /\/api\/jsonws\/invoke/i),
  S("php-cgi-args", "PHP-CGI argument injection", "cve", "critical", { cve: "CVE-2024-4577", in: "query" }, /^\s*-[dsn](\s|$)/i, /(^|\s)-d\s*(allow_url_include|auto_prepend_file|safe_mode|disable_functions|open_basedir|cgi\.force_redirect)/i),
  S("joomla-leak", "Joomla config leak", "cve", "critical", { cve: "CVE-2023-23752" }, /\/api\/index\.php\/v1\/(config\/application|users)\?.*public=true/i),
  S("wp-file-manager", "WP File Manager upload RCE", "cve", "critical", { cve: "CVE-2020-25213" }, /wp-file-manager\/lib\/php\/connector\.minimal\.php/i),
  S("grafana-traversal", "Grafana plugin path traversal", "cve", "critical", { cve: "CVE-2021-43798" }, /\/public\/plugins\/[\w-]+\/(\.\.\/|%2e%2e)/i),
  S("jira-leak", "Jira / Confluence WEB-INF read", "cve", "critical", { cve: "CVE-2021-26086" }, /\/_\/;\/(meta-inf|web-inf)\//i),
  S("moveit-rce", "MOVEit Transfer SQLi", "cve", "critical", { cve: "CVE-2023-34362" }, /\/moveitisapi\/moveitisapi\.dll\?action=m2/i),
  S("cisco-iosxe", "Cisco IOS XE web UI implant", "cve", "critical", { cve: "CVE-2023-20198" }, /\/webui\/logoutconfirm\.html\?logon_hash=/i, /\/%2577ebui_wsma_https?/i),
  S("craft-rce", "Craft CMS conditions RCE", "cve", "critical", { cve: "CVE-2023-41892" }, /[?&]action=conditions\/render/i),
  S("spring-gateway", "Spring Cloud Gateway SpEL", "cve", "critical", { cve: "CVE-2022-22947" }, /\/actuator\/gateway\/(routes|refresh)/i),
  S("zimbra-rce", "Zimbra mboximport", "cve", "critical", { cve: "CVE-2022-27925" }, /\/service\/extension\/backup\/mboximport/i),
  S("panos-probe", "PAN-OS GlobalProtect exploit path", "cve", "high", { cve: "CVE-2024-3400" }, /\/ssl-vpn\/hipreport\.esp/i, /\/global-protect\/.*\.\.\//i),
  S("langflow-rce", "Langflow code validation RCE", "cve", "high", { cve: "CVE-2025-3248" }, /\/api\/v1\/validate\/code/i),
  S("shellshock", "Shellshock", "cve", "critical", { cve: "CVE-2014-6271" }, /\(\)\s*\{\s*[:_a-z]*\s*;?\s*\}\s*;/i),
  // ---- IoT exploits and botnet droppers --------------------------------------------------------
  S("gpon-rce", "GPON router RCE", "iot", "critical", { cve: "CVE-2018-10561" }, /\/gponform\/diag_form/i, /\/menu\.html\?images\//i),
  S("realtek-rce", "Realtek SDK miniigd RCE", "iot", "critical", { cve: "CVE-2014-8361" }, /\/picsdesc\.xml/i, /\/wanipcn\.xml/i),
  S("huawei-hg532", "Huawei HG532 RCE", "iot", "critical", { cve: "CVE-2017-17215" }, /\/ctrlt\/deviceupgrade/i),
  S("hikvision-rce", "Hikvision command injection", "iot", "critical", { cve: "CVE-2021-36260" }, /\/sdk\/weblanguage/i),
  S("tplink-rce", "TP-Link Archer command injection", "iot", "critical", { cve: "CVE-2023-1389" }, /\/cgi-bin\/luci\/;stok=\/locale\?form=country/i),
  S("dvr-leak", "TBK DVR credential leak", "iot", "critical", { cve: "CVE-2018-9995" }, /device\.rsp\?opt=(user|sys)&cmd=/i),
  S("botnet-dropper", "botnet droppers (Mirai, Mozi)", "iot", "critical", /\b(mozi\.[am]|mirai|okiru|hajime|gafgyt|bashlite|satori|masuta|kaiten|lolol)\b/i,
    /\bcd\s+\/(tmp|var\/tmp|var\/run|dev\/shm|mnt)\s*[;&|]/i, /\btftp\s+-[gr]\b/i, /\bchmod\s+(777|\+x)\s+\S+\s*;\s*(\.\/|sh\s)/i,
    /\b(wget|curl|tftp|ftpget)\b[^;|&]{0,120}\b[\w-]+\.(arm[4-7]?|mips(el)?|mpsl|x86(_64)?|i[3-6]86|ppc|m68k|sh4|spc)\b/i, /\/shell\?(cd|wget|busybox)\b/i,
    /\/setup\.cgi\?.*todo=syscmd/i, /\/boaform\/admin\/form(login|ping)/i, /\/(tmunblock|hndunblock)\.cgi/i, /\/goform\/(setusbshare|formsyscmd|set_lan)/i),
  S("router", "router & IoT exploits", "iot", "critical", /\/(boaform|hnap1\/?.*soapaction|setup\.cgi|shell\?|tmunblock\.cgi|hndunblock\.cgi)/i, /\/cgi-bin\/.*(\.sh|bash|;)/i,
    /\/goform\//i, /\/(cgi-bin\/)?luci\/;stok=/i, /\/(ctrlt|ud)\/deviceupgrade/i, /\/apply\.cgi/i, /\/cgi-bin\/(viewlog\.asp|mainfunction\.cgi|kerbynet|supervisor\/)/i),
  // ---- secrets & config ------------------------------------------------------------------------
  S("env-file", ".env files", "secrets", "critical", /(^|\/)\.env(\.[\w.-]*)?$/i),
  S("vcs", "Git / SVN metadata", "secrets", "critical", /(^|\/)\.(git|svn|hg|bzr)(\/|$)/i, /(^|\/)\.git-credentials$/i),
  S("cloud-creds", "cloud & SSH credentials", "secrets", "critical", /(^|\/)\.(aws|ssh|docker|kube|azure|gnupg)(\/|$)/i, /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$/i,
    /\/(aws|amazon|s3|gcp|firebase|stripe|twilio|sendgrid|mailgun)[-_.]?(credentials|config|keys?)\.(json|ya?ml|txt|env)/i),
  S("dotfiles", "dotfiles & editor configs", "secrets", "critical", /(^|\/)\.(npmrc|pypirc|netrc|htpasswd|htaccess|bash_history|zsh_history|mysql_history|psql_history|ds_store|dockercfg|s3cfg|pgpass|my\.cnf)$/i,
    /(^|\/)\.vscode\/sftp\.json$/i, /(^|\/)sftp-config\.json$/i, /(^|\/)\.idea\/(workspace|datasources|dataSources)\.xml$/i),
  S("config-leak", "config & secret files", "secrets", "critical", /wp-config\.php/i, /(^|\/)(config|settings|database|secrets?|credentials|parameters|local_settings)\.(ya?ml|ini|bak|old|sql|php\.bak|php~|php\.save|php\.swp|inc)$/i,
    /(^|\/)(configuration\.php|localsettings\.php|config\.inc\.php)(\.bak|\.old|~|\.save|\.txt)$/i),
  S("backup", "backups & dumps", "secrets", "critical", { in: "path" }, /^\/(?:[^/]+\/)?[\w.-]*\.(sql|sql\.gz|sql\.zip|sqlite3?|db|mdb|bak|old|swp|dump)$/i, /(^|\/)(backup|backups|dump|db|database|site|www|html|wwwroot|web|public_html|htdocs|data)\.(zip|tar|tar\.gz|tgz|rar|7z|gz|bz2)$/i),
  S("backup-deep", "backup files (deep in the tree)", "secrets", "medium", { in: "path", probe: true }, /\/[^/]+\/[^/]+\/.*\.(sql|sql\.gz|bak|old|swp)$/i),
  S("info-leak", "debug pages & build files", "secrets", "critical", /(^|\/)(phpinfo|info|pi|test|i|php_info|infophp)\.php$/i, /\/(server-info|_profiler|_debugbar|elmah\.axd|trace\.axd)(\/|$)/i,
    /\/storage\/logs\/laravel\.log/i, /(^|\/)(web\.config|appsettings(\.\w+)?\.json|docker-compose\.ya?ml|\.gitlab-ci\.yml|\.travis\.yml|\.circleci\/config\.yml|secrets\.json|credentials\.json|service-account\.json|firebase\.json|\.git-credentials|terraform\.tfstate(\.backup)?)$/i,
    /(^|\/)\.terraform(\/|$)/i, /(^|\/)(debug|error|access|laravel|production)\.log$/i),
  S("java-admin", "Java / Spring admin endpoints", "secrets", "critical", /\/(actuator\/(env|heapdump|threaddump|configprops|mappings|logfile)|_ignition\/health-check|telescope\/requests|jolokia(\/|$))/i,
    /\/(solr\/admin|jmx-console|web-console|vendor\/laravel-filemanager|server-status)/i),
  // ---- traversal & file inclusion --------------------------------------------------------------
  S("traversal", "path traversal", "traversal", "critical", /\/etc\/(passwd|shadow|group|hosts|issue|crontab)\b/i, /\/proc\/(self|\d+)\/(environ|cmdline|fd|maps|status)/i,
    /(^|[\/\\])(win\.ini|boot\.ini|system\.ini)$|[a-z]:[\\/]windows[\\/]|\\windows\\win\.ini/i, /web-inf\/web\.xml/i),
  S("traversal-path", "path traversal (dot segments in the path)", "traversal", "critical", { in: "path" }, /(^|\/)\.\.(\/|;|$)/, /%2e%2e/i, /%252e/i, /\.\.%2f|%2f\.\./i),
  S("traversal-query", "path traversal in a parameter", "traversal", "critical", Q, /(\.\.[\/\\]){2,}/, /\.\.[\/\\][^&]*(etc\/|windows\/|proc\/|\.env|wp-config|web\.config|boot\.ini)/i),
  S("traversal-lite", "a ../ in a parameter", "traversal", "low", Q, /(^|=)\.\.[\/\\]/),
  S("lfi", "file inclusion (PHP wrappers)", "traversal", "critical", /(php|zip|phar|glob|expect|compress\.zlib|compress\.bzip2):\/\//i, /data:\/\/text\/plain;base64,/i, /php:\/\/filter/i),
  // ---- code execution --------------------------------------------------------------------------
  S("php-rce", "PHP code execution", "rce", "critical", /php:\/\/input/i, /allow_url_include/i, /auto_prepend_file/i, /\b(base64_decode|gzinflate|str_rot13|assert|create_function|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i, /<\?php|<\?=/i, /die\(md5\(|print\(md5\(|echo\s*md5\(/i),
  S("cmd-inject", "command injection", "rce", "critical", /\$\{IFS\}|\$IFS\$\d/i,
    /([;|&`\n]|\$\()\s*(wget|curl|tftp|ftpget)\s+(-[\w-]+\s+)*['"]?(https?:\/\/|ftp:\/\/|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w.-]+\.[a-z]{2,}\/)/i,
    /([;|&`\n]|\$\()\s*(cat|head|tail|more|less|nl|tac)\s+\/(etc|proc|var|root|home)\//i, /([;|`\n]|&&|\$\()\s*(id|uname(\s+-a)?|whoami|ifconfig|hostname|pwd)\s*($|[;|&`)#])/i,
    /\|\s*(sh|bash|zsh|ash|dash|ksh)\b/i, /\b(nc|ncat|netcat)\s+(-[a-z]*e|-c)\s/i, /\bbusybox\s+(wget|tftp|telnetd|nc|sh|chmod)\b/i,
    /\bpowershell(\.exe)?\s+(-[a-z]+\s+)*-(e|enc|encodedcommand|nop|noprofile|w|windowstyle|c|command)\b/i, /\bcmd(\.exe)?\s*\/[ck]\s/i, /\bcertutil(\.exe)?\s+-urlcache/i,
    /\$\((curl|wget|id|whoami|uname|cat|echo|sleep|nslookup|ping|dig)\b/i, /`(curl|wget|id|whoami|uname|cat|sleep|nslookup|ping|dig)\b[^`]*`/i,
    /([;|&`]|\$\()\s*(sleep\s+\d|ping\s+-[cn]\s*\d|nslookup\s+\S+\.\S+)/i, /\b(bash|sh)\s+-[ci]\s+['"]?[^'"]*\b(wget|curl|\/dev\/tcp)/i, /\/dev\/tcp\/\d/i),
  S("rce", "remote code execution", "rce", "critical", /[?&](cmd|exec|execute|command|shell|run|system|passthru|cmdline)=\s*(wget|curl|id|uname|whoami|cat|ls|pwd|ifconfig|nc|bash|sh|powershell|cmd|echo|ping)(\b|$)/i,
    /[?&](ping|host|ip|addr|target)=[^&]*[;|`]\s*\w/i, /(^|[^a-z0-9])ognl([^a-z0-9]|$)/i, /\/bin\/(ba|z|da|k)?sh\b/i, /xdebug_session_start/i, /\/ws\/v1\/cluster\/apps\/new-application/i),
  S("proto-pollution", "prototype pollution", "rce", "high", Q, /(^|[&\[.])(__proto__|constructor\s*\[\s*prototype|constructor\.prototype)\b/i),
  S("ssti", "template injection (code)", "ssti", "critical", /__class__\s*\.\s*__(mro|bases?|subclasses)__|__globals__|__builtins__|__import__\s*\(/i,
    /\{\{[^}]{0,120}(\.popen\(|\.items\(\)|\[\s*['"]__|\|\s*attr\s*\(|_self\.env\.|\.__init__)/i, /freemarker\.template\.utility\.(execute|objectconstructor|jythonruntime)/i,
    /\bt\s*\(\s*java\.lang\.(runtime|system|processbuilder)/i, /__\$\{[^}]{1,200}\}__/, /\$class\.inspect|\.getclass\(\)\.forname\(/i, /<%=\s*(`|system|exec|io\.popen|%x)/i,
    /\{\{\s*['"]?[^}]{0,40}\|\s*filter\s*\(\s*['"]?(system|exec|passthru|shell_exec)/i, /\$\{[^}]{0,80}(getruntime|processbuilder|java\.lang\.)/i),
  S("ssti-probe", "template injection probe", "ssti", "high", Q, /\{\{\s*\d+\s*[*+\-/]\s*['"]?\d+['"]?\s*\}\}/, /\$\{\s*\d+\s*[*+]\s*\d+\s*\}/, /<%=?\s*\d+\s*[*+]\s*\d+\s*%>/, /[#*@]\{\s*\d+\s*\*\s*\d+\s*\}/,
    /<#assign\b|#set\s*\(\s*\$\w+\s*=/i, /\$\{\{<%\[%'"\}\}%\\\./),
  S("xxe", "XML external entities", "xxe", "critical", /<!doctype[^>]{0,200}\[?\s*<!entity/i, /<!entity\s+(%\s*)?[\w.-]+\s+(system|public)\s+["']/i, /<xi:include\b/i),
  S("deser", "serialized objects", "deser", "critical", /(^|[=&\/\s"':])rO0AB[A-Za-z0-9+/]{8}/, /(^|[=&\/])aced0005[0-9a-f]{8}/i, /O:\d{1,3}:"[a-z_\\][\w\\]{1,80}":\d{1,3}:\{/i,
    /\b(ysoserial|ObjectDataProvider|TextFormattingRunProperties|TypeConfuseDelegate|ActivitySurrogateSelector|System\.Windows\.Data)\b/i,
    /["'](@type|\$type|__type)["']\s*:\s*["'][^"']*(templatesimpl|jdbcrowsetimpl|objectdataprovider|system\.diagnostics\.process|com\.sun\.rowset)/i, /\bAAEAAAD\/{5}/),
  // ---- web shells, phishing kits, miners ---------------------------------------------------------
  S("webshell", "web shells & backdoors", "webshell", "critical", /(^|\/)(alfa|alfacgiapi|alfa-?rex|alfa_data|wso|wso\d+|wso112233|c99|c100|r57|b374k|indoxploit|xleet|priv8|marijuana|gel4y|madspot|leafmailer|k2ll33d|sh3ll|haxor|anonsec|lufix|xmrlpc|webshell|phpshell|wp-shell|backdoor|mini_?shell|filesman|fox(wso)?|chitoo)\.(php\d?|phtml|asp|aspx|jsp|cgi)$/i,
    /(^|\/)(alfa_data|alfacgiapi|alfa-rex|\.tmb\/[^/]+\.php)(\/|$)/i, /(^|\/)\.well-known\/[^/]+\.php\d?$/i, /[?&](filesman|alfa_action|wso_cmd)=/i),
  S("webshell-generic", "web shell names", "webshell", "high", { in: "path", probe: true }, /(^|\/)(shell|cmd|cmd2|uploader|upload_file|bypass|byp|sym|symlink|xl|0x|sx|wp-info|wp-2019|admin-header)\d*\.php\d?$/i,
    /\/wp-includes\/(id3|text|requests|simplepie|css|fonts|js|images|customize|widgets|random_compat|certificates)\/[a-z0-9_-]{1,20}\.php$/i, /\/wp-content\/(uploads|upgrade)\/.{0,60}\.php\d?$/i),
  S("phish-kit", "phishing kits (looked for, or planted)", "phishing", "critical", /(^|\/)[a-z]{2,10}_(ch|de|at|fr|it|es|uk|nl|pl|us)\.js$/i, /(^|\/)(qrcode_twint|twint|antibot(-client)?|bot-connect|licensor|anti_?bot|blocker|visitor_log|telegram_?bot)\.(js|php)$/i,
    /\/(sys_files|style\/protect|static\/style\/protect|prevents|antibots?)\//i, /\/(webscr|signin\.ebay|paypal\.com\.|appleid\.apple\.com\.)/i),
  S("miner", "crypto-miner droppers", "miner", "critical", /\b(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|c3pool|supportxmr|moneroocean|nanopool|minexmr|hashvault|xmrpool|cryptonight)\b/i, /stratum\+(tcp|ssl|tls):\/\//i, /\/(ldr|xmr|mine|miner|kinsing)\.sh\b/i),
  // ---- cloud & infrastructure, edge devices ------------------------------------------------------
  S("infra-api", "Docker, Kubernetes & cluster APIs", "infra", "critical", /\/(containers\/(json|create)|v1\.\d+\/(containers|images|exec)|images\/json)/i, /\/api\/v1\/(namespaces|pods|secrets|nodes)/i, /\/v2\/_catalog/i,
    /\/(_cat\/indices|_all\/_search|_cluster\/health|_nodes)/i, /\/debug\/(pprof|vars)/i, /\/(metrics\/v1|v1\/metadata|computemetadata|latest\/(meta-data|user-data|api\/token)|metadata\/(instance|v1))/i, /\/(run|exec|runningpods)\/[\w-]+\/[\w-]+/i),
  S("edge-exploit", "VPN & firewall exploits", "cve", "critical", /\/remote\/fgt_lang/i, /\/\+CSCOE\+\//i, /\/mifs\//i, /\/webui\/logoutconfirm/i, /\/api\/v2\/cmdb\//i,
    /\/(owa\/auth\/x\.js|autodiscover\/autodiscover\.json\?.*powershell)/i, /\/(vpn|dana-na|dana-cached)\/.*\.\./i, /\/(ssl-vpn|sslvpn)\/.*(\.\.|%2e)/i),
  // ---- probes: asking for software that isn't here ------------------------------------------------
  S("wordpress", "WordPress logins", "bruteforce", "low", { in: "path", probe: true }, /(^|\/)(wp-login|wp-admin|xmlrpc)/i),
  S("db-admin", "database admin panels", "bruteforce", "low", { in: "path", probe: true }, /(^|\/)(phpmyadmin|pma|myadmin|mysql|adminer|phppgadmin|pgadmin|sqladmin|dbadmin)(\/|\.php|$)/i),
  S("vpn-panel", "VPN, mail & admin panels", "bruteforce", "low", { in: "path", probe: true }, /(^|\/)(manager\/html|owa|ecp|autodiscover|remote\/login|dana-na|global-protect|geoserver|druid|nacos|jenkins|solr|axis2|jmx-console|hudson|weblogic|ofbiz|cpanel|whm|webmail|plesk|zabbix)(\/|$)/i),
  S("device", "device & legacy paths", "recon", "low", { in: "path", probe: true }, /(^|\/)(cgi-bin|hnap1|onvif|reportserver|api\/jsonws|level\/15|mgmt|fcgi-bin|cgi-mod)(\/|$)/i),
  S("php-probe", "PHP / ASP / CGI scripts", "recon", "low", { in: "path", probe: true }, /\.(php\d?|phtml|asp|aspx|jsp|cgi|pl|do|action|cfm)(\?|$)/i),
];

// Tools that announce themselves in the User-Agent. Attack tools are payloads
// whatever they ask for; the rest only label (a bot is not an attack).
export const UA_SIGNATURES = [
  S("attack-tool", "attack tools", "recon", "critical", /\b(sqlmap|nikto|nuclei|wpscan|gobuster|dirbuster|dirsearch|ffuf|feroxbuster|wfuzz|hydra|commix|joomscan|whatweb|acunetix|netsparker|nessus|openvas|jaeles|xray\/|fuzz faster|zgrab\/[\d.]+ .*exploit|masscan\/.*exploit|havij|arachni|w3af|skipfish|vega\/|appscan|burp collaborator|interact\.sh|oast\.(fun|live|pro|site|online|me))\b/i),
  S("scanner-ua", "mass scanners", "bot", "info", /\b(zgrab|masscan|l9explore|l9tcpid|l9scan|leakix|nmap scripting engine|censysinspect|expanse|internet-measurement|odin|zmap|httpx|fasthttp|go-http-client\/1\.1$|python-requests|aiohttp|libwww-perl|python-urllib|java\/1\.|okhttp|scrapy|colly|wpdetector|netcraft|binaryedge|shadowserver|onyphe|criminalip|palo alto networks|keydrop)\b/i,
    /^Mozilla\/5\.0 \(compatible; ?\)$/, /^Hello,? World/i),
  S("headless", "headless browsers", "bot", "info", /\b(headlesschrome|phantomjs|slimerjs|puppeteer|playwright|selenium|webdriver)\b/i),
  S("old-browser", "ancient browser strings", "bot", "info", /\bMSIE [2-7]\.0\b/, /Windows NT 5\.[01]\b.*(Chrome|Firefox)\/(1|2|3)\d\./, /^Mozilla\/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)$/),
];

// Hits that come from shape (lexers), the request line, or behaviour: named
// here so every hit has a name, a category and a severity.
export const DYNAMIC = [
  S("sqli", "SQL injection", "sqli", "critical"),
  S("xss", "cross-site scripting", "xss", "critical"),
  S("ssrf", "server-side request forgery", "ssrf", "critical"),
  S("log4shell", "Log4Shell / JNDI lookup", "log4shell", "critical"),
  S("header-attack", "an attack in the User-Agent or Referer", "rce", "critical"),
  S("bad-method", "an unknown HTTP method", "protocol", "medium"),
  S("trace-method", "TRACE / TRACK / DEBUG", "protocol", "medium"),
  S("proxy-probe", "open-proxy probe (CONNECT, absolute URI)", "protocol", "high"),
  S("malformed-target", "a malformed request target", "protocol", "medium"),
  S("crlf-injection", "CRLF / header injection", "protocol", "high"),
  S("overlong-utf8", "overlong UTF-8 (evasion)", "protocol", "high"),
  S("null-byte", "a null byte (evasion)", "protocol", "medium"),
  S("evasion", "encoding evasion", "protocol", "low"),
  S("oversized-url", "an oversized URL", "dos", "medium"),
  S("param-flood", "a parameter flood", "dos", "medium"),
  S("no-ua", "no User-Agent", "bot", "info"),
  S("flood", "a request flood", "dos", "medium"),
  S("content-discovery", "content discovery (wordlist scanning)", "recon", "high"),
  S("brute-force", "login brute force", "bruteforce", "high"),
  S("method-fuzz", "HTTP method fuzzing", "recon", "medium"),
];
const ALL = [...SIGNATURES, ...UA_SIGNATURES, ...DYNAMIC];
ALL.forEach((s, i) => { s.ord = i; });
const BYID = new Map(ALL.map((s) => [s.id, s]));
export const signatureById = (id) => BYID.get(id) || null;
export const categoryOf = (id) => BYID.get(id)?.cat || null;
// for the dashboard: everything the engine can name
export const catalog = () => ALL.map(({ id, name, cat, sev, score, cve, probe }) => ({ id, name, cat, sev, score, cve, probe }));

// ------------------------------------------------------------------ the parts
// A segment that is one long opaque token (an id, a signed or encrypted link:
// 40+ of [A-Za-z0-9_-] and nothing else) is data. Exploits need punctuation, and
// a random token spells a short keyword (ognl, …) about once in 16 000 links.
const opaque = (x) => (x.length < 40 ? x : x.replace(/(^|\/|=)[A-Za-z0-9_-]{40,}(?=\/|\?|&|$)/g, "$1x"));
const opaqueValue = (v) => v.length >= 40 && /^[A-Za-z0-9_\-+/=.~]+$/.test(v);

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]);
const DAV = new Set(["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH", "MKCALENDAR", "ACL", "BIND", "UNBIND", "REBIND", "ORDERPATCH",
                     "VERSION-CONTROL", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY", "PURGE", "LINK", "UNLINK", "QUERY"]);
export const methodKind = (m) => (!m || METHODS.has(m) ? 0 : DAV.has(m) ? 1 : m === "TRACE" || m === "TRACK" || m === "DEBUG" ? 2 : m === "CONNECT" ? 3 : 4);

// SSRF: a parameter that is a URL to somewhere only the server can reach
const META = /^(169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|fd00:ec2::254|\[fd00:ec2::254\]|instance-data|0xa9fea9fe|2852039166|0251\.0376\.0251\.0376|\[::ffff:a9fe:a9fe\]|169\.254\.169\.254\.nip\.io)$/i;
const LOOP = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0|\[::1?\]|\[0:0:0:0:0:0:0:1\]|0x7f0{0,6}1|2130706433|017700000001|127\.1|[\w.-]*\.localtest\.me|localtest\.me|127\.0\.0\.1\.nip\.io|\[::ffff:127\.0\.0\.1\])$/i;
const PRIV = /^(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+)$/;
function ssrf(v) {
  const m = /^\s*([a-z][a-z0-9+.-]{1,12}):\/\/(?:[^@/?#\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)/i.exec(v);
  if (!m) return null;
  const scheme = m[1].toLowerCase(), host = m[2].toLowerCase();
  if (/^(gopher|dict|file|ldap|ldaps|tftp|jar|netdoc|sftp|smb|ftp)$/.test(scheme) && (scheme !== "ftp" || LOOP.test(host) || PRIV.test(host) || META.test(host))) return { sev: "critical", why: `a ${scheme}:// URL in a parameter` };
  if (!/^https?$/.test(scheme)) return null;
  if (META.test(host)) return { sev: "critical", why: `the cloud metadata service (${host})` };
  if (LOOP.test(host)) return { sev: "medium", why: `the server itself (${host})` };
  if (PRIV.test(host)) return { sev: "low", why: `an internal address (${host})` };
  return null;
}
// ${jndi:…}, also when it hides behind nested lookups (${${::-j}ndi:…}, ${lower:j}…)
function jndi(s) {
  if (s.indexOf("${") < 0 && !/jndi/i.test(s)) return null;
  let x = s;
  for (let i = 0; i < 6; i++) {
    const y = x.replace(/\$\{(?:lower|upper):([^${}]*)\}/gi, "$1").replace(/\$\{[^${}]*?:-([^${}]*)\}/g, "$1").replace(/\$\{date:'([^']*)'\}/gi, "$1");
    if (y === x) break;
    x = y;
  }
  if (/\$\{\s*jndi\s*:/i.test(x) || /jndi\s*:\s*(ldaps?|rmi|dns|iiop|corba|nds|nis|http)s?:/i.test(x)) return { sev: "critical", why: x === s ? "a ${jndi:…} lookup" : "an obfuscated ${jndi:…} lookup" };
  if (/\$\{(env|sys|java|main|ctx|k8s|docker|spring|base64|bundle|log4j|web|marker):/i.test(s)) return { sev: "high", why: "a Log4j lookup (${env:…})" };
  return null;
}

const hit = (id, extra) => { const s = BYID.get(id); return { id, sev: extra?.sev || s.sev, cat: s.cat, cve: s.cve, probe: s.probe, why: extra?.why }; };
// Per surface, every signature regex in one literal automaton (matcher.mjs):
// a string with none of their literals costs one pass, and only the regexes
// whose literal is there are asked.
const groups = new Map();
function group(list, where) {
  const key = `${list === SIGNATURES ? "s" : "u"}:${where}`;
  let g = groups.get(key);
  if (!g) {
    const pairs = [];
    for (const s of list) if (s.in === where) for (const re of s.res) pairs.push([s, re]);
    g = { pairs, m: new Matcher(pairs.map(([, re]) => re)) };
    groups.set(key, g);
  }
  return g;
}
export const matcherStats = () => [...groups].map(([k, g]) => ({ surface: k, regexes: g.pairs.length, literals: g.m.literals, always: g.m.always.length, states: g.m.states }));
function matchAll(list, strs, out, seen) {
  for (const surface of ["path", "query", "url"]) {
    const where = strs[surface];
    if (!where?.length) continue;
    const g = group(list, surface);
    const cand = new Set();
    for (const x of where) g.m.candidates(x, cand);
    if (!cand.size) continue;
    for (const k of [...cand].sort((a, b) => a - b)) {
      const [sig, re] = g.pairs[k];
      if (seen.has(sig.id)) continue;
      for (const x of where) if (re.test(x)) { out.push(hit(sig.id)); seen.add(sig.id); break; }
    }
  }
}

// a value of letters, digits and a few separators can't carry script or a URL
const PLAIN = /^[\w .,\-]*$/;
// a request target (path?query): everything it says, cached
function target(raw) {
  const n = normalize(raw);
  const out = [], seen = new Set();
  const paths = [...new Set([opaque(n.path), opaque(n.collapsed), opaque(n.rawPath)])];
  const vals = [], params = [];
  for (const [k, v] of n.params) { if (!opaqueValue(v)) vals.push(v); params.push(`${k}=${opaqueValue(v) ? "x" : v}`); }
  const query = params.join("&");
  const strs = { path: paths, query: query ? [query] : [], url: query ? [...new Set([...paths, `${paths[0]}?${query}`, opaque(n.raw)])] : paths };
  matchAll(SIGNATURES, strs, out, seen);
  // serialized objects are long base64: looked for in the values the opaque rule set aside
  if (!seen.has("deser")) for (const [, v] of n.params) if (opaqueValue(v) && /^(rO0AB|AAEAAAD\/{5}|aced0005)/i.test(v)) { out.push(hit("deser")); seen.add("deser"); break; }
  // value by value: SQL injection, XSS, SSRF
  const segs = n.path.split("/").filter((x) => x && /['"`<(]/.test(x));
  let sq = null, xs = null, sr = null;
  for (const v of [...vals, ...n.params.map(([k]) => k), ...segs]) {
    if (!v || v.length < 2) continue;
    const a = sqli(v); if (a && (!sq || sevRank(a.sev) > sevRank(sq.sev))) sq = a;
    if (PLAIN.test(v)) continue;                       // words and digits: SQL maybe (UNION SELECT needs none), never script or a URL
    const b = xss(v); if (b && (!xs || sevRank(b.sev) > sevRank(xs.sev))) xs = b;
    const c = ssrf(v); if (c && (!sr || sevRank(c.sev) > sevRank(sr.sev))) sr = c;
  }
  if (sq) out.push(hit("sqli", sq));
  if (xs) out.push(hit("xss", xs));
  if (sr) out.push(hit("ssrf", sr));
  const j = jndi(`${n.path}?${n.query}`) || jndi(n.raw);
  if (j) out.push(hit("log4shell", j));
  // the request line itself
  const r0 = n.raw[0];
  if (r0 && r0 !== "/" && r0 !== "*") {
    if (/^https?:\/\//i.test(n.raw)) out.push(hit("proxy-probe", { why: "an absolute URI (asking a proxy)" }));
    else out.push(hit("malformed-target", { why: "a target that isn't a path" }));
  }
  if (/[\r\n]/.test(n.path) || /[\r\n]\s*[\w-]{2,40}\s*:\s*\S/.test(n.query) || /%0d%0a\s*[\w-]{2,40}:/i.test(n.raw)) out.push(hit("crlf-injection", { sev: /[\r\n]\s*(set-cookie|location|content-(type|length)|transfer-encoding|x-[\w-]+)\s*:/i.test(`${n.path}\n${n.query}`) ? "critical" : "high" }));
  if (n.raw.length > 8192) out.push(hit("oversized-url", { sev: "high" })); else if (n.raw.length > 4096) out.push(hit("oversized-url"));
  if (n.nparams > 200) out.push(hit("param-flood"));
  if (n.flags.overlong) out.push(hit("overlong-utf8"));
  if (n.flags.nul) out.push(hit("null-byte"));
  // evasion only counts when it hid something
  if (out.length && (n.flags.double || n.flags.unicode || n.flags.fold || n.flags.entity || n.flags.backslash) && out.some((h) => sevPoints(h.sev) >= 2 && h.cat !== "protocol" && h.cat !== "dos"))
    out.push(hit("evasion", { why: Object.keys(n.flags).filter((k) => k !== "nul" && k !== "overlong").join(", ") }));
  return out;
}

function header(ua, kind) {
  const out = [], seen = new Set();
  if (kind === "ua") {
    if (!ua) return out;
    matchAll(UA_SIGNATURES, { url: [ua] }, out, seen);
  }
  if (/[$(<'"`{]/.test(ua)) {
    const j = jndi(ua); if (j) out.push(hit("log4shell", { ...j, why: `${j.why} in the ${kind === "ua" ? "User-Agent" : "Referer"}` }));
    if (/\(\)\s*\{\s*[:_a-z]*\s*;?\s*\}\s*;/i.test(ua)) out.push(hit("shellshock", { why: `in the ${kind === "ua" ? "User-Agent" : "Referer"}` }));
    else if (/<\s*script|<\?php|\bunion\b.{0,30}\bselect\b|\bsleep\s*\(\s*\d|\$\{\s*\d+\s*\*\s*\d+\s*\}|\{\{\s*\d+\s*\*\s*\d+\s*\}\}|;\s*(wget|curl)\s+https?:/i.test(ua)) out.push(hit("header-attack", { why: `a payload in the ${kind === "ua" ? "User-Agent" : "Referer"}` }));
  }
  return out;
}

// ------------------------------------------------------------------ the engine
const NONE = Object.freeze({ score: 0, id: null, name: null, cat: null, sev: null, pts: 0, hits: [], cve: null, label: false });
// small bounded caches: most traffic asks for the same few paths, with the same few clients
const cacheT = new Map(), cacheU = new Map();
const cached = (m, key, fn, max) => {
  let v = m.get(key);
  if (v === undefined) { v = fn(); if (m.size >= max) m.clear(); m.set(key, v); }
  return v;
};
// Combine hits into one verdict: distinct ids, points added (CRS anomaly scoring)
export function verdictOf(hits) {
  if (!hits.length) return NONE;
  const by = new Map();
  for (const h of hits) { const o = by.get(h.id); if (!o || sevRank(h.sev) > sevRank(o.sev)) by.set(h.id, h); }
  const list = [...by.values()].sort((a, b) => sevRank(b.sev) - sevRank(a.sev) || (BYID.get(a.id)?.ord ?? 999) - (BYID.get(b.id)?.ord ?? 999));
  let pts = 0;
  for (const h of list) pts += sevPoints(h.sev);
  pts = Math.min(pts, 50);
  const top = list[0], def = BYID.get(top.id);
  const cves = [...new Set(list.map((h) => h.cve).filter(Boolean))];
  // probes only (software that may simply not be here): never a payload, worth their strongest hit
  const probe = list.every((h) => h.probe || sevPoints(h.sev) === 0) && list.some((h) => h.probe);
  if (probe) pts = sevPoints(top.sev);
  return { score: pts >= DROP_AT && !probe ? 3 : 1, id: top.id, name: def?.name || top.id, cat: top.cat, sev: top.sev, pts, hits: list.map((h) => h.id), cve: cves[0] || null, cves,
           det: top.why || null, label: pts === 0, probe, list };
}
export function inspect({ method, path, ua, referer } = {}) {
  const p = String(path || "");
  // long targets aren't kept: an attacker's unique URLs would fill the cache
  let t = p === "/" || p.length < 2 ? null : p.length > 512 ? target(p) : cached(cacheT, p, () => target(p), 4096);
  if (t && !t.length) t = null;
  const u = ua === undefined ? null : String(ua).length > 400 ? header(String(ua), "ua") : cached(cacheU, ua || "", () => header(String(ua || ""), "ua"), 2048);
  const r = referer && /[$(<'"`{]/.test(referer) ? header(String(referer), "ref") : null;
  const mk = methodKind(method);
  if (!t && !(u && u.length) && !(r && r.length) && mk < 2) return NONE;
  const hits = [...(t || []), ...(u || []), ...(r || [])];
  if (ua === "" && t) hits.push(hit("no-ua"));
  if (mk === 2) hits.push(hit("trace-method", { why: method }));
  else if (mk === 3) hits.push(hit("proxy-probe", { why: "CONNECT" }));
  else if (mk === 4) hits.push(hit("bad-method", { why: String(method).slice(0, 20) }));
  if (!hits.length) return NONE;
  const v = verdictOf(hits);
  // a client that only labels itself (or sends no User-Agent): a label, never a mark
  v.ua = !!u?.length && !t && !r;
  return v;
}

// The old interface: path (and User-Agent) -> {score, id, name, ...}
export const classify = (path) => inspect({ path });
export const classifyRequest = (path, ua, method) => inspect({ path, ua, method });
export const classifyUa = (ua) => inspect({ path: "/", ua });
export { SEVERITY, categoryById };
