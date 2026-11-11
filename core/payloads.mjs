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
import * as D from "./detect.mjs";
import { sqli, xss } from "./lexers.mjs";
import { Matcher } from "./matcher.mjs";
import { SEVERITY, DROP_AT, categoryById, sevPoints, sevRank } from "./taxonomy.mjs";

// Raised whenever the signatures learn something: the app then reads its log
// again with them (Brain.rescan), so what slipped past before is caught now.
export const SIGNATURES_VERSION = 4;

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
  S("ofbiz-rce", "Apache OFBiz auth bypass RCE", "cve", "critical", { cve: "CVE-2023-51467" }, /\/webtools\/control\/[^?]*\bprogramexport\b/i, /\/webtools\/control\/(forgotpassword\/)?(programexport|xmlrpc)\b.*(requirepasswordchange|;|\?)/i, /requirepasswordchange=y/i),
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
  S("teamcity-bypass2", "TeamCity path bypass", "cve", "critical", { cve: "CVE-2024-27198" }, /\/hax\?jsp=/i, /\/app\/rest\/[\w\/]*;\.jsp/i, /\/(res|update|\.well-known\/acme-challenge)\/\.\.\/admin\/diagnostic\.jsp/i),
  S("screenconnect", "ConnectWise ScreenConnect setup bypass", "cve", "critical", { cve: "CVE-2024-1709" }, /\/setupwizard\.aspx\/./i),
  S("citrix-gw", "Citrix Gateway / NetScaler exploits", "cve", "critical", { cve: "CVE-2023-3519" }, /\/gwtest\/formssso/i, /\/oauth\/idp\/\.well-known\/openid-configuration/i, /\/p\/u\/doauthentication\.do/i, /\/oauth\/idp\/logout\?post_logout_redirect_uri=[^&]*[\r\n<]/i),
  S("confluence-2023", "Confluence template / restore RCE", "cve", "critical", { cve: "CVE-2023-22527" }, /\/template\/aui\/text-inline\.vm/i, /\/json\/setup-restore(-local|-progress)?\.action/i, /\/pages\/doenterpagevariables\.action/i),
  S("papercut", "PaperCut setup bypass", "cve", "critical", { cve: "CVE-2023-27350" }, /\/app\?service=page\/setupcompleted/i),
  S("checkpoint-leak", "Check Point gateway file read", "cve", "critical", { cve: "CVE-2024-24919" }, /\/clients\/mycrl\b/i),
  S("vite-fs", "Vite dev server file read", "cve", "critical", { cve: "CVE-2025-30208" }, /\/@fs\//i, /[?&](raw|import|inline)[^&]*\?\?|\?raw\?\?|[?&]inline=1\.wasm/i),
  S("jenkins-rce", "Jenkins CLI / script console", "cve", "critical", { cve: "CVE-2024-23897" }, /\/jenkins\/script(text)?\/?$/i, /^\/cli\?remoting=false/i, /\/descriptorbyname\/org\.jenkinsci\.plugins\.(scriptsecurity|workflow)\./i, /\/(script|scripttext)\?(script|command)=/i),
  S("crushftp", "CrushFTP template injection / auth bypass", "cve", "critical", { cve: "CVE-2024-4040" }, /\/webinterface\/function\/\?.*(c2f=|\{working_dir\}|<include>)/i),
  S("vmware-aria", "VMware Aria / vRealize RCE", "cve", "critical", { cve: "CVE-2023-20887" }, /\/saas\.\/resttosaasservlet/i, /\/casa\/nodes\/thumbprints/i),
  S("manageengine", "ManageEngine SAML / ADSelfService RCE", "cve", "critical", { cve: "CVE-2022-47966" }, /\/samlresponseservlet\b/i, /\/\.\/restapi\/(licensemgr|logonCustomization)/i, /\/restapi\/importtechnicians/i),
  S("rejetto-hfs", "Rejetto HFS template RCE", "cve", "critical", { cve: "CVE-2024-23692" }, /\{\.exec\|/i, /%7b\.exec%7c/i),
  S("owncloud-leak", "ownCloud graphapi phpinfo leak", "cve", "critical", { cve: "CVE-2023-49103" }, /\/apps\/graphapi\/vendor\//i),
  S("sap-netweaver", "SAP NetWeaver metadata uploader", "cve", "critical", { cve: "CVE-2025-31324" }, /\/developmentserver\/metadatauploader/i),
  S("sharepoint-toolshell", "SharePoint ToolShell", "cve", "critical", { cve: "CVE-2025-53770" }, /\/_layouts\/1[56]\/toolpane\.aspx/i),
  S("cleo-rce", "Cleo Harmony / VLTrader RCE", "cve", "critical", { cve: "CVE-2024-50623" }, /^\/synchronization\b/i),
  S("panos-2024", "PAN-OS management bypass", "cve", "critical", { cve: "CVE-2024-0012" }, /\/php\/(ztp_gate|utils\/createremoteappwebsession)\.php/i, /\.php\/[^?]*\.js\.map/i, /\/sslmgr\?scep-profile-name=%[0-9]{3}/i),
  S("fortiweb-sqli", "FortiWeb Fabric Connector SQLi", "cve", "critical", { cve: "CVE-2025-25257" }, /\/api\/fabric\/device\/status/i),
  S("cacti-rce", "Cacti remote_agent command injection", "cve", "critical", { cve: "CVE-2022-46169" }, /\/remote_agent\.php\?.*action=polldata/i),
  S("sophos-rce", "Sophos Firewall user portal RCE", "cve", "critical", { cve: "CVE-2022-1040" }, /\/userportal\/controller\?mode=8700/i, /\/webconsole\/controller\?mode=/i),
  S("wsftp-rce", "Progress WS_FTP Ad Hoc deserialization", "cve", "critical", { cve: "CVE-2023-40044" }, /\/aht\/ahtapiservice\.asmx/i),
  S("cyberpanel-rce", "CyberPanel pre-auth RCE", "cve", "critical", { cve: "CVE-2024-51567" }, /\/(databases|ftp|dns)\/(upgrademysqlstatus|getresetstatus)/i),
  S("goanywhere", "GoAnywhere MFT license / setup RCE", "cve", "critical", { cve: "CVE-2023-0669" }, /\/goanywhere\/lic\/accept/i, /\/wizard\/initialaccountsetup\.xhtml/i),
  S("ivanti-2024", "Ivanti Connect Secure SAML / XXE", "cve", "critical", { cve: "CVE-2024-21893" }, /\/dana-ws\/saml(20)?\.ws/i, /\/dana-na\/auth\/saml-sso\.cgi/i, /\/client\/index\.php%3f\.php\/gsb\//i, /\/gsb\/datetimetab\.php/i),
  S("oracle-ebs", "Oracle E-Business Suite / BI Publisher", "cve", "critical", { cve: "CVE-2022-21587" }, /\/oa_html\/bneviewerxmlservice\?bne:uueupload/i, /\/xmlpserver\/reporttemplateservice\.xls/i, /\/oa_html\/(configurator\/uiservlet|syncservlet)/i),
  S("openfire", "Openfire setup path traversal", "cve", "critical", { cve: "CVE-2023-32315" }, /\/setup\/setup-s\/(%u002e|%2e|\.)/i),
  S("bitbucket-rce", "Bitbucket archive argument injection", "cve", "critical", { cve: "CVE-2022-36804" }, /\/archive\?.*(--exec=|%00--)/i),
  S("glpi-htmlawed", "GLPI htmLawed command injection", "cve", "critical", { cve: "CVE-2022-35914" }, /\/htmlawed\/htmlawedtest\.php/i),
  S("wp-plugin-rce", "WordPress plugin exploits", "cve", "critical", { cve: "CVE-2024-27956" }, /\/wp-content\/plugins\/wp-automatic\/inc\/csv\.php/i, /\/wp-json\/bricks\/v1\/render_element/i,
    /\/wp-content\/plugins\/backup-backup\/includes\/backup-heart\.php/i, /action=(revslider_show_image|duplicator_download|uploadfonticon|kaswara_)/i, /[?&]swp_debug=load_options/i, /\/wp-content\/plugins\/(ultimate-member|forminator|royal-elementor-addons|litespeed-cache)\/.*\.(php|json)\?.*(debug|shell|upload)/i),
  S("dlink-nas", "D-Link NAS / camera command injection", "cve", "critical", { cve: "CVE-2024-3273" }, /\/cgi-bin\/nas_sharing\.cgi/i, /\/config\/getuser\?index=/i, /\/cgi-bin\/(account_mgr|system_mgr|webproc)\.cgi/i),
  S("minio-leak", "MinIO cluster bootstrap leak", "cve", "critical", { cve: "CVE-2023-28432" }, /\/minio\/bootstrap\/v1\/verify/i),
  S("coldfusion", "Adobe ColdFusion RCE", "cve", "critical", { cve: "CVE-2023-26360" }, /\/cfide\/(adminapi|wizards\/common)\/\w+\.cfc/i, /\/cf_scripts\/scripts\/ajax\/ckeditor\/plugins\/filemanager\//i, /[?&]_cfclient=true/i),
  S("spring-function", "Spring Cloud Function SpEL", "cve", "critical", { cve: "CVE-2022-22963" }, /^\/functionrouter\b/i),
  S("nextjs-middleware", "Next.js middleware auth bypass", "cve", "critical", { cve: "CVE-2025-29927" }, /x-middleware-subrequest/i),
  S("mitel-traversal", "Mitel MiCollab path traversal", "cve", "critical", { cve: "CVE-2024-41713" }, /\/npm-pwg\/\.\.;\//i),
  S("kemp-rce", "Kemp LoadMaster / Ivanti vTM", "cve", "critical", { cve: "CVE-2024-7593" }, /\/apps\/zxtm\/login\.cgi/i, /\/access\/set\?param=enableapi/i),
  S("nacos-bypass", "Nacos auth bypass", "cve", "critical", { cve: "CVE-2021-29441" }, /\/nacos\/v1\/(auth\/users|cs\/ops\/derby)/i),
  S("flink-upload", "Apache Flink / Druid / Metabase RCE", "cve", "critical", { cve: "CVE-2023-38646" }, /^\/jars\/upload\b/i, /\/api\/setup\/validate\b/i, /\/druid\/indexer\/v1\/sampler/i, /\/api\/geojson\?url=/i),
  S("jira-ssrf", "Jira / Atlassian gadget SSRF", "cve", "critical", { cve: "CVE-2019-8451" }, /\/plugins\/servlet\/gadgets\/makerequest\?url=/i, /\/plugins\/servlet\/oauth\/users\/icon-uri\?consumeruri=/i),
  S("cn-oa-rce", "Weaver / Seeyon / Yonyou OA RCE", "cve", "critical", { cve: "CVE-2019-9670" }, /\/weaver\/bsh\.servlet\.bshservlet/i, /\/seeyon\/(htmlofficeservlet|thirdpartycontroller\.do|autoinstall\.do)/i, /\/(servlet\/~ic\/bsh\.servlet\.bshservlet|uapjs\/jsinvoke)/i),
  S("exchange-viewstate", "Exchange / ASP.NET ViewState RCE", "cve", "critical", { cve: "CVE-2020-0688" }, /\/ecp\/default\.aspx\?.*__viewstate=/i),
  S("splunk-traversal", "Splunk Windows path traversal", "cve", "critical", { cve: "CVE-2024-36991" }, /\/modules\/messaging\/(c:\.\.\/){2,}/i),
  S("servu-traversal", "SolarWinds Serv-U path traversal", "cve", "critical", { cve: "CVE-2024-28995" }, /[?&]internaldir=[^&]*\.\./i),
  S("nexus-traversal", "Sonatype Nexus path traversal", "cve", "critical", { cve: "CVE-2024-4956" }, /^(\/%2f){4,}/i),
  S("fabrik-lfi", "Joomla Fabrik file read", "cve", "critical", { cve: "CVE-2018-7482" }, /option=com_fabrik.*imgfile=/i),
  S("zyxel-rce", "Zyxel / DrayTek / Tenda command injection", "cve", "critical", { cve: "CVE-2022-30525" }, /\/ztp\/cgi-bin\/handler/i, /\/cgi-bin\/supervisor\/cloudsetup\.cgi\?exefile=/i, /\/web_shell_cmd\.gch/i, /\/cgi-bin\/admin\.cgi\?command=syscommand/i, /\/upgrade_handle\.php\?cmd=/i, /\/language\/\w+\$\{ifs\}/i),
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
    /\/setup\.cgi\?.*todo=syscmd/i, /\bhnap1\b.*[`$;]/i, /\/boaform\/admin\/form(login|ping)/i, /\/(tmunblock|hndunblock)\.cgi/i, /\/goform\/(setusbshare|formsyscmd|set_lan)/i),
  S("router", "router & IoT exploits", "iot", "critical", /\/(boaform|hnap1\/?.*soapaction|setup\.cgi|shell\?|tmunblock\.cgi|hndunblock\.cgi)/i, /\/cgi-bin\/.*(\.sh|bash|;)/i,
    /\/goform\//i, /\/(cgi-bin\/)?luci\/;stok=/i, /^\/stssys\.htm/i, /^\/ud\/act\?1\b/i, /\/cgi-bin\/nobody\/machine\.cgi/i, /^\/dvr\/cmd\b/i, /\/stalker_portal\//i, /\/(ctrlt|ud)\/deviceupgrade/i, /\/apply\.cgi/i, /\/cgi-bin\/(viewlog\.asp|mainfunction\.cgi|kerbynet|supervisor\/)/i),
  // ---- secrets & config ------------------------------------------------------------------------
  S("env-file", ".env files", "secrets", "critical", /(^|\/)\.env[\w.~-]*$/i, /(^|\/)[\w-]+\.env(\.\w+)?$/i, /(^|\/)\.(envrc|flaskenv|secrets?)$/i, /(^|\/)_?environment$/i, /^\/@vite\/env\b/i),
  S("ai-agent", "AI coding-agent configs (API keys, MCP servers)", "secrets", "critical", /(^|\/)\.(claude|cursor|continue|codeium|windsurf|gemini|codex|roo|cline|aider[\w.-]*|copilot|openai|anthropic)(\/|\.(json|ya?ml|env)$|$)/i,
    /(^|\/)(\.?mcp|claude_desktop_config|cline_mcp_settings)\.json$/i, /(^|\/)(openai|anthropic|gemini)[\w-]*\.(env|json|key|txt)$/i),
  S("cloud-keys", "cloud service-account keys", "secrets", "critical", /(^|\/)(firebase[\w-]*adminsdk[\w-]*|serviceaccountkey|service[-_]account[\w-]*|application_default_credentials|google[-_]credentials|gcp[-_][\w-]+|client_secrets?[\w-]*|credentials|token|keyfile|aws|aws[-_]credentials|azure[-_]credentials)\.json$/i,
    /(^|\/)\.config\/gcloud\//i, /(^|\/)aws[-_]credentials$/i, /(^|\/)\.(boto|s3cfg|amplifyrc|ftpconfig|remote-sync\.json|deployment-config\.json)$/i),
  S("private-keys", "private keys, keystores & wallets", "secrets", "critical", /(^|\/)[\w.-]+\.(pem|key|ppk|p12|pfx|jks|keystore|kdbx)$/i, /(^|\/)(wallet\.dat|\.ethereum\/keystore|\.bitcoin\/|\.electrum\/)/i),
  S("ci-config", "CI pipelines & submodules", "secrets", "critical", /(^|\/)\.(github\/workflows|gitmodules|drone\.yml|buildkite)/i, /(^|\/)(bitbucket-pipelines\.yml|jenkinsfile|azure-pipelines\.yml|cloudbuild\.ya?ml|\.?buildspec\.ya?ml)$/i),
  S("app-config", "framework configs (Rails, Magento, Spring, Symfony)", "secrets", "critical", /(^|\/)config\/(master\.key|credentials(\/\w+)?\.yml\.enc|(database|secrets|storage|aws|s3|mongoid|redis|cable|settings|application|parameters|mail|smtp)\.ya?ml)$/i,
    /(^|\/)app\/etc\/(env\.php|local\.xml|config\.php)$/i, /(^|\/)(application|bootstrap|database|db|jdbc|hibernate|sentry|mail|smtp|datasource)[\w-]*\.properties$/i, /(^|\/)(web-inf|meta-inf)\/(web\.xml|manifest\.mf|[\w.-]+\.(xml|properties))$/i,
    /(^|\/)config\.inc\.php$/i, /(^|\/)(application|bootstrap)(-[\w-]+)?\.ya?ml$/i, /(^|\/)\.(firebaserc|vercel\/project\.json|netlify\/state\.json)$/i, /(^|\/)(settings|local_settings|production)\.py$/i, /(^|\/)(database|db)\.(ya?ml|json|ini|conf)$/i, /(^|\/)docker-compose[\w.-]*\.ya?ml$/i),
  S("source-backup", "source files left as backups or editor swaps", "secrets", "critical", /\.(php|asp|aspx|jsp|py|rb|js|json|ya?ml|xml|conf|config|cfg|ini|env|inc|sql|sh)(\.(bak|backup|old|orig|save|swp|swo|tmp|temp|copy|dist|\d)|~|\.save\.\d)$/i, /(^|\/)\.[\w.-]+\.sw[op]$/i, /(^|\/)\.?#[\w.-]+#$/),
  S("app-logs", "application logs", "secrets", "critical", /(^|\/)(error_log|php_errors?\.log|npm-debug\.log|yarn-error\.log|lerna-debug\.log|(development|production|staging|test|debug|error|access|laravel|django|app|application|server|sql|mysql)\.log)$/i, /(^|\/)logs?\/[\w.-]+\.log$/i),
  S("vcs", "Git / SVN metadata", "secrets", "critical", /(^|\/)\.(git|svn|hg|bzr)(\/|$)/i, /(^|\/)\.git-credentials$/i),
  S("cloud-creds", "cloud & SSH credentials", "secrets", "critical", /(^|\/)\.(aws|ssh|docker|kube|azure|gnupg)(\/|$)/i, /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$/i,
    /\/(aws|amazon|s3|gcp|firebase|stripe|twilio|sendgrid|mailgun)[-_.]?(credentials|config|keys?)\.(json|ya?ml|txt|env)/i),
  S("dotfiles", "dotfiles & editor configs", "secrets", "critical", /(^|\/)\.(npmrc|pypirc|netrc|htpasswd|htaccess|bash_history|zsh_history|mysql_history|psql_history|python_history|node_repl_history|sqlite_history|rediscli_history|lesshst|viminfo|history|ds_store|dockercfg|s3cfg|pgpass|my\.cnf|user\.ini|gem\/credentials|config\/(hub|gh\/hosts\.yml)|ssh\/[\w.-]+)(\.bak|\.old)?$/i,
    /(^|\/)\.vscode\/sftp\.json$/i, /(^|\/)sftp-config\.json$/i, /(^|\/)\.idea\/(workspace|datasources|dataSources)\.xml$/i),
  S("config-leak", "config & secret files", "secrets", "critical", /wp-config\.php/i, /(^|\/)(config|settings|database|secrets?|credentials|parameters|local_settings)\.(ya?ml|ini|bak|old|sql|php\.bak|php~|php\.save|php\.swp|inc)$/i,
    /(^|\/)(configuration\.php|localsettings\.php|config\.inc\.php)(\.bak|\.old|~|\.save|\.txt)$/i),
  S("backup", "backups & dumps", "secrets", "critical", { in: "path" }, /^\/(?:[^/]+\/)?[\w.-]*\.(sql|sql\.gz|sql\.zip|sqlite3?|db|mdb|dump)$/i, /(^|\/)(backup|backups|dump|db|database|site|www|html|wwwroot|web|public_html|htdocs|data)\.(zip|tar|tar\.gz|tgz|rar|7z|gz|bz2)$/i),
  S("backup-deep", "backup files (deep in the tree)", "secrets", "medium", { in: "path", probe: true }, /\/[^/]+\/[^/]+\/.*\.(sql|sql\.gz|bak|old|swp)$/i, /^\/(?:[^/]+\/)?[\w.-]*\.(bak|old|swp|orig|save)$/i),
  S("info-leak", "debug pages & build files", "secrets", "critical", /(^|\/)(phpinfo|info|pi|test|i|php_info|infophp|php-info|phpversion|status)\.php([~.][\w.]*)?$/i, /(^|\/)phpinfo\/?$/i, /\/debug\/default\/(view|index)/i, /\/(__debug__|_debugbar\/open|telescope)(\/|$)/i, /(^|\/)heapdump(\.hprof)?$/i, /\/(server-info|_profiler|_debugbar|elmah\.axd|trace\.axd)(\/|$)/i,
    /\/storage\/logs\/laravel\.log/i, /(^|\/)(web\.config|appsettings(\.\w+)?\.json|docker-compose\.ya?ml|\.gitlab-ci\.yml|\.travis\.yml|\.circleci\/config\.yml|secrets\.json|credentials\.json|service-account\.json|firebase\.json|\.git-credentials|terraform\.tfstate(\.backup)?)$/i,
    /(^|\/)\.terraform(\/|$)/i, /(^|\/)(debug|error|access|laravel|production)\.log$/i),
  S("java-admin", "Java / Spring admin endpoints", "secrets", "critical", /\/(actuator;?\/(env|heapdump|threaddump|configprops|mappings|logfile|beans|gateway|shutdown|restart|refresh|loggers|jolokia)|_ignition\/health-check|telescope\/requests|jolokia(\/|$))/i, /\/actuator;\//i, /\/manager\/(text|status)\b/i,
    /\/(solr\/admin|jmx-console|web-console|vendor\/laravel-filemanager|server-status)/i),
  // ---- traversal & file inclusion --------------------------------------------------------------
  S("traversal", "path traversal", "traversal", "critical", /\/etc\/(passwd|shadow|group|hosts|issue|crontab)\b/i, /\/proc\/(self|\d+)\/(environ|cmdline|fd|maps|status)/i,
    /(^|[\/\\])(win\.ini|boot\.ini|system\.ini)$|[a-z]:[\\/]windows[\\/]|\\windows\\win\.ini/i, /web-inf\/web\.xml/i),
  S("traversal-path", "path traversal (dot segments in the path)", "traversal", "critical", { in: "path" }, /(^|\/)\.\.(\/|;|$)/, /%2e%2e/i, /%252e/i, /\.\.%2f|%2f\.\./i),
  S("traversal-query", "path traversal in a parameter", "traversal", "critical", Q, /(\.\.[\/\\]){2,}/, /\.\.[\/\\][^&]*(etc\/|windows\/|proc\/|\.env|wp-config|web\.config|boot\.ini)/i),
  S("traversal-lite", "a ../ in a parameter", "traversal", "low", Q, /(^|=)\.\.[\/\\]/),
  S("lfi", "file inclusion (PHP wrappers)", "traversal", "critical", /(php|zip|phar|glob|expect|compress\.zlib|compress\.bzip2):\/\//i, /data:\/\/text\/plain;base64,/i, /php:\/\/filter/i),
  // ---- code execution --------------------------------------------------------------------------
  S("php-rce", "PHP code execution", "rce", "critical", /php:\/\/input/i, /allow_url_include/i, /auto_prepend_file/i, /\b(base64_decode|gzinflate|str_rot13|assert|create_function|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i, /<\?php|<\?=/i, /die\(@?md5\(|print\(@?md5\(|echo\s*@?md5\(|hellothinkphp/i),
  S("cmd-inject", "command injection", "rce", "critical", /\$\{IFS\}|\$IFS\$\d/i,
    /([;|&`\n]|\$\()\s*(wget|curl|tftp|ftpget)\s+(-[\w-]+\s+)*['"]?(https?:\/\/|ftp:\/\/|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w.-]+\.[a-z]{2,}\/)/i,
    /([;|&`\n]|\$\()\s*(cat|head|tail|more|less|nl|tac)\s+\/(etc|proc|var|root|home)\//i, /([;|`\n]|&&|\$\()\s*(id|uname(\s+-a)?|whoami|ifconfig|hostname|pwd)\s*($|[;|&`)#])/i,
    /\|\s*(sh|bash|zsh|ash|dash|ksh)\b/i, /\b(nc|ncat|netcat)\s+(-[a-z]*e|-c)\s/i, /\bbusybox\s+(wget|tftp|telnetd|nc|sh|chmod)\b/i,
    /\bpowershell(\.exe)?\s+(-[a-z]+\s+)*-(e|enc|encodedcommand)\s+[a-z0-9+\/=]{12,}/i, /([;|&`\n]|\$\()\s*powershell(\.exe)?\s+-/i, /\bcmd(\.exe)?\s*\/[ck]\s/i, /\bcertutil(\.exe)?\s+-urlcache/i,
    /\$\((curl|wget|id|whoami|uname|cat|echo|sleep|nslookup|ping|dig)\b/i, /`(curl|wget|id|whoami|uname|cat|sleep|nslookup|ping|dig)\b[^`]*`/i,
    /([;|&`]|\$\()\s*(sleep\s+\d|ping\s+-[cn]\s*\d|nslookup\s+\S+\.\S+)/i, /\b(bash|sh)\s+-[ci]\s+['"]?[^'"]*\b(wget|curl|\/dev\/tcp)/i, /\/dev\/tcp\/\d/i),
  S("rce", "remote code execution", "rce", "critical", /[?&](cmd|exec|execute|command|shell|run|system|passthru|cmdline)=\s*(wget|curl|id|uname|whoami|cat|ls|pwd|ifconfig|nc|bash|sh|powershell|cmd|echo|ping)(\b|$)/i,
    /[?&](ping|host|ip|addr|target)=[^&]*[;|`]\s*\w/i, /(^|[^a-z0-9])ognl([^a-z0-9]|$)/i, /\/bin\/(ba|z|da|k)?sh\b/i, /xdebug_session_start/i, /\/ws\/v1\/cluster\/apps\/new-application/i),
  S("proto-pollution", "prototype pollution", "rce", "critical", Q, /(^|[&\[.=])(__proto__|constructor\s*\[\s*prototype|constructor\.prototype)\b/i),
  S("ssti", "template injection (code)", "ssti", "critical", /__class__\s*\.\s*__(mro|bases?|subclasses)__|__globals__|__builtins__|__import__\s*\(/i,
    /\{\{[^}]{0,120}(\.popen\(|\.items\(\)|\[\s*['"]__|\|\s*attr\s*\(|_self\.env\.|\.__init__)/i, /freemarker\.template\.utility\.(execute|objectconstructor|jythonruntime)/i,
    /\bt\s*\(\s*java\.lang\.(runtime|system|processbuilder)/i, /__\$\{[^}]{1,200}\}__/, /\$class\.inspect|\.getclass\(\)\.forname\(/i, /<%=\s*(`|system|exec|io\.popen|%x)/i,
    /\{\{\s*['"]?[^}]{0,40}\|\s*filter\s*\(\s*['"]?(system|exec|passthru|shell_exec)/i, /\$\{[^}]{0,80}(getruntime|processbuilder|java\.lang\.)/i),
  S("ssti-probe", "template injection probe", "ssti", "critical", Q, /\$\{\{<%\[%'"\}\}%\\?/, /\{\{\s*\d+\s*[*+\-/]\s*['"]?\d+['"]?\s*\}\}/, /\$\{\s*\d+\s*[*+]\s*\d+\s*\}/, /<%=?\s*\d+\s*[*+]\s*\d+\s*%>/, /[#*@]\{\s*\d+\s*\*\s*\d+\s*\}/,
    /<#assign\b|#set\s*\(\s*\$\w+\s*=/i, /\$\{\{<%\[%'"\}\}%\\\./),
  S("xxe", "XML external entities", "xxe", "critical", /<!doctype[^>]{0,200}\[?\s*<!entity/i, /<!doctype\s+[\w:-]+\s+(system|public)\s+["']/i, /<!entity\s+(%\s*)?[\w.-]+\s+(system|public)\s+["']/i, /<xi:include\b/i),
  S("deser", "serialized objects", "deser", "critical", /(^|[=&\/\s"':])rO0AB[A-Za-z0-9+/]{4}/, /(^|[=&\/])aced0005[0-9a-f]{8}/i, /O:\d{1,3}:"[a-z_\\][\w\\]{1,80}":\d{1,3}:\{/i,
    /\b(ysoserial|ObjectDataProvider|TextFormattingRunProperties|TypeConfuseDelegate|ActivitySurrogateSelector|System\.Windows\.Data)\b/i,
    /["'](@type|\$type|__type)["']\s*:\s*["'][^"']*(templatesimpl|jdbcrowsetimpl|objectdataprovider|system\.diagnostics\.process|com\.sun\.rowset)/i, /\bAAEAAAD\/{5}/),
  // ---- web shells, phishing kits, miners ---------------------------------------------------------
  S("webshell", "web shells & backdoors", "webshell", "critical", /(^|\/)(alfa|alfacgiapi|alfa-?rex|alfa_data|wso|wso\d+|wso112233|c99|c100|r57|b374k|indoxploit|xleet|priv8|marijuana|gel4y|madspot|leafmailer|k2ll33d|sh3ll|haxor|anonsec|lufix|xmrlpc|webshell|phpshell|wp-shell|backdoor|mini_?shell|filesman|fox(wso)?|chitoo)\.(php\d?|phtml|asp|aspx|jsp|cgi)$/i,
    /(^|\/)(alfa_data|alfacgiapi|alfa-rex|\.tmb\/[^/]+\.php)(\/|$)/i, /(^|\/)\.well-known\/.*\.(php\d?|phtml|jsp|aspx?)$/i, /(^|\/)(0byt3m1n1|byp4ss|r00t|h4x0r|sh3ll|c0d3|up10ad|l0g1n)\.php$/i, /\/wp-content\/plugins\/[^/]+\/(temp|tmp|uploads?|update_extract|cache)\/.*\.(php\d?|phtml)$/i, /[?&](filesman|alfa_action|wso_cmd)=/i,
    /(^|\/)(tinyfilemanager|wp_filemanager|filemanager|fm|gecko|gecko-litespeed|wp-blog|radio|system_log|ups|mini|simple|inputs|chosen|classwithtostring|wp-conflg|wp-good|admin-post2|moon|lock360|goat\d*|ova|wp-signup2|xmrlpc|wp-l0gin|wp-2019|wp-p\.php|class-wp-page-[\w-]+|xl\d*|sid|wsx|olux|marvins|priv8|ninja|kill|aaa|bala|zeus|sudo|cloud|rindex|siteindex|dropdown)\.(php\d?|phtml)$/i,
    /\/wp-admin\/(css|images|js)\/.*\.php$/i, /\/wp-admin\/maint\/(?!repair\.php)[^/]+\.php$/i, /\/wp-content\/(uploads|upgrade)\/.{0,80}\.(php\d?|phtml|phar)$/i, /\/wp-content\/plugins\/wp-file-manager\/lib\/files\//i,
    /\.(php\d?|phtml|jsp|aspx?|cgi)\?(cmd|exec|command|shell)=/i),
  S("webshell-generic", "web shell names", "webshell", "high", { in: "path", probe: true }, /(^|\/)(shell|cmd|cmd2|uploader|upload_file|bypass|byp|sym|symlink|xl|0x|sx|wp-info|wp-2019|admin-header)\d*\.php\d?$/i,
    /\/wp-includes\/(id3|text|requests|simplepie|css|fonts|js|images|customize|widgets|random_compat|certificates)\/[a-z0-9_-]{1,20}\.php$/i),
  S("phish-kit", "phishing kits (looked for, or planted)", "phishing", "critical", /(^|\/)[a-z]{2,10}_(ch|de|at|fr|it|es|uk|nl|pl|us)\.js$/i, /(^|\/)(qrcode_twint|twint|antibot(-client)?|bot-connect|licensor|anti_?bot|blocker|visitor_log|telegram_?bot)\.(js|php)$/i,
    /\/(sys_files|style\/protect|static\/style\/protect|prevents|antibots?)\//i, /\/(webscr|signin\.ebay|paypal\.com\.|appleid\.apple\.com\.)/i),
  S("miner", "crypto-miner droppers", "miner", "critical", /\b(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|c3pool|supportxmr|moneroocean|nanopool|minexmr|hashvault|xmrpool|cryptonight)\b/i, /stratum\+(tcp|ssl|tls):\/\//i, /\/(ldr|xmr|mine|miner|kinsing)\.sh\b/i),
  // ---- cloud & infrastructure, edge devices ------------------------------------------------------
  S("infra-api", "Docker, Kubernetes & cluster APIs", "infra", "critical", /^\/(_search|_mapping|_aliases|_cat\/\w+|_snapshot|_security\/user)\b/i, /\/v1\/(agent\/(self|members|checks|services)|kv\/\?recurse|catalog\/(services|nodes)|acl\/tokens)/i, /\/v2\/keys\/?\?recursive/i, /\/(runningpods|pods|spec|stats\/summary|configz)\/?$/i, /\/var\/run\/secrets\/kubernetes\.io/i, /\/(containers\/(json|create)|v1\.\d+\/(containers|images|exec)|images\/json)/i, /\/api\/v1\/(namespaces|pods|secrets|nodes)/i, /\/v2\/_catalog/i,
    /\/(_cat\/indices|_all\/_search|_cluster\/health|_nodes)/i, /\/debug\/(pprof|vars)/i, /\/(metrics\/v1|v1\/metadata|computemetadata|latest\/(meta-data|user-data|api\/token)|metadata\/(instance|v1))/i, /\/(run|exec|runningpods)\/[\w-]+\/[\w-]+/i),
  S("edge-exploit", "VPN & firewall exploits", "cve", "critical", /\/remote\/fgt_lang/i, /\/\+CSCOE\+\//i, /\/mifs\//i, /\/webui\/logoutconfirm/i, /\/api\/v2\/cmdb\//i,
    /\/(owa\/auth\/x\.js|autodiscover\/autodiscover\.json\?.*powershell)/i, /\/(vpn|dana-na|dana-cached)\/.*\.\./i, /\/(ssl-vpn|sslvpn)\/.*(\.\.|%2e)/i),
  // ---- probes: asking for software that isn't here ------------------------------------------------
  S("secret-probe", "config & build files a site may serve", "secrets", "medium", { in: "path", probe: true }, /^\/(config|settings|app\.config|runtime-config|env-config|env|aws-exports|firebase-config|constants|secrets?)\.(js|json|txt)$/i, /^\/config\/config\.js$/i,
    /(^|\/)(composer|package|bower)(-lock)?\.(json|lock)$/i, /(^|\/)(dockerfile|vagrantfile|makefile|gemfile(\.lock)?|requirements\.txt|go\.mod|cargo\.toml|\.gitignore|\.dockerignore|\.dockerenv|\.editorconfig|\.php_cs(\.cache|\.dist)?|\.eslintrc(\.json)?)$/i,
    /(^|\/)(key|sa|auth|keys|access|api[-_]?keys?)\.json$/i, /(^|\/)(swagger|openapi)(-ui)?(\.(json|ya?ml|html))?$|\/(v[123]\/)?api-docs\b/i, /(^|\/)vendor\/composer\/installed\.json$/i, /(^|\/)nbproject\//i, /^\/(credentials|info|env|server-info|metrics|version)$/i),
  S("infra-probe", "monitoring & admin consoles", "infra", "low", { in: "path", probe: true }, /^\/(hystrix\.stream|_stats|jmx|beans|mappings|configprops)\/?$/i),
  S("wp-users", "WordPress user enumeration", "recon", "low", { probe: true }, /\/wp-json\/wp\/v2\/users\b|[?&]rest_route=\/wp\/v2\/users|[?&]author=\d+$/i),
  S("graphql-introspection", "GraphQL schema introspection", "recon", "medium", Q, /__schema\b|__type\s*\(/i),
  S("wordpress", "WordPress logins", "bruteforce", "low", { in: "path", probe: true }, /(^|\/)(wp-login|wp-admin|xmlrpc)/i),
  S("db-admin", "database admin panels", "bruteforce", "low", { in: "path", probe: true }, /(^|\/)(phpmyadmin|pma|myadmin|mysql|adminer|phppgadmin|pgadmin|sqladmin|dbadmin)(\/|\.php|$)/i),
  S("vpn-panel", "VPN, mail & admin panels", "bruteforce", "low", { in: "path", probe: true }, /(^|\/)(manager\/html|owa|ecp|autodiscover|remote\/login|dana-na|global-protect|geoserver|druid|nacos|jenkins|solr|axis2|jmx-console|hudson|weblogic|ofbiz|cpanel|whm|webmail|plesk|zabbix)(\/|$)/i),
  S("device", "device & legacy paths", "recon", "low", { in: "path", probe: true }, /(^|\/)(cgi-bin|hnap1|onvif|reportserver|api\/jsonws|level\/15|mgmt|fcgi-bin|cgi-mod)(\/|$)/i),
  S("php-probe", "PHP / ASP / CGI scripts", "recon", "low", { in: "path", probe: true }, /\.(php\d?|phtml|asp|aspx|jsp|cgi|pl|do|action|cfm)(\?|$)/i),
];

// Tools that announce themselves in the User-Agent. Attack tools are payloads
// whatever they ask for; the rest only label (a bot is not an attack).
export const UA_SIGNATURES = [
  S("attack-tool", "attack tools", "recon", "critical", /\b(sqlmap|nmap scripting engine|nikto|nuclei|wpscan|gobuster|dirbuster|dirsearch|ffuf|feroxbuster|wfuzz|hydra|commix|joomscan|whatweb|acunetix|netsparker|nessus|openvas|jaeles|xray\/|fuzz faster|zgrab\/[\d.]+ .*exploit|masscan\/.*exploit|havij|arachni|w3af|skipfish|vega\/|appscan|burp collaborator|interact\.sh|oast\.(fun|live|pro|site|online|me))\b/i),
  S("scanner-ua", "mass scanners", "bot", "info", /\b(zgrab|masscan|l9explore|l9tcpid|l9scan|leakix|censysinspect|expanse|internet-measurement|odin|zmap|httpx|fasthttp|go-http-client\/1\.1$|python-requests|aiohttp|libwww-perl|python-urllib|java\/1\.|okhttp|scrapy|colly|wpdetector|netcraft|binaryedge|shadowserver|onyphe|criminalip|palo alto networks|keydrop)\b/i,
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
  S("nosqli", "NoSQL injection (MongoDB operators, $where)", "sqli", "critical"),
  S("ldapi", "LDAP injection", "sqli", "critical"),
  S("xpathi", "XPath injection", "sqli", "critical"),
  S("code-inject", "code injection (PHP, Node, Java, Python, Ruby)", "rce", "critical"),
  S("oast", "out-of-band callback domains (Burp Collaborator, interactsh)", "recon", "critical"),
  S("open-redirect", "open redirect", "redirect", "high"),
  S("smuggling", "request smuggling (Content-Length / Transfer-Encoding)", "protocol", "high"),
  S("access-bypass", "URL-override headers (X-Original-URL)", "protocol", "medium"),
  S("ip-spoof", "a forged client address (X-Forwarded-For: 127.0.0.1)", "protocol", "medium"),
  S("default-creds", "default credentials (admin:admin)", "bruteforce", "high"),
  S("httpsys-range", "HTTP.sys Range overflow (MS15-034)", "cve", "critical", { cve: "CVE-2015-1635" }),
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
  S("probe-sweep", "a sweep for software and secrets", "recon", "high"),
  S("multi-vector", "many kinds of attack from one address", "recon", "high"),
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
// …and so is a long value of base64 / hex / token characters, but not one that is a path
// ("../../../../usr/local/etc/php/php.ini" is as long and spelled from the same letters)
const opaqueValue = (v) => v.length >= 40 && /^[A-Za-z0-9_\-+/=.~]+$/.test(v) && v.indexOf("..") < 0 && !/^[/~]?[a-z]+[/.]/i.test(v)
  && (/[A-Z]/.test(v) ? 1 : 0) + (/[a-z]/.test(v) ? 1 : 0) + (/\d/.test(v) ? 1 : 0) >= 2;

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]);
const DAV = new Set(["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH", "MKCALENDAR", "ACL", "BIND", "UNBIND", "REBIND", "ORDERPATCH",
                     "VERSION-CONTROL", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY", "PURGE", "LINK", "UNLINK", "QUERY"]);
export const methodKind = (m) => (!m || METHODS.has(m) ? 0 : DAV.has(m) ? 1 : m === "TRACE" || m === "TRACK" || m === "DEBUG" ? 2 : m === "CONNECT" ? 3 : 4);

// ${jndi:…}, also when it hides behind nested lookups (${${::-j}ndi:…}, ${lower:j}…)
export function jndi(s, where = "") {
  if (s.indexOf("${") < 0 && s.indexOf("jndi") < 0 && s.indexOf("JNDI") < 0) return null;
  let x = s;
  for (let i = 0; i < 8; i++) {
    const y = x.replace(/\$\{(?:lower|upper):([^${}]*)\}/gi, "$1").replace(/\$\{[^${}]*?:-([^${}]*)\}/g, "$1").replace(/\$\{date:'([^']*)'\}/gi, "$1")
      .replace(/\$\{base64:([A-Za-z0-9+/=]{4,})\}/gi, (m, b) => { try { return Buffer.from(b, "base64").toString("latin1"); } catch { return m; } })
      .replace(/\$\{(?:::-)?\}/g, "");
    if (y === x) break;
    x = y;
  }
  const w = where ? ` ${where}` : "";
  if (/\$\{\s*jndi\s*:/i.test(x) || /jndi\s*:\s*(ldaps?|rmi|dns|iiop|corba|nds|nis|http)s?:/i.test(x)) return { id: "log4shell", sev: "critical", why: (x === s ? "a ${jndi:…} lookup" : "an obfuscated ${jndi:…} lookup") + w };
  // Log4j and Commons Text lookups: in a request they only ever read secrets or run code (Text4Shell)
  const m = /\$\{\s*(env|sys|java|main|ctx|k8s|docker|spring|base64|bundle|log4j|web|marker|script|url|dns|file|properties|xml|const|resourcebundle|sd|event|map|jvmrunargs|localhost)\s*:/i.exec(s);
  if (m) return { id: "log4shell", sev: "critical", why: `a \${${m[1].toLowerCase()}:…} lookup${w}` };
  return null;
}

const hit = (id, extra) => { const s = BYID.get(id) || BYID.get("header-attack"); return { id: s.id, sev: extra?.sev || s.sev, cat: s.cat, cve: s.cve, probe: s.probe, why: extra?.why }; };
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
const CMD_NAME = /^(cmd|exec|execute|command|cmdline|shell|run|system|passthru|c|e|x)$/i;
const sqlHit = (r) => (r ? { id: "sqli", ...r } : null);
const xssHit = (r) => (r ? { id: "xss", ...r } : null);
// a request target (path?query): everything it says, cached
function target(raw) {
  const n = normalize(raw);
  const out = [], seen = new Set();
  const paths = [...new Set([opaque(n.path), opaque(n.collapsed), opaque(n.rawPath)])];
  const params = [];
  for (const [k, v] of n.params) params.push(`${k}=${opaqueValue(v) ? "x" : v}`);
  const query = params.join("&");
  const strs = { path: paths, query: query ? [query] : [], url: query ? [...new Set([...paths, `${paths[0]}?${query}`, opaque(n.raw)])] : paths };
  matchAll(SIGNATURES, strs, out, seen);
  // serialized objects are long base64: looked for in the values the opaque rule set aside
  if (!seen.has("deser")) for (const [, v] of n.params) if (opaqueValue(v) && /^(rO0AB|AAEAAAD\/{5}|aced0005)/i.test(v)) { out.push(hit("deser")); seen.add("deser"); break; }
  // value by value: every detector that judges meaning (lexers.mjs, detect.mjs)
  const best = new Map();
  const keep = (r) => { if (!r) return; const o = best.get(r.id); if (!o || sevRank(r.sev) > sevRank(o.sev)) best.set(r.id, r); };
  const segs = [];
  for (const x of n.path.split("/")) if (x.length > 1 && /['"`<(;|$ ]/.test(x)) segs.push(x);
  const items = [];
  for (const [k, v] of n.params) items.push([k, v]);
  // the same name twice: ASP.NET joins them with commas, so a payload can be split across them
  if (n.params.length > 1) {
    const by = new Map();
    for (const [k, v] of n.params) by.set(k, by.has(k) ? `${by.get(k)},${v}` : v);
    for (const [k, v] of by) if (v.indexOf(",") >= 0 && n.params.filter(([q]) => q === k).length > 1) items.push([k, v]);
  }
  for (const [k, v] of items) {
    if (k.length > 1 && /['"`<(;$\[{]/.test(k)) { keep(sqlHit(sqli(k))); keep(D.nosql(k, "")); }
    if (!v || v.length < 2) { if (k.indexOf("$") >= 0) keep(D.nosql(k, "")); continue; }
    if (opaqueValue(v)) { keep(D.deser(v)); continue; }
    keep(sqlHit(sqli(v)));
    if (PLAIN.test(v)) { if (CMD_NAME.test(k)) keep(D.shell(v, k)); continue; }      // words and digits: SQL maybe, never script or a URL
    keep(xssHit(xss(v)));
    keep(D.ssrf(v, k)); keep(D.redirect(v, k)); keep(D.nosql(k, v)); keep(D.ldap(v)); keep(D.xpath(v));
    keep(D.code(v)); keep(D.shell(v, k)); keep(D.deser(v)); keep(D.ssti(v)); keep(D.rfi(v, k));
  }
  // a script called with a command in any parameter (shell.php?0=id, up.php?a=whoami): a web shell in use
  if (/\.(php\d?|phtml|phar|jsp|jspx|aspx?|ashx|cgi|pl)$/i.test(n.collapsed)) for (const [, v] of n.params) { const r = v && D.shell(v, "cmd"); if (r) { keep({ ...r, id: "webshell", why: `a command sent to a script (${v.slice(0, 30)})` }); break; } }
  for (const v of segs) { keep(sqlHit(sqli(v))); keep(xssHit(xss(v))); keep(D.shell(v)); keep(D.code(v)); keep(D.ssti(v)); }
  for (const r of best.values()) out.push(hit(r.id, r));
  const j = (n.raw.indexOf("$") >= 0 || n.raw.indexOf("%24") >= 0 || /jndi/i.test(n.raw)) ? jndi(`${n.path}?${n.query}`) || jndi(n.raw) : null;
  if (j) out.push(hit("log4shell", j));
  const o = D.oast(n.raw.length > 2048 ? n.raw.slice(0, 2048) : n.raw) || (n.query && D.oast(n.query));
  if (o) out.push(hit("oast", o));
  if (n.flags.crlf16 && /[\r\n]/.test(n.path + n.query)) out.push(hit("crlf-injection", { sev: "critical", why: "a line break spelled with U+560A / U+560D" }));
  // the request line itself
  const r0 = n.raw[0];
  if (r0 && r0 !== "/" && r0 !== "*") {
    if (/^https?:\/\//i.test(n.raw)) out.push(hit("proxy-probe", { why: "an absolute URI (asking a proxy)" }));
    else out.push(hit("malformed-target", { why: "a target that isn't a path" }));
  }
  if (/[\r\n]/.test(n.path) || /[\r\n]\s*[\w-]{2,40}\s*:\s*\S/.test(n.query) || /%0d%0a\s*[\w-]{2,40}:/i.test(n.raw)) out.push(hit("crlf-injection", { sev: /[\r\n]\s*(set-cookie|location|content-(type|length)|transfer-encoding|x-[\w-]+)\s*:/i.test(`${n.path}\n${n.query}`) ? "critical" : "high" }));
  // A long address that is one opaque token (Noxia's encoded links, signed links: letters, digits,
  // - _ . ~ and slashes, no escapes, a short query at most) carries no payload: only its sheer size
  // counts, past what web servers take anyway. Anything else stays held to 4 and 8 KB.
  const opaqueUrl = /^\/[A-Za-z0-9._~\/-]+(?:\?[A-Za-z0-9._~=&\/-]{0,1024})?$/.test(n.raw);
  if (opaqueUrl ? n.raw.length > 16384 : n.raw.length > 8192) out.push(hit("oversized-url", { sev: "high" }));
  else if (!opaqueUrl && n.raw.length > 4096) out.push(hit("oversized-url"));
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
  const where = kind === "ua" ? "in the User-Agent" : "in the Referer";
  if (kind === "ua") {
    if (!ua) return out;
    matchAll(UA_SIGNATURES, { url: [ua] }, out, seen);
  }
  if (/[$(<'"`{;|]/.test(ua)) {
    const j = jndi(ua, where); if (j) out.push(hit("log4shell", j));
    if (/\(\)\s*\{\s*[:_a-z]*\s*;?\s*\}\s*;/i.test(ua)) out.push(hit("shellshock", { why: where }));
    else if (/<\s*script|<\?php|\bunion\b.{0,30}\bselect\b|\bsleep\s*\(\s*\d|\$\{\s*\d+\s*\*\s*\d+\s*\}|\{\{\s*\d+\s*\*\s*\d+\s*\}\}|;\s*(wget|curl)\s+https?:/i.test(ua)) out.push(hit("header-attack", { why: `a payload ${where}` }));
    else {
      // a Referer is a URL (its query may hold anything a page did); a User-Agent is never code
      const v = kind === "ref" ? ua.replace(/^[a-z]+:\/\/[^/?#]*/i, "") : ua;
      const r = (/['"]/.test(v) && sqli(v)?.sev === "critical" && { id: "sqli", ...sqli(v) }) || (kind === "ua" && (D.shell(v) || D.code(v) || D.ssti(v))) || (/</.test(v) && xss(v)?.sev === "critical" && { id: "xss", ...xss(v) });
      if (r) out.push(hit(r.id, { sev: "critical", why: `${r.why} ${where}` }));
    }
  }
  const o = D.oast(ua); if (o) out.push(hit("oast", o));
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
const look = { jndi, sqli };
const VOLATILE_HINT = /=[0-9a-f]{6}/i;
const VOLATILE = /=(?:\d{6,24}|(?!aced)[0-9a-f]{12,64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=&|$)/gi;
export function inspect({ method, path, ua, referer, headers } = {}) {
  const p = String(path || "");
  // long targets aren't kept: an attacker's unique URLs would fill the cache. Numbers,
  // hex and UUIDs in the query (cache busters, ids, timestamps) can't carry anything,
  // so /time?_=1794182401305 and /time?_=1794182402305 are one entry
  const k = p.length < 512 && p.indexOf("?") > 0 && VOLATILE_HINT.test(p) ? p.replace(VOLATILE, "=0") : p;
  let t = k === "/" || k.length < 2 ? null : k.length > 512 ? target(k) : cached(cacheT, k, () => target(k), 4096);
  if (t && !t.length) t = null;
  const u = ua === undefined ? null : String(ua).length > 400 ? header(String(ua), "ua") : cached(cacheU, ua || "", () => header(String(ua || ""), "ua"), 2048);
  const r = referer && /[$(<'"`{;|]|oast|interact|burpcollab/i.test(referer) ? header(String(referer), "ref") : null;
  const hh = headers ? D.headers(headers, look).map((x) => hit(x.id, x)) : null;
  const mk = methodKind(method);
  if (!t && !(u && u.length) && !(r && r.length) && !(hh && hh.length) && mk < 2) return NONE;
  const hits = [...(t || []), ...(u || []), ...(r || []), ...(hh || [])];
  if (ua === "" && t) hits.push(hit("no-ua"));
  if (mk === 2) hits.push(hit("trace-method", { why: method }));
  else if (mk === 3) hits.push(hit("proxy-probe", { why: "CONNECT" }));
  else if (mk === 4) hits.push(hit("bad-method", { why: String(method).slice(0, 20) }));
  if (!hits.length) return NONE;
  const v = verdictOf(hits);
  // a client that only labels itself (or sends no User-Agent): a label, never a mark
  v.ua = !!u?.length && !t && !r && !hh?.length;
  return v;
}

// The old interface: path (and User-Agent) -> {score, id, name, ...}
export const classify = (path) => inspect({ path });
export const classifyRequest = (path, ua, method) => inspect({ path, ua, method });
export const classifyUa = (ua) => inspect({ path: "/", ua });
export { SEVERITY, categoryById };
