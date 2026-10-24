import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
// The tests exercise validation/error paths only. Replace the Cloudflare-only socket
// import so Node can load the Worker module without opening any network connections.
const nodeCompatible = source.replace(
  'import { connect } from "cloudflare:sockets";',
  'const connect = () => { throw new Error("Network probing is disabled in tests."); };'
);
const workerUrl = "data:text/javascript;base64," + Buffer.from(nodeCompatible).toString("base64");
const { default: worker } = await import(workerUrl);
const origin = "https://codex-inn.github.io";

function request(path, { method = "GET", body, requestOrigin = origin } = {}) {
  return new Request("https://worker.test" + path, {
    method,
    headers: {
      ...(requestOrigin ? { Origin: requestOrigin } : {}),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {})
    },
    ...(body !== undefined ? { body } : {})
  });
}

test("health reports online and zero configured targets without scanning", async () => {
  const response = await worker.fetch(request("/health"), {});
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("access-control-allow-origin"), origin);
  assert.deepEqual(await response.json(), {
    status: "ok",
    scan_mode: "allowlisted-public-targets",
    configured_targets: 0
  });
});

test("rejects a browser origin that is not allowlisted", async () => {
  const response = await worker.fetch(request("/health", { requestOrigin: "https://not-allowed.example" }), {});
  assert.equal(response.status, 403);
  assert.match((await response.json()).detail, /Origin is not allowed/);
});

test("handles CORS preflight for the configured frontend", async () => {
  const response = await worker.fetch(request("/scan", { method: "OPTIONS" }), {});
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("access-control-allow-origin"), origin);
});

test("returns 404 for unknown routes", async () => {
  const response = await worker.fetch(request("/missing"), {});
  assert.equal(response.status, 404);
});

test("rejects malformed JSON", async () => {
  const response = await worker.fetch(request("/scan", { method: "POST", body: "{" }), {});
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /JSON request body/);
});

test("requires explicit authorization before processing a target", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", ports: [443], authorized: false })
  }), { ALLOWED_SCAN_TARGETS: "example.com" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /authorized/);
});

test("reports missing allowlist as a configuration error", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", ports: [443], authorized: true })
  }), {});
  assert.equal(response.status, 503);
  assert.match((await response.json()).detail, /ALLOWED_SCAN_TARGETS/);
});

test("blocks targets not present in the configured allowlist", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", ports: [443], authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "my-owned-host.example" });
  assert.equal(response.status, 403);
  assert.match((await response.json()).detail, /not on the service owner's/);
});

test("rejects URL strings instead of a hostname", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "https://example.com/path", ports: [443], authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "example.com" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /hostname only/);
});

test("rejects unsupported ports before any network operation", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", ports: [12345], authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "example.com" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /supported list/);
});

test("blocks private addresses even when mistakenly placed on the allowlist", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "10.0.0.8", ports: [443], authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "10.0.0.8" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /non-public IP/);
});

test("blocks documentation-only public-looking address ranges", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "198.51.100.7", ports: [443], authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "198.51.100.7" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /non-public IP/);
});

test("rejects more than eight requested ports before resolving a target", async () => {
  const response = await worker.fetch(request("/scan", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", ports: [22, 53, 80, 443, 445, 3389, 8080, 8443, 80], authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "example.com" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /1–8 unique ports/);
});

test("website inspection requires explicit authorization", async () => {
  const response = await worker.fetch(request("/inspect", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", authorized: false })
  }), { ALLOWED_SCAN_TARGETS: "example.com" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).detail, /authorized/);
});

test("website inspection remains restricted to the exact service allowlist", async () => {
  const response = await worker.fetch(request("/inspect", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", authorized: true })
  }), { ALLOWED_SCAN_TARGETS: "my-owned-host.example" });
  assert.equal(response.status, 403);
  assert.match((await response.json()).detail, /not on the service owner's/);
});

test("authorized website inspection reports headers and cookie flags", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async input => {
    const url = new URL(input);
    calls.push(url.href);
    if (url.hostname === "cloudflare-dns.com") return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }), { headers: { "content-type": "application/json" } });
    return new Response("ok", { status: 200, headers: {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "set-cookie": "sid=value; Secure; HttpOnly; SameSite=Lax"
    } });
  };
  try {
    const response = await worker.fetch(request("/inspect", { method: "POST", body: JSON.stringify({ target: "example.com", authorized: true }) }), { ALLOWED_SCAN_TARGETS: "example.com" });
    assert.equal(response.status, 200);
    const report = await response.json();
    assert.equal(report.target, "example.com");
    assert.equal(report.checks.find(x => x.id === "hsts").passed, true);
    assert.equal(report.checks.find(x => x.id === "content_type").passed, true);
    assert.equal(report.cookie_summary[0].secure, true);
    assert.equal(report.cookie_summary[0].http_only, true);
    assert.equal(calls.length, 4);
  } finally { globalThis.fetch = originalFetch; }
});

test("authorized website inspection never follows a redirect to another hostname", async () => {
  const originalFetch = globalThis.fetch;
  const visited = [];
  globalThis.fetch = async input => {
    const url = new URL(input);
    visited.push(url.href);
    if (url.hostname === "cloudflare-dns.com") {
      const type = url.searchParams.get("type");
      return new Response(JSON.stringify({ Status: 0, Answer: type === "A" ? [{ type: 1, data: "93.184.216.34" }] : [] }));
    }
    return new Response(null, { status: 302, headers: { location: "https://other.example/login" } });
  };
  try {
    const response = await worker.fetch(request("/inspect", { method: "POST", body: JSON.stringify({ target: "example.com", authorized: true }) }), { ALLOWED_SCAN_TARGETS: "example.com" });
    const report = await response.json();
    assert.equal(response.status, 200);
    assert.equal(report.external_redirect, "https://other.example/login");
    assert.equal(visited.filter(url => new URL(url).hostname === "other.example").length, 0);
  } finally { globalThis.fetch = originalFetch; }
});


test("rejects an allowlisted domain with a non-public IPv6 DNS answer", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async input => {
    const url = new URL(input);
    if (url.hostname !== "cloudflare-dns.com") throw new Error("Website fetch must not occur.");
    const type = url.searchParams.get("type");
    const answer = type === "A" ? [{ type: 1, data: "93.184.216.34" }] : [{ type: 28, data: "2001:db8::5" }];
    return new Response(JSON.stringify({ Status: 0, Answer: answer }));
  };
  try {
    const response = await worker.fetch(request("/inspect", {
      method: "POST",
      body: JSON.stringify({ target: "example.com", authorized: true })
    }), { ALLOWED_SCAN_TARGETS: "example.com" });
    assert.equal(response.status, 502);
    assert.match((await response.json()).detail, /non-public IP/);
  } finally { globalThis.fetch = originalFetch; }
});

test("caps inspection request bodies before parsing", async () => {
  const response = await worker.fetch(request("/inspect", {
    method: "POST",
    body: JSON.stringify({ target: "example.com", authorized: true, notes: "x".repeat(5000) })
  }), { ALLOWED_SCAN_TARGETS: "example.com" });
  assert.equal(response.status, 413);
  assert.match((await response.json()).detail, /too large/);
});

test("inspection report includes evidence-based findings and honest TLS limitations", async () => {
  const originalFetch = globalThis.fetch;
  let pageCalls = 0;
  globalThis.fetch = async input => {
    const url = new URL(input);
    if (url.hostname === "cloudflare-dns.com") {
      const type = url.searchParams.get("type");
      return new Response(JSON.stringify({ Status: 0, Answer: type === "A" ? [{ type: 1, data: "93.184.216.34" }] : [] }));
    }
    pageCalls++;
    if (url.protocol === "http:") return new Response(null, { status: 301, headers: { location: "https://example.com/" } });
    return new Response(null, { status: 200, headers: { "content-security-policy": "default-src 'self'", "set-cookie": "sid=private; Secure; HttpOnly; SameSite=Lax" } });
  };
  try {
    const response = await worker.fetch(request("/inspect", {
      method: "POST", body: JSON.stringify({ target: "example.com", authorized: true })
    }), { ALLOWED_SCAN_TARGETS: "example.com" });
    const report = await response.json();
    assert.equal(response.status, 200);
    assert.equal(report.http_probe.redirects_to_https, true);
    assert.equal(report.tls.certificate_details_available, false);
    assert.ok(report.findings.some(f => f.title === "Strict-Transport-Security not observed" && f.severity === "medium"));
    assert.ok(report.findings.every(f => f.confirmed_vulnerability === false));
    assert.equal(pageCalls, 2);
  } finally { globalThis.fetch = originalFetch; }
});

