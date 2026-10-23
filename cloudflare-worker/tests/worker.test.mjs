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
