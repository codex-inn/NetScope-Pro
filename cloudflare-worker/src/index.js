import { connect } from "cloudflare:sockets";

const PORTS = {
  22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
  445: "SMB", 3389: "RDP", 8080: "HTTP alternate", 8443: "HTTPS alternate"
};
const recent = new Map();

function json(data, status = 200, origin = "*", extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "Content-Type",
      "access-control-max-age": "86400",
      "cache-control": "no-store",
      ...extra
    }
  });
}
function isPublicIPv4(value) {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a,b,c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 0 || b === 168)) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}
function cleanTarget(raw) {
  const target = String(raw || "").trim().toLowerCase().replace(/\.$/, "");
  if (!target || target.length > 253 || /[\s/:@?#\\]/.test(target)) {
    throw new Error("Enter a hostname only, not a URL, path, or network range.");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target) && !isPublicIPv4(target)) {
    throw new Error("Private, loopback, reserved, and non-public IP addresses are blocked.");
  }
  if (!/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(target) &&
      !/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) {
    throw new Error("Enter a valid public hostname or IPv4 address.");
  }
  return target;
}
function isPublicIPv6(value) {
  if (typeof value !== "string" || value.includes("%")) return false;
  const input = value.toLowerCase();
  if (input.includes(".")) return false;
  const halves = input.split("::");
  if (halves.length > 2) return false;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if ([...left, ...right].some(part => !/^[0-9a-f]{1,4}$/.test(part))) return false;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return false;
  const groups = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right].map(x => parseInt(x || "0", 16));
  if (groups.length !== 8) return false;
  const first = groups[0];
  if (first < 0x2000 || first > 0x3fff) return false;
  if (groups[0] === 0x2001 && (groups[1] <= 0x01ff || groups[1] === 0x0db8 || groups[1] === 0x0020)) return false;
  if (groups[0] === 0x2002 || (groups[0] === 0x3fff && groups[1] <= 0x0fff)) return false;
  return true;
}
async function queryDns(name, type) {
  const url = "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type;
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, { headers: { accept: "application/dns-json" }, signal: controller.signal });
    if (!response.ok) throw new Error("Public DNS lookup failed.");
    const data = await response.json();
    if (!data || !Number.isInteger(data.Status)) throw new Error("Public DNS returned an invalid response.");
    return data;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Public DNS lookup timed out.");
    throw error;
  } finally { clearTimeout(timer); }
}
async function resolvePublicIPv4(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    if (!isPublicIPv4(host)) throw new Error("Non-public IP addresses are blocked.");
    return [host];
  }
  const answers = await Promise.all(["A", "AAAA"].map(type => queryDns(host, type)));
  const addresses = answers.flatMap((data, index) => (data.Answer || [])
    .filter(a => a.type === (index === 0 ? 1 : 28)).map(a => a.data));
  if (!addresses.length) throw new Error("No public IP address was returned for this target.");
  if (addresses.some(ip => ip.includes(":") ? !isPublicIPv6(ip) : !isPublicIPv4(ip))) {
    throw new Error("Target resolves to a private or non-public IP and was blocked.");
  }
  return [...new Set(addresses)];
}
async function probe(address, port) {
  const started = Date.now();
  let socket, timer;
  try {
    socket = connect({ hostname: address, port }, { secureTransport: "off" });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), 1800); })
    ]);
    clearTimeout(timer);
    try { await socket.close(); } catch {}
    return { address, port, service: PORTS[port], state: "open", latency_ms: Date.now() - started };
  } catch {
    clearTimeout(timer);
    try { if (socket) await socket.close(); } catch {}
    return { address, port, service: PORTS[port], state: "closed_or_filtered", latency_ms: Date.now() - started };
  }
}
async function probeBounded(jobs, concurrency = 4) {
  const results = new Array(jobs.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length) }, async () => {
    while (cursor < jobs.length) {
      const index = cursor++;
      results[index] = await probe(jobs[index].address, jobs[index].port);
    }
  }));
  return results;
}
async function inspectResponse(url) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 6000);
  try {
    const response = await fetch(url, {
      method: "GET", redirect: "manual", signal: controller.signal,
      headers: { "user-agent": "NetScope-Pro-Authorized-Inspector/1.0", range: "bytes=0-0" },
      cache: "no-store"
    });
    try { await response.body?.cancel(); } catch {}
    return response;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Website request timed out after 6 seconds.");
    throw new Error("Website could not be reached.");
  } finally { clearTimeout(timer); }
}
async function inspectWebsite(target) {
  const started = Date.now(), redirects = [];
  let current = new URL("https://" + target + "/"), response;
  for (let hop = 0; hop <= 4; hop++) {
    response = await inspectResponse(current);
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    const location = response.headers.get("location");
    if (!location) break;
    if (hop === 4) throw new Error("Redirect limit reached.");
    const next = new URL(location, current);
    redirects.push({ status: response.status, url: current.href, location: next.href });
    if (!["https:", "http:"].includes(next.protocol) || next.hostname.toLowerCase() !== target || next.port) {
      return {
        target, checked_at: new Date().toISOString(), status: response.status, latency_ms: Date.now() - started,
        final_url: current.href, redirects, external_redirect: next.href, http_probe: null,
        tls: { https_response_observed: false, certificate_details_available: false }, checks: [], findings: [],
        cookie_summary: [], limitations: ["Redirect targets outside the exact authorized hostname and standard ports are not followed."]
      };
    }
    current = next;
  }
  const headers = response.headers, has = name => Boolean(headers.get(name));
  const csp = headers.get("content-security-policy") || "";
  const checks = [
    { id: "https", title: "HTTPS response", passed: current.protocol === "https:", severity: "info",
      evidence: current.protocol + " · HTTP " + response.status, explanation: "An HTTPS response indicates that this request completed over TLS.",
      impact: "This does not establish that the website is safe.", fix: "Serve the site over HTTPS and redirect HTTP to HTTPS." },
    { id: "hsts", title: "Strict-Transport-Security", passed: has("strict-transport-security"), severity: "medium",
      evidence: headers.get("strict-transport-security") || "Header not present",
      explanation: "HSTS asks browsers to use HTTPS for future visits.", impact: "Without HSTS, a first HTTP visit may remain unencrypted.",
      fix: "Add an appropriate HSTS policy after HTTPS is confirmed for all intended hosts." },
    { id: "csp", title: "Content-Security-Policy", passed: has("content-security-policy"), severity: "medium",
      evidence: csp || "Header not present", explanation: "CSP limits which resources a browser may load.",
      impact: "No CSP restriction was observed on this response.", fix: "Define and test a CSP for the site's required resources." },
    { id: "frame", title: "Clickjacking framing control", passed: has("x-frame-options") || /frame-ancestors/i.test(csp), severity: "medium",
      evidence: headers.get("x-frame-options") || (/frame-ancestors/i.test(csp) ? "CSP frame-ancestors directive observed" : "No framing directive observed"),
      explanation: "Frame controls limit who can embed this page.", impact: "The page may be embeddable; this alone does not confirm clickjacking.",
      fix: "Set CSP frame-ancestors or X-Frame-Options according to the site's embedding needs." },
    { id: "content_type", title: "X-Content-Type-Options", passed: (headers.get("x-content-type-options") || "").toLowerCase() === "nosniff", severity: "low",
      evidence: headers.get("x-content-type-options") || "Header not present",
      explanation: "nosniff asks browsers to use the declared content type.", impact: "Some clients may infer content types.",
      fix: "Set X-Content-Type-Options: nosniff." },
    { id: "referrer", title: "Referrer-Policy", passed: has("referrer-policy"), severity: "low",
      evidence: headers.get("referrer-policy") || "Header not present",
      explanation: "This controls how much referrer data is shared during navigation.", impact: "Navigation may disclose more referrer context than intended.",
      fix: "Set a privacy-conscious Referrer-Policy." },
    { id: "permissions", title: "Permissions-Policy", passed: has("permissions-policy"), severity: "low",
      evidence: headers.get("permissions-policy") || "Header not present",
      explanation: "This constrains browser features available to the page.", impact: "No explicit feature policy was observed.",
      fix: "Disable browser capabilities the site does not use." }
  ];
  const cookies = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : (headers.get("set-cookie") || "").split(/,(?=\s*[^;,]+=)/);
  const cookie_summary = cookies.filter(Boolean).map((cookie, index) => ({
    index: index + 1, secure: /(?:^|;)\s*secure(?:;|$)/i.test(cookie),
    http_only: /(?:^|;)\s*httponly(?:;|$)/i.test(cookie),
    same_site: (cookie.match(/(?:^|;)\s*samesite=([^;]*)/i) || [])[1] || null
  }));
  const httpProbe = await inspectResponse(new URL("http://" + target + "/"));
  const httpLocation = httpProbe.headers.get("location");
  const httpRedirectsToHttps = [301, 302, 303, 307, 308].includes(httpProbe.status) && httpLocation &&
    new URL(httpLocation, "http://" + target + "/").protocol === "https:" &&
    new URL(httpLocation, "http://" + target + "/").hostname.toLowerCase() === target;
  const findings = checks.filter(x => !x.passed).map(x => ({
    severity: x.severity, title: x.title + " not observed", evidence: x.evidence,
    explanation: x.impact, remediation: x.fix, confirmed_vulnerability: false
  }));
  if (cookie_summary.some(c => !c.secure || !c.http_only || !c.same_site)) {
    for (const cookie of cookie_summary) {
      const missing = [!cookie.secure && "Secure", !cookie.http_only && "HttpOnly", !cookie.same_site && "SameSite"].filter(Boolean);
      if (missing.length) findings.push({
        severity: "low", title: "Cookie attributes need review",
        evidence: "Cookie " + cookie.index + " is missing " + missing.join(", ") + "; cookie values were not recorded.",
        explanation: "Cookie risk depends on its purpose and how the application uses it.",
        remediation: "Set Secure, HttpOnly, and an intentional SameSite policy where appropriate.",
        confirmed_vulnerability: false
      });
    }
  }
  if (!httpRedirectsToHttps) findings.push({
    severity: "medium", title: "HTTP-to-HTTPS redirect not observed",
    evidence: "HTTP returned " + httpProbe.status + (httpLocation ? " with Location " + httpLocation : " without an HTTPS redirect"),
    explanation: "A visitor beginning with HTTP may not be upgraded to encrypted transport.",
    remediation: "Redirect HTTP to the exact HTTPS hostname and enable HSTS after validation.",
    confirmed_vulnerability: false
  });
  return {
    target, checked_at: new Date().toISOString(), status: response.status, latency_ms: Date.now() - started,
    final_url: current.href, redirects, http_probe: { status: httpProbe.status, location: httpLocation || null, redirects_to_https: Boolean(httpRedirectsToHttps) },
    tls: { https_response_observed: true, certificate_details_available: false },
    checks, findings, cookie_summary,
    limitations: [
      "The Worker Fetch API does not expose the peer certificate, issuer, SANs, or validity dates; this is not a certificate-detail assessment.",
      "The HTTPS response is evidence of a completed HTTPS request only, not a complete protocol/cipher/certificate review.",
      "The request is unauthenticated and bounded; signed-in pages can differ.",
      "Only redirects on the exact allowlisted hostname and standard ports are followed; external redirect destinations are recorded, not fetched.",
      "Header presence is measured; policy contents are not fully evaluated. Findings are not confirmed vulnerabilities.",
      "DNS is preflight-checked, but Fetch performs its own hostname resolution; only public destinations are supported."
    ]
  };
}
function rateLimit(key) {
  const now = Date.now();
  for (const [oldKey, stamps] of recent) {
    const live = stamps.filter(t => now - t < 60_000);
    if (live.length) recent.set(oldKey, live); else recent.delete(oldKey);
  }
  if (!recent.has(key) && recent.size >= 2048) return false;
  const values = (recent.get(key) || []).filter(t => now - t < 60_000);
  if (values.length >= 8) return false;
  values.push(now);
  recent.set(key, values);
  return true;
}
async function readJsonBounded(request, maxBytes = 4096) {
  const length = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(length) && length > maxBytes) throw Object.assign(new Error("Request body is too large."), { status: 413 });
  if (!request.body) throw new Error("Send a JSON request body.");
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw Object.assign(new Error("Request body is too large."), { status: 413 });
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new Error("Send a JSON request body."); }
}

export default {
  async fetch(request, env) {
    const allowedOrigin = (env.CORS_ORIGINS || "https://codex-inn.github.io").split(",").map(v => v.trim());
    const origin = request.headers.get("Origin") || "";
    const corsOrigin = allowedOrigin.includes(origin) ? origin : (origin ? "" : allowedOrigin[0]);
    if (request.method === "OPTIONS") {
      if (origin && !corsOrigin) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: {
        "access-control-allow-origin": corsOrigin,
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "Content-Type",
        "access-control-max-age": "86400"
      }});
    }
    const url = new URL(request.url);
    if (origin && !corsOrigin) return json({ detail: "Origin is not allowed." }, 403, "null");
    if (url.pathname === "/health" && request.method === "GET") {
      const configured = (env.ALLOWED_SCAN_TARGETS || "").split(",").map(v => v.trim()).filter(Boolean);
      return json({ status: "ok", scan_mode: "allowlisted-public-targets", configured_targets: configured.length }, 200, corsOrigin);
    }
    if (!["/scan", "/inspect"].includes(url.pathname) || request.method !== "POST") {
      return json({ detail: "Not found." }, 404, corsOrigin);
    }
    let body;
    try { body = await readJsonBounded(request); }
    catch (error) { return json({ detail: error.message }, error.status || 400, corsOrigin); }
    if (!body || typeof body !== "object" || Array.isArray(body)) return json({ detail: "Request body must be a JSON object." }, 400, corsOrigin);
    if (body.authorized !== true) return json({ detail: "Confirm that you are authorized to assess this target." }, 400, corsOrigin);
    let target;
    try { target = cleanTarget(body.target); } catch (e) { return json({ detail: e.message }, 400, corsOrigin); }
    const allowlist = (env.ALLOWED_SCAN_TARGETS || "").split(",").map(v => v.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean);
    if (!allowlist.length) return json({ detail: "Scan API is not configured. Set ALLOWED_SCAN_TARGETS in Worker settings." }, 503, corsOrigin);
    if (!allowlist.includes(target)) return json({ detail: "Target is not on the service owner's ALLOWED_SCAN_TARGETS allowlist." }, 403, corsOrigin);
    const client = request.headers.get("CF-Connecting-IP") || "unknown";
    if (url.pathname === "/inspect") {
      if (!rateLimit(client)) return json({ detail: "Rate limit reached. Wait one minute before trying again." }, 429, corsOrigin);
      try { await resolvePublicIPv4(target); return json(await inspectWebsite(target), 200, corsOrigin); }
      catch (e) { return json({ detail: e.message || "Website inspection failed." }, 502, corsOrigin); }
    }
    const ports = Array.isArray(body.ports) ? body.ports : [80, 443, 8080, 8443];
    if (!ports.length || ports.length > 8 || new Set(ports).size !== ports.length || ports.some(p => !Object.hasOwn(PORTS, p))) {
      return json({ detail: "Choose 1–8 unique ports from the supported list." }, 400, corsOrigin);
    }
    if (!rateLimit(client)) return json({ detail: "Rate limit reached. Wait one minute before trying again." }, 429, corsOrigin);
    let addresses;
    try { addresses = await resolvePublicIPv4(target); } catch (e) { return json({ detail: e.message || "Target resolution failed." }, 403, corsOrigin); }
    const jobs = addresses.flatMap(address => ports.map(port => ({ address, port })));
    if (jobs.length > 32) return json({ detail: "Scan exceeds the maximum number of checks." }, 400, corsOrigin);
    const results = await probeBounded(jobs);
    results.sort((a,b) => a.address.localeCompare(b.address) || a.port-b.port);
    return json({
      target, addresses, checked: results.length,
      open_count: results.filter(r => r.state === "open").length,
      results,
      limitations: [
        "Only TCP connection checks on selected allowlisted ports were performed.",
        "Closed or filtered is inconclusive; firewall and network conditions affect results.",
        "This hosted service cannot discover devices on your private Wi-Fi/LAN."
      ]
    }, 200, corsOrigin);
  }
};

