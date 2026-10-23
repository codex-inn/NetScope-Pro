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
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
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
async function resolvePublicIPv4(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    if (!isPublicIPv4(host)) throw new Error("Non-public IP addresses are blocked.");
    return [host];
  }
  const url = "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(host) + "&type=A";
  const response = await fetch(url, { headers: { accept: "application/dns-json" } });
  if (!response.ok) throw new Error("Public DNS lookup failed (HTTP " + response.status + ").");
  const data = await response.json();
  const answers = (data.Answer || []).filter(a => a.type === 1).map(a => a.data);
  if (!answers.length) throw new Error("No public IPv4 address was returned for this target.");
  if (answers.some(ip => !isPublicIPv4(ip))) throw new Error("Target resolves to a private or non-public IP and was blocked.");
  return [...new Set(answers)];
}
async function probe(address, port) {
  const started = Date.now();
  let socket;
  try {
    socket = connect({ hostname: address, port }, { secureTransport: "off" });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1800))
    ]);
    try { await socket.close(); } catch {}
    return { address, port, service: PORTS[port], state: "open", latency_ms: Date.now() - started };
  } catch {
    try { if (socket) await socket.close(); } catch {}
    return { address, port, service: PORTS[port], state: "closed_or_filtered", latency_ms: Date.now() - started };
  }
}
function rateLimit(key) {
  const now = Date.now();
  const values = (recent.get(key) || []).filter(t => now - t < 60_000);
  if (values.length >= 8) return false;
  values.push(now);
  recent.set(key, values);
  return true;
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
    if (url.pathname !== "/scan" || request.method !== "POST") {
      return json({ detail: "Not found." }, 404, corsOrigin);
    }
    let body;
    try { body = await request.json(); } catch { return json({ detail: "Send a JSON request body." }, 400, corsOrigin); }
    if (body.authorized !== true) return json({ detail: "Confirm that you are authorized to assess this target." }, 400, corsOrigin);
    let target;
    try { target = cleanTarget(body.target); } catch (e) { return json({ detail: e.message }, 400, corsOrigin); }
    const allowlist = (env.ALLOWED_SCAN_TARGETS || "").split(",").map(v => v.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean);
    if (!allowlist.length) return json({ detail: "Scan API is not configured. Set ALLOWED_SCAN_TARGETS in Worker settings." }, 503, corsOrigin);
    if (!allowlist.includes(target)) return json({ detail: "Target is not on the service owner's ALLOWED_SCAN_TARGETS allowlist." }, 403, corsOrigin);
    const ports = Array.isArray(body.ports) ? body.ports : [80, 443, 8080, 8443];
    if (!ports.length || ports.length > 8 || new Set(ports).size !== ports.length || ports.some(p => !Object.hasOwn(PORTS, p))) {
      return json({ detail: "Choose 1–8 unique ports from the supported list." }, 400, corsOrigin);
    }
    const client = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!rateLimit(client)) return json({ detail: "Rate limit reached. Wait one minute before trying again." }, 429, corsOrigin);
    let addresses;
    try { addresses = await resolvePublicIPv4(target); } catch (e) { return json({ detail: e.message || "Target resolution failed." }, 403, corsOrigin); }
    const jobs = addresses.flatMap(address => ports.map(port => ({ address, port })));
    if (jobs.length > 32) return json({ detail: "Scan exceeds the maximum number of checks." }, 400, corsOrigin);
    const results = await Promise.all(jobs.map(job => probe(job.address, job.port)));
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
