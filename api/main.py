"""NetScope Pro public-target scan API.

Only scans explicitly allowlisted public hostnames/IPs. It never scans LAN/private
ranges, CIDRs, arbitrary ports, or ranges. Configure ALLOWED_SCAN_TARGETS before
deploying. This is an assistive security check, not a vulnerability scanner.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
}
MAX_TARGETS_PER_MINUTE = 8
REQUEST_TIMES: dict[str, list[float]] = {}
RATE_LOCK = Lock()

app = FastAPI(title="NetScope Pro Scan API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "https://codex-inn.github.io").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443], max_length=8)
    authorized: bool

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str) -> str:
        value = value.strip().rstrip(".").lower()
        if not value or any(ch in value for ch in "/\\@?#") or " " in value:
            raise ValueError("Enter a hostname or single IP address, not a URL or range.")
        return value

    @field_validator("ports")
    @classmethod
    def safe_ports(cls, value: list[int]) -> list[int]:
        if not value or len(set(value)) != len(value):
            raise ValueError("Select one or more unique supported ports.")
        if any(p not in PORTS for p in value):
            raise ValueError("One or more ports are not in the supported safe list.")
        return value


def allowlisted_targets() -> set[str]:
    return {x.strip().lower().rstrip(".") for x in os.getenv("ALLOWED_SCAN_TARGETS", "").split(",") if x.strip()}


def resolve_public(target: str) -> list[str]:
    try:
        ip = ipaddress.ip_address(target)
        addresses = [str(ip)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise HTTPException(400, "Target hostname did not resolve from the scan service.") from exc
        addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise HTTPException(400, "No address records were found.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise HTTPException(403, "Private, loopback, link-local, reserved, and non-public targets are blocked.")
    return addresses


def enforce_rate_limit(key: str) -> None:
    now = time.time()
    with RATE_LOCK:
        recent = [t for t in REQUEST_TIMES.get(key, []) if now - t < 60]
        if len(recent) >= MAX_TARGETS_PER_MINUTE:
            raise HTTPException(429, "Rate limit reached. Wait one minute before scanning again.")
        recent.append(now)
        REQUEST_TIMES[key] = recent


def probe(address: str, port: int) -> dict:
    started = time.perf_counter()
    state: Literal["open", "closed_or_filtered"] = "closed_or_filtered"
    try:
        with socket.create_connection((address, port), timeout=0.8):
            state = "open"
    except (OSError, TimeoutError):
        pass
    return {
        "address": address,
        "port": port,
        "service": PORTS[port],
        "state": state,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "scan_mode": "allowlisted-public-targets", "configured_targets": len(allowlisted_targets())}


@app.post("/scan")
def scan(payload: ScanRequest, request: Request) -> dict:
    if not payload.authorized:
        raise HTTPException(400, "Confirm you are authorized to assess this target.")
    allowed = allowlisted_targets()
    if not allowed:
        raise HTTPException(503, "Scan service is not configured. The owner must set ALLOWED_SCAN_TARGETS.")
    if payload.target not in allowed:
        raise HTTPException(403, "This target is not on the service owner's ALLOWED_SCAN_TARGETS list.")
    enforce_rate_limit(request.client.host if request.client else "unknown")
    addresses = resolve_public(payload.target)
    jobs = [(address, port) for address in addresses for port in payload.ports]
    if len(jobs) > 32:
        raise HTTPException(400, "Scan exceeds the maximum number of checks.")
    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(probe, address, port) for address, port in jobs]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda r: (r["address"], r["port"]))
    return {
        "target": payload.target,
        "addresses": addresses,
        "checked": len(results),
        "open_count": sum(1 for r in results if r["state"] == "open"),
        "results": results,
        "limitations": [
            "Only TCP connection checks on the selected allowlisted ports were performed.",
            "Closed or filtered is inconclusive; firewalls and network conditions can affect results.",
            "This hosted service cannot discover devices on your private Wi-Fi/LAN.",
        ],
    }
