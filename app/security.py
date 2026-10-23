from __future__ import annotations
import hashlib, hmac, ipaddress, os, secrets
from typing import Iterable

PBKDF2_ITERATIONS = 310_000

def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError('Passwords must contain at least 12 characters.')
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS)
    return f'pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}'

def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split('$', 3)
        if algorithm != 'pbkdf2_sha256': return False
        candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError): return False

def approved_networks(raw: str | None = None):
    value = os.getenv('APPROVED_CIDRS', '') if raw is None else raw
    networks = []
    for item in value.split(','):
        item = item.strip()
        if not item: continue
        net = ipaddress.ip_network(item, strict=False)
        if net.prefixlen < (16 if net.version == 4 else 48):
            raise ValueError(f'Approved range {item} is too broad; use /16 or narrower IPv4 and /48 or narrower IPv6 ranges.')
        networks.append(net)
    return networks

def validate_target(target: str, max_hosts: int = 256, raw_allowlist: str | None = None) -> str:
    try: network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc: raise ValueError('Enter a valid IPv4 address or CIDR.') from exc
    if network.version != 4: raise ValueError('This MVP supports IPv4 targets only.')
    if network.num_addresses > max_hosts: raise ValueError(f'Target contains {network.num_addresses} addresses; limit is {max_hosts}.')
    allowed = approved_networks(raw_allowlist)
    if not allowed: raise ValueError('Scanning is disabled: configure APPROVED_CIDRS in .env first.')
    if not any(network.subnet_of(a) for a in allowed if a.version == network.version):
        raise ValueError('Target is not fully contained in an approved CIDR.')
    return str(network)

ALLOWED_PORTS = {21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017}
def validate_ports(ports: Iterable[int], max_ports: int = 25) -> list[int]:
    values = list(dict.fromkeys(ports))
    if not values: raise ValueError('Select at least one allowed TCP port.')
    if len(values) > max_ports: raise ValueError(f'At most {max_ports} ports may be scanned per job.')
    if any(not isinstance(p, int) or p not in ALLOWED_PORTS for p in values): raise ValueError('One or more ports are outside the built-in allowed-port list.')
    return values
