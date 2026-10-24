# Operations checklist

## Website security assessment
- Obtain written authorization for the exact hostname and checks.
- Keep `AUTHORIZED_WEB_HOSTS` to exact approved hostnames; an empty value disables the Python website assessment. Never use wildcard entries.
- Bind the local Python API to `127.0.0.1`; do not expose it publicly.
- Review certificate verification, redirect chains, DNS provider disclosure, findings, and limitations in every report.
- Keep API secrets unique, do not put credentials or tokens in target URLs, and protect browser-local history on shared devices.

## Before a network scan
- Obtain written approval for the exact CIDR, ports, scan window, and responsible operator.
- Confirm the range is present in `APPROVED_CIDRS` and is no broader than necessary.
- Start with the smallest possible lab/test subnet.
- Confirm Nmap is installed and the machine has the appropriate route.
- Tell network operations staff when scanning will occur.

## Roles
- Admin: manage user accounts and optional schedules.
- Operator: launch scans inside configured scope and review scan history.
- Protect the Windows account and local SQLite database; access to the host effectively grants access to scan history.

## Optional scheduler
Scheduling is disabled by default. To use it, confirm recurring-scan approval, set `SCHEDULER_ENABLED=true`, restart the app, create a disabled schedule, then explicitly enable it. Monitor scan history and disable schedules if they affect network performance. The scheduler revalidates target scope before each run.

## Known limitations
This MVP has session-based authentication and local-only defaults, but is not hardened for public or multi-host internet exposure. Do not publish the API publicly. Before multi-user remote deployment, implement CSRF protection for state-changing endpoints, HTTPS, login rate limiting, account lockout, session rotation, backup/restore, and independent security review.

