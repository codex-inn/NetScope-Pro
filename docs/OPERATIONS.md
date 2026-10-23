# Operations checklist

## Before a scan
- Obtain written approval for the exact CIDR, ports, scan window, and responsible operator.
- Confirm the range is present in APPROVED_CIDRS and is no broader than necessary.
- Start with the smallest possible lab/test subnet.
- Confirm Nmap is installed and the machine has the appropriate route.
- Tell network operations staff when scanning will occur.

## Roles
- Admin: manage user accounts and optional schedules.
- Operator: launch scans inside the configured scope and review findings.
- Protect the Windows account and local SQLite database; access to the host effectively grants access to scan history.

## Optional scheduler
Scheduling is disabled by default. To use it:
1. Confirm the network owner approves recurring scans and the selected interval.
2. Set SCHEDULER_ENABLED=true in .env and restart the app.
3. Create a schedule in the dashboard; it is saved disabled.
4. Explicitly enable it in the Schedules page.
5. Monitor scan history and disable the schedule if it affects network performance.
The scheduler starts recurring scans only for enabled schedule records and revalidates target scope before each run.

## Known limitations
This MVP has session-based authentication and local-only defaults, but it is not hardened for public or multi-host internet exposure. Do not publish the API publicly. Before multi-user remote deployment, implement CSRF tokens for all state-changing endpoints, HTTPS, rate limiting on login, account lockout, session rotation, backup/restore, and independent security review.
