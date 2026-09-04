# Operations

## Health model

`/health` proves the process can answer and identifies its version plus embedded
source commit when the distribution supplies `LLMAP_BUILD_SHA`. `/ready` currently proves startup,
configuration, and database opening completed. A ready process can still have
zero eligible provider accounts, so alert on request outcomes and active account
count as well as the probe.

Account outcomes have distinct effects:

- `401`/`403` marks that upstream account unhealthy and evicts its sessions.
- `429` depletes it until `Retry-After` or 60 seconds.
- `529` depletes it until `Retry-After` or 30 seconds.
- other `5xx` and network failures clear sticky bindings for future traffic.
- no outcome causes unsafe automatic replay after the streaming boundary.

## Account runbook

Pause before planned credential or proxy work. Confirm it disappears from the
routing pool and its old token no longer authenticates clients in enforce mode.
Update the credential through the write-only form, validate a small request,
then resume. Delete only after deciding its audit attribution is no longer
needed.

## Backup and restore

Keep the master key outside the database backup. Use a SQLite-aware snapshot
or stop the process and copy the database plus `-wal`/`-shm` files together.
Encrypt backups and test restore on an isolated host:

1. Restore the database and the same master key.
2. Start on loopback with forward mode disabled.
3. Confirm accounts list without credentials appearing.
4. Send a synthetic request through one designated test account.
5. Destroy the isolated copy securely.

Back up the MITM CA separately. The public certificate alone is insufficient;
the private key is high-impact interception material.

## Capacity

Use explicit session IDs for long-running agents. Sticky sessions reduce cache
and conversation discontinuity. Model maps prevent routing a request to an
account that cannot serve it. Utilization and in-flight inputs are internal
routing signals; provider errors remain authoritative.
