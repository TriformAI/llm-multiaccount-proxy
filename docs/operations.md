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

Keep the master key outside the database backup. Create a transactionally
consistent snapshot with the built-in online backup command:

```bash
llmap backup create --config /etc/llmap/llmap.toml \
  --output /secure/backups/llmap-$(date -u +%Y%m%dT%H%M%SZ).db
```

The command refuses to overwrite an existing destination and verifies the
snapshot with SQLite's integrity check. Provider credentials and residential
proxy userinfo remain application-encrypted, but account labels and audit
metadata do not; encrypt the whole backup at rest as operational data. Retain
the configured master key in a separate secret system.

Test restore on an isolated host:

1. Restore the database and the same master key.
2. Start on loopback with forward mode disabled.
3. Start the restored database with the same master key and confirm the
   redacted account inventory and metadata audit are present.
4. Confirm startup with a deliberately different key cannot decrypt an
   account credential.
5. Search the database, logs, audit export, and browser response for the test
   credential and proxy-userinfo sentinels; none may appear in plaintext.
6. Send a synthetic request through one designated test account.
7. Destroy the isolated copy securely.

Copying only the main `llmap.db` file from a running WAL database is not a
backup. If the built-in command cannot be used, stop the process before
copying the database plus any `-wal` and `-shm` files as one unit.

Back up the MITM CA separately. The public certificate alone is insufficient;
the private key is high-impact interception material.

## Capacity

Use explicit session IDs for long-running agents. Sticky sessions reduce cache
and conversation discontinuity. Model maps prevent routing a request to an
account that cannot serve it. Utilization and in-flight inputs are internal
routing signals; provider errors remain authoritative.
