# Migration from Claudeproxy

The current internal Python Claudeproxy remains the production path until the
standalone service proves parity. Migration is an evidence sequence, not a
replacement deployment.

## 1. Inventory and import locally

Record account labels, provider kinds, client-facing model names, current
enabled state, and whether each account uses direct or residential egress. Move
credential values only through the approved secret channel into the write-only
control plane. Triform-specific Plane routing, operator pause mechanisms, and
pipeline controls stay outside the public core.

`llmap` can read Claudeproxy's `CLAUDE_ACCOUNT_N_NAME` and
`CLAUDE_ACCOUNT_N` env-file format directly. It never evaluates the file as a
shell script and reports counts only—never credential values:

```bash
export LLMAP_MASTER_KEY="$(openssl rand -base64 32)"
llmap migrate claudeproxy-env \
  --config llmap.toml \
  --input /secure/path/env-claude-accounts
```

The importer creates deterministic IDs (`claudeproxy-1`, `claudeproxy-2`,
and so on), preserves commented/paused accounts as disabled, and converts
Claude OAuth, Anthropic API-key, Bedrock API-key/SigV4, and configured
Anthropic-compatible entries. OAuth expiry is converted from milliseconds to
RFC 3339 and the supported Claude refresh endpoint is installed. Legacy
`proxyUrl`, `proxyUrls`, and `egressProxies` fields become encrypted per-account
egress chains.

Existing IDs are skipped. Inspect the redacted control-plane result before
using `--replace`; replacement rotates both provider and proxy credentials and
is intentionally explicit. Keep the source file outside the repository and
delete or archive it only through your normal secret-handling procedure.

## 2. Shadow configuration

Run `llmap` on private canary sockets with `auth.mode = "observe"`. Add accounts
one at a time. Compare classified outcomes, time-to-first-byte, stream
completion, sticky-session behavior, provider attribution, and redaction. Do
not mirror real prompt bodies merely to test the new proxy; use an explicitly
approved synthetic workload.

## 3. Canary callers

Move designated low-risk clients to the reverse endpoint, then the forward
endpoint if they need it. The rollback is client/ingress routing back to Python;
keep the old account configuration and health checks intact. Any duplicate send
must be initiated by a caller that knows the operation is safe, never by the
proxy after an ambiguous stream failure.

## 4. Enforce and expand

After observe-mode evidence shows every caller sends a token from an active
configured account, enable enforce for the canary. Expand traffic in measured
steps while comparing authentication, rate-limit, overload, transport, and
latency signals.

## 5. Soak and retire

Require all [GA readiness](ga-readiness.md) gates plus 30 consecutive days with
no severity-1/2 security or data-plane regression, tested backup/restore, and a
successful rollback rehearsal. Only then remove traffic from Python. Archive
its non-secret configuration and operational decisions; revoke credentials and
delete sensitive legacy state through the normal controlled process.
