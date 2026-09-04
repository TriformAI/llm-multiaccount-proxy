# Migration from Claudeproxy

The current internal Python Claudeproxy remains the production path until the
standalone service proves parity. Migration is an evidence sequence, not a
replacement deployment.

## 1. Inventory without exporting secrets

Record account labels, provider kinds, client-facing model names, current
enabled state, and whether each account uses direct or residential egress. Move
credential values only through the approved secret channel into the write-only
control plane. Triform-specific Plane routing, operator pause mechanisms, and
pipeline controls stay outside the public core.

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
