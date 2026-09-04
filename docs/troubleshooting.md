# Troubleshooting

## `401 authentication_failed`

In enforce mode, confirm the client sends exactly one current token through
Bearer or `x-api-key`, and that the owning account is active. Pause/remove takes
effect immediately. Do not print the value while debugging.

## `503 credential_store_unavailable`

This is deliberately distinct from bad auth. Check database path permissions,
volume health, SQLite availability, and the master key. In enforce mode the
service fails closed when it cannot establish membership.

## `503 no_eligible_account`

Inspect active accounts, model maps, recent `401`/`403`, `429`, and `529`
outcomes. A healthy HTTP process is not evidence that a provider account has
capacity.

## `502 upstream_unavailable`

Check destination allowlists, DNS, firewall, account residential proxy health,
and provider reachability. The proxy does not know whether an upstream consumed
request bytes; do not blindly replay non-idempotent work.

## Admin login loops

Use `secure_cookies = false` only for direct loopback HTTP. Behind HTTPS it must
be true, and the proxy/ingress must preserve Set-Cookie. Five failed attempts
lock the login client key for 15 minutes. Restart clears in-memory sessions and
lockouts.

## Forward proxy TLS errors

Confirm the client trusts the configured public CA, the service can read the
matching private key, the CONNECT host is allowlisted, and the system clock is
correct. Never solve trust errors by disabling TLS verification globally.

## SQLite busy or corrupt

Run only one `llmap` process against the database, keep it on a local persistent
volume, and use a SQLite-aware backup. Restore into an isolated copy before
attempting repair. Preserve evidence and do not post the database publicly.
