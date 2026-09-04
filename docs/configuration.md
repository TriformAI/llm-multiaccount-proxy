# Configuration reference

`llmap` reads TOML. `llmap config check --config PATH` validates it without
opening listeners or reading secret values. Unknown fields are rejected so a
misspelled security setting cannot silently fall back to a default.

## `[server]`

| Field | Meaning | Default |
|---|---|---|
| `bind` | Reverse proxy, admin, health, and metrics socket | required |
| `max_request_bytes` | Buffered client request limit, 1 byte to 256 MiB | 32 MiB |
| `allowed_upstream_hosts` | Exact hosts or whole-label wildcard patterns the data plane may call | Anthropic and Bedrock defaults |

Bind to loopback unless a trusted ingress provides TLS and network policy.
Provider base URLs must be HTTPS and contain no userinfo.

## `[auth]`

`mode` is `off`, `observe`, or `enforce`. `LLMAP_AUTH_MODE` overrides the file
and makes the control-plane display read-only. See [authentication](authentication.md).

## `[storage]`

`database_path` points to the SQLite database. `master_key_env` names an
uppercase environment variable containing exactly 32 random bytes encoded as
standard or unpadded URL-safe Base64. The key never belongs in TOML.

## `[admin]`

`username` identifies the single-node administrator.
`bootstrap_password_env` names the password environment variable. The password
is Argon2id-verified and never stored in SQLite. `secure_cookies` must be `true`
when users reach the control plane over HTTPS; loopback HTTP development may set
it to `false`.

## `[forward_proxy]`

`enabled` controls whether the second listener starts. `bind`, `ca_cert_path`,
and `ca_key_path` define that listener and its local CA. `allowed_hosts` is an
independent CONNECT allowlist. Forward and reverse sockets must differ.
Use `bedrock-runtime.*.amazonaws.com` for regional Bedrock Runtime endpoints;
avoid the broader `*.amazonaws.com` pattern.

## `[telemetry]`

`audit_retention_days` accepts 1–365 and defaults to 30. Expired metadata rows
are pruned at startup. Prompts, responses, credentials, authorization headers,
cookies, and proxy userinfo are excluded from audit and metrics.

The maintained example is [examples/llmap.toml](../examples/llmap.toml).
