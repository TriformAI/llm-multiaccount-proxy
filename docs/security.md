# Security and threat model

## Assets and trust boundaries

The database contains encrypted provider and proxy credentials. The master key,
admin bootstrap password, administrator session cookies, and MITM CA private key
remain outside public APIs. Anyone controlling the process host can observe
decrypted traffic; harden that host accordingly.

The reverse listener is a data and admin boundary. Use TLS, ingress network
policy, and `auth.mode = "enforce"` for shared networks. The forward listener is
an additional TLS interception boundary and should have a narrower network
allowlist whenever possible.

## Implemented controls

- XChaCha20-Poly1305 credentials with random nonces and account-bound associated
  data; Argon2id administrator password verification.
- Keyed, constant-time client-token matching without plaintext inventories.
- Random opaque administrator sessions, idle/absolute expiry, login lockout,
  HttpOnly SameSite cookies, and CSRF protection.
- HTTPS-only upstream URLs, no redirects, destination allowlists, unsafe IP
  literal denial, bounded request bodies, and strict header forwarding.
- Write-only credentials and proxy userinfo; metadata-only audit and metrics.
- Non-overwriting CA creation and `0600` Unix private-key permissions.
- No automatic replay after an upstream may have observed request bytes.

## Residual risks and GA gates

DNS rebinding protection must pin or validate resolved addresses at connection
time, not only validate configured host text. Native Bedrock SigV4 and streaming
translation, automatic OAuth refresh overlap, external penetration testing,
dependency review, and the 30-day canary soak remain first-GA gates. Track them
in [GA readiness](ga-readiness.md).

SQLite is a single-node boundary. Do not place multiple writers on a network
filesystem. Backups and database copies are sensitive even though credential
columns are encrypted.

## Incident response

If the master key or database is exposed, pause traffic, rotate every provider
and residential-proxy credential, replace the master key through a controlled
migration, invalidate administrator sessions by restarting, and review
metadata attribution. If the CA key is exposed, disable forward mode, create a
new CA, distribute its public root, remove the old root from every client, and
treat intercepted traffic in the exposure window as potentially compromised.

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
