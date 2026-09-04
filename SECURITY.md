# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Email
`security@triform.ai` with a concise description, affected version, and a
reproduction if available. We will acknowledge receipt and coordinate a fix
and disclosure timeline.

## Security boundary

`llmap` handles provider credentials and can terminate TLS when its forward
proxy mode is enabled. Treat the service, its database, master key, generated
certificate authority, backups, and host as sensitive infrastructure.

The project never intends to record prompt or response bodies. A report that
shows credentials, request bodies, or response bodies entering logs, metrics,
audit rows, crash reports, or the admin UI is security-sensitive.

## Supported versions

Security support begins with the first GA release. Until then, builds from
`main` are development snapshots and should be evaluated only in controlled
environments.

