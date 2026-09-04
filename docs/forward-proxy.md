# HTTPS forward proxy and local CA

Forward mode serves clients that can configure a conventional HTTP proxy but
cannot change their Anthropic base URL. `llmap` accepts CONNECT, terminates TLS
with an operator-owned local CA, and feeds the decrypted HTTP request into the
same authentication, routing, provider, egress, audit, and streaming path as
reverse mode.

## Create and protect the CA

```bash
llmap ca init --config /etc/llmap/llmap.toml
```

The command refuses to overwrite either file and creates the private key with
mode `0600` on Unix. Back up the CA only through an encrypted operator process.
Distribute the certificate, never the key, to the smallest possible client
trust store. Do not install it as an organization-wide root unless that broad
interception authority is explicitly intended and reviewed.

Configure clients with `HTTPS_PROXY=http://HOST:8081`. The CONNECT host must
match `forward_proxy.allowed_hosts`; IP literals for loopback, private,
link-local, multicast, documentation, and metadata ranges are denied.

## Rotation

Create a second CA on a maintenance host, distribute its public certificate,
stop the old listener, atomically replace both configured files, then restart.
Remove the old root from clients only after every intended client trusts the
new root. A lost CA key requires rotation; it must never be copied into logs,
issues, container images, or this repository.

## Limitations

WebSocket tunnelling is outside the GA API contract. The listener exists for
Anthropic-compatible HTTP request/response and streaming traffic to explicitly
allowlisted provider destinations.
