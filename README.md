# LLM Multiaccount Proxy

LLM Multiaccount Proxy (`llmap`) gives teams one Anthropic-compatible endpoint
for the Claude accounts and compatible providers they already control.

The project is being extracted from Triform's production Claude proxy into a
standalone, provider-neutral Rust service. The first general-availability
release targets a secure single-node deployment with:

- configurable client authentication (`off`, `observe`, or `enforce`);
- sticky session routing across multiple accounts;
- Claude OAuth, Anthropic API key, Amazon Bedrock, and configurable
  Anthropic-compatible upstreams;
- account-scoped residential proxy chains with explicit failover;
- a branded browser control plane and operational API;
- SQLite-backed encrypted state, metrics, health checks, and audit history;
- both reverse-proxy and HTTPS forward-proxy entry points.

## Status

The public repository is in release-candidate development toward its first GA
release. The Rust 1.85 service, encrypted account store, reverse data plane,
branded control plane, and opt-in HTTPS MITM listener are implemented. Do not
place a development snapshot in front of untrusted traffic until the security
checklist and soak requirements in [GA readiness](docs/ga-readiness.md) are
complete.

## Quick start

```bash
cp examples/llmap.toml llmap.toml
export LLMAP_MASTER_KEY="$(openssl rand -base64 32)"
export LLMAP_ADMIN_PASSWORD="$(openssl rand -base64 24)"
llmap config check --config llmap.toml
llmap serve --config llmap.toml
```

Open <http://127.0.0.1:8080/admin/login>, add an account, then point an
Anthropic-compatible client at `http://127.0.0.1:8080`. In `enforce` mode the
client sends the current token of any active configured account; that proves
membership in the pool, while routing may select a different eligible account.

Start with the [quick-start guide](docs/quickstart.md), then read
[configuration](docs/configuration.md), [client authentication](docs/authentication.md),
and [provider adapters](docs/providers.md).

Existing Claudeproxy operators can import the legacy env-file safely with
`llmap migrate claudeproxy-env`; see the [migration guide](docs/migration.md).

## Why it exists

A growing team often has several legitimate Claude or compatible-provider
accounts, but every tool still needs one reliable endpoint. `llmap` turns that
fragmented capacity into an observable pool: sticky agent sessions,
least-utilized eligible routing, explicit account pause/revoke controls,
per-account residential egress, and one control plane. Read the full
[product story and deployment proposal](docs/product-story.md).

## Responsible use

`llmap` is for routing accounts and provider capacity that you are authorized
to use. It is not designed or marketed to bypass provider limits, access
controls, terms, or regional restrictions. Operators remain responsible for
their provider agreements and for the traffic sent through the proxy.

## Source and mirrors

- Public home: <https://github.com/TriformAI/llm-multiaccount-proxy>
- Integration source: <https://forgejo.triform.dev/triform/llm-multiaccount-proxy>

Forgejo is the integration authority. The protected `main` branch and signed
version tags are mirrored to GitHub, where public releases are published.

## Documentation

- [Documentation map](docs/index.md)
- [Architecture](docs/architecture.md)
- [Operations and backup](docs/operations.md)
- [Security and threat model](docs/security.md)
- [Migration from Claudeproxy](docs/migration.md)
- [Acceptance test plan](docs/uat.md)
- [Upgrade and rollback](docs/upgrades.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
