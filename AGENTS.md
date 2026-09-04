# AGENTS.md — LLM Multiaccount Proxy

This repository is the standalone source for `llmap`.

## Working agreement

- Preserve a clean public history. Never copy the private monorepo history,
  credentials, traffic logs, account data, or generated secrets into this repo.
- Work on `agent/*` branches. Commit each meaningful step and open a pull
  request against Forgejo `main`; do not push directly to protected branches.
- Forgejo is the integration authority. GitHub receives protected `main` and
  signed tags through the configured push mirror.
- New behavior follows strict RED -> GREEN -> REFACTOR TDD unless an explicit,
  documented exception is approved.
- Secret values are never logged, rendered, returned by APIs, or stored in
  plaintext. Tests use unmistakably fake values.
- Provider-specific behavior stays behind provider adapters. Routing,
  authentication, storage, egress, and the admin UI depend on provider-neutral
  contracts.
- The GA support boundary is single-node SQLite. Preserve storage interfaces so
  a future HA backend does not leak into routing or API code.
- Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, and `cargo test --all-features` before requesting review.

## Public language

Describe the product as one endpoint for accounts the operator controls, with
sticky sessions, capacity-aware routing, per-account egress, and operational
visibility. Do not describe it as unlimited access, ban avoidance, or provider
control circumvention.

