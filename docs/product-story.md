# Product story and proposal

## The problem

AI engineering teams rarely have one neat source of Claude capacity. They may
hold several authorized Claude seats, an Anthropic API account, Bedrock access,
and a compatible provider. Individual tools each understand one credential and
one endpoint. Operators get fragile hand-edited switching, lost session
affinity, inconsistent network origin, and little evidence about which account
served which workload.

## The proposal

LLM Multiaccount Proxy turns accounts the operator already controls into one
deliberate service boundary:

- one Anthropic-compatible endpoint for tools and agents;
- current-token membership, so any active pool account can authenticate a
  caller without introducing another shared proxy secret;
- sticky sessions with least-loaded eligible placement and model maps;
- classified account health and depletion instead of opaque round robin;
- stable, account-scoped residential egress with explicit ordered fallback;
- a calm Triform-harmonized control plane for add, pause, resume, revoke, and
  operational visibility;
- encrypted state and metadata attribution without recording conversations.

## Who buys or adopts it

The primary user is a power-user team or platform engineer already responsible
for multiple legitimate accounts and agent runtimes. They value continuity,
operational control, and a migration path they can audit. A managed Triform
offering can add hosted operations, upgrades, backup drills, alerting, and
provider-adapter support; the Apache-2.0 core remains deployable on their own
infrastructure.

## Value narrative

The product does not create capacity and does not bypass provider policy. It
makes authorized capacity reliable. The economic story is fewer interrupted
agent runs, less manual credential switching, better account utilization,
predictable egress, and faster diagnosis. Measure successful stream completion,
time-to-first-byte, session rebind rate, account depletion time, operator effort,
and incidents—not an “unlimited requests” claim.

## Packaging

- Open-source core: reverse and forward proxy, encrypted single-node state,
  account routing, residential egress, control plane, metrics, and docs.
- Supported distribution: signed multi-platform binaries and OCI image,
  maintenance releases, compatibility matrix, and upgrade guidance.
- Managed Triform service: hardened hosting, backup/restore, monitoring,
  provider onboarding, egress integrations, and response support.

## Responsible positioning

Always say “accounts you control,” “authorized provider capacity,” and “stable
per-account egress.” Never promise ban avoidance, identity masking, unlimited
usage, terms circumvention, or geographic-control evasion. Customers remain
responsible for provider terms and the workload sent through the service.
