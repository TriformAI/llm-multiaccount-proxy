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

The public repository is under active development toward its first GA release.
Do not place it in front of untrusted traffic until the security checklist and
GA acceptance suite in `docs/ga-readiness.md` are complete.

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

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

