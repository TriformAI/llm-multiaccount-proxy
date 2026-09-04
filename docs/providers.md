# Provider adapters

Provider-specific authentication and model rewriting live in `src/providers.rs`.
Routing sees only account eligibility, model support, utilization, health, and
depletion state.

| Kind | Credential input | Upstream authentication | Status |
|---|---|---|---|
| `claude_oauth` | Claude OAuth access token | `Authorization: Bearer` plus the Claude OAuth beta header | implemented; operator rotation |
| `anthropic_api_key` | Anthropic API key | `x-api-key` | implemented |
| `bedrock_api_key` | Amazon Bedrock long-term API key | `Authorization: Bearer` | implemented for explicitly configured Bedrock-compatible request paths |
| `bedrock_sig_v4` | AWS signing credential envelope | AWS SigV4 | release gate; see GA readiness |
| `anthropic_compatible` | Provider token | explicitly named header and optional prefix | implemented |

`base_url` must be HTTPS and its host must appear in
`server.allowed_upstream_hosts`. Redirects are disabled so credentials cannot
escape to another origin. Hop-by-hop, cookie, forwarding, and inbound
authorization headers are discarded; each adapter owns its outbound auth.

## Model maps

`model_map` maps a client-facing model name to an upstream name. Empty maps mean
the account advertises all client model names and sends them unchanged. A
non-empty map both controls eligibility and rewrites the JSON `model` field.

## Anthropic-compatible providers

Set `compatible_auth_header` and, when needed, `compatible_auth_prefix`. For
example, header `Authorization` and prefix `Bearer `. Header names are validated
before use. The provider must accept Anthropic request and response semantics;
`llmap` does not guess proprietary formats.

## Bedrock and OAuth release boundary

The first stable tag is blocked until the SigV4 vector suite, native Bedrock
payload/stream translation, and automated OAuth refresh/overlap tests are
green. Development snapshots expose the account kinds so the control-plane and
storage contracts can stabilize, but the readiness document—not the dropdown—
defines GA support.
