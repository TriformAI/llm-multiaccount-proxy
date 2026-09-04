# RC1 evidence

The repository produces a metadata-only RC1 contract bundle on Forgejo and
GitHub CI. Run the same harness locally or in a disposable runner with:

```bash
./scripts/rc1-evidence target/rc1-evidence/summary.json
```

The harness runs the locked, all-feature Rust test suite and writes a small
JSON summary containing the tested commit, timestamps, result, scenario IDs,
and explicit unverified boundaries. It does not copy test logs, prompts,
responses, authorization headers, provider credentials, proxy credentials, or
database contents into the artifact.

## Automated contract matrix

| Evidence area | Contract |
|---|---|
| Health, admin, and account auth | Runtime, admin session/CSRF, redacted account, and `off`/`observe`/`enforce` tests |
| Routing | Sticky least-loaded selection, model eligibility, account mutation, and depletion tests |
| Faults | Deterministic 401, 403, 429, 529, and pre-response disconnect outcomes with metadata-only audit assertions |
| Load and streams | 64 simultaneous synthetic long streams reach both eligible accounts and every request/response/audit is accounted for |
| Retry safety | Pre-request retry is distinguished from irreversible request/response streaming boundaries |
| Residential egress | Ordered failover after three failures and no implicit direct fallback |
| Bedrock | AWS-published SigV4 vector, signed content type, EventStream CRC/header/limit semantics, chunk translation, and redacted exceptions |
| Restore | Online SQLite backup, no-overwrite behavior, integrity check, same-key restore, wrong-key rejection, metadata preservation, and fake-secret scan |
| Canary | Inert base, no Ingress/Secret object, default deny, immutable digest placeholder, and selector-only activation/rollback |

## What this does not prove

GREEN automated evidence is necessary but does not prove a live provider
account, a cluster rollout, a real SIGTERM drain, disk-pressure behavior, an
independent penetration test, or a 30-day soak. Those remain open in
[GA readiness](ga-readiness.md) and must be executed against the exact image
digest in the [canary package](../examples/kubernetes/canary/README.md).

For each live run, attach the CI artifact URL, source commit, image digest,
configuration hash, operator, timestamps, synthetic workload identifier,
dashboard window, restore record, and selector rollback record. Never attach
provider tokens, prompt/response bodies, proxy userinfo, the SQLite database,
or the master key.
