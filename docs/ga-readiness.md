# GA readiness

No stable tag or production cutover is complete until every mandatory item has
linked evidence. A source commit, successful process start, or HTTP 200 alone is
not end-to-end proof.

## Product and compatibility

- [x] Provider-neutral Rust 1.85 service and single-node SQLite boundary.
- [x] Reverse Anthropic-compatible routes and response streaming.
- [x] Opt-in HTTPS MITM listener and non-overwriting CA lifecycle.
- [x] `off` / `observe` / `enforce` account-membership authentication.
- [x] Sticky least-loaded routing, model eligibility, classified depletion,
  and no unsafe replay.
- [x] Account-scoped HTTP(S)/SOCKS5/SOCKS5h chains without implicit direct
  fallback.
- [x] Branded session/CSRF administrator control plane and immediate
  pause/delete effect.
- [x] Automatic Claude OAuth refresh with bounded previous-token overlap and
  compare-and-swap persistence.
- [ ] Native Bedrock SigV4 vectors and Anthropic-to-Bedrock streaming parity.
- [x] Upstream DNS resolution validation and address pinning before direct
  connections; remote-DNS proxy chains remain inside the configured egress
  trust boundary.

## Security and privacy

- [x] Encrypted credentials, Argon2id passwords, constant-time token matching,
  redacted debug/API/UI output, and metadata-only audit fields.
- [x] HTTPS-only upstreams, no redirects, host allowlists, unsafe literal-IP
  denial, strict headers, bounded bodies, and login lockout.
- [ ] Independent threat-model review and penetration test closed without an
  unresolved critical/high finding.
- [ ] Secret scan, dependency audit, license policy, CodeQL, container scan,
  SBOM, provenance, and signed release artifacts green on the release commit.

## Operations

- [x] Health, readiness, Prometheus counters, classified audit, and 30-day
  default pruning.
- [x] Quick start, configuration, provider, auth, egress, forward-proxy,
  architecture, API, operations, security, upgrade, rollback, migration, and
  troubleshooting documentation.
- [ ] Restore drill proves encrypted SQLite recovery with no plaintext leak.
- [ ] Load/soak test covers long streams, disconnects, 401/403/429/529, proxy
  failure, account mutation, restart, and disk pressure.
- [ ] Python-to-Rust canary and rollback rehearsal, then 30 consecutive clean
  days before legacy retirement.

## Distribution

- [x] Apache-2.0 public repository on GitHub and Forgejo integration authority.
- [x] Forgejo-to-GitHub push mirror configured for branches and tags.
- [ ] Protected branches require review and CI; mirror parity monitor is green.
- [ ] Reproducible container and multi-platform binaries published from a
  signed tag with checksums, SBOM, and provenance.

Release owners attach CI URLs, image digests, signed tag, scan reports, UAT
records, canary dashboards, restore record, rollback record, and soak dates to
the release issue.
