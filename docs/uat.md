# Acceptance test plan

Run these scenarios against the exact release candidate in an isolated canary.
Use synthetic prompts and test credentials. Record the image or binary digest,
configuration hash, operator, timestamps, and observed result for every run.

## Claude Code user: one endpoint, several owned accounts

**Context:** Two active Claude OAuth accounts are configured and client auth
is `observe`. The user has an ordinary Claude Code session whose existing
token belongs to one of those accounts.

**Intention:** Work normally through the reverse endpoint without learning
which upstream account serves each request.

**Observe:**

- login and streaming responses complete without buffered pauses;
- repeated turns stay on one eligible account while that session is active;
- metadata audit identifies caller fingerprint, selected account, model,
  status, outcome, and latency, but contains no prompt, response, or token;
- switching to `enforce` keeps this user working and rejects a synthetic token
  that belongs to no active account;
- pausing the matching account invalidates that client token immediately.

## Proxy-aware tool user: HTTPS forward mode

**Context:** The canary CA is installed only in a disposable client trust
store, and the forward listener allows Anthropic and regional Bedrock runtime
hosts.

**Intention:** Use a client that supports `HTTPS_PROXY` but cannot change its
API base URL.

**Observe:**

- allowed CONNECT traffic is decrypted and routed through the same auth,
  account, audit, and streaming path as reverse mode;
- an unlisted host and a private/metadata address fail closed;
- removing the CA makes the client reject interception; the operator can remove
  the generated key and certificate without affecting reverse mode.

## Pool operator: import and rotate without exposing secrets

**Context:** A copy of a Claudeproxy env file contains OAuth, API-key, paused,
and residential-proxy examples.

**Intention:** Import it into a new encrypted SQLite database, inspect the
result, rotate one entry, and restore a backup.

**Observe:**

- the command prints imported/skipped counts only and preserves paused entries
  as disabled;
- the browser/API shows labels, kinds, models, state, and redacted proxy
  authorities only;
- searching the database, logs, audit export, and browser response finds no
  test provider token, refresh token, proxy username, or proxy password;
- a second import skips existing IDs unless `--replace` is given;
- the documented SQLite-plus-master-key restore returns the same redacted
  inventory and can serve a synthetic request.

## Reliability operator: depletion, ambiguous failure, and rollback

**Context:** A scripted upstream can return 401, 403, 429, 529, disconnect
before headers, or disconnect after response bytes. One account has a primary
and backup residential proxy.

**Intention:** Prove routing reacts without duplicating an accepted generation.

**Observe:**

- capacity responses classify and affect subsequent eligibility as documented;
- three primary-proxy connection failures move later requests to the backup,
  with no implicit direct connection;
- no request is replayed after request bytes or response bytes may have crossed
  the irreversible boundary;
- SIGTERM drains listeners within the deployment grace period;
- changing the canary client/ingress route back to Python restores service
  without credential or database mutation.

## Release owner: soak decision

**Context:** All automated gates, external review, restore drill, load run, and
rollback rehearsal have linked evidence.

**Intention:** Decide whether the legacy proxy can be retired.

**Observe:**

- 30 consecutive days contain no severity-1/2 security or data-plane
  regression;
- mirror refs, signed tag, checksums, SBOM, provenance, image digest, and
  release notes all identify the same source commit;
- any missing item leaves the GA checklist open and the Python service in
  place.
