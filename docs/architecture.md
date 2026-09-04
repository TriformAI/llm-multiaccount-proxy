# Architecture

```text
Anthropic client ── reverse HTTP ──┐
                                   ├─ client auth ─ routing ─ provider adapter
Proxy-aware client ─ CONNECT/TLS ──┘                    │
                                                       ▼
                                      per-account egress chain ─ provider
                                                       │
                         encrypted SQLite ◄─ metadata audit / account state
                                                       │
                                     branded admin UI + Prometheus metrics
```

## Modules

- `auth` performs mode-aware, constant-time membership checks over active
  account credentials.
- `routing` owns sticky least-utilized selection, model eligibility, depletion,
  and safe retry-boundary decisions.
- `providers` owns upstream URL, model, and authentication translation.
- `egress` validates destinations and models sticky ordered proxy chains.
- `data_plane` composes those contracts and streams upstream responses without
  buffering them.
- `forward_proxy` terminates allowlisted CONNECT traffic with a local CA and
  adapts it into the data plane.
- `storage` is the single-node SQLite implementation behind repository
  interfaces; credentials use XChaCha20-Poly1305 with per-account associated
  data.
- `admin` and `http_app` implement sessions, branded pages, CSRF-protected
  account operations, health, metrics, and actionable JSON errors.
- `config` validates the file and environment override contract before startup.

## State and concurrency

SQLite runs in WAL mode with a busy timeout. Account writes refresh the in-memory
routing pool immediately. Sticky sessions and egress health are deliberately
ephemeral; restart reconstructs safe account state and may choose a new healthy
account. That is the documented single-node GA boundary.

The repository interfaces keep a future transactional HA store possible without
teaching routing or HTTP handlers about a particular database.

## Streaming and retry safety

Client request bodies are bounded and buffered so models can be mapped safely.
Provider responses remain streams. The proxy never automatically replays after
request bytes may have reached an upstream or response bytes have been seen.
Rate limits and authentication failures evict sticky bindings for future
requests instead.
