# HTTP API

## Data plane

- `ANY /v1` and `ANY /v1/*` proxy Anthropic-compatible traffic.
- `ANY /session/{id}/v1` and descendants provide explicit sticky sessions.
- `x-llmap-session` is the equivalent header; path and header values must agree.
- `GET /health` is liveness and reports build version/commit lineage; `GET
  /ready` is process readiness.
- `GET /metrics` returns metadata-only Prometheus text.

Failures use an Anthropic-shaped JSON error plus an actionable `_suggestion`.
`401` means configured client authentication failed, `503` means credential
state or capacity is unavailable, and `502` means no safe upstream response was
obtained. A `502` is not permission to replay a non-idempotent request.

## Administrator plane

- `GET /admin/login` and `GET /admin/` serve branded pages.
- `POST /admin/api/v1/login` accepts JSON `username` and `password` and sets an
  HttpOnly SameSite session cookie.
- `GET /admin/api/v1/session` returns the current CSRF token and non-secret mode
  status.
- `GET|POST /admin/api/v1/accounts` lists redacted accounts or creates one.
- `PUT /admin/api/v1/accounts/{id}/enabled` pauses or resumes immediately.
- `PUT /admin/api/v1/accounts/{id}/credential` replaces a write-only provider
  credential while preserving account and encrypted egress configuration.
- `DELETE /admin/api/v1/accounts/{id}` revokes and removes an account.
- `GET /admin/api/v1/audit` returns the latest 200 metadata events.
- `POST /admin/api/v1/logout` invalidates the session.

Every mutating endpoint except login requires `x-llmap-csrf`. Provider
credentials and proxy userinfo are write-only and never appear in responses.
The admin API is not a remote automation API in v1; expose it only through the
same trusted operator boundary as the UI.
