# Observability

`GET /metrics` exports counters:

- `llmap_requests_total`
- `llmap_authentication_failures_total`
- `llmap_upstream_failures_total`
- `llmap_responses_total`

Useful first alerts are a sustained authentication-failure increase after
observe-mode mismatch or enforcement, upstream failures above the provider baseline, request/response
counter divergence, and a process that is ready but has no eligible account.

SQLite audit rows retain timestamp, caller account attribution when matched,
routed account, provider, model name, a keyed session fingerprint, status,
outcome, and latency. Default retention is 30 days. Prompts, response bodies,
provider credentials, client authorization values, cookies, and residential
proxy userinfo are not fields and must not be added to ad-hoc logs.

Set `LLMAP_LOG_FORMAT=json` for structured process logs and use `RUST_LOG` for
level filtering. Current process logs cover lifecycle and maintenance events;
the SQLite audit is the request attribution source. When debugging, reproduce
with synthetic content and correlate by time/account/outcome—not by dumping a
request or response body.

Dashboards should separate client-auth failures, account entitlement failures,
rate limits, overload, transport failure, and absence of capacity. Combining
them into a generic 5xx graph hides the operational decision.
