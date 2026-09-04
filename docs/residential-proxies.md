# Per-account residential proxies

Each account may have an ordered egress list using `http://`, `https://`,
`socks5://`, or `socks5h://`. Userinfo may contain the residential provider
credential; it is encrypted at rest and removed from API/UI output.

```text
socks5h://username:password@se-stockholm.example:1080
https://username:password@backup.example:8443
```

The first endpoint is sticky. A network-level success keeps it active. Three
consecutive connection failures select the next endpoint for subsequent
requests. The failed request is not replayed because an upstream may have
accepted bytes before the client observed the failure. HTTP status responses
are account-capacity signals, not proxy connection failures.

When a chain is configured there is no implicit direct fallback. An empty chain
means direct egress. Changing the list rebuilds that account's health state.
Prefer `socks5h` when DNS resolution should occur at the residential proxy.

Operate proxies you are authorized to use. Stable per-account egress is useful
for provider consistency and location-sensitive enterprise policy; it is not a
mechanism for disguising abuse or evading provider controls.
