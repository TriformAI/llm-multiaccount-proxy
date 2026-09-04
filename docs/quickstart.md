# Quick start

This guide starts a single-node instance on loopback. Put TLS and network access
control in front of it before exposing it beyond a trusted host.

## 1. Prepare configuration and secrets

```bash
cp examples/llmap.toml llmap.toml
mkdir -p state
export LLMAP_MASTER_KEY="$(openssl rand -base64 32)"
export LLMAP_ADMIN_PASSWORD="$(openssl rand -base64 24)"
llmap config check --config llmap.toml
```

Keep both values in a secret manager. Losing `LLMAP_MASTER_KEY` makes stored
provider credentials unrecoverable; changing it without a migration prevents
startup from using existing accounts.

## 2. Start and add an account

```bash
llmap serve --config llmap.toml
```

Open `http://127.0.0.1:8080/admin/login`, sign in with the configured username
and bootstrap password, and add one account. Credentials and proxy userinfo are
write-only. Pause an account to remove it immediately from both authentication
and routing.

## 3. Test a client

Start with `auth.mode = "observe"`. Configure an Anthropic-compatible client:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_API_KEY='the-current-token-of-any-active-account'
```

Send a small non-sensitive request. Confirm a `proxy.request` audit row exists,
the chosen account is expected, and the response streams normally. Unknown
tokens are counted but allowed in observe mode. After every intended client has
been seen using a configured token, switch to `enforce` and restart.

## 4. Optional HTTPS forward mode

Set `forward_proxy.enabled = true`, then create the local CA once:

```bash
llmap ca init --config llmap.toml
```

Install only the public CA certificate on intended client hosts. Never copy the
CA private key away from the proxy host. See [HTTPS forward proxy](forward-proxy.md).

## Container deployment

Copy `examples/docker-compose.yml` and adjust the config paths to
`/var/lib/llmap`. Set `LLMAP_IMAGE` to the immutable image digest from a signed
release. Bind public listeners deliberately; the example uses loopback.
