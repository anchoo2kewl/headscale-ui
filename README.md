# Headscale UI

A small, read-only dashboard for Headscale with optional form login and session authentication. One Go binary, no JavaScript,
no frontend build, no external Go dependencies.

Shows enrolled devices, live online status, mesh IPv4 addresses, owners,
tags, last seen time and node key expiry. Refreshes every 30 seconds. An
optional link opens your existing monitoring dashboard. Online status means
a device is connected to Headscale; it does not certify host or disk health.

This is an independent community project, not an official Headscale component.
It currently supports the Headscale v0.29.7 node-list API. There are no device
approval, rename, deletion, enrollment or ACL editing controls.

## Run

Requires Go 1.24 or newer. Run on the same host as Headscale.

```sh
go build -trimpath -o headscale-ui .
export HEADSCALE_URL=http://127.0.0.1:8080
export HEADSCALE_KEY_FILE=/path/to/protected/headscale-api.key
./headscale-ui
```

Open `http://127.0.0.1:8091`. For access from another machine, use an SSH tunnel:

```sh
ssh -N -L 8091:127.0.0.1:8091 user@server.example.com
```

Create an API key with Headscale's `headscale apikeys create` command and save
its output directly to the protected file above. Keep that file readable only
by its owner; never paste the key into a URL or source file. Rotate it before
expiry and restart the dashboard.

| Variable | Default | Purpose |
| --- | --- | --- |
| `HEADSCALE_KEY_FILE` | Required | File containing the API key |
| `HEADSCALE_URL` | `http://127.0.0.1:8080` | Headscale HTTP API, loopback IP with explicit port |
| `LISTEN` | `127.0.0.1:8091` | Dashboard listen address |
| `HEADSCALE_UI_USERNAME` | Unset | Login username |
| `HEADSCALE_UI_PASSWORD_FILE` | Unset | File containing a strong 20–256 character login password |
| `PUBLIC_URL` | Listen address | Browser-facing URL, including a proxy prefix such as `/ui/` |
| `MONITORING_URL` | Unset | Optional HTTP(S) link to Beszel, Grafana or another monitor |

`LISTEN` accepts loopback or a Tailscale IPv4 address in `100.64.0.0/10`.
Mesh bindings require HTTP Basic authentication as well as restrictive network ACLs. Plain
HTTP is intended only for loopback/tunnels or the encrypted mesh connection.
Public bindings and external API endpoints are rejected.

## Security model

Loopback binding plus an SSH tunnel is the default. To enable the login page,
set `HEADSCALE_UI_USERNAME` and `HEADSCALE_UI_PASSWORD_FILE`. Generate a long
random password with a password manager and save it in an owner-only file.
`PUBLIC_URL` must match the browser-facing origin and optional path prefix,
for example `https://dashboard.example.com/ui/`.

Successful login creates an opaque server-side session with an HttpOnly,
SameSite=Strict cookie. HTTPS URLs also set Secure. Sessions expire after
12 hours and are cleared on application restart. Logout revokes the server
session. Login and logout POSTs require an exact Origin match. There is one
configured account, without multi-user roles or password recovery.

For public reverse proxy access, **enable login and use HTTPS**. Keep the
application bound to loopback and rate-limit requests at the proxy. Avoid
logging passwords or cookies. The password file is plaintext protected by
filesystem permissions or systemd credentials, distinct from the API key.

A proxy must strip a prefix such as `/ui/` before forwarding. Login redirects,
form actions and the session cookie path use the configured `PUBLIC_URL`
prefix. Mesh bindings require login and restrictive Headscale ACLs. Do not
expose an unauthenticated reverse proxy. Every route, including health checks,
is protected when authentication is enabled.

The dashboard performs only `GET /api/v1/node`, but Headscale API keys can
carry broad administrative authority. The server-side key remains sensitive:
read-only UI does not make the key itself read-only. The API key and raw node
authentication/enrollment fields are never rendered in the browser.

The API URL is restricted to loopback, redirects and HTTP environment proxies
are disabled, and upstream request time/size are bounded. HTML escapes node
metadata. Responses use `no-store`, a restrictive CSP and `nosniff`.
`/healthz` returns 204 only when the actual Headscale node-list API responds
successfully; upstream failures return 502 without exposing response bodies.

## systemd

An example unit is included. Install the binary at `/usr/local/bin/headscale-ui`
and save the API key as root-only `/etc/headscale-ui/api.key`. The example unit
enables form login as user `admin`; also create root-only
`/etc/headscale-ui/ui-password` with a strong random password. Install the unit
under `/etc/systemd/system/`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now headscale-ui
```

The service uses a dynamic unprivileged user and systemd `LoadCredential`.
If overriding `LISTEN` to a mesh IP, systemd restarts failed startup attempts
every ten seconds until the interface is available. Set `HEADSCALE_URL` to the local port your Headscale uses.

## Development

```sh
go test -race ./...
go vet ./...
```

Tests exercise login, session expiry/logout, CSRF origin checks, cookie flags,
live-node rendering, HTML escaping and credential omission,
upstream errors, request cancellation, read-only routes and address validation.

MIT licensed. See [LICENSE](LICENSE).
