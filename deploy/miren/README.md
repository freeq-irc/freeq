# Self-hosting freeq on Miren

The recommended way to self-host freeq. [Miren](https://miren.md/) is a
container platform you run on your own server: the CLI builds the app from
the repo's Dockerfile, runs it with an injected `$PORT`, routes HTTPS
traffic for your domain, and provisions TLS automatically.

The repo carries a ready-to-use Miren config at
[`.miren/app.toml`](../../.miren/app.toml) — there is nothing to generate
and no staging script. One deploy gives you:

- the web client at the root of your domain (automatic Let's Encrypt TLS)
- WebSocket IRC at `/irc` and the REST API at `/api/v1/*`
- a **persistent managed disk** at `/data` (SQLite + server keys survive
  redeploys)
- **exactly one instance, always** — freeq holds IRC state in-process and
  must never autoscale
- AT Protocol (Bluesky) login via the embedded OAuth broker — no second
  service

## Prerequisites

- A Miren server (see [Getting Started](https://miren.md/getting-started)).
  Minimum **4 GB RAM / 50 GB storage**; **8 GB / 100 GB recommended** — the
  first deploy runs a full Rust release build on the host.
- Host firewall / security group open on **TCP 80 + 443** (HTTPS and the
  HTTP-01 ACME challenge) and **UDP 8443** (Miren API / QUIC — the CLI talks
  to your cluster here). Any [node ports](#native-irc-over-raw-tcp-opt-in)
  you enable need their own rules. See
  [Firewall Configuration](https://miren.md/firewall).
- The `miren` CLI installed and authenticated (`miren login`).
- `git`.

## Deploy

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq

# Which cluster? (the CLI also reads $MIREN_CLUSTER)
export MIREN_CLUSTER=my-cluster

# 1. Inspect what Miren will build and run — no changes are made.
miren deploy --analyze -C "$MIREN_CLUSTER"

# 2. Deploy. Pass the IRC server name as deploy-time config.
export DOMAIN=irc.example.com
miren deploy -C "$MIREN_CLUSTER" -e "FREEQ_SERVER_NAME=$DOMAIN"

# 3. Route your hostname to the app (DNS below).
miren route set "$DOMAIN" freeq -C "$MIREN_CLUSTER"

# 4. Optional: server operator password (masked prompt).
miren env set -a freeq -C "$MIREN_CLUSTER" -s OPER_PASSWORD
```

The first build takes a while (Rust release build + web client); later
deploys reuse Docker layer caching on the host.

## DNS & TLS

Point your hostname at the cluster (see
[DNS Configuration](https://miren.md/custom-domains)):

- **Subdomain**: a CNAME to your cluster's `*.miren.systems` hostname is
  the usual choice (find it with `miren cluster list`).
- **Apex domain**: most DNS providers don't allow a CNAME at the apex —
  use ALIAS/ANAME where supported, or an A record at the cluster's IP.

Once the route exists and DNS resolves, Miren provisions a Let's Encrypt
certificate automatically (HTTP-01, so port 80 must be reachable) and
renews it for you. Open `https://irc.example.com` — you should see the
freeq web client.

## Secrets

The server reads these from its environment:

| Var | Purpose |
|---|---|
| `OPER_PASSWORD` | Enables the `OPER` command |
| `OPER_DIDS` | DIDs auto-granted server operator (comma-separated) |
| `BROKER_SHARED_SECRET` | HMAC secret shared with a standalone auth broker — **leave unset** to use the embedded broker (setting it disables embedded mode) |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth for the credential verifier |

Set them with `miren env set` — `-s` marks a value sensitive (masked in CLI
output, never written into source config). This rolls out a new version
automatically; no manual restart or redeploy needed:

```bash
miren env set -a freeq -C "$MIREN_CLUSTER" -s OPER_PASSWORD   # masked prompt
miren env set -a freeq -C "$MIREN_CLUSTER" -e OPER_DIDS=did:plc:abc123
```

You can also pass them at deploy time (`miren deploy -e KEY=VALUE` /
`-s KEY=VALUE`), or bake non-secret defaults into the `[[env]]` blocks of
`.miren/app.toml`. **Never write secret values into `app.toml`.**

## Verify the deployment

```bash
miren app status -a freeq -C "$MIREN_CLUSTER"
miren sandbox list -C "$MIREN_CLUSTER"
miren logs -a freeq -C "$MIREN_CLUSTER" --since 10m

curl -fsS "https://$DOMAIN/" >/dev/null && echo web ok
```

**Persistence check (run this once, after your second deploy):** the point
of the managed disk is that state survives redeploys. Prove it before
trusting the server with real history:

```bash
miren deploy -C "$MIREN_CLUSTER"          # redeploy
miren sandbox list -C "$MIREN_CLUSTER"    # get the new sandbox ID
miren sandbox exec -i <sandbox-id>        # then, inside:
ls -l /data                               # irc.db + *.secret files must be the same ones
```

## Data & backups

Everything persistent lives on the managed Miren disk at `/data`:

| File | Purpose |
|---|---|
| `irc.db` (+ `-wal`/`-shm`) | Messages, channels, users (SQLite) |
| `*.secret` | Signing keys, DB encryption key, iroh identity |

> **Critical**: `db-encryption-key.secret` is required to read stored
> messages — if you lose it, history is irrecoverable. Back up the key
> files alongside the database.

Backup options:

```bash
# 1. Managed-disk snapshot (run where it can reach the cluster), then copy
#    the snapshot file off the host:
miren disk backup -C "$MIREN_CLUSTER"

# 2. Hot backup of the live database from inside the app:
miren sandbox exec -i <sandbox-id>        # then, inside:
sqlite3 /data/irc.db ".backup /data/irc-backup.db"
```

Copying `irc.db` alone while the server runs can produce a corrupt
snapshot — either use SQLite's `.backup` as above, or snapshot the whole
disk. Always include the `*.secret` files. See
[Miren Disks](https://miren.md/disks) for restore procedures.

## Upgrading

```bash
cd freeq
git pull
miren deploy -C "$MIREN_CLUSTER"
```

Each deploy builds a fresh image and rolls over to it — the disk is
untouched, env vars persist, and database schema migrations run
automatically on startup.

## Native IRC over raw TCP (opt-in)

The default deployment serves IRC over the WebSocket gateway at `/irc` on
your HTTPS domain — that covers the freeq web/desktop/mobile clients and
anything else that speaks WebSocket. Plain-TCP IRC stays on container
loopback.

To let any IRC client (irssi, WeeChat, HexChat…) connect directly, edit
[`.miren/app.toml`](../../.miren/app.toml):

1. Uncomment the `irc` ports block (`type = "tcp"`, `node_port = 6667`).
2. Change `--listen-addr` to `0.0.0.0:6667`.
3. Allow inbound TCP 6667 in your host firewall / security group, then
   redeploy.

Node ports bind the host directly and bypass Miren's HTTP router — so its
automatic TLS does **not** protect port 6667, and clients get a plaintext
connection. For TLS-native IRC (6697) freeq needs its own cert/key files
(`--tls-cert`/`--tls-key`); Miren's route certificates are for HTTP ingress
only. WebSocket-first is the recommended default for a reason.

## Auth broker (AT Protocol web login)

Password-less AT Protocol (Bluesky) login **works out of the box**: with
`BROKER_SHARED_SECRET` unset, the server runs the OAuth broker in-process —
`/auth/login`, `/auth/callback`, `/session`, and `/api/graph/*` are all
served by the same app. Nothing extra to deploy.

Embedded sessions are in-memory, so users log in again after a redeploy. If
you want sessions that survive restarts, or a separate auth domain, run the
standalone broker (`freeq-auth-broker`, already built into the same image)
as a second Miren app with its own disk and:

| Var | Value |
|---|---|
| `BROKER_SHARED_SECRET` | same value as on the server (required) |
| `BROKER_PUBLIC_URL` | `https://auth.example.com` |
| `FREEQ_SERVER_URL` | `https://irc.example.com` |
| `BROKER_DB_PATH` | `/data/broker.db` |

## Federation

S2S federation flags are ordinary `freeq-server` arguments — add them to
the `command` in [`.miren/app.toml`](../../.miren/app.toml):

```
--iroh --s2s-peers <peer-endpoint-id> --s2s-allowed-peers <peer-endpoint-id>
```

The server prints its own iroh endpoint ID on startup (`miren logs`) — give
that to your peers. iroh is QUIC over UDP with NAT traversal via relays, so
it generally works without extra ports; for direct UDP, pin `--iroh-port`
and add a matching `type = "udp"` node port + firewall rule. See
[docs/federation.md](../../docs/federation.md) and
[docs/SECURITY.md](../../docs/SECURITY.md) — always use
`--s2s-allowed-peers` in production.

## Troubleshooting

- **Web client 404s** — the image builds the web client into `/app/web`;
  check the build logs (`miren logs -b`) for the web-builder stage.
- **Can't write to /data** — shouldn't happen (managed disks are chowned to
  the container's run user by default); check the disk's `owner` field and
  `miren logs`.
- **AT login fails on the web client** — embedded mode needs no broker; if
  you run the standalone broker (above), `BROKER_SHARED_SECRET` must be set
  identically on both apps.
- **Can't connect on 6667** — node ports are exposed on the host directly;
  check the firewall/security group, and that no other app on the cluster
  claimed the port (Miren rejects conflicts at deploy time).
- **CLI can't reach the cluster** — UDP 8443 must be open (a TCP-only allow
  rule is the classic failure); `miren doctor` probes this.
- **General Miren issues** — https://miren.md/troubleshooting and
  `miren doctor`.
