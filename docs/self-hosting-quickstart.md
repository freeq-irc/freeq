# Self-Hosting Quickstart

The fastest ways to run your own freeq server. Pick one:

| Option | Best for | You need |
|---|---|---|
| **1. Miren** | A deploy you don't have to babysit | A Miren instance + the `miren` CLI |
| **2. Docker** | Everything on your own box, no external service | Docker |
| **3. Single binary** | Trying it out, a LAN, or a hand-rolled VPS | Rust toolchain |

All three give you the same thing: an IRC server, the web client, and
SQLite persistence. Guests can connect with any IRC client; Bluesky
sign-in works from the web client and TUI.

For the full configuration reference (TLS, nginx, systemd, federation,
backups), see the [Self-Hosting Guide](self-hosting.md).

---

## Option 1: Miren (recommended)

[Miren](https://miren.md/) is a container platform you run on your own
server. The repo ships a ready Miren config (`.miren/app.toml`) — three
commands build and deploy the server **and** web client, then route your
domain:

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq

miren deploy -e FREEQ_SERVER_NAME=irc.example.com
miren route set irc.example.com freeq
miren env set -s OPER_PASSWORD   # optional, masked prompt
```

Then point DNS at your cluster (CNAME to its `*.miren.systems` hostname, or
an A/ALIAS record — Miren provisions the TLS certificate automatically).
Done.

- Web client: `https://irc.example.com`
- WebSocket IRC at `/irc`, REST API at `/api/v1/*` (native TCP IRC is a
  documented opt-in)
- Persistent managed disk at `/data` — history and keys survive redeploys
- Pinned to one instance — IRC state is in-process, so no autoscaling

Prereqs: CLI installed and `miren login` done; TCP 80/443 and UDP 8443 open
on the host.

Full walkthrough (DNS options, secrets, backups, upgrades, federation,
native IRC): [deploy/miren/README.md](../deploy/miren/README.md).

## Option 2: Docker on your own box

No external service — just a machine with Docker.

**Build and run** (nothing but Docker needed):

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq
docker build -t freeq .
docker run -d --name freeq --restart unless-stopped \
  -p 6667:6667 -p 8080:8080 \
  -v freeq-data:/data \
  freeq
```

(Prebuilt `ghcr.io/freeq-irc/freeq` images arrive with the first tagged
release; until then, build from source as above. Once available, prefer an
explicit version tag over `latest`.)

**Or Docker Compose** (also builds from source, configured via `.env`):

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq
cp .env.example .env   # set SERVER_NAME, MOTD, OPER_PASSWORD
docker compose up -d
```

Optional Compose profiles:

```bash
docker compose --profile with-tls up -d     # + nginx TLS on 443 (needs certs)
docker compose --profile with-broker up -d  # + standalone OAuth broker (rarely needed — see below)
```

Either way:

- Web client: `http://your-box:8080`
- IRC: port `6667` with any client (irssi, WeeChat, HexChat, …)
- Data lives in the `freeq-data` volume at `/data`

> For a **public** server, put the web port behind a TLS reverse proxy and
> use the TLS listener (`:6697`) for IRC — see
> [TLS in the full guide](self-hosting.md#tls).

## Option 3: Single binary

For a LAN, a test, or a hand-managed VPS:

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq
cargo build --release -p freeq-server

# IRC on 6667, SQLite in ./data
./target/release/freeq-server --bind 0.0.0.0:6667 --db-path ./data/irc.db
```

Add the web client:

```bash
cd freeq-app && npm install && npm run build && cd ..
./target/release/freeq-server --bind 0.0.0.0:6667 --db-path ./data/irc.db \
  --web-addr 0.0.0.0:8080 --web-static-dir freeq-app/dist
```

For a public Ubuntu VPS, `./deploy/setup.sh yourdomain.com --nginx`
automates the rest (systemd service, nginx, certbot, firewall) — see
[deploy/README.md](../deploy/README.md).

---

## After it's running

**Connect.** Open the web client, or point any IRC client at port `6667`.
You're a guest by default — that's fine for a private server.

**Make yourself an operator.** Set `OPER_PASSWORD` and use
`/OPER <name> <password>` in any client, or set `OPER_DIDS` to your DID
(auto-oper on connect). Your DID is shown on the connect screen after
signing in.

**Backups.** Everything persistent is in the data directory. The one file
you *must not lose* is `db-encryption-key.secret` — without it, stored
message history is unrecoverable. Back it up alongside the `.db` files.

**Bluesky login works out of the box.** The OAuth broker is embedded in
`freeq-server` — no second service, no config. Embedded sessions are
in-memory, so users log in again after a server restart. The standalone
`freeq-auth-broker` is only needed for a split deployment (separate auth
domain, or sessions that survive restarts) — see
[deploy/miren/README.md § Auth broker](../deploy/miren/README.md#auth-broker-at-protocol-web-login).

**Federate with other servers** via `--iroh --s2s-peers <id>
--s2s-allowed-peers <id>` — see [federation.md](federation.md). Don't run
open federation in production; use the allowlist.

**Everything else** — TLS certs, nginx config, systemd units, connection
limits, logging, key rotation: [Self-Hosting Guide](self-hosting.md).
