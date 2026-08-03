# Self-Hosting Guide

Run your own freeq server with TLS, the web client, and optional federation.

> Just want it running? The [Self-Hosting Quickstart](self-hosting-quickstart.md)
> covers the three simplest paths (Miren, Docker, single binary) with
> copy-paste commands. This guide is the full reference.

## Recommended: Miren

The default self-hosting path. [Miren](https://miren.md/) is a container
platform you run on your own server. The repo ships a ready Miren config at
[`.miren/app.toml`](../.miren/app.toml) — three commands build and deploy
the IRC server **and** the web client, with HTTPS routing, automatic Let's
Encrypt certs, a persistent managed disk for the database and keys, and a
hard pin to one instance (IRC state is in-process — no autoscaling):

```bash
# Prerequisites: a Miren server + the miren CLI installed and logged in
# (host firewall: TCP 80/443 + UDP 8443 open)
git clone https://github.com/freeq-irc/freeq
cd freeq

miren deploy -e FREEQ_SERVER_NAME=irc.example.com
miren route set irc.example.com freeq
miren env set -s OPER_PASSWORD   # optional, masked prompt
```

Then point DNS at your cluster — a CNAME to its `*.miren.systems` hostname
for subdomains, or ALIAS/ANAME/A at the apex. The web client is served at
the root, WebSocket IRC at `/irc`, REST API at `/api/v1/*`; native TCP IRC
(6667) is a documented opt-in.

The full 10-minute walkthrough — DNS options, secrets, where the SQLite
data lives and how to back it up, upgrades, the auth broker, and federation
flags — is in [deploy/miren/README.md](../deploy/miren/README.md).

## Fallback: Docker Compose

If you don't run Miren, Docker Compose gives you the same stack (server +
web client, with optional nginx TLS termination and OAuth broker):

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq
cp .env.example .env    # edit with your values
docker compose up -d
```

For TLS termination with nginx:
```bash
docker compose --profile with-tls up -d
```

The OAuth broker (AT Protocol web login) is embedded in the server by
default — no extra service needed. To run it as a separate service instead
(separate auth domain, sessions that survive restarts):
```bash
docker compose --profile with-broker up -d
```

Plain Docker, without compose (builds from source — prebuilt
`ghcr.io/freeq-irc/freeq` images arrive with the first tagged release):

```bash
docker build -t freeq .
docker run -d \
  -p 6667:6667 -p 8080:8080 \
  -v freeq-data:/data \
  freeq
```

## From source

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq
cargo build --release -p freeq-server

# Start with defaults (port 6667, no TLS, in-memory)
./target/release/freeq-server --bind 0.0.0.0:6667
```

For a bare-VPS install with systemd + nginx + certbot, see
[deploy/README.md](../deploy/README.md) (`./deploy/setup.sh yourdomain.com --nginx`).

## Configuration Reference

### Listeners

| Flag | Default | Description |
|---|---|---|
| `--bind` | `127.0.0.1:6667` | Plain TCP listener |
| `--tls-bind` | `127.0.0.1:6697` | TLS listener (requires cert + key) |
| `--web-addr` | *(none)* | HTTP/WebSocket listener |

### TLS

```bash
freeq-server \
  --bind 0.0.0.0:6667 \
  --tls-bind 0.0.0.0:6697 \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

Use Let's Encrypt with auto-renewal for production. See the nginx config
below for TLS termination at the reverse proxy instead.

### Web Client

```bash
cd freeq-app && npm install && npm run build && cd ..

freeq-server \
  --bind 0.0.0.0:6667 \
  --web-addr 0.0.0.0:8080 \
  --web-static-dir freeq-app/dist
```

The web client is served at the root path. WebSocket IRC is at `/irc`.
REST API endpoints are at `/api/v1/*`.

### Persistence

```bash
freeq-server --db-path /data/irc.db --data-dir /data
```

| Flag | Default | Description |
|---|---|---|
| `--db-path` | *(none — in-memory)* | SQLite database file |
| `--migrate-to` | *(none)* | Run the schema ladder to this version and exit (see [Schema migrations](#schema-migrations)) |
| `--data-dir` | parent of `--db-path` | Directory for keys and iroh state |
| `--max-messages-per-channel` | `10000` | Prune oldest messages beyond this count |

### Identity & Auth

| Flag / Env | Description |
|---|---|
| `--server-name` | IRC server name (appears in messages) |
| `--challenge-timeout-secs` | SASL challenge validity window (default: 60) |
| `--oper-password` / `OPER_PASSWORD` | Enable OPER command with this password |
| `--oper-dids` / `OPER_DIDS` | DIDs auto-granted server operator on connect |
| `BROKER_SHARED_SECRET` | HMAC secret shared with auth broker |
| `GITHUB_CLIENT_ID` | GitHub OAuth for credential verifier |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth secret |

### Federation

```bash
freeq-server \
  --iroh \
  --s2s-peers <peer-id> \
  --s2s-allowed-peers <peer-id>
```

| Flag | Default | Description |
|---|---|---|
| `--iroh` | off | Enable iroh QUIC transport |
| `--iroh-port` | random | UDP port for iroh |
| `--s2s-peers` | *(none)* | Peer endpoint IDs to connect to on startup |
| `--s2s-allowed-peers` | *(none — open)* | Allowlist for incoming peer connections |
| `--s2s-peer-trust` | *(none)* | Trust levels per peer: `id:full`, `id:relay`, `id:readonly` |
| `--server-did` | *(none)* | Server DID for federation identity (e.g. `did:web:irc.example.com`) |

See [Federation](federation.md), [S2S Auth](S2S-AUTH-PLAN.md), [Server DID Setup](server-did.md), and [Security Guide](SECURITY.md) for details.

### MOTD

```bash
freeq-server --motd "Welcome to my server"
# or
freeq-server --motd-file /path/to/motd.txt
```

## nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name irc.example.com;

    ssl_certificate /etc/letsencrypt/live/irc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/irc.example.com/privkey.pem;

    location /irc {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## systemd Service

```ini
[Unit]
Description=freeq IRC server
After=network.target

[Service]
Type=simple
User=freeq
WorkingDirectory=/opt/freeq
ExecStart=/opt/freeq/freeq-server \
  --bind 0.0.0.0:6667 \
  --tls-bind 0.0.0.0:6697 \
  --tls-cert /etc/letsencrypt/live/irc.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/irc.example.com/privkey.pem \
  --web-addr 127.0.0.1:8080 \
  --web-static-dir /opt/freeq/freeq-app/dist \
  --db-path /opt/freeq/data/irc.db \
  --data-dir /opt/freeq/data \
  --server-name irc.example.com
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Data Files

| File | Purpose |
|---|---|
| `irc.db` | Message history, channels, user data (SQLite) |
| `irc-policy.db` | Policy rules and credentials (SQLite) |
| `msg-signing-key.secret` | Server message signing key (ed25519) |
| `verifier-signing-key.secret` | Credential verifier signing key |
| `db-encryption-key.secret` | Database encryption-at-rest key |
| `iroh-key.secret` | iroh QUIC endpoint identity key |

All key files are generated automatically on first run.

> **⚠️ WARNING**: Never commit `*.secret` or `*.pem`/`*.key` files to version
> control. They are excluded by `.gitignore` but always verify before pushing.
> See [Security Hardening Guide](SECURITY.md) for key rotation procedures.

## Encryption at Rest

Message text is encrypted with AES-256-GCM before writing to SQLite. The key
is stored in `db-encryption-key.secret`. Messages are transparently decrypted
on read. Back up this key — losing it makes all stored messages unreadable.

## Backups

### Database

```bash
# Hot backup (SQLite VACUUM INTO)
sqlite3 /data/irc.db "VACUUM INTO '/backup/irc-$(date +%Y%m%d).db'"
sqlite3 /data/irc-policy.db "VACUUM INTO '/backup/irc-policy-$(date +%Y%m%d).db'"
```

Or simply copy the `.db` file while the server is stopped.

### Keys

```bash
# Back up all key files
cp /data/*.secret /backup/keys/
chmod 600 /backup/keys/*
```

> **Critical**: The `db-encryption-key.secret` file is required to read
> encrypted messages. If lost, message history is irrecoverable.

### Restore

1. Stop the server
2. Copy backup `.db` files to `--db-path` location
3. Copy backup `.secret` files to `--data-dir` location
4. Start the server

### Schema migrations

The database schema is versioned, and startup migrates it forward automatically — upgrading the server never needs a manual step. A binary refuses to open a database stamped with a *newer* schema than it knows, so **rolling back to an older binary requires downgrading the schema first**:

```bash
# Stop the server, then run the ladder down to the version the old binary expects:
freeq-server --db-path /data/irc.db --migrate-to 2
# Then start the older binary as usual.
```

The command prints the version it moved from and to, then exits without starting the server. Downgrades stop with an error at any migration that is irreversible by design (the database is left at the last version reached) — in that case, restore from backup instead. Take a backup before any downgrade regardless.

## Connection Limits

- **Per-IP**: 20 concurrent connections (TCP and WebSocket)
- **Rate limiting**: 10 commands/sec per client (token bucket, exempt during registration)
- **S2S**: 100 events/sec per peer

These are hardcoded. For additional rate limiting, configure your reverse proxy.

## Logging

```bash
# Default: human-readable
RUST_LOG=info freeq-server ...

# Structured JSON (for log aggregation)
RUST_LOG=info FREEQ_LOG_JSON=1 freeq-server ...

# Debug logging for specific modules
RUST_LOG=freeq_server::s2s=debug,info freeq-server ...
```

## Security

See [Security Hardening Guide](SECURITY.md) for:

- S2S federation allowlists
- Key management and rotation
- Production configuration checklist
