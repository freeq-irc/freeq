# Self-Hosting freeq End-to-End

A definitive, copy-pasteable guide to standing up a **private, production** freeq
instance for your company on a single host, from a fresh clone.

Audience: a competent engineer/sysadmin who has never deployed freeq. Goal: the
**simplest reliable** structure that works.

> This guide targets a **single-host, single-domain, non-federated** deployment
> — the right topology for a private company chat server. Federation (server-to-server
> / `did:web`) and the standalone OAuth broker are **not needed** for this and are
> intentionally left off. See [§8 Optional extras](#8-optional-extras-you-probably-dont-need) if you
> think you need them.

---

## 1. Overview

### Components

For a private single-host install you run exactly **three** things:

| Component | What it is | Where it comes from |
|---|---|---|
| **freeq-server** | One Rust binary. Handles IRC (plain TCP + TLS), the WebSocket/HTTP listener, the REST API, **and the AT Protocol (Bluesky) OAuth login flow** — all in-process. | `cargo build --release -p freeq-server` |
| **Web client** | Static React/Vite build (HTML/JS/CSS). Served by the freeq-server's web listener. | `cd freeq-app && npm run build` → `freeq-app/dist` |
| **nginx** | Reverse proxy that terminates TLS on 443 and forwards to the server's web listener. | Your distro's `nginx` package + certbot |

**You do NOT need the separate `freeq-auth-broker` service.** The server has a
built-in OAuth flow. The standalone broker only exists for the setup where login
lives on a *different* subdomain (e.g. production `irc.freeq.at` uses `auth.freeq.at`).
For a single domain, the web client detects that the login origin equals the web
origin and lets the server handle OAuth directly. (See `freeq-app/src/components/ConnectScreen.tsx`:
*"If brokerOrigin is the same as webOrigin, there's no external broker — the server
handles auth directly via /auth/login."*)

### Architecture (single host)

```
                          Internet
                             │
             ┌───────────────┼────────────────────────┐
             │               │                        │
        443 (HTTPS)     6697 (IRC+TLS)           6667 (IRC plain)
             │          native IRC clients       (optional; LAN/VPN only)
             ▼               │                        │
   ┌──────────────────┐      │                        │
   │      nginx       │      │                        │
   │  TLS termination │      │                        │
   └────────┬─────────┘      │                        │
            │ proxy_pass     │ TLS handled            │
            │ 127.0.0.1:8080 │ by the server itself   │
            ▼                ▼                        ▼
   ┌────────────────────────────────────────────────────────┐
   │                     freeq-server                         │
   │  • web listener (127.0.0.1:8080): web client, /irc WS,   │
   │    /api/v1/*, /auth/login (built-in OAuth)               │
   │  • TLS IRC listener (0.0.0.0:6697)                       │
   │  • plain IRC listener (0.0.0.0:6667)   [optional]        │
   └───────────────────────────┬─────────────────────────────┘
                               │ reads/writes
                               ▼
        /var/lib/freeq/  (data-dir)
          irc.db  irc-policy.db  media/
          db-encryption-key.secret   msg-signing-key.secret
          verifier-signing-key.secret   iroh-key.secret
```

nginx terminates TLS for the browser (443). Native IRC clients (irssi, WeeChat,
HexChat) connect straight to the server's own TLS listener on **6697** — nginx
does not proxy raw IRC, so the server needs the cert directly for that port.

---

## 2. Prerequisites

- **OS**: Ubuntu 22.04+ / Debian 12+ (any modern Linux with systemd). Commands below assume Debian/Ubuntu.
- **A domain** you control, e.g. `chat.example.com`, with an **A/AAAA record** pointing at the host's public IP. Browser OAuth **requires** HTTPS on a real domain — `did:web`/PDS redirect URIs will not work over plain HTTP or a bare IP.
- **Packages**: `build-essential pkg-config libssl-dev curl git nginx certbot python3-certbot-nginx sqlite3`
- **Rust toolchain**: stable, 1.89+ (install via [rustup](https://rustup.rs)).
- **Node.js**: 20+ (for building the web client).
- **Open ports**: 80 + 443 (web/TLS), 6697 (IRC over TLS). 6667 (plain IRC) only if you want it — keep it firewalled to your LAN/VPN.

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev curl git \
    nginx certbot python3-certbot-nginx sqlite3
# Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
# Node 20 (if not present)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

---

## 3. Step-by-step deploy

Throughout, replace `chat.example.com` with **your** domain.

### 3.1 Create a service user and directories

```bash
sudo adduser --system --group --no-create-home freeq
sudo mkdir -p /opt/freeq /var/lib/freeq
sudo chown freeq:freeq /var/lib/freeq
```

### 3.2 Clone and build the server

```bash
cd /opt
sudo chown "$USER" /opt/freeq
git clone https://github.com/freeq-irc/freeq /opt/freeq
cd /opt/freeq
cargo build --release -p freeq-server
# Binary lands at /opt/freeq/target/release/freeq-server
```

### 3.3 Build the web client

```bash
cd /opt/freeq/freeq-app
npm ci          # a prebuild hook also builds the bundled @freeq/sdk
npm run build   # outputs to /opt/freeq/freeq-app/dist
cd /opt/freeq
```

The web client is origin-relative: it talks to `/irc`, `/api/v1/*`, and `/auth/*`
on whatever host it is served from, so there is **nothing to configure** in the
build for a single-domain install.

### 3.4 Generate secrets (or let the server do it)

All key files are **auto-generated on first run** inside `--data-dir`. You don't
have to pre-create them. The only secret you must supply yourself is optional
operator/broker config:

```bash
# Server operator password for the IRC OPER command (optional but recommended)
openssl rand -hex 24        # copy this into OPER_PASSWORD below
```

The auto-generated files (in `/var/lib/freeq/`) are:

| File | Purpose |
|---|---|
| `db-encryption-key.secret` | AES-256-GCM key encrypting message text at rest. **Losing it makes all history unreadable.** |
| `msg-signing-key.secret` | Server's ed25519 message-signing key (fallback signing). |
| `verifier-signing-key.secret` | Credential-verifier signing key. |
| `iroh-key.secret` | Federation transport identity — only created if you enable `--iroh`. |

> Back these up the moment they exist (see [§6](#6-backups--operations)). They are `.gitignore`d — never commit them.

### 3.5 Obtain a TLS certificate

Point DNS at the host first, then:

```bash
# Temporary minimal nginx vhost so certbot can complete the HTTP-01 challenge:
sudo tee /etc/nginx/sites-available/freeq.conf >/dev/null <<'EOF'
server {
    listen 80;
    server_name chat.example.com;
    root /var/www/html;
}
EOF
sudo ln -sf /etc/nginx/sites-available/freeq.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

sudo certbot certonly --nginx -d chat.example.com --agree-tos -m you@example.com --non-interactive
```

This writes `/etc/letsencrypt/live/chat.example.com/{fullchain,privkey}.pem`.
Certbot installs an auto-renew timer.

**Let the `freeq` user read the cert** (needed for the 6697 IRC TLS listener):

```bash
sudo groupadd -f ssl-cert
sudo usermod -aG ssl-cert freeq
sudo chgrp ssl-cert /etc/letsencrypt/live /etc/letsencrypt/archive
sudo chmod g+x     /etc/letsencrypt/live /etc/letsencrypt/archive
sudo chgrp -R ssl-cert /etc/letsencrypt/archive/chat.example.com
sudo chmod -R g+rX      /etc/letsencrypt/archive/chat.example.com
```

### 3.6 Configure the nginx reverse proxy

Replace the temporary vhost with the real one (adapted from the repo's
`deploy/nginx.conf.template`):

```nginx
# /etc/nginx/sites-available/freeq.conf
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # WebSocket IRC transport
    location /irc {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # Uploads (authenticated users push media to their PDS via the server)
    location /api/v1/upload {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 12M;
    }

    # Hashed, immutable JS/CSS assets
    location /assets/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Web client, REST API, and the built-in OAuth endpoints (/auth/login, /auth/callback, /client-metadata.json)
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        client_max_body_size 12M;
        add_header Cache-Control "no-cache";
    }
}

server {
    listen 80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}
```

> **Important:** keep `proxy_set_header Host $host;` exactly as written. The server
> builds OAuth `redirect_uri`s from the incoming Host header, so it must see the
> real public hostname or Bluesky login will fail.

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 3.7 Create the systemd unit for the server

```ini
# /etc/systemd/system/freeq-server.service
[Unit]
Description=freeq IRC server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=freeq
Group=freeq
WorkingDirectory=/opt/freeq
ExecStart=/opt/freeq/target/release/freeq-server \
    --listen-addr 127.0.0.1:6667 \
    --tls-listen-addr 0.0.0.0:6697 \
    --tls-cert /etc/letsencrypt/live/chat.example.com/fullchain.pem \
    --tls-key  /etc/letsencrypt/live/chat.example.com/privkey.pem \
    --web-addr 127.0.0.1:8080 \
    --web-static-dir /opt/freeq/freeq-app/dist \
    --db-path /var/lib/freeq/irc.db \
    --data-dir /var/lib/freeq \
    --server-name chat.example.com \
    --motd "Welcome to Example Corp chat"
EnvironmentFile=-/etc/freeq/secrets
Restart=on-failure
RestartSec=5

# Hardening
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/freeq
ReadOnlyPaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
```

Notes on the flags above:
- `--listen-addr 127.0.0.1:6667` binds **plain** IRC to loopback only, so it is
  not exposed to the internet. Change to `0.0.0.0:6667` only if you want plain IRC
  on the LAN/VPN (and firewall it).
- `--tls-listen-addr 0.0.0.0:6697` is the public port for native IRC clients over TLS.
- `--web-addr 127.0.0.1:8080` is loopback because nginx fronts it.

Put secrets in `/etc/freeq/secrets` (loaded via `EnvironmentFile`):

```bash
sudo mkdir -p /etc/freeq
sudo tee /etc/freeq/secrets >/dev/null <<'EOF'
OPER_PASSWORD=<paste the openssl rand output>
# Optionally auto-op specific Bluesky DIDs on connect:
# OPER_DIDS=did:plc:youradmin,did:plc:anotheradmin
RUST_LOG=info
EOF
sudo chown root:freeq /etc/freeq/secrets
sudo chmod 640 /etc/freeq/secrets
```

### 3.8 Start everything

```bash
sudo chown -R freeq:freeq /opt/freeq/target /var/lib/freeq
sudo systemctl daemon-reload
sudo systemctl enable --now freeq-server
sudo systemctl status freeq-server --no-pager
sudo journalctl -u freeq-server -f     # watch it come up
```

### 3.9 Firewall

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 6697/tcp        # IRC over TLS for native clients
# Do NOT open 6667 (plain) or 8080 to the internet.
sudo ufw enable
```

Done. Open `https://chat.example.com` in a browser.

---

## 4. Configuration reference

Every flag below is a real `freeq-server` flag (from `freeq-server/src/config.rs`).
Flags marked *(env)* can also be set via the named environment variable.

### Listeners & web

| Flag | Default | Recommended (private) | Description |
|---|---|---|---|
| `--listen-addr` (alias `--bind`) | `127.0.0.1:6667` | `127.0.0.1:6667` | Plain-text IRC listener. Keep on loopback/LAN. |
| `--tls-listen-addr` | `127.0.0.1:6697` | `0.0.0.0:6697` | IRC-over-TLS listener. Active only if `--tls-cert` **and** `--tls-key` are set. |
| `--tls-cert` / `--tls-key` | none | your Let's Encrypt PEMs | Enables the TLS IRC listener. |
| `--web-addr` | none (no web) | `127.0.0.1:8080` | HTTP/WebSocket/REST listener. Required for the web client. Loopback behind nginx. |
| `--web-static-dir` | none | `/opt/freeq/freeq-app/dist` | Directory of the built web client. Served at `/`. |

### Identity, storage & limits

| Flag / Env | Default | Recommended | Description |
|---|---|---|---|
| `--server-name` | `freeq` | your domain | Name shown in IRC numerics/messages. |
| `--db-path` | none (**in-memory**) | `/var/lib/freeq/irc.db` | SQLite DB. **If unset, nothing persists across restarts.** |
| `--data-dir` | parent of `--db-path` | `/var/lib/freeq` | Where the `*.secret` keys and iroh state live. |
| `--max-messages-per-channel` | `10000` | `10000` (0 = unlimited) | Oldest messages pruned beyond this. |
| `--challenge-timeout-secs` | `60` | `60` | SASL challenge validity window. |
| `--motd` / `--motd-file` | none | a short welcome | Message of the day. `--motd-file` overrides `--motd`. |
| `--oper-password` *(env `OPER_PASSWORD`)* | none | set a strong one | Enables the IRC `OPER <name> <password>` command → global operator. |
| `--oper-dids` *(env `OPER_DIDS`)* | none | your admins' DIDs | Comma-separated DIDs auto-granted operator on connect. |

### Encryption / secrets (env)

| Env | Description |
|---|---|
| `RUST_LOG` | Log level, e.g. `info`, or `freeq_server::s2s=debug,info`. |
| `FREEQ_LOG_JSON=1` | Emit structured JSON logs (for aggregation). |
| `BROKER_SHARED_SECRET` | **Leave unset for single-host.** Only needed if you run a *separate* auth-broker subdomain; enables the server's `/auth/broker/*` push endpoints. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | Optional — only for the GitHub credential verifier feature. |

### Federation (leave OFF for a private instance)

| Flag | Default | Private recommendation |
|---|---|---|
| `--iroh` | off | **off** — do not enable. No S2S, no `iroh-key.secret`, nothing to peer. |
| `--iroh-port` | random | n/a |
| `--s2s-peers` | none | leave empty |
| `--s2s-allowed-peers` | none (**= open federation if `--iroh` is on**) | leave empty |
| `--s2s-peer-trust` | none | leave empty |
| `--require-did-for-ops` | off | n/a unless federating |

> **Hardening note:** `--s2s-allowed-peers` empty means *any* peer may connect —
> but only if `--iroh` is enabled. Since a private instance leaves `--iroh` off
> entirely, there is no federation surface at all. That is the safe default.

### Connection limits (hardcoded — no flags)

- **20** concurrent connections per IP (TCP and WebSocket).
- **10** commands/sec per client (token bucket; exempt during registration).
- **3** SASL failures before disconnect.
- **100** S2S events/sec per peer (only relevant with federation).

For anything beyond these, rate-limit at nginx.

---

## 5. Verifying the install

**TLS / web:**
```bash
curl -I https://chat.example.com/           # 200, serves the web client
curl -s https://chat.example.com/api/v1/health   # health JSON
```

**Browser + OAuth SASL:**
1. Open `https://chat.example.com`.
2. Enter a Bluesky handle (e.g. `you.bsky.social`) and click **Sign in with Bluesky**.
   You'll be redirected to your PDS's OAuth page, then back. On success you land in `#freeq`.
3. This proves the built-in OAuth flow works end-to-end (challenge → PDS sign → SASL `903`).

**Native IRC client over TLS (guest + SASL):**
```bash
# Guest connect (no auth) — proves standard IRC still works:
#   Server: chat.example.com   Port: 6697 (TLS)
# In WeeChat, for example:
/server add mycorp chat.example.com/6697 -ssl
/connect mycorp
/join #general
```
Send a message and confirm it appears in the web client too.

**Confirm auth binding:** after signing in, `/whois <yournick>` should show your
cloaked host as `freeq/plc/xxxxxxxx` (authenticated) rather than `freeq/guest`.

**Check logs:** `sudo journalctl -u freeq-server -n 100 --no-pager` — you should
see `Starting IRC server`, `TLS enabled`, and `HTTP/WebSocket enabled`.

---

## 6. Backups & operations

### What to back up

| Item | Path | Why |
|---|---|---|
| Message/channel DB | `/var/lib/freeq/irc.db` | All history, channels, users. |
| Policy DB | `/var/lib/freeq/irc-policy.db` | Policy rules, credentials. |
| **Encryption key** | `/var/lib/freeq/db-encryption-key.secret` | **Without it, `irc.db` history is permanently unreadable.** |
| Signing keys | `/var/lib/freeq/*.secret` | Server identity/signing continuity. |
| Config | `/etc/freeq/secrets`, the systemd unit, nginx vhost | Reproducibility. |

### Backup commands

```bash
# Hot DB backup (safe while running):
sudo -u freeq sqlite3 /var/lib/freeq/irc.db \
    "VACUUM INTO '/var/backups/freeq/irc-$(date +%F).db'"
sudo -u freeq sqlite3 /var/lib/freeq/irc-policy.db \
    "VACUUM INTO '/var/backups/freeq/irc-policy-$(date +%F).db'"

# Keys (do this once; they don't change unless you rotate):
sudo cp /var/lib/freeq/*.secret /var/backups/freeq/keys/
sudo chmod 600 /var/backups/freeq/keys/*
```

Store the `*.secret` backups **off-host** and encrypted. Treat `db-encryption-key.secret`
like a database master password.

### Restart

```bash
sudo systemctl restart freeq-server
```

### Upgrade (matches how production `irc.freeq.at` is deployed)

```bash
cd /opt/freeq
sudo -u freeq git pull --ff-only
cargo build --release -p freeq-server
cd freeq-app && npm ci && npm run build && cd ..
sudo systemctl restart freeq-server
```

(This is exactly the `git pull → cargo build → npm build → systemctl restart`
flow the maintainer uses; see `deploy/deploy.sh`.) Certbot renews TLS automatically;
after a renewal the server picks up the new cert on its next restart.

### Restore

1. `sudo systemctl stop freeq-server`
2. Copy backed-up `*.db` files into `/var/lib/freeq/`
3. Copy backed-up `*.secret` files into `/var/lib/freeq/` (must match the DB they encrypted)
4. `sudo chown freeq:freeq /var/lib/freeq/*`
5. `sudo systemctl start freeq-server`

---

## 7. Hardening checklist for a private/company deployment

- [ ] **Firewall.** Expose only 80, 443, 6697. Keep 6667 (plain IRC) and 8080 (web listener) on loopback/LAN — the systemd unit above already binds them to `127.0.0.1`.
- [ ] **No federation.** Do not pass `--iroh`. With it off there is no S2S peer surface and no `--s2s-allowed-peers` "open by default" risk.
- [ ] **Secrets locked down.** `/etc/freeq/secrets` is `640 root:freeq`; `/var/lib/freeq/*.secret` are `600 freeq:freeq`. Never commit them (`.gitignore` covers `*.secret`/`*.pem`, but verify).
- [ ] **Strong `OPER_PASSWORD`** and a curated `OPER_DIDS` list of just your admins.
- [ ] **TLS everywhere.** Force HTTPS (the `:80 → 301 https` block does this). Native clients use 6697 only.
- [ ] **systemd sandboxing.** Keep `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/freeq`, `ReadOnlyPaths=/etc/letsencrypt`.
- [ ] **Encryption-at-rest key is backed up off-host.** Message text is AES-256-GCM encrypted in SQLite; losing the key loses the history.
- [ ] **Lock down membership** (see caveat below): make company channels **invite-only** (`+i`) and/or **keyed** (`+k`), and appoint ops. There is no server-wide "members only" flag today.
- [ ] **Log aggregation.** Set `FREEQ_LOG_JSON=1` and ship `journald` to your SIEM.
- [ ] **Off-host, encrypted DB + key backups on a schedule** (cron the §6 commands).

### Caveats / gaps to know before you commit

These are real limitations discovered in the code — plan around them:

1. **Anyone can connect (including as a guest).** There is **no flag to disable
   guest login or restrict registration to your company's DIDs** at the server
   level. A private instance is made private by **network isolation** (firewall /
   VPN / IP allowlist at nginx) and/or **invite-only channels** (`+i`) — not by an
   account allowlist. If you need "only employees may even connect," put the whole
   thing behind a VPN or an nginx `allow/deny` / mTLS layer.
2. **The server-side OAuth flow authenticates against the user's real Bluesky PDS.**
   Users log in with their own AT Protocol identities; freeq does not run its own
   identity provider. For a closed company deployment where staff lack (or shouldn't
   use) public Bluesky accounts, plan on either issuing bot/app-password DIDs or
   running your own PDS — both are outside freeq's scope.
3. **TLS cert access for the 6697 listener.** nginx only proxies HTTP/WebSocket, so
   raw IRC-over-TLS is served by freeq itself and the `freeq` user must be able to
   read the cert (the `ssl-cert` group steps in §3.5). Forgetting this makes 6697
   silently fail to start TLS while the web app still works.
4. **The separate `freeq-auth-broker` is only for split-origin login.** You can
   ignore it entirely on a single domain. If you *do* split login onto a subdomain,
   both the broker and server need the same `BROKER_SHARED_SECRET`, the broker needs
   `FREEQ_SERVER_URL`/`BROKER_PUBLIC_URL`/`BROKER_DB_PATH` env vars, and its CORS
   allow-list is currently **hardcoded** in `freeq-auth-broker/src/main.rs` (you'd
   have to edit + rebuild it to add your origin). This is why single-origin is simpler.
5. **Connection/rate limits are hardcoded** (20/IP, 10 cmd/s). No flags to tune;
   use nginx if you need different limits for the web path.

---

## 8. Optional extras (you probably don't need)

### Federation (`did:web` + iroh S2S)
Only if you want to peer with *other* freeq servers. Enable `--iroh` and
restrict peers with `--s2s-allowed-peers`. Full details:
[`docs/federation.md`](federation.md).
For a private company instance, **skip this**.

### Standalone auth broker (split-origin login)
Only if login must live on a different subdomain than the web app (production does
this: `auth.freeq.at` vs `irc.freeq.at`). Run the `freeq-auth-broker` binary with
`BROKER_SHARED_SECRET`, `FREEQ_SERVER_URL`, `BROKER_PUBLIC_URL`, and `BROKER_DB_PATH`,
set the same `BROKER_SHARED_SECRET` on the server, and edit the broker's hardcoded
CORS list. **Not needed** for the single-domain setup in this guide.

### Docker Compose (alternative to bare-metal)
The repo ships a `Dockerfile` + `docker-compose.yml` that build the server + web
client into one image. `docker compose up -d` runs the server; `--profile with-tls`
adds nginx; `--profile with-broker` adds the (optional) broker. The bare-metal
systemd path in this guide is preferred for a small private instance because it's
easier to back up and inspect, but Compose is a valid one-command alternative.

---

## Appendix: file/port cheat-sheet

| Port | Bind | Purpose | Public? |
|---|---|---|---|
| 443 | nginx | HTTPS web client + WS IRC + REST + OAuth | **yes** |
| 80 | nginx | HTTP → HTTPS redirect + certbot | yes |
| 6697 | freeq-server | IRC over TLS (native clients) | **yes** |
| 6667 | freeq-server | IRC plaintext | no (loopback/LAN) |
| 8080 | freeq-server | web/WS/REST (behind nginx) | no (loopback) |

| Path | What |
|---|---|
| `/opt/freeq` | source + built binary + web `dist/` |
| `/var/lib/freeq` | DBs, `*.secret` keys, `media/` |
| `/etc/freeq/secrets` | env vars for systemd |
| `/etc/systemd/system/freeq-server.service` | unit |
| `/etc/nginx/sites-available/freeq.conf` | reverse proxy |
| `/etc/letsencrypt/live/chat.example.com/` | TLS cert + key |
