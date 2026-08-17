# Security Hardening Guide

Operational security guidance for running freeq in production.

## Table of Contents

- [S2S Federation Security](#s2s-federation-security)
- [SASL & DPoP Authentication](#sasl--dpop-authentication)
- [Connection Limits & Server Bans](#connection-limits--server-bans)
- [Key Management](#key-management)
- [Configuration Checklist](#configuration-checklist)

---

## S2S Federation Security

### Default: Open Federation

By default, **any iroh peer can connect** to your server. This is convenient
for development but inappropriate for production.

```bash
# DEVELOPMENT ONLY — open federation (default)
freeq-server --iroh
```

### Production: Allowlist-Only Federation

Use `--s2s-allowed-peers` to restrict which peers can connect:

```bash
freeq-server \
  --iroh \
  --s2s-peers <peer-id-1>,<peer-id-2> \
  --s2s-allowed-peers <peer-id-1>,<peer-id-2>
```

When `--s2s-allowed-peers` is set:

- **Incoming** connections from peers not in the list are rejected with a
  logged warning
- **Outgoing** connections are only made to `--s2s-peers` (these should be
  a subset of allowed peers)
- Both sides should configure each other in their allowlists for **mutual
  authorization**

> **Note**: `--s2s-allowed-peers` currently only enforces incoming connections.
> Outgoing connections go to whatever `--s2s-peers` specifies. Ensure both
> flags are consistent.

### S2S Rate Limiting

All S2S connections are rate-limited to **100 events/second per peer**.
Events exceeding this rate are dropped with a warning log. This prevents
a compromised or misbehaving peer from overwhelming your server.

### S2S Authorization Checks

The following operations from federated peers are authorized before execution:

| Operation | Authorization |
|---|---|
| Mode changes (+o, +v, etc.) | Sender must be a channel op |
| Kicks | Kicker must be an op or channel founder |
| Topic changes (+t channels) | Setter must be an op |
| Joins | Checked against bans and invite-only (+i) |
| Bans | Authorized set/remove via S2S Ban variant |

### Example: Two-Server Federation

**Server A** (`peer-id-a`):
```bash
freeq-server \
  --iroh \
  --s2s-peers <peer-id-b> \
  --s2s-allowed-peers <peer-id-b> \
  --s2s-peer-api <peer-id-b>=https://server-b.example.com
```

**Server B** (`peer-id-b`):
```bash
freeq-server \
  --iroh \
  --s2s-peers <peer-id-a> \
  --s2s-allowed-peers <peer-id-a> \
  --s2s-peer-api <peer-id-a>=https://server-a.example.com
```

`--s2s-peer-api` tells this server where each peer serves its users' signing keys. Without it, a peer's message signatures are uncheckable here — reported as unverifiable, never as forged — so cross-server signature verification is inert. It is deliberately operator configuration rather than something a peer announces: no peer gets to choose where this server sends requests.

---

## SASL & DPoP Authentication

### Overview

freeq supports three SASL verification methods:

1. **Cryptographic signature** (`crypto`) — Client signs challenge with private key
2. **PDS session** (`pds-session`) — Client provides app-password JWT
3. **PDS OAuth** (`pds-oauth`) — Client provides DPoP-bound OAuth token

### DPoP Nonce Handling

AT Protocol PDS servers use DPoP (Demonstrating Proof of Possession) with
rotating nonces. The nonce rotation can cause SASL verification to fail if
the client's nonce has expired.

**How the retry works:**

1. Client sends SASL response with DPoP proof (possibly with stale or no nonce)
2. Server forwards to PDS, which responds with `use_dpop_nonce` error
3. Server extracts the fresh nonce from the PDS `dpop-nonce` header
4. Server sends `NOTICE <nick> :DPOP_NONCE <nonce>` to the client
5. Server re-issues a fresh AUTHENTICATE challenge
6. Client updates its DPoP nonce and retries with a new proof
7. Server re-verifies — this time the nonce matches

This is handled automatically by the SDK (`freeq-sdk`) and TUI client.
Web clients use the broker OAuth flow which handles nonces server-side.

### Challenge Security

- Challenges use cryptographically random nonces (32 bytes)
- Each challenge is **single-use** (consumed on verification attempt)
- Challenges expire after **60 seconds** (configurable via `--challenge-timeout-secs`)
- Session ID uniqueness is enforced per TCP connection

---

## Connection Limits & Server Bans

### Per-IP Connection Limits

Both TCP and WebSocket listeners enforce a per-IP connection limit:

| Transport | Limit | Behavior |
|---|---|---|
| TCP | 20 connections/IP | Connection refused with log warning |
| WebSocket | 20 connections/IP | WebSocket upgrade rejected (429) |

These limits are hardcoded. Connections from the same IP beyond the limit
are immediately closed. The limit applies to concurrent connections, not
rate.

### Channel Bans

Channel operators can ban users:

```
/MODE #channel +b nick!*@*       # Ban by nick
/MODE #channel +b *!*@host       # Ban by host mask
```

Bans are:
- Persisted to the database
- Synchronized across federated servers via S2S
- Enforced on join (including S2S joins)
- Checkable via `/MODE #channel b` (ban list)

### Server Operator Privileges

Server operators (configured via `--oper-dids` or the `OPER` command) can:

- Kick users from any channel
- Set modes in any channel
- Ban users in any channel
- Are not subject to channel-level permission checks

```bash
# Auto-grant oper to specific DIDs
freeq-server --oper-dids did:plc:abc123,did:plc:def456

# Or via environment variable
OPER_DIDS=did:plc:abc123 freeq-server

# Or via OPER command (requires --oper-password)
freeq-server --oper-password "secret"
# Then in client: /OPER admin secret
```

### Host Cloaking

Authenticated users get cloaked hostnames:

- DID users: `freeq/plc/xxxxxxxx` (truncated DID hash)
- Guests: `freeq/guest`

Real IP addresses are never exposed to other users.

---

## Key Management

### Generated Key Files

The server generates the following key files automatically on first run:

| File | Purpose | Rotation |
|---|---|---|
| `msg-signing-key.secret` | Server message signatures (ed25519) | Replace file + restart |
| `verifier-signing-key.secret` | Credential verifier signatures | Replace file + restart |
| `db-encryption-key.secret` | Database encryption at rest (AES-256-GCM) | **Cannot rotate** without re-encrypting all data |
| `iroh-key.secret` | iroh QUIC endpoint identity | Replace file + restart (changes your peer ID) |

### Key File Security

All key files are automatically excluded from git:

```gitignore
# In .gitignore
*.secret
iroh-key.secret
verifier-signing-key.secret
freeq-server/certs/*.pem
freeq-server/certs/*.key
```

> **⚠️ WARNING**: Never commit `*.secret` files or TLS private keys to version
> control. If a key is accidentally committed, rotate it immediately:
>
> 1. Delete the compromised key file
> 2. Restart the server (a new key is generated)
> 3. Use `git filter-branch` or BFG Repo-Cleaner to purge from history
> 4. Force-push and notify collaborators

### TLS Certificate Paths

TLS certificates and keys are specified via command-line flags:

```bash
freeq-server \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem
```

- Use absolute paths outside the repository
- Ensure the server process has read access
- Use Let's Encrypt with auto-renewal for production

### Key Rotation

**Message signing key** (`msg-signing-key.secret`):
1. Stop the server
2. Delete `msg-signing-key.secret`
3. Start the server (new key generated)
4. The public key endpoint (`/api/v1/signing-key`) updates automatically
5. Old signatures remain valid for verification (clients cache public keys)

**iroh endpoint key** (`iroh-key.secret`):
1. Stop the server
2. Delete `iroh-key.secret`
3. Start the server (new key generated, **new peer ID**)
4. Update `--s2s-peers` and `--s2s-allowed-peers` on all peer servers

**Database encryption key** (`db-encryption-key.secret`):
- ⚠️ Rotating this key makes all existing encrypted messages unreadable
- Back up the key file securely
- There is currently no re-encryption utility

### File Permissions

Set restrictive permissions on key files:

```bash
chmod 600 *.secret
chmod 600 /path/to/tls-key.pem
chown freeq:freeq *.secret
```

---

## Configuration Checklist

Production deployment checklist:

- [ ] TLS enabled (`--tls-cert`, `--tls-key`)
- [ ] S2S allowlist set (`--s2s-allowed-peers`) if federating
- [ ] Operator DIDs configured (`--oper-dids` or `OPER_DIDS` env)
- [ ] No `*.secret` files in version control
- [ ] Key files have `chmod 600` permissions
- [ ] Database file on encrypted filesystem (defense in depth)
- [ ] Reverse proxy (nginx) with rate limiting in front of web listener
- [ ] Firewall rules limiting direct TCP access if using web-only
- [ ] Log monitoring for `"Rejecting S2S connection"` and `"per-IP limit reached"`
- [ ] Broker shared secret set if using auth broker (`BROKER_SHARED_SECRET`)
