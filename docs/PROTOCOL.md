# Freeq Protocol Notes

## SASL Mechanism: ATPROTO-CHALLENGE

Freeq implements a custom SASL mechanism for authenticating IRC users with
AT Protocol (Bluesky) identities. The mechanism name is `ATPROTO-CHALLENGE`.

### Flow

```
Client                          Server
  |                               |
  |  CAP REQ :sasl                |
  |------------------------------>|
  |  CAP ACK :sasl                |
  |<------------------------------|
  |  AUTHENTICATE ATPROTO-CHALLENGE
  |------------------------------>|
  |  AUTHENTICATE <base64 challenge>
  |<------------------------------|
  |  AUTHENTICATE <base64 response>
  |------------------------------>|
  |  900 RPL_LOGGEDIN             |
  |  903 RPL_SASLSUCCESS          |
  |<------------------------------|
```

### Challenge Format

The server sends a JSON challenge encoded as base64url:

```json
{
  "session_id": "<unique per TCP connection>",
  "nonce": "<32 bytes, cryptographically random, base64url>",
  "timestamp": <unix epoch seconds>
}
```

### Response Format

The client responds with base64url-encoded JSON:

```json
{
  "did": "did:plc:abc123...",
  "method": "crypto" | "pds-session" | "pds-oauth",
  "signature": "<base64url signature over raw challenge bytes>",
  "pds_url": "https://bsky.social"
}
```

An agent may add `owner_did`, the DID of the account it acts for. A server
with a connect allowlist that does not know the agent's own DID may admit it
when that account is allowed and its `at.freeq.agentKey` records name the
agent (`--allow-delegated-agents`).

### Verification Methods

1. **`crypto`** — Client signs the raw challenge bytes with a key listed in
   the DID document's `authentication` or `assertionMethod` sections.
   Supported curves: secp256k1 (required), ed25519 (recommended).

2. **`pds-session`** — Client provides a Bearer JWT (from an app password
   session). Server calls `com.atproto.server.getSession` on the claimed
   PDS to verify the token belongs to the claimed DID.

3. **`pds-oauth`** — Client provides a DPoP-bound OAuth access token.
   Server constructs a DPoP proof and calls `getSession` on the PDS.

### Refusals

A sign-in the server refuses carries a standard reply just before its `904`:

```
FAIL AUTHENTICATE <code> :<sentence>
904 <nick> :<sentence>
```

The server does not close the connection on a `904`; the reference clients,
having asked to sign in, end it themselves rather than stay on as a guest. A session the server ends for a
reason of the client's own carries `FAIL * <code> :<sentence>` (the `*`
because it answers no command the client sent), then `ERROR :<sentence>`,
and the server closes the connection. A refused signing key carries
`FAIL MSGSIG KEY_EXPIRED` or `FAIL MSGSIG KEY_RETIRED`, and the connection is
closed.

Only `TEMPORARILY_UNAVAILABLE` means try again: the server could not get an
answer it needs, or the challenge expired, so the same credentials may get in
later. Every other code is final, so a client that comes back with the same
credentials is refused again. A `904` with no `FAIL` before it, or an unknown
code, is final too. `spec/sasl-refusals.json` lists every code with its kind.

A browser sign-in through `LOGIN` that the server refuses carries
`FAIL LOGIN NOT_ALLOWED :<sentence>` before its `904`. The SDKs do not count
`FAIL LOGIN` as a refusal, so the `904` behind it is read as a bare one, and
is final.

| Reply | Code | Kind | When |
|---|---|---|---|
| `FAIL AUTHENTICATE` | `TEMPORARILY_UNAVAILABLE` | try again | the DID document, the handle behind an allowed domain or the PDS could not be checked, or the challenge expired |
| `FAIL AUTHENTICATE` | `NOT_ALLOWED` | final | the connect allowlist refuses this DID and no delegation admits it |
| `FAIL AUTHENTICATE` | `SIGNATURE_INVALID` | final | the signature verifies against none of the DID's keys |
| `FAIL AUTHENTICATE` | `IDENTITY_INVALID` | final | the DID document cannot be used to sign in |
| `FAIL AUTHENTICATE` | `TOKEN_INVALID` | final | the sign-in token was not accepted |
| `FAIL AUTHENTICATE` | `BAD_RESPONSE` | final | the response cannot be read, or answers no challenge this connection holds |
| `FAIL AUTHENTICATE` | `MECHANISM_UNSUPPORTED` | final | a mechanism other than `ATPROTO-CHALLENGE` |
| `FAIL AUTHENTICATE` | `ABORTED` | final | the client sent `AUTHENTICATE *` |
| `FAIL *` | `ACCOUNT_REQUIRED` | final | a guest on a server started with `--no-guest` |
| `FAIL *` | `IDENTITY_INVALID` | final | the identity re-check found the DID with no key left (deactivated, or its key removed) |
| `FAIL *` | `NOT_ALLOWED` | final | a delegated agent's owner withdrew it, or is no longer allowed |
| `FAIL *` | `TEMPORARILY_UNAVAILABLE` | try again | a delegated agent's owner's records could not be read for three re-read periods |
| `FAIL *` | `AGENT_REVOKED` | final | an op's or a server operator's `AGENT REVOKE` |
| `FAIL MSGSIG` | `KEY_EXPIRED`, `KEY_RETIRED` | signing key | this device's signing key ran past its lifetime, or was retired |

### Security Properties

- **Nonce uniqueness**: Each challenge contains a 32-byte cryptographically
  random nonce. Challenges are single-use (invalidated after verification).
- **Timestamp window**: Challenges expire after 60 seconds (configurable
  via `--challenge-timeout-secs`).
- **No private key transmission**: The server never sees private keys.
  All verification uses public keys from DID documents or PDS token validation.
- **DID document resolution**: The server resolves `did:plc` via plc.directory
  and `did:web` via HTTPS, then extracts verification keys.

### Deviations from a Hypothetical IRCv3 Spec

- **JSON encoding**: Both challenge and response are JSON (not binary).
  This aids debuggability at the cost of a few extra bytes. A production
  IRCv3 specification would likely use a binary format.
- **Multi-method auth**: The mechanism supports three verification methods
  (crypto, pds-session, pds-oauth). A formal spec might split these into
  separate SASL mechanism names.
- **Signature over raw bytes**: The signature is over the raw challenge
  bytes (the decoded JSON), not a hash. This is simpler but means the
  signed payload is larger than strictly necessary.

---

## DID-Aware IRC Extensions

### Nick Ownership

When a user authenticates, their nick is bound to their DID. This binding:
- Persists across server restarts (stored in SQLite)
- Prevents other users from using the nick
- Unauthenticated users claiming a registered nick are renamed to `GuestXXXX`
- Propagated across federated servers via CRDT

### DID-Based Channel Authority

- **Founder**: The first authenticated user to create a channel becomes its
  founder. Founder status is permanent and survives server restarts.
- **DID ops**: Channel operators can be granted by DID. DID-based ops
  persist across reconnects and work across federated servers.
- **DID bans**: `MODE +b did:plc:xyz` bans by identity rather than hostmask.
  DID bans survive nick changes.

### WHOIS Extensions

Freeq adds custom WHOIS numerics:
- **330 (RPL_WHOISACCOUNT)**: Shows the authenticated DID
- **671**: Shows the resolved AT Protocol handle (e.g. `chadfowler.com`)
- **672**: Shows the iroh P2P endpoint ID (if connected via iroh)

---

## Transport Stack

All transports feed into the same IRC protocol handler. The server is
transport-agnostic — clients can mix transports freely.

| Transport | Port | Notes |
|-----------|------|-------|
| TCP | 6667 | Standard IRC |
| TLS | 6697 | Standard IRC over TLS |
| WebSocket | configurable | IRC-over-WebSocket at `/irc` |
| iroh QUIC | auto | NAT-traversing, end-to-end encrypted |

### iroh Transport

The server advertises its iroh endpoint ID in CAP LS:
```
CAP * LS :sasl message-tags ... iroh=<endpoint-id>
```

Clients that support iroh can discover the endpoint and upgrade their
connection to QUIC, gaining NAT traversal and relay fallback.

### S2S Federation

Servers connect to each other over iroh QUIC links using a JSON-based
protocol. State convergence uses Automerge CRDTs for:
- Channel membership
- Topics
- Nick ownership
- DID-based ops
- Bans

See `docs/s2s-audit.md` for details on the S2S protocol.

---

## IRCv3 Capabilities

Freeq supports these IRCv3 capabilities:

| Capability | Notes |
|------------|-------|
| `sasl` | ATPROTO-CHALLENGE mechanism |
| `message-tags` | Full tag routing per client |
| `server-time` | Timestamps on history replay |
| `batch` | History wrapped in chathistory batch |
| `multi-prefix` | All prefix chars in NAMES |
| `echo-message` | Echo own messages back |
| `account-notify` | ACCOUNT broadcast on auth |
| `extended-join` | JOIN includes account + realname |
| `draft/chathistory` | On-demand CHATHISTORY command |

---

## Plugin System

Freeq supports server plugins that hook into events:

| Hook | Description |
|------|-------------|
| `on_connect` | New client connection (before registration) |
| `on_auth` | SASL authentication complete (can override displayed identity) |
| `on_join` | User joins a channel |
| `on_message` | PRIVMSG/NOTICE (can suppress or rewrite) |
| `on_nick_change` | Nick change |

Plugins are compiled into the binary and activated by name via CLI or
TOML config files. See `examples/plugins/` for examples.
