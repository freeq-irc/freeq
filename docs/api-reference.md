# REST API Reference

freeq exposes a REST API alongside the IRC and WebSocket interfaces.

## Base URL

```
https://irc.freeq.at/api/v1
```

## Endpoints

### Health

```
GET /api/v1/health
```

Returns server status:

```json
{
  "server_name": "irc.freeq.at",
  "connections": 42,
  "channels": 12,
  "uptime_secs": 86400
}
```

### Channels

```
GET /api/v1/channels
```

Returns public channels with member counts:

```json
[
  {
    "name": "#freeq",
    "topic": "Welcome to freeq",
    "members": 15,
    "modes": "+nt"
  }
]
```

Filters out empty channels with no topic.

### Channel History

```
GET /api/v1/history/{channel}?limit=50&before={msgid}
```

Returns recent messages. Requires the channel name without `#` prefix.

### Message Verification

```
GET /api/v1/verify/{msgid}
```

Verify a message's cryptographic signature. Returns the signing key, signature, and verification result. A `verified_by` of `key-retired` means the key that signed was retired by its owner before the message was made, and the verdict is `invalid`: the signature is not evidence of anything once the key it names was withdrawn. `key_source` names where the key that checked the signature came from: `server-key` for this server's own key, otherwise `local-session`, `origin-server`, `identity-record`, `did-document`, or `unknown` for a key filed before sources were recorded; it is absent when no key was found.

### Server Signing Key

```
GET /api/v1/signing-key
```

Returns the server's ed25519 public key (base64url-encoded) used for message attestation. `kid` is the key's id, and `registered_at` is when this server first filed the key in its own key store, in seconds since the epoch, or `null` for a server running without a database. `did` is the name the server files its own keys under, `did:web:<server-name>`; the server's whole key set, current and retired, is at `/api/v1/signing-keys/{did}` for that value.

### Signing Keys by DID

```
GET /api/v1/signing-keys/{did}
```

Returns the signing keys an identity has registered. `public_key` is the key it is signing with now — the most recently used key its owner has not retired — or `null` if it has registered none. `keys` lists every key, newest registration first: `kid`, `public_key`, `registered_at`, `last_seen_at`, and `removed_at`, which is `null` while the key is live and otherwise the time its owner retired it. Times are seconds since the epoch. A DID with no keys is a 200 with a null `public_key` and an empty list, not a 404.

```
GET /api/v1/signing-keys/{did}/{kid}
```

Returns the one key that identity registered under `kid`, with the same window fields. This is the lookup a verifier uses when a signature names its kid: the key stays fetchable after the session that made it ends. An unknown kid is a 404.

### Blob Proxy

```
GET /api/v1/blob?url={encoded-pds-url}&mime={encoded-mime}
```

Proxies PDS blob downloads. Strips `Content-Disposition: attachment` headers that block browser playback. Supports `Range` requests for streaming.

### OG Preview

```
GET /api/v1/og?url={encoded-url}
```

Fetches Open Graph metadata for a URL. Returns title, description, image, and site name. Server-side fetch prevents IP leakage.

### Upload

```
POST /api/v1/upload
Authorization: Bearer {web-token}
Content-Type: multipart/form-data
```

Upload a file to the user's PDS. Returns the blob URL and media attachment tags.

### Pinned Messages

```
GET /api/v1/pins/{channel}
```

Returns pinned messages for a channel:

```json
[
  {
    "msgid": "01ABCDEF...",
    "from": "alice",
    "text": "Welcome!",
    "pinned_by": "bob",
    "pinned_at": "2024-01-01T00:00:00Z"
  }
]
```

### Rooms

Instant rooms (see `INSTANT-ROOMS.md`): end-to-end encrypted channels minted
for one collaboration and shared as a single URL. All calls take
`Authorization: Bearer <irc-session-id>`. Channel names may be given with or
without the leading `#`.

```
POST /api/v1/rooms
```

Body (optional): `{ "topic": "...", "invite_ttl_secs": 604800 }`. Creates a
`#r-<word>-<word>-<word>` channel that is `+i +E +n +t`, with the caller as
founder and sole roster member, and one invite. Returns `201`:

```json
{
  "channel": "#r-quiet-copper-fox",
  "invite": "Xk3…",
  "url": "https://irc.freeq.at/r/r-quiet-copper-fox#Xk3…",
  "invite_expires_at": 1760000000,
  "room": { "channel": "#r-quiet-copper-fox", "founder_did": "did:key:z…", "created_at": 1759000000, "expires_at": 1760200000 }
}
```

Share `url`. The token after `#` is the invite; browsers and HTTP clients
never send a fragment, so it never reaches the server. Limits: 20 rooms per
founder per 24 h (`429`), plus the per-IP REST limiter.

```
GET /api/v1/rooms/{channel}
```

Roster member, founder or DID-op. `members[].epochs` lists the epochs that
member already holds a sealed key for, so a steward can see who needs the
latest one:

```json
{
  "channel": "#r-quiet-copper-fox",
  "topic": null,
  "founder_did": "did:key:z…",
  "created_at": 1759000000,
  "last_activity": 1759001000,
  "expires_at": 1760210600,
  "latest_epoch": 2,
  "members": [
    { "did": "did:key:z…", "joined_at": 1759000000, "online": true, "epochs": [1, 2] }
  ]
}
```

```
POST   /api/v1/rooms/{channel}/invites    body { "invite_ttl_secs"?, "max_uses"? }  → 201 { invite, url, invite_expires_at }
DELETE /api/v1/rooms/{channel}/invites                                                → { revoked: n }
POST   /api/v1/rooms/{channel}/keep                                                   → { expires_at }
DELETE /api/v1/rooms/{channel}/members/{did}                                          → { removed: did }
```

Invites and member removal are founder/DID-op only; `keep` is open to any
roster member and pushes `expires_at` out by the idle TTL (`--room-idle-secs`,
default 14 days). Removing a member sets the roster row's `removed_at`, bans
the DID, and kicks any live session; the caller then rotates the epoch. The
founder cannot be removed.

`POST /api/v1/channels/{channel}/groupkeys` changes for rooms only: an
`epoch` above the latest stored one needs the founder or a DID-op; an `epoch`
at or below it may be uploaded by any roster member; keys addressed to DIDs
not on the roster are dropped and reported in `skipped`.

```
GET /r/{name}
```

The share URL's landing page (no auth). `Accept: text/markdown` returns
markdown join instructions for an agent (`npx -y @freeq/mcp room join <full
url>`); anything else returns HTML with the same text and an "Open in freeq"
button that goes to `/?room={name}` keeping the fragment. Unknown names are
`404` in both forms.

Rooms are swept every 10 minutes: a room with fewer than two roster members
is deleted after `--room-unclaimed-secs` (default 24 h), an idle room after
its `expires_at`, and live members get a NOTICE in the last 24 h before
expiry. Deletion removes the channel, its messages, pins, group keys, roster
and invites.

## Authentication

Most read endpoints are public. Write endpoints (upload, pin) require a web-token from the auth broker, sent as `Authorization: Bearer {token}`.

## CORS

Allowed origins: `irc.freeq.at`, `auth.freeq.at`, `freeq.at`, `localhost:*`.

## Security headers

All responses include:
- `Content-Security-Policy` (strict)
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
