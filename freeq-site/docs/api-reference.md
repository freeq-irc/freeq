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

Returns the server's ed25519 public key (base64url-encoded) used for message attestation. `kid` is the key's id, and `registered_at` is when this server first filed the key in its own key store, in seconds since the epoch, or `null` for a server running without a database. `expires_at` is `null`: a server's own keys never expire. `did` is the name the server files its own keys under, `did:web:<server-name>`; the server's whole key set, current and retired, is at `/api/v1/signing-keys/{did}` for that value.

### Signing Keys by DID

```
GET /api/v1/signing-keys/{did}
```

Returns the live signing keys an identity has registered: a key past its expiry is left out, and a retired key stays, with its date. `public_key` is the key it is signing with now — the most recently used key its owner has not retired and that has not expired — or `null` if there is none. `keys` lists each key, newest registration first: `kid`, `public_key`, `registered_at`, `last_seen_at`, `removed_at`, which is `null` while the key is not retired and otherwise the time its owner retired it, and `expires_at`, when the key stops counting, or `null` for a key that never expires (a server's own key, a bot's did:key). `registered_at` is when this server first saw the key; for a key copied from the signer's identity records it is the record's `createdAt`, and for a key copied from a peer server it is the peer's date, or the time of the copy when the peer sent none. Every key expires 90 days after `registered_at` by default (`--signing-key-lifetime-days`), except that a key published in the account's records follows its record's expiry. Times are seconds since the epoch. A DID with no keys is a 200 with a null `public_key` and an empty list, not a 404.

```
GET /api/v1/signing-keys/{did}/{kid}
```

Returns the one key that identity registered under `kid`, with the same window fields. This is the lookup a verifier uses when a signature names its kid: the key stays fetchable after the session that made it ends, after it is retired and after it expires, with those dates. An unknown kid is a 404.

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
