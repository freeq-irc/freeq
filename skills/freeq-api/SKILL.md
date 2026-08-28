---
name: freeq-api
description: Read, search and verify freeq conversations over the REST API, and authenticate when an endpoint needs it. Use when you need channel history, full-text search, a transcript export, pinned messages, a user's DID, or proof that a particular message was really written by a particular person — without joining IRC.
---

# The freeq REST API

Every freeq server exposes its conversations over plain HTTP. The contract is
machine-readable and served by the server itself:

```
GET /api/v1/openapi.json      # OpenAPI 3.1, the authoritative contract
GET /llms.txt                 # short index of this server's agent surfaces
GET /.well-known/agent.json   # the diagnostic tools it offers
```

Read the OpenAPI document when you need a parameter or a response shape. It
cannot drift: a test fails the server's build if a route exists without a spec
entry, or the other way round.

Base URL for the public server: `https://irc.freeq.at`.

## Reading (no auth for public channels)

```bash
curl -s "$S/api/v1/channels"
curl -s "$S/api/v1/channels/%23general/history?limit=50"
curl -s "$S/api/v1/search?channel=%23general&q=deploy"
curl -s "$S/api/v1/channels/%23general/export?format=markdown"
curl -s "$S/api/v1/channels/%23general/pins"
curl -s "$S/api/v1/channels/%23general/topic"
curl -s "$S/api/v1/messages/01J…"
curl -s "$S/api/v1/users/alice/whois"
```

Notes that save time:

- The `#` must be percent-encoded as `%23`. A bare `#` in a shell URL silently
  truncates it to a fragment.
- Timestamps are Unix **seconds**; `before` pages backwards, `limit` caps rows.
- Deleted messages are excluded; an edited message comes back in its final
  form with `replaces_msgid` pointing at what it replaced.
- **403** means the channel is invite-only (`+i`) or key-protected (`+k`) —
  those are not readable over REST at all, so a token will not help. Join over
  IRC instead.
- **503** on history or search usually means the server runs without
  persistence, not that it is down.

## Verifying who said what

This is the part worth being pedantic about.

```bash
curl -s "$S/api/v1/verify/01J…"
```

- `signed_by: "client"` — the author's own per-session key signed it. That is
  non-repudiable authorship.
- `signed_by: "server"` — the server signed it on the sender's behalf. That
  proves the server relayed it and nothing more.
- `verified: false` — do not quote it as attributable.

Supporting endpoints: `/api/v1/signing-key` (the server's key),
`/api/v1/signing-keys/{did}` (a user's session keys), `/api/v1/actors/{did}`
(handle, PDS, verification keys) and `/api/v1/channels/{name}/evidence`
(messages together with the exact canonical bytes that were signed, so a third
party can verify without reconstructing the canonicalization).

## Authenticating

Most reads need nothing. Endpoints that act as a user (favorites, uploads,
pre-key publication, group keys, the metered model proxy) take a bearer token:

```
Authorization: Bearer <token>
```

Two ways to get one:

1. Connect over IRC and authenticate with SASL. Immediately after `903` the
   server sends `NOTICE * :API-BEARER <token>`. Clients built on the SDKs
   expose it (`client.apiBearer`), and `@freeq/mcp` wires it through
   automatically.
2. `POST /auth/broker/web-token`, signed with the broker shared secret
   (`X-Broker-Signature`) — for services that already hold an OAuth session.

## Asking the server why something failed

```bash
curl -s "$S/.well-known/agent.json"
curl -s -X POST "$S/agent/tools/diagnose_join_failure" \
  -H 'content-type: application/json' -d '{"channel":"#private"}'
```

These return a conclusion plus the evidence for it, never raw server state.
Prefer them over guessing from a status code.

## Rate limits and etiquette

The blob proxy and link-preview endpoints are rate limited (429). History and
search are cheap but not free — page with `before` rather than requesting huge
limits, and cache what will not change (a message with a given msgid is
immutable; an edit gets a new one).

## Related

- [api-reference.md](https://freeq.at/docs/api-reference.md) — prose reference
- `spec/openapi.yaml` in the repository — the contract itself
- `skills/freeq` — participating in conversations
- `skills/freeq-bots` — building an agent that lives in a channel
