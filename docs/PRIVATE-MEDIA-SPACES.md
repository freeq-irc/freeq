# Private Media via AT Protocol Spaces

**Status: experimental.** This is built on the AT Protocol Spaces alpha
([proposal 0016](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data)),
which is itself not production-ready. The feature is off by default and
everything about it may change.

## Why

freeq can already put your public media on your own PDS ("save a public
copy to my PDS"). This feature is the other side of that: your private
media on your own PDS too, under your control, following AT Protocol
concepts.

Today, private attachments are held by the freeq server instead. It stores
the files, holds the key, and access rides on possession of a link. That
works, but the files are not yours in any atproto sense: you cannot take
them with you or truly delete them.

With spaces, a private file stays in your own repo on your PDS. The channel
decides who may read it (joining grants access, a kick or ban removes it),
the freeq server stores nothing, and deleting your file from your own repo
is a real deletion. The server still handles the management of the media.

## How it works

The server gets its own AT Protocol account. That account is the gatekeeper,
and owns a private "space" per channel.

When you attach a file, it goes into your own repo inside that channel's
space. The browser has no PDS credentials of its own, so freeq writes
the media.

Reading is the same, freeq confirms the member and fetches the file on
their behalf.

## Using it

You need an account for the server on a PDS that supports the Spaces alpha.
Then configure:

```toml
# server.toml
media_space_did = "did:plc:..."        # the server's spaces account
media_space_password = "..."
```

(Or use the matching CLI flags / `FREEQ_MEDIA_SPACE_*` environment
variables.) Leave these unset and the feature is completely off; media
works exactly as before.

To enable it under docker compose, ensure the variables are set in your
`.env` and add these to the freeq service:

```yaml
environment:
  - FREEQ_MEDIA_SPACE_DID=${FREEQ_MEDIA_SPACE_DID:-}
  - FREEQ_MEDIA_SPACE_PASSWORD=${FREEQ_MEDIA_SPACE_PASSWORD:-}
```

and set the values in your `.env`.

Two things to know when enabling it:

- The server publishes an identity document at
  `https://{server_name}/.well-known/did.json` so the PDS can find it.
  `server_name` must be the server's public hostname, reachable over HTTPS.
  If a front proxy handles `/.well-known/` for certificate renewal, make
  sure `did.json` still reaches freeq.
- Posting private media requires a Spaces-capable PDS. Viewing media does not.

Uploads are a per-message choice in the client, opt-in per file.

## Limitations

- Access control, not encryption: files sit unencrypted on the uploader's
  PDS, readable by anyone the gatekeeper authorizes. Encrypted (+E)
  channels are not supported yet.
- Access is checked per request against live channel membership, so losing
  the channel simultaneously stops media access.
- Private media spaces are per channel: DMs and federated (S2S) members are
  not currently supported.
- In a public channel, media is readable by anyone who can read the channel,
  including anonymous readers.
- The server can read the media it serves, since it fetches on each
  viewer's behalf. The difference from server-side storage is custody: the
  file is in your repo, portable and deletable by you, and access is
  decided by live channel membership rather than by whoever holds a link.
