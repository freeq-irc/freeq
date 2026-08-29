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
space. Your browser never holds your PDS tokens — they live on the freeq
server from the OAuth flow — so freeq performs the write on your behalf.

Reading is the same: freeq confirms the member and fetches the file on
their behalf. Fetched files are cached in memory for five minutes so a
scrolling message list does not hammer the uploader's PDS.

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
- Access is checked against live channel membership when a space credential
  is *minted*, and the server caches that credential for up to 30 minutes.
  A kick or ban therefore stops access eventually, not instantly: it takes
  effect on the next mint. Treat revocation as bounded-lag, not immediate.
- A file goes to exactly one place. Private-space upload and the public
  "save a copy to my PDS" / "post to Bluesky" options are mutually
  exclusive, and the server rejects a request asking for both.
- Encrypted-only (`+E`) channels are refused server-side: space media sits
  unencrypted in the author's repo and is proxied in the clear through the
  server, which is the thing `+E` exists to prevent.
- A server holds at most 500 media spaces (`MAX_MEDIA_SPACES`). Minting is a
  write to the operator's own PDS account, and anyone who can create a
  channel can ask for one.
- Private media spaces are per channel: DMs and federated (S2S) members are
  not currently supported.
- In a public channel, media is readable by anyone who can read the channel,
  including anonymous readers.
- The server can read the media it serves, since it fetches on each
  viewer's behalf. The difference from server-side storage is custody: the
  file is in your repo, portable and deletable by you, and access is
  decided by live channel membership rather than by whoever holds a link.
