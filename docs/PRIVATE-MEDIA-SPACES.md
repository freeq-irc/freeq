# Private Media via AT Protocol Spaces

**Status: experimental.** This is built on the AT Protocol Spaces alpha
([proposal 0016](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data)),
which is itself not production-ready. The feature is off by default and
everything about it may change.

## Why

Media shared through freeq is public. Attachments are uploaded to the
sender's PDS as public blobs, so anyone with the link can fetch them,
forever, no matter how locked down the channel is. An image posted in an
invite-only channel is exactly as public as one posted in #freeq, and
deleting the message does not delete the file.

With this feature on, media shared in a channel is visible to exactly the
people who are in that channel. Joining grants access, being kicked or
banned removes it, and the uploader can genuinely delete their files. The
freeq server never stores or even sees the media itself: files live on
each uploader's own PDS, and clients fetch them from there directly.

## How it works, briefly

The server gets its own AT Protocol account, which acts as the gatekeeper
for one private "space" per channel. Members' clients put media into the
channel's space instead of uploading it publicly. Whenever someone tries to
read from a space, the gatekeeper asks the freeq server "is this person in
the channel right now?" and the server answers from its live member list.
There is no separate access list to manage; the channel is the access list.

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

Two things to know when enabling it:

- The server publishes an identity document at
  `https://{server_name}/.well-known/did.json` so the PDS can find it.
  `server_name` must be the server's public hostname, reachable over HTTPS.
  If a front proxy handles `/.well-known/` for certificate renewal, make
  sure `did.json` still reaches freeq.
- Users who want private media need accounts on a Spaces-capable PDS, and
  web users who were already logged in must log out and back in once to
  grant the extra permission. Everyone else just keeps using public media.

Uploads are a per-message choice in the client: private is the default in
invite-only or keyed channels, public elsewhere, and either can be picked
explicitly. A private upload that fails is never quietly turned into a
public one.

## Limitations

- Access control, not encryption: files sit unencrypted on the uploader's
  PDS, readable by anyone the gatekeeper authorizes. Encrypted (+E)
  channels are not supported yet.
- Someone kicked from a channel may keep access for up to about two hours,
  until their last-issued credential expires.
- DMs and federated (S2S) members are not supported yet.
