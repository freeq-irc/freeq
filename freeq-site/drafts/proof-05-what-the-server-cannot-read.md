# What the server sees when it cannot read your message

Everything so far has been about what a room can show you. This post is about
what it cannot see — and, more usefully, about the part it still can.

A direct message between two accounts is sealed at the sending edge. Here is the
whole of it, with nothing hidden.

## One sentence, on the wire

```
plaintext   : the invoice is attached, do not forward it
on the wire : ENC3:kxSSzGB9Tkbd1WY2mZnLh4QqnkkUFXYdCTYUtwSueVkAAAAAAAAAAA:AkRVwNPZ_Mts_3X-:tELEFNqaIiKUWZUkQpZM9voWCBXD8qSjIo4AoOFUSnhmK86kzIiTsJBXpEF80CHirbOSxLxytQwTrw
sizes       : plaintext 42 bytes, wire 155 bytes
bob reads   : the invoice is attached, do not forward it
```

Three colon-separated fields after the tag: a 40-byte header, a 12-byte nonce,
and the ciphertext. The header carries the sender's current ratchet public key,
the length of the previous chain, and this message's number — and it is fed to
AES-GCM as additional authenticated data, so tampering with the counters breaks
the tag rather than silently reordering your conversation.

Send the same sentence twice and nothing repeats:

```
same sentence again: ENC3:kxSSzGB9Tkbd1WY2mZnLh4QqnkkUFXYdCTYUtwSueVkAAAAAAAAAAQ:Jb7XFmvaJLOELj8r:lej1WaP6p7LJ0wPweNN3AiMfTBk9KpNMen-3Pn-T6UTSle378SQPzIq5ooFnlKeF-5HMBD5pZnrezw
identical?  : false
```

The only visible difference in the header is the last byte — message number 0
became 1 — and every other byte changed, because the message key changed with
it. When the other side answers, the header's key changes too:

```
bob replies : ENC3:GdSziEUg0H73qjIt47CCsRlgGcbn9Du4_wApBywQ_HsAAAAAAAAAAA:PPK8IKNESP-WsIRE:6qeGui6_pjJqLGNdjF0FNeDaR9gNDJTg0ev_9ynhSWY_EKh-iUw
```

A new ratchet key, a chain that starts again at zero. That is the Diffie-Hellman
ratchet stepping: each direction change mixes in fresh key material, so a key
recovered today does not unlock what was said before it.

## What the machine in the middle gets

Hand that exact ciphertext to a server and watch what it relays:

```
@msgid=01M0E6ZYHSBC3DF0FNHSWCTJCH :alice!alice@freeq/key/z6MksZ1D PRIVMSG bob ENC3:kxSSzGB9Tkbd1WY2mZnLh4QqnkkUFXYdCTYUtwSueVkAAAAAAAAAAA:AkRVwNPZ_Mts_3X-:tELEFNqaIiKUWZUkQpZM9voWCBXD8qSjIo4AoOFUSnhmK86kzIiTsJBXpEF80CHirbOSxLxytQwTrw
```

Now the honest inventory. Everything the relay learns from that line:

- **who sent it** — `alice`, and more durably `freeq/key/z6MksZ1D`: the first
  eight characters of her `did:key`, cloaked into the hostmask and stable across
  sessions. The full DID resolves to her ed25519 public key, which is the point
  of the signature chain, and the reason the relay cannot forge her.
- **who receives it** — `bob`, by name, resolved to an account.
- **when** — arrival time, to the millisecond, and the ULID in `msgid` embeds
  the sender's own clock.
- **how much** — 155 bytes on the wire for 42 bytes of text. Length is not
  padded, so message size leaks approximate message size.
- **that a conversation exists at all**, its rhythm, its bursts, who answered
  whom and how fast.
- **the ratchet header**, which is public by design: the current public key and
  the counters.

What it does not get is the sentence. There is no configuration, no operator
role, and no subpoena that turns those bytes into "the invoice is attached" —
the key never left the two endpoints.

Both statements are true at once, and a system that only tells you the second
one is selling you something.

## Where the first key comes from

A ratchet needs a shared secret before it can start. The opening message carries
one — that is the `ENC4` form, which wraps the same three fields plus the
agreement that begins the session, so a recipient who has never spoken to you
can derive the root key on receipt. The agreement is X3DH-style: long-term
identity keys plus a per-session ephemeral, mixed into one secret over X25519.

The primitives, all of them: X25519 for the agreement and the DH ratchet,
HKDF-SHA256 for key derivation, HMAC-SHA256 for the KDF chains, AES-256-GCM for
message encryption. The construction follows Signal's published Double Ratchet
specification. It is not Signal's implementation, and it has not been reviewed
by anyone outside this project.

## Channels are a different, weaker story

A channel has more than two ends, so the ratchet does not apply. Two mechanisms
exist. The one you can drive from the terminal today is a passphrase:
`/encrypt <passphrase>` in the TUI derives a channel key that every member types
in out of band. It keeps content away from the relay, and it has the property
every shared-passphrase scheme has: anyone who ever learns the phrase reads
everything encrypted under it, and removing a member means changing it
everywhere.

The other is sender-keys with a random group secret sealed individually to each
member's published key, so the server relays the sealed blob and can never open
it. That scheme gets its own post later on, because the interesting question is
not encryption — it is what happens the day you throw someone out.

## Try it

**See it in 30 seconds.** The relay line above. A server carrying a sentence it
cannot read, with the sender, the recipient and the size in plain view.

**Run it in 5 minutes.** The ratchet is in the SDK, and its tests are the
cheapest way to watch it work:

```bash
git clone https://github.com/freeq-irc/freeq && cd freeq
cargo test -p freeq-sdk ratchet -- --nocapture
```

Then start a server and send one of those ciphertexts through it yourself with
[the ninety-line client](https://github.com/freeq-irc/freeq/tree/main/examples/python-agent):
the server relays a string it has no way to interpret.

**Extend it in 30 minutes.** Write a passive observer: join a channel, log every
DM line you can see, and produce the report a hostile relay would produce — who
talks to whom, when, how often, how much. Then decide whether the content being
sealed is the part you cared about. That exercise is worth more than any
threat-model diagram.

## What this does not claim

**Not reviewed.** No external audit, no published test vectors. The
construction follows a public specification and the code is small and readable,
which is not the same as being correct. Until someone independent has looked,
the confidentiality claim rests on our own testing.

**Metadata is not protected, at all.** Read the inventory above again. Sender,
recipient, timing, size, and the social graph they draw are visible to the relay
and to anyone who can see the relay's traffic. Sealing content is not anonymity,
and freeq does not offer anonymity.

**Compromise of an endpoint ends the discussion.** The ratchet limits what a key
recovered later can open. It does nothing about a device someone else is holding,
a screenshot, or a client that logs plaintext locally — which clients do, because
that is what scrollback is.

**Forward secrecy is a property of the construction, not a promise about your
disk.** Keys advance and old message keys are dropped in memory; what your client
persists is a client decision.

**Channel passphrases are not equivalent to the DM path.** Anyone with the
phrase reads the channel. Saying "the channel is encrypted" without saying that
is the exact overclaim this post exists to avoid.

## What is rough

Session state lives with the client. Two devices on one account do not share a
ratchet, so a DM read on your laptop is not automatically readable on your phone.

Key agreement uses long-term identity keys published for the account. Rotating
one is a manual affair, and there is no automatic re-agreement for sessions
already running.

The ciphertext is not padded, so length leaks. Padding is cheap and absent.

## Come in

`#freeq-dev` on `irc.freeq.at`, and the source is at
[github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq). A hostile
reading of `freeq-sdk/src/ratchet.rs` is the most welcome contribution this
post could produce.

Next: calls, and why the server carrying them knows almost nothing about them.
