# Throw someone out of a sealed room

The last post sealed a conversation between two people. A room is harder, and
the hard part is not the sealing. It is the day somebody leaves.

Shared-passphrase encryption fails this test completely: everyone who ever knew
the phrase can read everything encrypted under it, forever, and "removing" a
member means asking the others to re-type a new secret. The scheme below fails
it honestly instead — it draws a line at the moment of departure, and it tells
you exactly which side of that line each message is on.

## A key nobody shares

The channel's key is a random 32-byte secret that only members hold. Nobody
derives it from the channel name or the member list, so the server cannot
recompute it. It reaches each member sealed to their own published key:

```
epoch 1 minted for #board
  sealed to ann   : EGK1:#board:1:rkKkmMf_cIyg_eSMpdfOzCwC3cGlJUAHNFV6f5MyvmM:sHK7xV6SDYE_8ItJ:0XTxh11IBWt47eKYfHmTy
  sealed to bob   : EGK1:#board:1:Yq91BDhR2z8-dzvuxAwL3V1a9NThy2BpSHSrRGgWUQs:RSs0kPEneNcX37mC:FFh0adx78_MAiFEH0ivBx
  sealed to cara  : EGK1:#board:1:f4JristX9MpP_WW6DILdZYTlDcuCLML2w9eRVzw4gBM:aH4UQDnhd3rZWoeW:5uNHXJDVvv5etJmQsj2N9
```

Three envelopes carrying the same secret, each openable by exactly one person —
the recipient named by the `did:key` whose X25519 sealing key the steward
looked up.
Traffic under it names its epoch and nothing else:

```
message at epoch 1:
  EG1:1:NVknypsyout6Tu14:TU1OYdybi_2imVKmXsRwTbQgc-X4cD3c5LIdOPA7r5SvbWLISE7lu-HcaNJuFMik-snhIg
  bob reads: board packet is in the shared folder
```

Those envelopes travel as ordinary messages. Hand one to a server and it does
what it does with everything else — carries it:

```
→ PRIVMSG #board :EGK1:#board:1:Yq91BDhR2z8-dzvuxAwL3V1a9NThy2BpSHSrRGgWUQs:RSs0kPEneNcX37mC:FFh0adx78_MAiFEH0ivBx
```

No key-distribution service, no server feature, no operator with a master copy.
Key distribution is a message.

## Bob leaves

Two things happen, and they are deliberately independent.

The room's membership is revoked the ordinary way, by an op, in public:

```
→ MODE #board +b bob!*@*
→ KICK #board bob :board membership ended
```

```
:steward!steward@freeq/key/z6Mkrmmz MODE #board +b bob!*@*
:steward!steward@freeq/key/z6Mkrmmz KICK #board bob :board membership ended
:irc.freeq.at 474 bob #board :Cannot join channel (+b)
```

And the key moves on. The steward mints a fresh secret at the next epoch and
seals it only to the people still there:

```
bob is removed → epoch 2
message at epoch 2:
  EG1:2:Zc_z0USCwo7zpUT-:OyIRaKVcH8RkUhXF9w9d5p8C63xw5sJRzcpMlUSJ9khrBFmA3_byUhklXc-vnj1J
```

Bob holds a perfectly valid key. It is valid for a conversation that has moved:

```
bob still holds epoch 1 and tries to read epoch 2:
  refused: epoch mismatch: have 1, got 2 (need the sealed key for that epoch)
ann, re-sealed at epoch 2: new packet, bob is off the board
```

The refusal is not a permission check that Bob's software chose to honour. There
is no epoch-2 key inside anything Bob has, and no amount of pretending to still
be a member produces one.

## The line, and which side things fall on

```
bob re-reads epoch 1 traffic: board packet is in the shared folder
```

That is the honest half. Revocation removes access to **future** keys and future
messages. It cannot reach into what Bob already read, already copied, or already
decrypted onto his own disk. Anyone who tells you their system can un-send a
message that was successfully delivered is describing a UI, not cryptography.

So the guarantee is precise and worth stating in one sentence: *from the moment
of rotation, a departed member reads nothing new.*

## Where admission comes from

The steward does not decide membership by taste. It seals to the members the
room's policy admitted — the same chain the gatekeeper post described, where an
external fact becomes a signed credential and the channel's rules decide what
follows.
Authorization and key access share one source of truth, which is the property
that keeps a "removed" member from lingering in the key list because someone
forgot.

The complete path, end to end:

```
external fact  →  signed credential  →  policy admits  →  sealed key at epoch N
                                                       ↓
                        membership revoked  →  rotate  →  sealed key at epoch N+1
                                                          (to everyone else)
```

## Try it

**See it in 30 seconds.** The refusal line. A former member, a valid key, and a
conversation that moved without him.

**Run it in 5 minutes.** The group scheme lives in the SDK with the same wire
format in Rust and TypeScript:

```bash
git clone https://github.com/freeq-irc/freeq && cd freeq
cargo test -p freeq-sdk e2ee_group -- --nocapture
cd freeq-sdk-js && npm ci && npx vitest run e2ee_group
```

Both suites cover the same vectors: seal, open, rotate, and the epoch mismatch
above.

**Extend it in 30 minutes.** Write the steward. It is a bot that watches JOIN
and KICK in a channel, keeps the current epoch, seals to each admitted member's
published key, and rotates on departure. Everything it needs is in the SDK and
none of it requires a server change — which is the claim this whole thread
rests on, tested by doing it.

## What this does not claim

**No shipped client does this automatically.** The scheme, the wire formats and
the cross-language tests are real and runnable today. The steward that watches
membership and rotates without being asked is the missing piece, and this post
does not pretend otherwise. What is demonstrated here is the mechanism, driven
by hand.

**Not reviewed.** Like the ratchet before it: a small, readable
implementation of a construction that is standard in shape, with no external
audit and no published vectors. Judge it accordingly.

**Rotation is not retroactive.** Stated above, repeated here because it is the
sentence people skip: Bob keeps what Bob already had.

**A steward is a role with power.** Whoever holds it can seal the key to an
identity that policy never admitted. The scheme removes the *server* from the
trusted set; it does not remove the steward, and a compromised steward is a
compromised room.

**Kicking is not sealing.** The `MODE +b` and `KICK` above are ordinary IRC
enforcement — visible, auditable, and completely independent of the key. A room
that kicks without rotating has removed someone from the conversation and left
them able to read it if they can still see the traffic.

## What is rough

Rotation is a manual call in this post. Automating it is the steward bot above,
and until one ships, an operator has to remember.

Members publish one X25519 key for sealing. Rotating that key means re-sealing
every group they are in, and nothing coordinates that today.

A member who is offline during a rotation gets the new epoch when they next
receive the sealed envelope. Messages sent in between are readable to them
afterwards, because the envelope carries the key, not a time window.

## Come in

`#freeq` on `irc.freeq.at` is the channel. A plain client is asked to accept
the house rules on the way in — `POLICY #freeq ACCEPT`, then `JOIN #freeq`.

Source at [github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq). If
you write the steward before we do, that is the best possible outcome for this
post.

Next: two servers with no address between them.
