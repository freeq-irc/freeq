# Your identity signs in, and signs what it says

Here is the question this post exists to answer. You receive a message from a
channel. Can you determine who produced it without trusting the relay that
delivered it?

The honest answer today is: partly, and the part that is missing is specific
enough to name. This post shows the chain, and then shows where it currently
stops.

## Four different things

Most arguments about identity go wrong by collapsing these together. Keep them
apart.

**Authentication** is the current connection proving it holds a key.
**Authorization** is the account saying that a particular session key may speak
for it. **Authorship** is a single message carrying a signature. **Revocation**
is the account withdrawing that permission before the key would otherwise
expire.

A system can do the first and third well and still be weak, because those two
only establish that *some* key signed, and that *some* key authenticated. The
link between "the key that signed" and "the account you think it belongs to" is
authorization, and it is the interesting one.

## The chain

```
DID controls a root key
  -> a session signing key is authorized to speak for that DID
  -> the connection authenticates with ATPROTO-CHALLENGE
  -> each message carries +freeq.at/sig over its bytes
  -> a third party verifies the signature and the authorization
```

The first four steps run today. Start at the bottom and work up.

A message arrives:

```
@account=did:plc:4qsyxmnsblo4luuycm3572bq;msgid=01KTC7AY5JPAZ8GXQVYTVJG327;
+freeq.at/sig=qSFPlTzaA4w7dKktQDZsP6S-f5pL4Vm8ja-5y1sYyS_lYoT2TyddGlq-XkZH3fTNMIv2tl-EY9JH7TE0hVLdDA
:chadfowler.com!chadfowler.com@freeq/plc/4qsyxmns PRIVMSG #lobby :this server is lit
```

Fetch the key that signed it:

```
curl https://irc.freeq.at/api/v1/signing-keys/did:plc:4qsyxmnsblo4luuycm3572bq
```

```json
{"algorithm":"ed25519","did":"did:plc:4qsyxmnsblo4luuycm3572bq",
 "encoding":"base64url","public_key":"Oq-cs6779KVZ6LcNEkxAvWB8adDioyQU1u8DvN7icyQ",
 "source":"key-store"}
```

Verify the signature over the message bytes with any ed25519 library, about
twenty lines. If it checks, you know the message was not altered in transit and
that it was signed by the holder of that key. That is independently verifiable
message authorship and integrity, and it is a narrower claim than it sounds. It
is not a legal-grade claim about a person's intent, and freeq does not make one.

Authentication is a separate step from signing. A connection proves control of a
key by answering a challenge, using a single new SASL mechanism called
`ATPROTO-CHALLENGE`. The server sends a nonce, the client signs it, the private
key never leaves the device. There is no password and no registration.

## did:key and did:plc are not the same trust model

Both strings start with `did:`, and that is where the similarity ends.

A `did:key` **is** its public key. Resolution is local: you parse the string and
you have the key. Nothing to fetch and nobody to ask. It cannot rotate, because
rotating means becoming a different identity. Agents use these, which is why
`cartographer` appears as `freeq/key/z6Mkp5we`.

A `did:plc` is a pointer into a directory. Resolving it means fetching a
document that can change over time, which is what makes key rotation and account
recovery possible, and which also means you depend on that directory. Humans
signing in with Bluesky get these.

For a `did:key`, a verifier needs nothing but the message. For a `did:plc`, a
verifier has to go somewhere to learn what the account currently authorizes. You
can fetch that document without asking freeq anything:

```
curl https://plc.directory/did:plc:4qsyxmnsblo4luuycm3572bq
```

```json
{"id":"did:plc:4qsyxmnsblo4luuycm3572bq","alsoKnownAs":["at://chadfowler.com"],
 "verificationMethod":[{"id":"#atproto","type":"Multikey",
 "publicKeyMultibase":"zQ3shhEsEspoGmdb84GSCAx7ULBhMj3CsoGrvEcWTjdMUeQ3v"}], ...}
```

That is the account's root of trust, served by a directory that is not freeq.

## Where the chain currently stops

Compare the two documents above and you will see the gap immediately.

The signing key is `Oq-cs6779KVZ6LcNEkxAvWB8adDioyQU1u8DvN7icyQ`, and it came
from `irc.freeq.at`. The DID document from `plc.directory` does not mention it.
It lists the account's atproto key and nothing about freeq session keys.

So if you fetch the message from freeq and the key from freeq, you have verified
integrity against a key the relay handed you. A hostile relay that wanted to
attribute a message to me could serve you a key it controls, and your
verification would pass. The signature proves the message was not tampered with
in flight. It does not, on its own, prove the account authorized that key.

Closing this requires a signed authorization: an object, signed by the key the
DID document actually names, that says this ed25519 session key may speak for
this DID until some expiry. Then a verifier fetches the DID document from
`plc.directory`, checks the authorization against the root key, checks the
message against the session key, and never has to trust the relay for anything
except delivery.

That object exists for agents. Signed delegation certificates for `did:key`
identities landed in the bot kit in July. For `did:plc` humans it does not exist
today, which is the case most readers will test first.

We could have written this post without that paragraph. The claim would have
sounded stronger and been wrong, and the first cryptographer to read it would
have found the hole in about a minute.

## Try it

**See it in 30 seconds.** Fetch a signing key with the curl above and read the
JSON.

**Run it in 5 minutes.** Capture a signed message from `#lobby`, fetch the key,
verify the signature with an ed25519 library.

**Extend it in 30 minutes.** Write a verifier that does the honest thing: check
the signature, then check whether the key binding can be confirmed independently
of the relay, and **flag every message where it cannot**. Today that verifier
will flag every `did:plc` message on the server. That is the correct output, and
it is the most useful contribution anyone could make to this proof.

## What this does not claim

A signature proves integrity and authorship relative to a key. Binding that key
to an account is a separate step, complete for agents and incomplete for humans.

Nothing here protects message contents in an unencrypted channel. The relay sees
plaintext. Encryption is a different mechanism and a later proof.

A verified signature says nothing about whether the signer was compromised.

## What is rough

The human key binding, described above, is the largest open item and the reason
this post is proof 3 rather than a finished story.

Revocation for session keys is expiry-based. Immediate revocation for `did:plc`
sessions is not implemented, so a compromised session key stays valid until it
expires.

There is no published test vector set. If you write a verifier, you are working
from the running server rather than from a specification with fixtures, and that
is a gap we should close.

## Come in

`#freeq-dev` on `irc.freeq.at`. If you build the flagging verifier, that is where
to bring it, and it will be the most welcome kind of contribution: the kind that
tells us we are wrong in public. `#freeq` is the general channel.

Next: we give one of these identities to something that is not a person, and
watch it work from irssi.
