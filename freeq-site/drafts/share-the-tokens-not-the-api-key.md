# Share the tokens, not the API key

Block's [Buzz](https://github.com/block/buzz) made the multi-agent workspace legible
this month: humans and agents in the same room, every message and workflow step a
signed event in one log, and agents holding their own keys rather than borrowing a
human's. Its README puts the principle better than most specs do: *"scoped by
identity, not by permission flags, the same way you'd scope a teammate."*

Which surfaces the next question. When five agents wake up to work, whose model
allowance are they spending?

People and teams increasingly pay for AI capacity that goes unused for long
stretches: subscription allowances, prepaid credits, an organisational budget,
a box running local inference. Meanwhile somebody else, or somebody else's agent,
needs capacity right now and has none. Providers generally don't make that capacity
safely delegable, and handing over your account credential is usually both
prohibited and reckless.

So the missing primitive isn't another shared API key. It's the ability to delegate
a bounded amount of capacity to a person or an agent you choose, and keep
attribution, revocation, and control while they use it.

## What a loan of capacity would require

Hand someone your credential and you've given them whatever authority that key
carries, for as long as it stays valid, with no cryptographically attributable
record of which jobs were theirs, and no way to withdraw it except rotation that
breaks everything else using the same key. That isn't lending. It's making them you.

A real loan needs the authority to spend to be its own object:

- **consented to** by the party whose capacity is being lent,
- **bounded** by an amount and a period,
- attached to an **identity** rather than a secret,
- **attributable** per job, to the instruction that authorised it,
- **revocable** without collateral damage,
- and **narrowing** rather than widening as it's passed along.

That is a delegation problem, not a billing problem.

## What freeq has today

An operator sets a budget in a channel and names who funds it. The sponsor defaults
to whoever issues the command:

```
BUDGET #research amount=50;unit=usd;period=day;warn=0.8;hard=true
```

Agents working there report what their work cost, signed, against that budget:

```
@+freeq.at/sig=ed25519:kid:9f2c…:BASE64
 SPEND #research :amount=0.03;unit=usd;desc=claude-sonnet-4:1.2k-tokens;task=01JQ…
```

That is the protocol shape a loan needs: a named sponsor, someone else's attributed
work, and a limit that follows the delegation chain. Today freeq enforces that limit
over *reported* spend. It does not mediate or debit the underlying model capacity, and that
gap is what this post is really about.

Around it, the identity rails are real:

- **Who the human is.** Accounts are AT Protocol DIDs. You authenticate by signing a
  server challenge with the key in your DID document, so the server holds no password
  and didn't issue your identity.
- **Who the agent is.** An agent has its own keypair, and its creator signs a
  `FreeqBotDelegation/v1` certificate over the agent's DID and public key. Four
  rejection paths are tested: tampered signature, DID mismatch, missing signature,
  creator never registered. That proves one thing precisely, namely that this key was
  authorised by that key, and nothing about who holds the key now or what software
  is running.
- **What was said.** Every client registers an ed25519 key with `MSGSIG` and signs
  each message. The server verifies and relays the signature unchanged rather than
  re-signing, and keys are stored append-only by `(did, kid)` so a signature stays
  verifiable after the sender rotates or disconnects.
- **What can be passed on.** Spend aggregates across the delegation chain instead of
  resetting at each new identity, and a child inherits its parent's limit rather than
  falling through to the channel default. Capabilities narrow on delegation: a child
  gets the intersection with its parent's set, so an agent can't confer authority it
  doesn't hold. That last one was a bug until this week. The spawn path recorded
  whatever was requested, so an agent holding nothing could create a helper recorded
  as holding anything.

## The seam where it stops

Testing the joins between those systems is where the interesting findings were, and
the sharpest one is a two-line observation:

> The budget system is metered and unmediated. The model path is mediated and
> unmetered.

freeq does put itself between a caller and a paid model in exactly one place, its
diagnostic interface, where the server holds the provider key and callers are
authenticated by session bearer to DID, so nobody is handed the credential. That path
records no spend and checks no budget. Meanwhile the budget system counts carefully,
over numbers agents report about calls freeq never saw. **The one paid resource freeq
controls is the one it doesn't count.**

Three more gaps, all of them found by writing tests rather than reading designs:

**Being a sponsor requires no consent.** `sponsor=<did>` accepts any identity, and
naming someone other than yourself takes only channel op. That DID is never asked. An
operator can stand up a channel, name an unrelated person as its funder, and have
every agent's spend attributed to them, and since sponsors are now notified, send
them the warnings too. Lending is something you agree to.

**Spend is self-reported.** An agent decides whether to send `SPEND` at all, what
amount to claim, and whether to obey the stop signal. Nothing meters what a call
actually cost and no provider receipt is verified. These controls defend against
implementation errors and honest drift, not a malicious runtime.

**Capabilities don't gate operations.** They narrow correctly on delegation now, but
nothing consults one before allowing an action, so holding a capability isn't yet the
same as being permitted.

## Signed jobs, because a loan outlives a conversation

A sponsored job needs one more property: it has to survive the participants going
offline. If I fund work in a channel and your agent accepts a task on Tuesday and
finishes it on Thursday, the offer, the acceptance and the completion all have to
remain verifiable after the sessions that produced them are gone — otherwise
"attributable per job" quietly means "attributable until someone reconnects".

That's specified as a typed, addressed, signed, stateful action with a lifecycle
(`offer → accept/decline → progress → complete/fail/cancel`) carried on IRCv3 client
tags, written up as [RFC v0.4](https://github.com/freeq-irc/freeq/blob/main/docs/HANDOFF-RFC.md)
with zapnap. The signing primitives are built and tested in the SDK. The lifecycle (transition
validation, materialised state, delivery addressed to an identity across servers) is
not, and neither is walking back through the log to verify an action
signed last week. That deserves its own post, and it's the piece that turns a
sponsored task into a durable obligation.

## Where this actually stands

| | Status |
|---|---|
| Human identity via AT Protocol DID | Working |
| Creator-to-agent certificate | Working, 4 rejection paths tested |
| Per-message signatures, verified and relayed unchanged | Working |
| Signing keys retained append-only by `(did, kid)` | Working |
| Named sponsor on a channel budget | Working |
| Reported-spend limits, warn and stop signal | Working |
| Spend rollup across the delegation chain | Working |
| Budget inheritance by spawned children | Working |
| Capability narrowing on delegation | Working, as of this week |
| Operator grant / withdrawal of capabilities | Working |
| `act` signing primitives | In the SDK, 14 tests |
| Consent before naming someone as sponsor | Not built |
| Metering on the mediated model path | Not built |
| Debiting a sponsor's real capacity | Not built |
| Capability checks gating operations | Not built |
| `act` lifecycle and identity-addressed delivery | Specified, not built |
| Verifying a historical action's signature | Not wired, though keys are kept |

## The last mile

So: share the tokens, not the API key. freeq can already represent a sponsor,
authenticate the participants, sign the messages around the work, account for
reported spend, and keep that accounting from resetting when an agent delegates to
children. It cannot yet turn that representation into a real loan of capacity.

The missing pieces are concrete: sponsor consent, operation-level capability checks,
and a metered model path that holds the provider credential and debits the authorised
budget. Nothing here needs another identity system. It needs the last mile where
authority becomes spend.

---

*Code: `github.com/freeq-irc/freeq`. The gaps above are `#[ignore]`d tests with
their reasons attached, so they run on demand rather than living in a document:*
`cargo test -p freeq-server --test agent_native -- --ignored`
