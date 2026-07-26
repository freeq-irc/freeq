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

freeq is unusually well-shaped for that problem. [The first post in this
series](https://freeq.at/blog/what-is-freeq/) explains the foundation: it's an IRC
server that speaks the protocol a 1999 client speaks, except every participant holds a
cryptographic key. This post is about what those keys become useful for once agents
start consuming resources on somebody else's behalf.

(If protocol machinery is not your idea of a good time, the same substrate is rendered
at [FreeqWorld](https://world.freeq.at/) as a multiplayer town: rooms are live
channels, people and agents keep their DID-derived characters, and federation appears
as travel between independently operated towns.)

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

That was the state when I started writing this. freeq put itself between a caller and
a paid model in exactly one place, its diagnostic interface, where the server holds
the provider key and callers are authenticated by session bearer to DID, so nobody is
handed the credential. That path recorded no spend and checked no budget. Meanwhile
the budget system counted carefully, over numbers agents reported about calls freeq
never saw. **The one paid resource freeq controlled was the one it didn't count.**

Writing that sentence down made it impossible to leave alone, so the two halves are
now joined.

## The join, now that it exists

`POST /api/v1/model/chat/completions` is an OpenAI-compatible call made *by the
server*, charged to a channel budget:

```
Authorization: Bearer <session>
{ "channel": "#research", "model": "provider/small",
  "messages": [{ "role": "user", "content": "…" }] }
```

The caller authenticates as a DID and must be in the channel it names. The budget is
resolved through the delegation chain, spend for the period is totalled, and the
decision happens *before* dispatch. If the budget is exhausted, the response is `402`
and **no upstream request is made at all** — which is the difference between a limit
and a request to stop. The tests assert that by counting hits on a mock provider, so
"we refused" cannot quietly mean "we asked nicely and it went ahead".

The charge is computed from the provider's own token counts rather than the caller's
claim, priced per model, and recorded against the budget:

```json
"freeq": { "charged": 4, "unit": "credits", "channel": "#research",
           "sponsor": "did:plc:…", "spent_after": 17 }
```

Two details that took a test to get right. An unpriced model is not free — it falls
back to a deliberately expensive default, because "ask for a model nobody priced" is
the obvious way to get unlimited capacity. And a declared `max_tokens` is billed as
output in the pre-call estimate, so the last call before a ceiling can't overshoot it
by an unbounded amount. Without a declared maximum, the limit is enforced at call
granularity and can be passed by one call's cost, which is the honest bound and is
what the test pins.

The credential never leaves the server. So withdrawing capacity means editing a
budget, not rotating a key and breaking everything else that used it.

The proxy is not the protocol. It is where the protocol's decision becomes
enforceable. Anyone can put a metering proxy in front of a model; what makes this one
answer "should this call happen" is everything upstream of it — the identities, the
delegation graph, the named sponsor, the narrowing, the channel membership, and the
signed context of the job being paid for.

## What is still missing

Three gaps, all found by writing tests rather than reading designs:

**Being a sponsor requires no consent.** `sponsor=<did>` accepts any identity, and
naming someone other than yourself takes only channel op. That DID is never asked. An
operator can stand up a channel, name an unrelated person as its funder, and have
every agent's spend attributed to them, and since sponsors are now notified, send
them the warnings too. Lending is something you agree to.

**Externally incurred spend is still self-reported.** Calls through freeq's model
endpoint are mediated, measured from the provider's token counts, and refused before
dispatch when the budget is exhausted. An agent can still call a model somewhere else
and file a `SPEND` report afterwards, and freeq cannot verify that report, detect an
omitted one, or prevent the external call. So the two paths have genuinely different
guarantees: the mediated path enforces a budget, and `SPEND` is accounting for
cooperative runtimes. `hard=true` means "no provider call" on the first and "please
stop" on the second.

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
| Identity rails: DID auth, creator-to-agent certificate, per-message signatures, keys kept by `(did, kid)` | Working |
| Metered model path, credential held server-side | Working |
| Budget refuses before any upstream call | Working, verified by hit count |
| Cost from the provider's token counts | Working |
| Named sponsor, spend rollup, budget inheritance by children | Working |
| Capability narrowing on delegation, operator grant and withdrawal | Working |
| Consent before naming someone as sponsor | Not built |
| Lending a *lender's own* capacity, not the operator's | Not built |
| Capability checks gating operations | Not built |
| Durable signed jobs (`act` lifecycle, identity-addressed delivery) | Specified, primitives in the SDK |
| Verifying a historical action's signature | Not wired, though keys are kept |

## The last mile, and whose pool it is

So: share the tokens, not the API key. freeq can now delegate bounded access to model
capacity without exposing the provider credential. The caller authenticates as its own
identity, the budget is checked before dispatch, usage is measured from the provider's
response, and an exhausted budget stops the upstream call from happening.

The capacity being shared today belongs to the server operator. There is one provider
credential and the server holds it. So this is real, revocable delegation of an
operator-funded pool, and not yet a general mechanism for me to lend you capacity from
my own account.

Making the pool personal needs three more pieces: a lender can register a credential or
funding source under their own control, naming that lender as a sponsor requires their
signed consent, and the resulting capability gates the model operation itself. Then
"your budget authorised this" becomes "your capacity paid for this".

---

*Code: `github.com/freeq-irc/freeq`. The gaps above are `#[ignore]`d tests with
their reasons attached, so they run on demand rather than living in a document:*
`cargo test -p freeq-server --test agent_native -- --ignored`
