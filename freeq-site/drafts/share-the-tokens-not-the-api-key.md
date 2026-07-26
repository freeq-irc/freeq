# Share the tokens, not the API key

Most people paying for AI capacity are not using all of it. A Max subscription
sits idle overnight. A team's API credits reset monthly whether or not anyone spent
them. Meanwhile somebody else, or somebody else's agent, needs capacity right now
and doesn't have any.

The obvious way to share it is to hand over the credential. That works, and it also
gives the recipient your full authority, forever, with no record of which jobs were
theirs, and no way to take it back except rotating the key and breaking everything
else that uses it. You haven't lent them capacity. You've made them you.

Lending capacity properly means the authority to spend has to be its own object:
bounded by an amount and a period, attached to an identity rather than a secret,
attributable per job, revocable without collateral damage, and narrowing rather
than widening when it gets passed along. That is a delegation problem, not a
billing problem, and delegation is the part freeq is actually built around.

## How lending looks on the wire

An operator sets a budget in a channel and names who is funding it. The sponsor
defaults to whoever issues the command, so lending your own capacity is the
default case:

```
BUDGET #research amount=50;unit=usd;period=day;warn=0.8;hard=true
```

Agents working in that channel report what their work cost, signed, against that
budget:

```
@+freeq.at/sig=ed25519:kid:9f2c…:BASE64
 SPEND #research :amount=0.03;unit=usd;desc=claude-sonnet-4:1.2k-tokens;task=01JQ…
```

Spend aggregates across the delegation chain rather than resetting at each new
identity, so an agent that spawns helpers cannot multiply its allowance by
delegating, and a child inherits its parent's limit rather than falling through to
the channel default. Both of those took tests to establish, and one of them I got
wrong in an interesting way (below).

That is the shape of lending: your budget, someone else's work, bounded and
attributed. The next question is the one that matters, because a budget is only
meaningful if the jobs charged against it are really the jobs you authorised.

## Four things that have to be provable

**Who the human is.** freeq accounts are AT Protocol identities. You authenticate
over SASL by signing a server challenge with the key in your DID document, so the
server never holds a password and your identity is not something freeq issued you.
The nick in the channel is a display alias; the account is the DID.

**Who the agent is.** An agent gets its own keypair, which raises the obvious
question of who created it. The creator signs a `FreeqBotDelegation/v1` certificate
over the agent's DID and public key. The agent presents it after authenticating,
and the server verifies it against the creator's registered key. Four rejection
paths are tested: tampered signature, DID mismatch, no signature, creator never
registered.

That certificate proves exactly one thing: *this key was authorised by that key.*
It does not prove who currently holds the agent's key, what software is running, or
which model produced any particular action. Worth saying plainly, because
"cryptographic identity" is usually read as more.

**What was actually said.** Every client generates an ed25519 keypair, registers
the public half with `MSGSIG`, and signs each message it sends:

```
@msgid=01JQ…;+freeq.at/sig=ed25519:kid:9f2c…:BASE64 PRIVMSG #ops :ship it
```

The server verifies and relays the signature unchanged rather than re-signing, so
what a recipient checks is the sender's own signature, not the server's word about
it. Keys are stored append-only by `(did, kid)`, so registering a new key never
destroys an old one and a signature stays verifiable after the sender has
disconnected, rotated keys, or gone offline entirely.

**What an agent may pass on.** Agents delegate to other agents: an agent can spawn
a helper and hand it part of its own authority. That is where I found the sharpest
bug in this whole area. The spawn path recorded whatever capabilities were
requested for the child, without consulting what the parent held, so an agent
holding nothing could create a helper recorded as holding anything. The rule "you
cannot give away authority you do not have" sounds too obvious to test, which is
precisely why it went untested. A child's capabilities are now the intersection
with the parent's, the parent is told what was refused, and operators can confer
and withdraw capabilities with `AGENT GRANT` and `AGENT UNGRANT`.

## Handoff: an instruction that outlives the conversation

Everything above is about an instruction being *checkable*. The harder problem is
an instruction that has to be *durable*.

Agents call tools well and coordinate badly across time. When an agent goes
offline, in-flight work and its context evaporate. The usual answer is a separate
HTTP registry and inbox bolted on beside the chat system, which means agent work
lives somewhere humans aren't.

The freeq design, written up as [RFC v0.4](https://github.com/freeq-irc/freeq/blob/main/docs/HANDOFF-RFC.md)
with zapnap, models it natively instead. A handoff is a typed, addressed, signed,
*stateful* message: an action with a lifecycle (`offer → accept/decline →
progress → complete/fail/cancel`) correlated by a ULID and carried on IRCv3
client tags:

```
@+freeq.at/act=handoff;+freeq.at/act-verb=offer;+freeq.at/act-id=01JABC…;
 +freeq.at/act-to=did:plc:scholar;+freeq.at/act-title=Cite 3 sources on X;
 +freeq.at/act-caps=freeq.at/web-search;+freeq.at/sig=ed25519:kid:… TAGMSG #ops
```

Omit `act-to` and the same wire format becomes an open task: unassigned is encoded
as unassigned, and the channel it was posted in is the queue. Change the kind and
it becomes a deploy approval. The signature covers every `act-*` tag present,
sorted, so a new kind can add fields without breaking the canonical form, and
there is no such thing as an unsigned field riding along on a signed action.

Two consequences of doing this on chat rails rather than beside them. The room
watches: a handoff between two agents is visible to the humans in the channel as
it happens, rather than being an internal state transition you audit afterwards.
And an action can escalate. The same identity holding the same task can be pulled
into a live voice room when async coordination needs to become a conversation.
An HTTP inbox cannot do that.

## Where this actually stands

| | Status |
|---|---|
| Human identity via AT Protocol DID | Working |
| Creator-to-agent certificate | Working, 4 rejection paths tested |
| Per-message signatures, verified and relayed unchanged | Working |
| Signing keys retained append-only by `(did, kid)` | Working |
| Capability narrowing on delegation | Working, as of this week |
| Operator grant / withdrawal of capabilities | Working |
| Signing and verification primitives for `act` | In the SDK, 14 tests |
| `act` lifecycle: transition validation, state view | Specified, not built |
| Delivery addressed to an identity across servers | Specified, not built |
| Capability checks gating individual operations | Not built |
| Metering on the mediated model path | Not built |
| Consent before naming someone as sponsor | Not built |
| Debiting a sponsor's actual capacity | Not built |
| Verification of a *historical* action's signature | Not wired, though the keys are kept |

The last two are worth being blunt about. Capabilities constrain what can be
delegated; they do not yet gate any operation, so holding one is not yet the same
as being allowed. And while old keys are retained, nothing today walks back through
the log to verify an action signed last week — the live path verifies against the
sender's current session key. An offer accepted next Tuesday needs that walk-back,
and it doesn't exist yet.

## Three things that would have to be true before I'd lend you my capacity

**Being a sponsor has to be something you agreed to.** It isn't. `sponsor=<did>`
accepts any identity, and naming somebody other than yourself takes only channel
op. That DID is never asked. So an operator can stand up a channel, name an
unrelated person as the one funding it, and have every agent's spend attributed to
them. Since sponsors now get notified, they'd receive the warnings too. Lending is
a thing you consent to, and there is no consent step. The fix needs a consent
record or a capability the sponsor grants, which is a design decision rather than a
patch, so for now it's a failing test with a reason attached.

**The tokens have to actually come out of the sponsor's capacity.** They don't.
An agent makes its own model calls with whatever credential it already has, then
reports what it spent. Nothing debits the sponsor, so the accounting says one thing
and the money says another. This is the honest limit of the current system: it can
express and bound a loan of capacity, and it cannot yet make one.

Which points at where the work goes, and here the seam is almost funny. freeq does
mediate model access in exactly one place, its diagnostic interface, where the
server holds the provider key and callers are authenticated by DID so nobody is
handed the credential. That path is mediated and unmetered. The budget system is
metered and unmediated. The one paid resource freeq controls is the one it doesn't
count. A metered proxy sitting on the rails that already exist — DID-authenticated
callers, a server-held key, per-DID budgets, spend rollup — is what turns "your
budget authorised this" into "your capacity paid for this."

**Capabilities have to gate something.** They narrow correctly on delegation now,
but nothing consults one before allowing an operation, so holding a capability is
not yet the same as being permitted.

## Why bother with signatures at all

Because "the agent did something expensive and nobody can say who told it to" is a
question every team running agents is about to face, and access logs are a poor
answer. A signed, addressed, stateful instruction gives you a different one: here
is the order, here is who signed it, here is the certificate showing that signer
was authorised to command this agent, and here is the agent's own signed
acceptance.

freeq has the identity and signing rails for that today, and a design for the
durable part. The gap between those two sentences is the interesting work.

So: share the tokens, not the API key. freeq can express that loan today, bound it,
attribute it, roll it up across delegation, and prove who authorised each job in it.
It cannot yet make the tokens themselves flow, and the thing standing between those
two is a metered proxy rather than a new protocol.

---

*Code: `github.com/freeq-irc/freeq`. The RFC is a draft and explicitly asking for
holes to be poked in it.*
