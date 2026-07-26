# An agent can use my tokens. Can it prove I asked?

People are starting to run several agents against AI capacity they already pay for:
a pool of API credits, an underused subscription, a budget shared across a team.
The obvious way to let an agent draw on it is to give the agent the same
credential everyone else uses. That does share the capacity. It also erases who
authorised each use, and hands every agent the full authority of the account
holder.

Which turns a billing question into an identity one. You tell an AI agent to do
something. How does the agent know the instruction came from you?

In most setups it doesn't, and doesn't ask. The instruction arrives through an API
call or a chat webhook, and the agent trusts it because of where it arrived from.
Whoever holds the token can issue orders, the agent has no way to tell a real
instruction from an injected one, and afterwards there is nothing to point at
except a log line saying the agent did it.

freeq treats an instruction as a signed object instead of a message in a room. The
agent can check who signed it, whether that signer was authorised, and — when the
work is handed off rather than done immediately — whether the authorisation still
holds. Some of that is built and running. The part that makes an instruction
survive time is specified and not yet built, and that gap is most of what this
post is about.

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
| Verification of a *historical* action's signature | Not wired, though the keys are kept |

The last two are worth being blunt about. Capabilities constrain what can be
delegated; they do not yet gate any operation, so holding one is not yet the same
as being allowed. And while old keys are retained, nothing today walks back through
the log to verify an action signed last week — the live path verifies against the
sender's current session key. An offer accepted next Tuesday needs that walk-back,
and it doesn't exist yet.

## The part where I have to be careful

freeq has an early cost-reporting layer: agents report what work cost, channels set
budgets with warnings and limits, and a sponsor can be named as the identity funding
the work. It does not mediate model access and it does not settle credits, so it
cannot honestly claim to enforce shared AI spending. Agents report their own costs
and are asked to stop when they exceed a limit.

There is a sharper version of that admission. The one place freeq *does* put itself
between a caller and a paid model is its diagnostic interface, where the server
holds the provider key, callers are authenticated by DID, and nobody is handed the
credential. That path is mediated and unmetered. The budget system is metered and
unmediated. The resource freeq controls is the one it does not count.

Both halves are the same missing idea, and it is the one this post is actually
about: knowing which principal authorised an agent to consume a shared resource
comes before counting what it consumed.

## Why bother with signatures at all

Because "the agent did something expensive and nobody can say who told it to" is a
question every team running agents is about to face, and access logs are a poor
answer. A signed, addressed, stateful instruction gives you a different one: here
is the order, here is who signed it, here is the certificate showing that signer
was authorised to command this agent, and here is the agent's own signed
acceptance.

freeq has the identity and signing rails for that today, and a design for the
durable part. The gap between those two sentences is the interesting work.

If you are going to let agents draw on capacity you pay for, the thing to hand them
is bounded, attributable authority, and not your credential. That is a smaller
claim than "share your tokens safely," and it is the one I can currently back with
code.

---

*Code: `github.com/freeq-irc/freeq`. The RFC is a draft and explicitly asking for
holes to be poked in it.*
