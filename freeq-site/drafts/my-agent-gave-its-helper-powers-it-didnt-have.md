# My AI agent gave its helper powers it didn't have

An AI agent working in a chat room can hire a helper. It hands the helper some of
its own authority, the helper does a piece of the job, and the bill goes to
whoever is funding the work.

That is three separate things that all have to be right: who an agent is, what it
is allowed to do, and who pays. I built them separately in freeq, then wrote tests
for the places where they meet. The helper turned out to be able to receive
authority its parent never had, and the person paying was never told anything at
all.

Giving agents cryptographic identity was the easy part. Several systems do it now,
freeq among them, and it solves attribution: you can tell which agent produced an
action, and prove a human authorised its key.

It does not solve what happens next. Once agents have identities they start
delegating to each other, spawning helpers, and consuming resources that somebody
else is paying for. Six properties have to hold for that to be safe:

1. Delegation is transitive, so authority moves further than you can see.
2. Authority must narrow as it moves. Nobody may confer what they do not hold.
3. Revocation must propagate through the delegation graph.
4. Resource usage must aggregate across that graph, not reset at each new identity.
5. The principal funding the work is usually not present where the work happens.
6. Most of the failures live in the joins between those mechanisms.

I had built the pieces separately in freeq. This is what happened when I wrote
tests for the joins.

## The pieces

A creator signs a `FreeqBotDelegation/v1` certificate over the bot's DID and
public key. The bot presents it after authenticating, and the server verifies the
signature against the creator's registered key. Four rejection paths are tested:
tampered signature, mismatched DID, unsigned, creator never registered.

That certificate proves one thing precisely: *this key was authorised by that
key.* It does not prove who currently controls the agent key, what software is
running, which model produced an action, or that the runtime was not compromised
a minute later. Worth stating plainly, because "cryptographic identity" tends to
be read as more than it is.

An agent can spawn a child, which gets a narrowed capability list and dies with
its parent. An agent reports what its work cost:

```
SPEND #factory :amount=0.03;unit=usd;desc=claude-sonnet-4:1.2k-tokens;task=01JQXYZ
```

A channel sets a budget with a unit, a period, a warning threshold and a limit,
and names a sponsor: the identity whose resources fund the work.

## Four things the joins turned up

**A parent could confer authority it did not have.** PHASE-4 says a child receives
the intersection of the parent's capabilities and the requested ones. The code
stored the requested list verbatim. An agent holding nothing could create a child
holding anything, and the server said so itself:

```
Spawned agent: parent=capparent, capabilities=deploy, admin, task=-
```

**The grants table had no writer.** `agent_capability_grants` had columns for
scopes, TTLs, rate limits and approval flags, and `grant_capability()` had exactly
one reference in the codebase: its own definition. Nothing ever wrote a row, so
an agent could only ever hold what its own manifest claimed about itself.

Both are fixed. What an agent holds is now computable: a spawned agent holds
exactly the list it was created with, a top-level agent holds its manifest's
channel capabilities plus defaults plus live grants, and a child's own manifest is
deliberately ignored — otherwise delegation is a formality anyone can widen by
publishing one. Spawning intersects against that set and says what it refused.
`AGENT GRANT` and `AGENT UNGRANT` are operator-only. (`UNGRANT`, because a test
caught me overloading `AGENT REVOKE`, which already means the governance
kill-switch for an entire agent.)

**The sponsor was never told anything.** `sponsor_did` is documented as "who gets
notified and pays". It was parsed, stored, and never read again. Budget warnings
went to the channel, which is exactly where someone funding the work tends not to
be. Warnings and blocks now reach the sponsor's live sessions.

**Revocation does not propagate.** Children are torn down on TTL expiry, on
explicit despawn, and when the parent's connection drops. They are *not* torn down
when the parent is revoked, because governance revoke sets no server state at all:
it writes the audit log and signals the agent. A revoked-but-connected parent
keeps its descendants. This one is not fixed.

And one hypothesis of mine was simply wrong. I expected a parent at its limit to
be able to spawn a child and keep spending, since spend is keyed by DID. It
cannot: a spawned child gets a synthetic DID and a *virtual* session the parent
relays, so there is no second connection and the charge lands on the parent. The
structure prevented it. I added the roll-up anyway, because the schema permits a
real agent to be recorded as a child.

## Threat model, stated bluntly

These controls assume a cooperative agent. The agent decides whether to send
`SPEND` at all, what amount to claim, and whether to obey the stop signal. Nothing
independently meters what a model call cost, and no receipt from the provider is
verified. The action being paid for happens somewhere freeq does not sit.

So this defends against implementation errors, accidental privilege widening, and
honest agents drifting over budget. It does not defend against a malicious or
compromised runtime. Enforcing a spending limit against an untrusted agent
requires mediating the paid resource or verifying externally issued receipts, and
freeq does neither today.

That also makes "hard limit" the wrong words for what happens at the ceiling. The
server broadcasts a notice and sends the agent a
`+freeq.at/governance=budget_exceeded` tag. It prevents nothing. It is an
advisory stop signal to a cooperating process.

## Where this actually stands

| Property | Status |
|---|---|
| Creator-to-agent key authorisation | Cryptographically verified, 4 rejection paths tested |
| Delegation narrowing (cannot confer what you lack) | Enforced |
| Capability grant / withdrawal by operators | Implemented |
| Capability checks on server operations | Not implemented |
| Child torn down with parent | Enforced on TTL, despawn, and parent disconnect |
| Child torn down on parent revocation | Not implemented |
| Governance pause / revoke | Logged and signalled, not enforced |
| Cost reporting | Self-reported by the agent |
| Cost aggregation across the delegation graph | Implemented |
| Independent cost verification | Not implemented |
| Sponsor notification | Implemented, while the sponsor is connected |
| Sponsor debit or settlement | Not implemented |
| Budget enforcement against a malicious agent | Not implemented |

Read plainly: the delegation half has real invariants now, and the money half is
telemetry. Nothing debits a sponsor. No balance moves. An agent does not spend
someone else's money so much as tell the room what it claims to have spent, in a
place the funder can see.

## The part worth keeping

Every gap above sat between two features that were designed in separate documents
and never wired to each other. None of them were found by reading either document.
Each showed up when I asked a question that spanned both: can this agent confer
that, does this limit still hold one hop further out, does the person paying know.

Agent identity is becoming table stakes. The interesting problems start one level
up, and they are mostly seams. "You cannot give away authority you do not have" is
the kind of rule that sounds too obvious to test, which is exactly why my server
broke it.

---

*Code: `github.com/freeq-irc/freeq`. The two unimplemented rows above have tests,
marked ignored with their reason, so the gaps run on demand rather than living in
a document:* `cargo test -p freeq-server --test agent_native -- --ignored`
