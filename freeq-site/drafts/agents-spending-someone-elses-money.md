# Agents that spend someone else's money

freeq lets one identity delegate to another, and lets an agent report what its
work cost. This is a note on what those two features actually do, what I found
when I tested the join between them, and what is still missing.

## Delegation

An agent's account is a keypair, so "who created this agent" has to be proved
rather than claimed. A creator signs a `FreeqBotDelegation/v1` certificate over
the bot's DID and public key. The bot presents it after authenticating, via a
`PROVENANCE` command. The server verifies the signature against the creator's
registered key and stores the result. A record from my own repository:

```
at://did:plc:4qsyxmns…/xyz.freeq.agent.delegation/3mj3ayfzxks2g
  botDid:              did:key:z6MkeXfFnbEQkJt3vLjHGzZn7Pa5j7mVsUWmU9nnScgFA76Q
  creatorDid:          did:plc:4qsyxmns…
  revocationAuthority: did:plc:4qsyxmns…
```

If the certificate is missing or fails verification, the bot still connects. It
is just marked unverified, and its creator is unproven. The server log says so
plainly:

```
Provenance declaration stored nick=yokota-z6mkeyab verified=false
  reason=Not a FreeqBotDelegation/v1 cert; stored as-is
```

Four failure modes have tests: a tampered signature, a DID that doesn't match the
certificate, an unsigned certificate, and a creator who was never registered.

An agent can also delegate to another agent. `AGENT SPAWN` creates a child that
inherits the parent's identity chain and dies when the parent is revoked, and the
child is recorded with a narrowed capability list.

Narrowed is the part that was missing when I started writing this. The PHASE-4
document says a child receives the intersection of the parent's capabilities and
the requested ones. The code stored the requested list verbatim, with no lookup
of the parent's own capabilities and no intersection, so an agent holding nothing
could create a child holding anything. The server said so itself:

```
Spawned agent: parent=capparent, capabilities=deploy, admin, task=-
```

That is a parent that had been granted nothing. Meanwhile
`agent_capability_grants` existed with the columns you would want:

```sql
agent_capability_grants(
  channel, agent_did, capability, scope,
  ttl_seconds, requires_approval, rate_limit,
  granted_by, granted_at, expires_at, revoked_at)
```

and `grant_capability()` had exactly one reference in the codebase, which was its
own definition. Nothing ever wrote a row. The TTLs and rate limits described
grants that could not be made.

Both halves are now implemented, because publishing "the capability lists are
decorative" about a running server is not a thing to do.

What an agent holds in a channel is now answerable: a spawned agent holds exactly
the narrowed list it was created with, and a top-level agent holds its manifest's
channel-specific capabilities, its manifest defaults, and every live grant. A
child's own manifest is deliberately ignored, or delegation would be a formality
anyone could widen by publishing one. Declaring nothing means holding nothing.

Spawning intersects the request against that set, tells the parent what was
refused, and logs it:

```
Not conferred (you do not hold): deploy, admin
```

And grants have a writer. `AGENT GRANT <nick> <capability> [ttl=…]` is
operator-only, because conferring authority in a channel is a moderation act.
Withdrawing one uses `AGENT UNGRANT`, not `AGENT REVOKE` — a collision the tests
caught, because `AGENT REVOKE` already means the governance kill-switch for an
entire agent, which is a different act.

So the chain holds end to end: an operator grants a capability, the agent holds
it, a child may receive it, and a child may not receive what its parent never
held.

## Money

An agent reports what an action cost, on the same wire as everything else:

```
SPEND #factory :amount=0.03;unit=usd;desc=claude-sonnet-4:1.2k-tokens;task=01JQXYZ
```

A channel can set a budget with a unit (`usd`, `credits`, `api_calls`, `tokens`),
a period, a warning threshold, and a hard limit. Cross the threshold and the
channel is told. Cross the limit with `hard_limit` set and the agent is told to
stop, over a `+freeq.at/governance=budget_exceeded` tag it can act on.

That much works, and has tests.

## What testing the join found

The two features were designed in separate documents. Neither mentions the other.
That is usually where things are broken, so I wrote tests for the seam.

**My first guess was wrong.** I expected a parent at its hard limit to be able to
spawn a child and keep spending, because spend is keyed by DID and the child has
its own. It cannot: a spawned child gets a synthetic `did:freeq:spawn:<ulid>` and
a *virtual* session that the parent relays. There is no second connection, so the
charge lands on the parent. The structure prevents the hole. I wrote the roll-up
anyway, because the schema permits a real agent to be recorded as a child, and if
that ever happens the limit should still hold. That is
`sum_spend_with_descendants`, budget inheritance down the spawn chain, and seven
tests covering chains, cycles, and despawned children whose spend must not
vanish.

**The second guess was right, and duller than a bypass.** A budget names a
sponsor:

```rust
/// DID of the budget sponsor (who gets notified and pays).
pub sponsor_did: String,
```

It was parsed from the command, written into the policy, and never read again.
The field that expresses *these are someone else's credits* did nothing. Budget
warnings went to the channel, which is exactly where someone funding the work
tends not to be. The test failed the way an unimplemented feature fails:

```
Timeout waiting for: sponsor is notified that their budget is nearly spent
```

Warnings and blocks now reach every live session of the sponsor's DID, and stay
silent if they are offline.

## What is still missing

Capabilities constrain delegation, but they do not yet gate actions. Narrowing
decides what a child can be given; nothing consults a capability before allowing
an operation. `requires_approval` and `rate_limit` are still columns nobody reads.
That one is left deliberately: making `spawn_agent` a required capability would
refuse every agent that has never been granted anything, which is all of them
today. It needs a migration, not a patch, and it has a test waiting for it:

```
cargo test -p freeq-server --test agent_native -- --ignored
```

The "and pays" half of sponsorship. Nothing debits a sponsor's own balance when
an agent they fund spends, and there is no view of what an identity has sponsored
across channels. Notifying the sponsor is a prerequisite for that, not a
replacement.

So, precisely: identity delegation is enforced, and the certificate is verified
with four rejection paths under test. Capability delegation is now enforced at the
point of delegation, and grants can be conferred and withdrawn. Spend reporting
and budget limits are enforced. Action-level capability checks are not
implemented. Shared credit is declared, now observable, and not yet settled.

Every gap here had one shape. Each sat between two features that were designed in
separate documents and never wired to each other, and each was found by writing a
test for the join rather than by reading either document.

---

*Code: `github.com/freeq-irc/freeq`. Design notes in
`docs/agent-native/PHASE-1-KNOWN-ACTORS.md` (delegation),
`PHASE-4-INTEROP-AND-SPAWNING.md` (spawning), and
`PHASE-5-ECONOMIC-CONTROLS.md` (budgets).*
