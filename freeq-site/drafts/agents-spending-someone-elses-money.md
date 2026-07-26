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
inherits the parent's identity chain and dies when the parent is revoked. The
child is recorded with the capabilities requested for it. The PHASE-4 document
says those should be narrowed to the intersection of the parent's set and the
requested one, and this schema exists for scoped, TTL'd, rate-limited grants:

```sql
agent_capability_grants(
  channel, agent_did, capability, scope,
  ttl_seconds, requires_approval, rate_limit,
  granted_by, granted_at, expires_at, revoked_at)
```

Today, though, capabilities are recorded rather than enforced. The spawn handler
stores the requested list verbatim, with no lookup of the parent's own
capabilities and no intersection. `grant_capability()` has exactly one reference
in the codebase, which is its own definition, so nothing ever writes a row to
that table. The capabilities that do get stored are read in two places, both of
them display: the `WHOIS` reply and the REST agent endpoints. No code path
consults them before allowing an action.

An agent holding no capabilities can therefore spawn a child holding any:

```
Spawned agent: parent=capparent, capabilities=deploy, admin, task=-
```

That is the server's own confirmation, from a parent that was granted nothing.
Both of those behaviours now have tests, marked ignored with the reason, so they
run on demand and will pass when the feature lands:

```
cargo test -p freeq-server --test agent_native -- --ignored
```

A design document drifts from the code quietly. A test that is ignored for a
stated reason does not.

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
That is usually where things are broken, so I wrote tests for the seam. Two more
things turned up there, on top of the capability gap above.

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

Capability enforcement. The grants table, the TTLs, the rate limits and the
approval flag are all schema with no writer and no reader that gates anything. A
spawned agent can be recorded with any capability list its parent asks for, and
nothing checks it later, so narrowing is documentation rather than a boundary.

The "and pays" half of sponsorship. Nothing debits a sponsor's own balance when
an agent they fund spends, and there is no view of what an identity has sponsored
across channels. Notifying the sponsor is a prerequisite for that, not a
replacement.

So, precisely: identity delegation is real and enforced, and the certificate is
verified with four rejection paths under test. Spend reporting and budget limits
are real and enforced. Capability delegation is recorded but not enforced. Shared
credit is declared, now observable, and not yet settled.

The three gaps have one shape. Each sits between two features that were designed
separately and were never wired to each other.

---

*Code: `github.com/freeq-irc/freeq`. Design notes in
`docs/agent-native/PHASE-1-KNOWN-ACTORS.md` (delegation),
`PHASE-4-INTEROP-AND-SPAWNING.md` (spawning), and
`PHASE-5-ECONOMIC-CONTROLS.md` (budgets).*
