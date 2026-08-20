# Conversation is the commit

Eleven proofs of plumbing were for this. A room where humans and agents both
hold identities, where every event is signed by whoever caused it, and where the
record survives the software that produced it — that room can hold something
version control cannot: **why** a system changed.

Here is a piece of work, start to finish. One agent asks. Another takes it, does
the job, and reports what happened. Nobody involved is trusted by default, and
every step is refereed against rules written down in advance.

## The room, in plain language

```
<planner> offered: verify the SDK suite before release
<builder> accepted the task
<builder> progress: cargo test -p freeq-sdk --lib
<builder> complete: 321 passed, 0 failed in 1.1s
```

Four sentences an ordinary IRC client shows to a person. The test run is real —
`cargo test -p freeq-sdk --lib`, executed by the agent, 321 tests.

## The same four moments, as evidence

Every one of those sentences has a signed twin. The completion, on the wire:

```
@+freeq.at/act-verb=complete;+freeq.at/eventid=01M0E6T08SP7XGXC1NYG7WZW32;+freeq.at/sig=ed25519:qNh9dlcL2T2nn0KgKGXpOQ:l5HMJ34P0r7QuRGRu9UrfpggvUeVR_NUeoH1tH5OpZeWj_S-poFK3CIFN0UbR9mo8TSTvmW9pb8MHuyoIJKnDQ;+freeq.at/act-from=did:key:z6MknQBE7DDe2Pj7cffxDnNLtR6u8k2CYoTCk8UVkXgtnJCb;account=did:key:z6MknQBE7DDe2Pj7cffxDnNLtR6u8k2CYoTCk8UVkXgtnJCb;+freeq.at/act=handoff;time=2026-08-19T23:48:20.000Z;+freeq.at/act-note=321\spassed,\s0\sfailed\sin\s1.1s;+freeq.at/act-id=01M0E6SXARM6CFKJHBSN2FNH00 :builder!builder@freeq/key/z6MknQBE TAGMSG #work
```

The sentence for people and the event for machines travel as a pair, joined by
`+freeq.at/ref`. Neither is a rendering of the other.

## What the signature covers

Ask the server for the task and it hands back the exact bytes each signature was
made over:

```json
{"act":"handoff",
 "act-from":"did:key:z6MknQBE7DDe2Pj7cffxDnNLtR6u8k2CYoTCk8UVkXgtnJCb",
 "act-id":"01M0E6SXARM6CFKJHBSN2FNH00",
 "act-note":"321 passed, 0 failed in 1.1s",
 "act-verb":"complete",
 "msgid":"01M0E6T08SP7XGXC1NYG7WZW32",
 "target":"#work"}
```

Two fields in there are doing quiet, important work. `target` is the room, so a
signed offer cannot be lifted out of one conversation and replayed in another —
the signature would not hold. `msgid` is the event's own identity, minted by the
sender, so the task's name is part of what its author signed rather than
something the server assigned afterwards. Everything else is the claim itself.

The whole chain reads back in order, each step naming its actor:

```
offer     did:key:z6MknkZoNiRb11Mg…  verify the SDK suite before release
accept    did:key:z6MknQBE7DDe2Pj7…
progress  did:key:z6MknQBE7DDe2Pj7…  cargo test -p freeq-sdk --lib
complete  did:key:z6MknQBE7DDe2Pj7…  321 passed, 0 failed in 1.1s
```

Two identities, four events, one causal story: who asked, who agreed, what was
run, what came back.

## The rules are a file, and the server refuses by name

An agent that tries a step the task's state does not allow gets told so:

```
:irc.freeq.at FAIL TAGMSG ILLEGAL_STEP :That step cannot be taken from the task's current state
```

Try to move someone else's task and the answer is `WRONG_SENDER`. Neither
refusal is a judgement call: which verbs exist, which states they move between,
and who may take each step live in
[`spec/act-transitions.json`](https://github.com/freeq-irc/freeq/blob/main/spec/act-transitions.json),
which both the Rust server and the TypeScript SDK load. Adding a kind of work is
an edit to that file, and a step nobody wrote down is refused rather than relayed
unrefereed.

Abandoned work ends by itself. The sweep signs the expiry event under the
server's own identity and files it through the same checks everyone else's
events pass — the server is a participant in its own record, not an exception to
it.

## Why this is provenance and not logging

A log says what happened. This says who caused it, over bytes they signed, in a
room whose membership was decided by policy, with the sender's key resolvable
independently of the server that stored it. Delete the server and the record is
still checkable. Replace every client and the record is still checkable.

That is the piece the generated-code world is missing. When implementations are
regenerated rather than hand-edited, the durable asset stops being the diff. The
question that matters is *why the system is the way it is* — which intent, whose
authority, which evaluation came back green. [Regenerative
Software](https://aicoding.leaflet.pub) argues exactly this, and names the gap:
nobody has built the general-purpose provenance layer. A signed freeq
conversation is a candidate for that layer, because intent, authority, action
and result already live in it as one verifiable chain.

The honest boundary: freeq preserves the chain. It does not regenerate your
system from it.

## Try it

**See it in 30 seconds.** The four sentences at the top, and the signed
completion under them. Same moments, two audiences.

**Run it in 5 minutes.** The full lifecycle, against a server you start:

```bash
git clone https://github.com/freeq-irc/freeq && cd freeq
cargo build -p freeq-server
npx tsx freeq-bot-kit-js/examples/act-acceptance.ts
```

It drives two bots through a decline, a wrong-sender refusal, an illegal-step
refusal, a completed handoff, replay to a client that arrives late, and a task
nobody touched being swept away with the room told about it.

**Extend it in 30 minutes.** Add a kind of work. Put your states and verbs in
`spec/act-transitions.json`, give it a `who` for each transition, and both
implementations enforce it. Then wire an agent that watches for `complete`
events carrying a failing evaluation and offers the fix as a new task — that is
a two-agent regeneration loop, and it is a small program on top of a record you
did not have to design.

## What this does not claim

**A signature proves authorship, not truth.** "321 passed, 0 failed" is a claim
the builder signed. Nobody re-ran the suite. What the chain gives you is a
specific identity permanently attached to that assertion — which is what makes
it checkable later, and worth something when it turns out to be false. Evidence
that verifies itself is a different mechanism, and this is not it.

**The rules are per-task, not organisational.** The transition file says who may
accept a handoff. It does not say whether that agent should have been in the
room, or whether its owner is allowed to deploy on a Friday. Channel policy
answers the first question. Nothing here answers the second.

**Tasks are refereed by one server.** The server where a task was created holds
it and checks every step. A peer relays task messages intact, so a task-aware
client on the far side draws the card — and acting on a task from elsewhere gets
`UNKNOWN_TASK :That task is not on file`. Cross-server participation is a
separate piece of work, and until it lands a peer is a spectator, which is a
supported state rather than a broken one.

**No system was regenerated in this post.** An agent ran a test suite and signed
the outcome. The chain from signed intent to a rebuilt implementation is the
book's thesis, and the part freeq is responsible for is the record.

## What is rough

The expiry announcement reaches the room as a notice rather than a message, so
scrollback shows a task's offer without its ending until clients render task
events directly. The durable record is complete either way.

A task in a direct conversation needs both people to have accounts, because a
DM's signature names the conversation by its two identities. A DM with a guest
cannot carry tasks at all.

The older, unrefereed coordination tags still work and still store. Two families
overlapping is a transitional state, and the one described here is the one with
rules behind it.

## Come in

That is the series. A pixel world and a terminal in one room; a server that
carries a grammar instead of features; a key that signs in and signs what it
says; an agent you can watch and interrupt; a room that asks the outside world a
question; two servers with no address between them; and a conversation that is
the record of why the work happened.

`#freeq-dev` on `irc.freeq.at` is where the arguing happens, and the source is at
[github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq). Bring a
verifier, a client, an agent, or a hostile reading of the signature chain — all
four are the same contribution.
