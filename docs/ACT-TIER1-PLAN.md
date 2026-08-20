# Tier 1 of RFC v0.5: receipts, `bounty`, `act-replaces`

The three pieces of RFC v0.5 (`freeq.at/act`) that are proposed or specified but
have no code behind them, scoped to **one server** — the federation phase
(defer queues, home routing, orphans) is explicitly out.

RFC: https://gist.github.com/zapnap/2510b695c9d5e1cf99aac2fba709d307
Everything here extends the substrate merged in PR #60 and realigned to the
v0.5 canonical on 2026-08-20 (`6732f129`, `24a71a9a`, `a9f17194`).

## Ground rules (read before writing code)

- **Rules are data.** Behavior differences between kinds live in
  `spec/act-transitions.json`, never in `match kind` arms. If a new kind needs
  code, the substrate failed its own test — fix the schema, not the validator.
- **Both SDKs move in lockstep.** Rust (`freeq-sdk/src/act.rs`,
  `act_transitions.rs`) and TypeScript (`freeq-bot-kit-js/src/act*.ts`,
  `freeq-sdk-js/src/signing.ts`) load the same transitions file and must reach
  the same verdict on every sequence in it. New wire shapes get frozen vectors
  in `spec/act-signing-vectors.json` that both implementations reproduce
  byte-for-byte — follow the existing conventions in that file exactly.
- **Every refusal has one approved sentence and a named test.** Study the
  existing copy in `spec/act-transitions.json` (`refusals`) and
  `freeq-server/src/connection/act.rs` before writing new copy; match the
  voice. Each new refusal gets a test in `freeq-server/tests/act_gate.rs`
  that triggers exactly it.
- **The canonical covers whatever is present.** `act-*` tags are swept into the
  signed document automatically; adding tags (`act-subject`, `act-replaces`,
  `act-bid`) requires **no** canonical change. Do not special-case them in
  signing code.
- **The log is the record; the view is derived.** Any new view column must be
  filled by the rebuild path too, and the rebuild-matches test
  (`freeq-server/src/db.rs` tests) must cover it.
- **House prose style** for comments and commit messages: plain sentences that
  say why, no bullet-list changelogs, no "Add X" — read recent commits by nap
  (`6732f129`, `24a71a9a`) and match them.

---

## 1. Receipts — the home's signed confirmation (`confirm` / `act-subject`)

RFC section "Confirmation: the receipt". Single-server resolution of the RFC's
undefined trigger ("an action other servers are involved in"): **always emit**.
Receipts are small, replay is free, and a rule with no condition cannot be
implemented wrong. Note this decision in a comment where the receipt is minted.

### What to build

When the server **files a participant-authored state transition** — a verb
whose `from` state differs from its `to` state: `accept`, `claim`, `decline`,
`complete`, `fail`, `cancel` — it appends one home-signed event:

```
@+freeq.at/act=<kind>;+freeq.at/act-verb=confirm;+freeq.at/from=did:web:<server>;
 +freeq.at/eventid=<fresh ULID>;+freeq.at/act-id=<action id>;
 +freeq.at/act-subject=<eventid of the confirmed event>;+freeq.at/sig=… TAGMSG <venue>
```

Not for: `offer` (opening creates the action; nothing raced it), `progress`
(additive, `from == to`), `expire`/system verbs (home-signed already — the
degenerate case, per the RFC).

### Mechanics

- **Mint and sign exactly as `expire_task` does** (`connection/act.rs`): server
  DID (`did:web:<server_name>`), fresh ULID, standard act canonical (the
  `act-subject` tag is swept like any other), `sign_canonical` with the server
  key, filed through `apply_act_event` with `from_system: true`.
- **`confirm` is generic, not a table row.** The validator recognizes it before
  the per-kind verb lookup. A client that sends `act-verb=confirm` is refused
  with the existing `WRONG_SENDER` machinery and a new approved sentence
  ("Only the action's home confirms" — adjust to match the copy sheet's voice).
  It must not fall through to `UNKNOWN_VERB`: that answer would imply a kind
  could add its own `confirm` row, which the RFC forbids.
- **A receipt carries no state.** Filing it must not touch the materialized
  view (state was already advanced when the subject event was filed). It is
  an appended record: event log + broadcast + replay only.
- **Broadcast** to the venue under the same `freeq.at/act` client-capability
  gating as every act event; **no companion PRIVMSG** (the subject event's
  companion already told the humans; a receipt is machine record).
- **Replay**: receipts ride `replay_lines` like any stored act event — verify
  they appear, in order, to a late joiner holding the `freeq.at/act` cap.
- **REST**: `GET /api/v1/actions/{id}` already serves all events for the
  action; confirm events must appear there with canonical + signature. Add
  nothing new; test that they do.
- **DM venues**: follow the expiry precedent exactly (deliver to both
  participants' sessions; the same known limitation about where clients file a
  server-authored line applies — restate it where the expiry code states it).

### Tests

- After an `accept`, the event log for the action holds a `confirm` whose
  `act-subject` is the accept's eventid, signed by `did:web:` — and the
  signature verifies against the server's published key.
- Every state transition gets exactly one receipt; `progress` gets none;
  `offer` gets none; `expire` gets none.
- A client-sent `confirm` is refused with the approved sentence; the refusal
  test names it.
- Replay to a late joiner includes the receipt; a client without the cap gets
  neither act events nor receipts.
- REST event list carries the receipt verbatim (canonical bytes + sig).
- Acceptance (`freeq-bot-kit-js/examples/act-acceptance.ts`): extend the
  existing lifecycle run to assert receipts appear for accept and complete,
  and that their signatures verify.

### Vectors

Add a receipt canonical to `spec/act-signing-vectors.json` following the file's
existing conventions (deterministic keys, byte-exact canonical, kid,
signature). Include one negative: a receipt whose `act-subject` was swapped
reads **invalid**.

---

## 2. `bounty` — the second kind, and the test of generality

RFC: "bids are additive events; the poster picks the winner with a signed
`award`; the server never picks." The deliverable is **a transitions-file entry
plus whatever schema the entry exposes as missing** — if the validator needs a
`match "bounty"` anywhere, stop and fix the schema instead.

### Transitions entry

```json
"bounty": {
  "opens": { "verb": "offer", "open": "open" },
  "terminal": ["completed", "failed", "cancelled", "expired"],
  "transitions": [
    { "verb": "bid",      "from": "open",     "to": "open",      "who": "anyone",   "before_deadline": true },
    { "verb": "award",    "from": "open",     "to": "assigned",  "who": "offerer",  "before_deadline": true,
      "assignee_from": "act-to", "requires": ["act-to"] },
    { "verb": "progress", "from": "assigned", "to": "assigned",  "who": "assignee" },
    { "verb": "complete", "from": "assigned", "to": "completed", "who": "assignee" },
    { "verb": "fail",     "from": "assigned", "to": "failed",    "who": "assignee" },
    { "verb": "cancel",   "from": ["open", "assigned"], "to": "cancelled", "who": "offerer" },
    { "verb": "expire",   "from": "*nonterminal", "to": "expired", "who": "system" }
  ]
}
```

Design notes, to be honored and documented in the file's `_readme`:

- **`opens` with no `directed` key**: a bounty is open by construction — a
  directed bounty is just a handoff. The schema must treat a missing `directed`
  as "an opener carrying `act-to` is refused" (`ILLEGAL_STEP` or a clearer
  refusal if one exists; pick and test).
- **Two schema additions**, both generic:
  - `assignee_from` — which field names the assignee when this transition
    assigns. Default (absent) is `actor`, which is what `accept`/`claim`
    already mean; `award` sets it to `act-to`. This is view logic driven by
    data, in both implementations.
  - `requires` — tags that must be present for the transition to be legal.
    Missing ⇒ a refusal with its own approved sentence ("An award names its
    winner" — match the copy voice) and named test. Guard the general case:
    an empty/absent `requires` changes nothing for existing kinds.
- **Bids are sovereign, so is the award.** The server does not check that the
  awarded DID ever bid — the RFC's "the server never picks" cuts both ways;
  the poster's signed choice is the record. State this in a comment and in the
  transitions `_readme`; do not add the check.
- **Bid payload**: a bid may carry `act-note` (freeform, already swept by the
  canonical). Do not invent an `act-bid-amount` tag — pricing semantics are
  agent-level, not substrate.

### SDK verbs

`freeq-bot-kit-js/src/act-verbs.ts`: `bid(ctx, taskId, opts)` and
`award(ctx, taskId, winnerDid, opts)`, shaped exactly like the existing verbs
(paired send: signed TAGMSG + companion PRIVMSG; `award` sets
`+freeq.at/act-to`). Mirror any Rust-side helpers if the Rust SDK has per-verb
helpers (check `freeq-sdk` — if it exposes only the canonical builder, that is
already enough; do not invent a new Rust surface).

### Tests

- The transitions sequences in `spec/act-transitions.json` gain bounty
  sequences (open → two bids → award → complete; a bid after deadline; an
  award by a non-poster; an award without `act-to`; a bid on an awarded
  bounty) — replayed by **both** implementations' sequence tests.
- Server gate tests for each new refusal, named.
- View: after `award`, the assignee is the awarded DID, not the actor; the
  rebuild-matches test covers a bounty.
- Acceptance: a second scenario in `act-acceptance.ts` — poster offers a
  bounty, two bots bid, poster awards one, winner completes; assert bids are
  all on file (additive), the loser's late `complete` is refused
  (`WRONG_SENDER`), receipts appear for `award` and `complete`.

### Vectors

Bounty vectors in `spec/act-signing-vectors.json`: a bid canonical and an award
canonical (with `act-to`), plus one negative (award with `act-to` stripped
reads invalid — the sweep covers it).

---

## 3. `act-replaces` — the typed revival relation

RFC: "`act-replaces` names a terminal predecessor a new action revives (a
failed handoff re-offered, a forfeited bounty re-listed). … Receivers must
tolerate an `act-replaces` naming an action they never saw — annotate, don't
refuse."

### Rules

- Legal **only on an opener** (`offer`). On any other verb: refuse (one
  sentence, one test).
- Value must be ULID-shaped. Malformed: refuse.
- If the named action is on file and **not terminal**: refuse —
  new refusal `replaces-not-terminal`, sentence in the transitions file's
  `refusals` map ("The action it replaces is not finished" — match voice).
- If the named action is not on file: **accept and annotate** — single-server
  today, but the rule is load-bearing for federation later; comment says so.
- The tag is swept by the canonical automatically — verify with a vector, not
  with new signing code.

### Storage & surfaces

- View: new column `replaces` on `act_actions` — **new migration** (007;
  migrations are append-only, do not touch 006), filled at apply time and by
  the rebuild path; rebuild-matches test extended.
- REST: `replaces` in the task JSON when present, both in the list and the
  detail.
- SDK: `offer(ctx, { …, replaces })` in bot-kit (tag only when present).

### Tests

- Re-offer of a failed handoff carries the link; REST shows it on the new
  action; the old action is untouched.
- Replaces naming a live (non-terminal) action: refused, named test.
- Replaces naming an unknown ULID: accepted, annotated, visible over REST.
- Replaces on a non-opener: refused, named test.
- A vector with `act-replaces` present (signature covers it).

---

## Sequencing, verification, and done

Build order: **receipts → act-replaces → bounty** (receipts first so bounty's
acceptance scenario can assert them; replaces before bounty because re-listing
a forfeited bounty is one of its uses).

After each stage, run at minimum:

```
cargo test -p freeq-server --test act_gate --test act_api
cargo test -p freeq-sdk
(cd freeq-sdk-js && npx vitest run)
(cd freeq-bot-kit-js && npx vitest run)
cargo build -p freeq-server && (cd freeq-bot-kit-js && FREEQ_SERVER_BIN=../target/debug/freeq-server npx tsx examples/act-acceptance.ts)
```

Before declaring done:

```
cargo fmt --all && cargo clippy --workspace --exclude freeq-av-client --exclude freeq-eliza --exclude freeq-av --exclude freeq-av-image -- -D warnings
cargo test --workspace --exclude freeq-av-client --exclude freeq-eliza --exclude freeq-av --exclude freeq-av-image
```

Definition of done:

- All three features implemented per above; all listed tests exist, are named
  for what they refuse or prove, and pass.
- `spec/act-transitions.json` and `spec/act-signing-vectors.json` extended;
  both implementations replay/reproduce them; no implementation contains
  kind-specific code.
- Full workspace suite green, fmt clean, clippy clean.
- Work committed in small commits on this branch (`act-tier1`), one concern
  per commit, messages in the house voice. **Do not push.**

Out of scope (do not build): federation defer queue, receipt park/eviction
rules, home routing, orphan annotation, receipt sequence numbers, DID-document
key anchoring, encrypted-content mode, any REST write path.
