# freeq as the Evidence, Policy, and Accountability Layer

*2026-07-05. Companion to `docs/what-is-freeq.md` and `docs/agents.md`. This is
the positioning + build plan for the thing freeq turned out to be — not "IRC
with Bluesky login," but the neutral substrate where identity, authority,
spend, and action history are cryptographic facts in one stream.*

---

## 1. The claim

Every serious deployment of AI agents — and increasingly, every serious
multi-party human collaboration — hits the same three unsolved questions:

1. **Evidence** — *what actually happened, and can anyone prove it?*
2. **Policy** — *who is allowed to do what, and why — derived from verifiable
   facts rather than admin fiat?*
3. **Accountability** — *which identity (and which human behind it) answers
   for each action, and what were they allowed to spend doing it?*

freeq already answers all three in one wire protocol. No other chat or agent
platform does. The claim to make — and to prove with running software — is:

> **freeq is the coordination fabric where work happens *on the record*:
> every actor is a DID, every action is signed, every permission is a
> verifiable credential, and every log is evidence.**

The IRC compatibility layer is a distribution strategy (any client from 1993
still connects), not the product.

## 2. What each layer means, concretely

### 2.1 The evidence layer

**Definition:** anything that happened in a freeq channel can be exported and
verified by a third party who trusts none of the participants *and not even
the server*.

Already true (server-side):
- Per-message ed25519 signatures with client-held session keys
  (`+freeq.at/sig`, `MSGSIG`, `connection/messaging.rs::resolve_signature`);
  signatures survive S2S relay.
- ULID msgids give a tamper-evident total order per channel (`msgid.rs`).
- `GET /api/v1/verify/{msgid}` and `/api/v1/signing-keys/{did}` expose
  verification material.
- Commit-reveal verification for coordination events
  (`verify_commit_reveal`) — sealed-bid/vote-shaped processes are possible
  *inside a channel*.
- Policy transparency log with Signed Tree Heads (`policy/types.rs`),
  privacy-preserving (no user DIDs in entries).
- Bot delegation certs chain agent actions to a human creator
  (`connection/provenance.rs`) — **now signable from both the Rust CLI and
  the TS bot-kit** (2026-07-05).

Missing in core (the build list, §4):
- **Evidence bundles**: one API call that exports a message range + all
  signatures + the signing-key material + channel policy hash into a single
  self-contained file.
- **`freeq-verify`**: a small offline CLI that takes a bundle and says
  VERIFIED/TAMPERED, resolving DIDs but needing no freeq server. Evidence
  that can only be checked by the server that produced it isn't evidence.
- Transparency-log **inclusion proofs** served over REST (STHs exist; proofs
  don't).

### 2.2 The policy layer

**Definition:** access and power in a channel derive from verifiable facts
about identities — employment, code ownership, social relationships,
appointment by a quorum — expressed in a deterministic, auditable language.

Already true:
- Requirement DSL (`ALL/ANY/NOT/PRESENT/PROVE/ACCEPT`, bounded, fail-closed —
  `policy/eval.rs`).
- Ed25519 VCs over JCS from *arbitrary decoupled issuers*
  (`policy/credentials.rs`); the server never talks to GitHub/Google — it
  checks signatures. Shipped verifiers: GitHub org/repo (OAuth), Bluesky
  follow-graph, OIDC SSO (**now with full JWKS signature + aud/iss/exp/nonce
  validation, 2026-07-05**), moderator appointment.
- Versioned, hash-chained policy documents with threshold-signed authority
  sets and key rotation (`policy/engine.rs`).
- Role escalation: credentials map to IRC modes automatically.
- Membership attestations with Continuous revalidation — and, as of
  2026-07-05, an attestation key that **survives restarts**
  (`attestation-key.secret`), so continuous-validity channels don't silently
  re-gate everyone on a server bounce.

Missing in core:
- Attestation verification *across* servers (attestations are HMAC-signed by
  one server; a federated channel can't check a peer's attestations). The
  fix is the same move as message signing: ed25519 attestations signed by the
  server's published key.
- Policy templates ("company channel", "repo channel", "follow-gated
  channel") as one-command setup — the DSL is powerful and nobody should
  have to hand-write it.

### 2.3 The accountability layer

**Definition:** every agent action is attributable to a DID, chained to a
sponsoring human, bounded by an explicit budget, and interruptible by human
governance — all visible in the same channel where the work happens.

Already true:
- Agents authenticate exactly like humans (did:key via ATPROTO-CHALLENGE);
  actor class rides extended-join/WHOIS.
- Delegation certs (creator chain), announce/heartbeat/presence protocol,
  typed task events (`task_request → task_update → evidence_attach →
  task_complete`), PAUSE/RESUME/REVOKE governance, per-channel budget
  policies with sponsor DIDs and approval gates (`BudgetPolicy`).

Missing in core:
- Delegation *chains* for spawned sub-agents (parent cert → child cert) are
  planned (agent-native Phase 4) but not enforced end-to-end.
- Budget enforcement is accounting-first; the "block at 100%" path needs the
  same adversarial test treatment SASL got.
- A canonical **work receipt**: when a task_complete lands, the server should
  be able to mint a signed receipt binding (task ULID, actor DID, sponsor
  DID, evidence msgids, spend) — the artifact a buyer of agent work actually
  wants.

## 3. What to build to show it

Three demos, in order of effort-to-impact. Each is an *ecosystem* app (see
§4) that exercises core primitives; each ends with an artifact a skeptic can
verify offline.

### Demo A — "The receipts room" (evidence layer, ~small)

An incident-response / decision channel at `irc.freeq.at`:
1. A gated channel (`PRESENT github_membership` or OIDC) where a real
   decision gets made — participants discuss, a decision bot runs a
   commit-reveal vote, the outcome posts with all reveals.
2. At the end, anyone runs `freeq-verify export.bundle` and gets: every
   message verified against its author's key, the vote verified against the
   commits, the policy hash verified against the transparency log.
3. The kicker for the demo writeup: *delete a message from the bundle, rerun
   the verifier, watch it fail.* Logs from Slack/Discord/Teams cannot do
   this.

Needs from core: evidence bundle export + `freeq-verify` (§2.1). Everything
else exists.

### Demo B — "Agent team, on the record" (accountability layer, ~medium)

The `freeq-bots` factory team (or freeqcc + Claude) ships a small real PR in
a public channel:
1. Sponsor (human DID) posts a `task_request` with a budget
   (`BUDGET #room :max=5;unit=usd;period=per_task`).
2. Agents with **signed delegation certs** (now possible from bot-kit) claim
   subtasks; every message signed; spend reported per LLM call; one agent
   gets deliberately paused mid-run by the human (`AGENT PAUSE`) and resumes.
3. Completion mints a work receipt; the receipt + evidence bundle verify
   offline; the channel log *is* the audit trail.
4. Stretch: one agent voice-briefs the sponsor via the `/freeq` AV skill —
   same identity, same record.

Needs from core: work receipts; budget block-at-limit hardening. Everything
else exists.

### Demo C — "The inter-company channel" (policy layer, ~large, the money demo)

Two freeq servers, run by two different orgs on independent hosts,
federate one channel:
1. Each side's members admitted by *their own* OIDC verifier (`ALL(ANY(
   PRESENT oidc_domain@issuerA, PRESENT oidc_domain@issuerB), ACCEPT rules)`).
2. The channel is `+E` with VC-bootstrapped group keys
   (`VC-BOOTSTRAPPED-CHANNEL-E2EE.md` — the remaining steward/EGK1 wiring is
   this demo's prerequisite): **host-blind on both servers**.
3. An employee is offboarded from org A's IdP; within the attestation TTL
   their access lapses and the next key epoch excludes them — no admin
   touched freeq.

This is Slack Connect without Slack — the B2B secure-room product that
currently does not exist anywhere. Needs from core: cross-server attestation
verification (§2.2), E2EE steward wiring (already speced + partially landed).

## 4. What goes in freeq core vs. what uses freeq

The boundary rule that has already served the project well (the verifier
pattern) generalizes:

> **Core carries facts and their verification. Ecosystem carries meaning and
> workflow.** If a feature makes the server *interpret* content, call third
> parties, or embed a product opinion, it belongs outside core. If removing a
> feature would make some claim unverifiable, it belongs inside.

### In freeq core (`freeq-server`, `freeq-sdk*`, protocol docs)

| Item | Layer | Status |
|---|---|---|
| Message/action signing, msgid order, verify APIs | Evidence | shipped |
| **Evidence bundle export API** | Evidence | build next |
| **`freeq-verify` offline CLI** | Evidence | build next |
| Transparency-log inclusion proofs | Evidence | build |
| Requirement DSL, VC verification, policy engine | Policy | shipped |
| **Ed25519 (cross-server) attestations** | Policy | build |
| Policy templates (`POLICY INIT company\|repo\|follow`) | Policy | build |
| DID auth for humans+agents, delegation cert verify | Accountability | shipped |
| Budget accounting + enforcement | Accountability | harden |
| **Signed work receipts** | Accountability | build |
| Delegation chains for spawned agents | Accountability | build (Phase 4) |
| AV session tokens; `FREEQ_AV_REQUIRE_TOKEN` flip | (transport trust) | shipped 2026-07-05, flip pending clients |
| MLS upgrade, CRDT-wired S2S, AT-label moderation | all | roadmap (unchanged) |

### Built ON freeq (separate repos/products — reference implementations live in `freeq-bots`, `examples/`, bot kits)

- **Decision/vote bots** (Demo A) — commit-reveal is a core primitive; *what
  a vote means* is an app.
- **Agent team products** (Demo B) — factory/auditor/freeqcc; task semantics,
  LLM brains, tooling are apps. Core only carries the typed event envelope,
  budgets, receipts.
- **Compliance/export tooling** — SOC2/discovery exporters that consume
  evidence bundles. (Sell-able.)
- **Verifiers beyond the reference set** — employer KYC, payment standing
  (Stripe), conference registration, DAO membership. Anyone can run one; the
  server only ever checks signatures. This is the extension point that makes
  the policy layer a *platform*.
- **Dashboards/consoles** — fleet views over agents, budgets, receipts
  (revenant console is the prototype).
- **Persona fleets** (revenant/eliza/mitosis) — the most futuristic tenant of
  the substrate, not the substrate.
- **Bridges** (pi bridge, AT-proto conversation bridge, Matrix/Slack
  read-only mirrors) — adapters, never trust roots.

### Explicitly NOT in core, ever

- LLM inference of any kind (agent-assist's summarizer stays optional+redacted).
- Callouts to identity providers (verifier pattern holds).
- Workflow/task semantics beyond the typed envelope.
- Moderation *decisions* (core carries labels/events; policy interprets).

## 5. Sequencing (the 90-day shape)

1. **Weeks 1–2 — finish the trust substrate.** ✅ SFU tokens, OIDC JWKS,
   signed delegations, persistent attestation key (all landed 2026-07-05).
   Remaining: ed25519 attestations, evidence bundle export + `freeq-verify`,
   work receipts. These are small, mostly-local changes with outsized claim
   value.
2. **Weeks 3–6 — Demo A then Demo B**, written up with verifiable artifacts
   attached (publish the bundles; invite people to tamper with them).
   Update `freeq-site` positioning to the §1 claim.
3. **Weeks 7–12 — Demo C** (steward E2EE wiring + cross-server attestations),
   plus the IRCv3 `ATPROTO-CHALLENGE` submission — standardization is what
   makes "neutral substrate" credible.

## 6. Risks / honesty box

- **Enforcement lag:** several trust features ship server-side before all
  clients present them (AV tokens now; S2 scoping earlier). Each needs its
  flip actually flipped — an unflipped flag is a hole with better docs.
- **Key custody:** all of this rests on `*.secret` files on one box and on
  laptops. Before Demo C, produce a KEY-CUSTODY.md (what exists where, what
  rotation looks like, what's fatal to lose — `db-encryption-key.secret` is
  make-or-break).
- **Moderation roster is in-memory** (`verifiers/moderation.rs`) — a
  credential-issuing component that forgets on restart undermines the policy
  story; persist it when touching that file next.
- **Don't over-rotate the positioning:** IRC-compat and "everything optional"
  are why any of this is adoptable. The evidence/policy/accountability story
  is the *ceiling*; guest mode from a 1993 client stays the floor.
