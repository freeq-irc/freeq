# RFC v0.3: `freeq.at/act` — stateful, signed, addressed actions for IRCv3

*(with `handoff` as the first action kind)*

**Status:** draft / request for comments · **Authors:** Chad Fowler & zapnap (freeq) · **Audience:** agent-coordination builders, IRCv3, AT Protocol

This is a casual RFC. Poke holes in it.

> **What changed since v0.2:** (1) **Addressing is DID-native end-to-end** — a cross-server *nick* DM has no well-defined recipient today, so directed actions key off the `act-to` DID for delivery, persistence, and validation, with the nick as display only. (2) **Transition authority is the minting server** — for every action, directed or open, the server that minted the `act-id` serializes transitions and resolves races; a federated channel has no "home server" and a multi-homed recipient has no single one either, so authority follows the one thing that's unambiguous, the offer's origin. (v0.2 put directed-action authority on the recipient's server; this unifies it.) (3) **Signing** — two things. Verifying a sig needs the signing *key* to still exist and be findable; keys are per-session and overwritten today, so long-lived actions aren't verifiable until we add a key store + a lookup path (DID-document anchoring is the endgame). And the act canonical is framed as freeq's *target* signing model, not an act-only special case — today's PRIVMSG signing breaks across federation the same way, so the RFC proposes migrating all message signing onto this canonical as follow-on work. (4) **Direct actions aren't private** — the server has to read an action's state to validate it, so that state is server-visible in every mode; only freeform content can be encrypted, and "direct" no longer gets called "private."

---

## TL;DR

A typed, addressed, signed, **stateful** message: an action with a lifecycle (`offer → accept/decline → progress → complete/fail/cancel`), distinguished from chat by an `act` kind tag and correlated by a ULID. Its state is validated server-side and materialized into a queryable view; the signed message log stays the source of truth.

`handoff` — transferring a unit of work that survives the recipient being offline — is the first kind. The same substrate carries `approval`, `grant`, and friends later. If those reuse it without reinventing, the shape is right.

## Motivation

AI agents call tools fine but coordinate badly *across time*: when an agent goes offline, in-flight work and context evaporate. The common answer (e.g. AIRC) is a separate HTTP registry + inbox just for agents.

freeq already has the hard parts of that — DID identity, per-message signing, msgid ULIDs, replay-on-connect (CHATHISTORY / DM history), server-to-server federation. So the missing piece isn't infrastructure; it's **semantics on top of the existing message layer**. Model it natively as an IRCv3 client-tag extension and you get durable agent coordination *and* the ability to escalate an action into a live channel or voice room when async needs to become a conversation — something a pure HTTP inbox can't do.

One caveat on that "already has," and it's why this RFC runs longer than a tag spec. A couple of those rails were built for **chat**, where the bar is lower than for a durable, signed, addressed *object* — and a handoff leans on them anyway. Addressing resolves *per-server*: fine for "message bob now," wrong for "this task is bob's and has to reach him on whatever server he's on." Signing keys live only as long as a *session*: fine for a line that scrolls past, wrong for an offer accepted next week. So two of the sections below — **Addressing**, and the key half of **Signing** — aren't handoff features; they're preconditions the headline quietly assumes ("addressed to an identity," "signed," "survives offline") and that don't actually hold until we firm them up. Everything else really is reuse.

## The reframing: an action substrate, not a handoff inbox

Once a handoff is a typed, signed, stateful action on a message, it stops looking unique. Reactions/edits/deletes/pins/replies are already "actions on a message." Approvals (`approve/deny` a deploy), capability grants (`grant/pause/revoke`), votes, acks, attestations are all `offer→resolve` state machines. They all want the same three things:

1. a **verb-tagged typed message**,
2. a **transition validator** (who may move it to which state),
3. a **materialized view** of current state.

So the wire uses generic `act-*` tags with the kind as a value. `handoff` is one kind:

```
@+freeq.at/act=handoff;+freeq.at/act-verb=offer;+freeq.at/act-id=01JABC…;
 +freeq.at/act-to=did:plc:scholar;+freeq.at/act-title=Cite 3 sources on X;
 +freeq.at/act-ctx=freeq:blob/cap/abc;+freeq.at/act-ctx-h=sha256:9f…;
 +freeq.at/act-caps=freeq.at/web-search;+freeq.at/act-deadline=1788000000;
 +freeq.at/sig=ed25519:… TAGMSG #ops
```

…and a deploy approval is the *same substrate*, different kind:

```
@+freeq.at/act=approval;+freeq.at/act-verb=request;+freeq.at/act-id=01KDEF…;
 +freeq.at/act-to=did:plc:opslead;+freeq.at/act-title=Deploy factory-bot v12;
 +freeq.at/act-ctx-h=sha256:1a…;+freeq.at/sig=… TAGMSG #ops
```

Same `act-id` correlation key, same `act-ref` to link replies, same validator mechanics, same view, same REST shape. The kind is a row in a registry, not a subsystem.

**Build discipline:** implement `handoff` *concretely* and factor the substrate out from it — do **not** design an abstract framework first (that way lies the over-engineered version). Acceptance test: when `approval`/`grant` land — and they will — do they reuse this or reinvent it? Reuse obvious ⇒ shape is right. "handoff" welded into storage/wire ⇒ it isn't.

> **Important caveat on generality:** the substrate generalizes the *plumbing* (wire, validator mechanics, view, REST), **not the policy**. Each `kind` must ship its own **transition table + authorization rules** as a first-class artifact — those differ per kind and are the actual hard design. "handoff is just a verb-set" is true for the plumbing and undersells the policy.

## Addressing: DIDs, not nicks

A handoff is addressed to *an identity*, and stays valid until that identity acts on it — maybe from another server, maybe after a reconnect. A nick can't carry that promise. A nick is unique only *per server*, so the same nick on two peers can be two different people, and a cross-server DM to a nick has no well-defined recipient: each receiving server maps it to whoever *it* thinks that is, and the sender never learns which identity actually received it. A DID is globally unique, so it resolves to the same identity everywhere. So directed actions address a DID (`act-to=did:plc:…`), resolved identically on every server. Concretely:

- **DID-addressed delivery is uniform.** Every server applies one rule: deliver to local sessions bound to the target DID **and** relay to peers, who do the same — so a multi-homed DID gets the event on every device, deduped by `msgid`. No per-server interpretation, no collision. This wants **DID targets at the wire level** (`PRIVMSG did:plc:x`, and likewise for the `TAGMSG` an action rides — CHATHISTORY already accepts `did:` targets, so there's precedent), so an agent can address a peer by DID and never has to resolve a nick or reason about a collision.
- **Persistence and validation key off the same DID**, so the sender's own stored copy of a directed action matches what was delivered.
- **Nick DMs still work** (humans type nicks): the sender's server resolves nick→DID *once* at send time and stamps the resolved recipient DID onto the relayed event; receivers honor that stamp rather than re-resolving. The stamp is best-effort — absent for legacy peers or an unresolvable nick (e.g. a guest), receivers fall back to today's nick handling. Guests have no durable identity to persist under anyway, and action participants are DIDs by definition, so actions never hit that fallback.

## Two orthogonal axes

DM-vs-channel conflates two independent knobs. Keep them separate:

- **Assignment** — *who does it.*
  - **directed**: `act-to=did:plc:bob` → starts assigned to Bob.
  - **open / claimable**: `act-to=#swarm` + `act-caps=…` → starts unassigned; any capable agent `claim`s it; first valid claim wins.
- **Visibility** — *where the event is posted.*
  - **channel**: visible to the room, logged in channel history.
  - **direct**: addressed to two DIDs, delivered over the DM layer.

These compose. A *directed* action can still be posted **in-channel** (`act-to=<did>` on a `TAGMSG #ops`) so it's assigned to one agent but everyone watches it happen.

**Channel is the default for multi-agent**, because it gives observability + logging for free (channel history already persists the whole `offer→complete` stream), enables an orchestrator agent to watch/reassign/escalate live, and enables claimable work queues. Direct is the two-participant special case (direct, not private — see the visibility note under Storage).

## Lifecycle & the transition validator

`handoff` verb-set and its rules:

| verb | who may send | precondition |
|---|---|---|
| `offer` | anyone | mints `act-id` |
| `accept` | the addressed DID (directed) | state = offered, before deadline |
| `claim` | any DID matching `act-caps` (open) | state = open; **first valid wins** |
| `decline` | the addressed DID | state = offered |
| `progress` | the assignee | state = assigned |
| `complete` | the assignee | state = assigned |
| `fail` | the assignee | state = assigned |
| `cancel` | the offerer | state = offered/assigned, before complete |

The validator, on each incoming event: **verify the signature first** (see Signing — a bad or unverifiable sig is rejected like an illegal transition), then look up prior events for `act-id`, check the verb is a legal transition **and** the sender is authorized, then store + route it like any message. Reject otherwise.

### Claim semantics (open/claimable)

`claim` is just a verb with one extra rule: **first valid claim wins, atomically** — which takes one server to order the competing claims. A directed action has its own version of the same problem: the offerer can `cancel` at the same instant the assignee `accept`s, and something has to decide which happened first. Either way, one authority orders the conflicting events. A federated channel can't be that authority: freeq channel state is symmetric peer-merge, no owner, so two peers would each award a local claim and the task runs twice.

So the serializer is **the server that minted the `act-id`** — the offerer's origin — for every action, directed or open. It's deterministic from the wire (every relayed event names its origin), needs no channel-ownership concept, and stays well-defined when the recipient is multi-homed: a DID logged into several servers has no single home, but an `act-id` has exactly one origin. Transitions relay to it; it emits the authoritative ordering; every other view follows. If it's unreachable, transitions **stall rather than fork** — the correct failure for "first valid wins." (Cross-server claimable also depends on the signing/trust work below: the minting server picks the winner, and the sig is what lets other servers trust that pick.)

## Storage & delivery: ride what already exists

There is **no new inbox/store.** Delivery and durability come from the message layer freeq already has:

- A **channel** action is in channel history; replayed via CHATHISTORY on reconnect.
- A **directed** action rides the DM store (keyed by the two participant DIDs — see Addressing), replayed on reconnect.
- An **open** action lives in the target channel's history, claimable while non-terminal.

Net-new code is two small things, identical whether it's handoff/approval/grant:

1. **A transition validator** (above).
2. **A materialized view** — a read-side index (`act-id → latest state, assignee, caps, deadline`) so you can answer "actions assigned to me" / "open actions I can claim" without scanning the log. **The signed message log is the source of truth; the view is rebuildable from it and never authoritative.**

> **Visibility — what the server can and can't see:** the substrate *depends* on the server reading the `act-*` tags to validate transitions and build the view. So in **every** mode — channel or direct — the server sees the action's existence, both participant DIDs, the title, caps, deadline, and the full state timeline; with freeq-hosted context (the default) it sees the payload too. freeq's E2EE only ever covers a freeform message body, never tags. **A direct action is therefore *direct*, not *private*.** The one thing that *can* be hidden later: the validator only needs `act-id`/verb/DIDs/deadline — never the title or context — so an **encrypted-content mode** (encrypted `act-title`/`act-ctx`, cleartext lifecycle) is possible with no wire change, at the cost of caps-based routing and human-readable audit. What can never be hidden is existence, participants, and timeline. (Same footnote as the trust section: DM prekeys are server-served today, so even that encrypted body holds only against an honest server — one more consumer of the same root-of-trust gap.)

## Context (`act-ctx` / `act-ctx-h`)

The real axis is **not payload size — it's whether the bytes live somewhere freeq commits to keeping.** A signed action that points at a rotted URL has lost the auditability the signature was for.

- **Default: freeq-hosted** context (capability URL), lifecycle tied to the action's retention. Only setup where the audit guarantee holds.
- **External refs** (gist, S3, an AT-Proto record on another PDS) are allowed but **explicitly best-effort**: ref dies, guarantee dies — caller's call.
- **The signature always covers a content hash** (`act-ctx-h`), so whatever you fetch later is checkable against what was signed — tamper-evidence wherever the bytes live, and the only integrity check you get at all for external refs.
- Tiny payloads may be inlined as a convenience; that's not a durability story, just an optimization.

## Signing & canonicalization

⚠️ freeq's current PRIVMSG signing isn't sufficient for a signed action. Its canonical is `{sender_did}\0{target}\0{text}\0{timestamp}` — it assumes a message body (a body-less `TAGMSG` has no `text`) and folds in a wall-clock `timestamp` that's minted at send and never stored or relayed, so a downstream server can't reconstruct it to verify. `act` therefore defines a canonical built to survive federation:

- **Canonical:** deterministic JSON (JCS / RFC 8785) over an explicit, fixed field set: `act`, `act-verb`, `act-id`, `act-from`, `act-to`, `act-title`, `act-ctx-h` (the hash, not raw context), `act-caps`, `act-deadline`, `act-ref`.
- **Sign over the ULID (`act-id`), not a wall-clock timestamp.** A ULID embeds its own creation time, is immutable, and already travels as a first-class tag — so the receiver rebuilds the exact signed bytes rather than re-minting a timestamp it can't match.
- **S2S relays the signed tags verbatim** (`act-from`, `act-id`, `sig`, plus the canonical fields) and the **receiver rebuilds the canonical from them — never re-mints.** Since DID and ULID are both already tags, this is far more achievable than retrofitting PRIVMSG.

**This is meant to be freeq's signing model, not an `act`-only special case.** The same weakness — a signed wall-clock timestamp that never crosses S2S — means **PRIVMSG signatures don't survive federation today either**: a receiver can't rebuild the canonical, so it can't actually check the sig — the 🔒 a federated client shows just means a signature is attached, not that anyone verified it. `act` gets the fix first because it's greenfield (no deployed clients signing the old way, no stored history to keep verifiable) and because non-repudiation is load-bearing for a durable action, where on an ephemeral chat line it's near-cosmetic. But there's no principled reason chat stays on the old path: sign a hash of the freeform body, sign the **wire** bytes (ciphertext when E2EE, so encryption and verification stay orthogonal), and carry the signed fields verbatim over S2S. This RFC proposes that **all message signing — PRIVMSG included — should eventually migrate onto this canonical**, as follow-on work. The end state we're arguing for is one signing path, not two; `act` just proves it first.

### The harder problem: key existence + key lookup

Reconstructing the signed bytes is only half of verification; you also need **the public key that made the sig**, and today that key doesn't survive. Two problems compound:

- **Keys are per-session and overwritten.** Clients mint a fresh ed25519 keypair each session and register it (`MSGSIG`); the key store keeps one key per DID and *overwrites* on re-register. So the moment a signer reconnects, every signature from a prior session becomes unverifiable. Chat tolerates this; actions are *specifically* long-lived, so "verify an offer signed in a session that has since ended" is the **normal** case, and the current model can't do it at all.
- **Even a retained key has to be *findable*.** A verifier needs to know who to ask.

The fix is two matching parts:

1. **Key existence** — put a **key-id in the sig tag** and make the key store **append-only** (history, not overwrite), so `(DID, key-id)` always resolves to the exact key that signed.
2. **Key lookup** — the interim answer is the event's **origin server**: sessions register keys where they lived, every relayed event already names its origin, so the lookup is `(origin, DID, key-id)` — no new "home server" concept. The cost: verification is then hostage to that origin being **reachable** (server dies → its signed history is unverifiable forever) and **honest** (the same honest-origin bound the trust section already admits). The real answer is DID-document anchoring (next section): a key resolvable from the DID alone removes the origin server from the loop entirely.

We should bake the **key-id into the sig format now**, even before the store is append-only, so the wire doesn't need revising when the key authority moves from origin-server to DID-doc.

## Trust & non-repudiation — today vs goal

Stated plainly so nobody over-reads the guarantee:

- **Canonicalization makes the signature *reconstructable*, not *trustless*.**
- The **DID↔signing-key binding is unattested today.** `MSGSIG` registers a bare ed25519 pubkey, and the server is the one publishing per-DID keys (`/api/v1/signing-keys/{did}` is local, server-controlled). A malicious server could publish its own key as yours and forge.
- **Net: non-repudiation holds against an *honest origin server*, not a malicious one** — until key distribution is server-independent.
- **Goal / path to real E2E non-repudiation:** anchor the signing key in the **DID document** (attest the ed25519 key via the AT-Proto identity — did:plc/did:web), so any party verifies the key independently of the freeq server. This is the same root-of-trust gap the broader "identity = DID, never the server's say-so" work cares about, and — per the signing section — it's also what makes key *lookup* work without a reachable, honest origin server. It's a prerequisite for trustworthy cross-server claimable queues and for verifiable long-lived actions generally.

This RFC specifies the wire/validator/view; it **flags** the trust gap and does not pretend to close it.

## Capabilities (`act-caps`)

Freeform, and **the server never interprets them** (it can't verify an agent really does `web-search` anyway). Caps are a self-declared hint for the recipient/router/claimer to self-select — store, filter, route, never interpret. Fuzzy/semantic matching belongs in the agents.

- No protocol-baked capability registry (it'd be stale in months and a governance chore).
- The one convention worth fixing now is **namespacing** — reverse-DNS / AT-style (`freeq.at/web-search`) — with meanings converging socially. Reserve well-known names later if needed; starting loose costs nothing.

## Liveness, backpressure, retention

Modeling actions as messages in the existing store dissolves most of this:

- **Flooding** — offers are messages, already under freeq's flood throttle + per-IP/connection limits. No new quota machinery.
- **Storage growth** — same message/DM/channel store under existing retention. The view stays small by construction (indexes only non-terminal actions) and is rebuildable.
- **The one genuinely new policy is liveness, not storage:** an action stuck in `accepted/progress` that never reaches a terminal state. `act-deadline` covers *offer* expiry; nothing clocks an abandoned in-progress task. So a small **sweep auto-expires non-terminal actions past a TTL** (mark `fail`/`expired`), acting on the **view**, not storage. The sweep is owned by the action's serializer (its `act-id`-minting server) and broadcast as a normal terminal event, so peers garbage-collect their views by relay rather than each computing expiry locally.

## Federation

Action events propagate over S2S like any tagged message, preserving `act-id`, the canonical fields, and `sig`. A directed action to a DID on a remote server routes to that DID's sessions (see Addressing); the **`act-id`-minting server owns claim serialization and TTL expiry** for that action. Receivers **rebuild and verify** the canonical from the relayed tags before applying it (see Signing) — subject to the key-lookup caveat, so cross-server verification and cross-server claimable both wait on the key-store + trust work.

## REST query interface (over the view)

A query surface over the materialized view — *not* a parallel table that owns data — so non-IRC agents and interop bridges can use it:

- `GET /api/v1/actions?kind=&to=&state=&caps=` — my inbox / claimable queue
- `GET /api/v1/actions/{act-id}` — current state + context ref + event log
- `POST /api/v1/actions` — emit an `offer`/`request`
- `POST /api/v1/actions/{act-id}/{verb}` — a transition

This shape maps cleanly onto AIRC-style `POST /messages` + payloads, so an interop bridge is a thin adapter.

## Orchestration pattern (why channel-default matters)

Put a supervisor/orchestrator agent in the channel. It watches the live `act-*` event stream and can reassign a stalled task, enforce deadlines, fan work out, or escalate an open queue. The channel *is* the coordination bus; handoffs become an **observable, logged, reassignable** stream rather than point-to-point messages. CHATHISTORY gives you the audit log for free.

## What's actually new to build

1. The `act-*` tag set + `freeq.at/act` CAP + TAGMSG handling.
2. A **transition validator** (per-kind transition table + authz), **with signature verification as its first check**; for open actions this includes **claim serialization at the `act-id`-minting server** — claims route to it, it atomically assigns and rejects the rest.
3. A **materialized view** + the REST query interface + reconnect replay (reusing CHATHISTORY/DM replay).
4. A **liveness sweep** for non-terminal actions past TTL, owned by the `act-id`-minting server.
5. The **new canonical + sign-over-ULID** signing path, and S2S relaying the signed tags verbatim.
6. **A durable signing-key model** — a key-id in the sig tag, an append-only history of each DID's keys (never overwrite), and **a way to look that key up for verification**. Required: without it no long-lived action's signature is verifiable after the signer reconnects. *Which* lookup — ask the origin server, or resolve the key from the DID document — is the open question below; the key-id and the key history are needed either way.
7. **DID-native addressing** — DID targets at the wire level, and the resolve-once-at-sender-and-stamp path for nick DMs, so directed delivery/persistence/validation share one authoritative recipient identity.

Everything else (delivery transport, durability, identity, msgid, flood limits, federation transport) is reuse.

## Non-goals

- Not a workflow engine / DAG executor — it's a transfer + state primitive; orchestration lives above it.
- Not a replacement for chat — actions are *tracked* units, not conversation.
- Not re-doing identity — it rides whatever identity the server already verifies (AT-Proto DIDs).
- Not (yet) solving server-independent key distribution — flagged, and now also identified as a prerequisite for verifying long-lived actions, but not closed here.

## Open questions

- **Substrate now, or handoff-first then factor?** (Hunch: handoff-first, factor out — but get the `act-*` shape right so approvals/grants reuse it.)
- **Per-kind authz spec format** — how do we declare each kind's transition table + rules so it's reviewable and not ad-hoc?
- **How does a verifier find an old signature's key?** — checking a signature later means fetching the public key that produced it, and there are two ways to make that key findable. **(a)** Ask the server where the signature was originally made: freeq keeps a history of every signing key a user has registered and hands back the one you name. Simple to build, but it only works while that server is online and honest — if it's down you can't verify, if it's malicious it can hand you a forged key. **(b)** Publish the key in the user's DID document — the public AT-Protocol identity record anyone can resolve — so the key is fetched straight from the DID with no freeq server in the loop. Robust (no dependence on any freeq server), but more to build. Do we ship **(a)** now so signatures verify soon and move to **(b)** later, or skip **(a)** and wait for **(b)**? (Either way, the key's id belongs in the signature from day one, so the wire doesn't change when the lookup does.)
- **What happens when the controlling server goes offline** — since the minting server is the sole authority for an action, that action freezes if the minting server goes down (`stall rather than fork`). This isn't a new failure class — delivery, replay, and history already assume the relevant servers are up, so a host outage breaks those too — which is the argument for accepting it as-is. Or hand authority to the assignee's server at `accept`, preserving locality at the cost of a mid-lifecycle authority handoff?
- **Claim fairness** beyond first-wins — bidding, priority, capability scoring? Or keep dumb and let orchestrators decide?
- **External context refs** — allow AT-Proto records as a first-class (best-effort) ref type, or discourage entirely?
- **Canonical field set** — is the list above complete? Versioning the canonical.
- **WG venue** — keep `+freeq.at/*` until the trust pieces are solid, then pitch IRCv3 WG? (Design the wire to be de-vendorable now regardless.)

---

*Feedback welcome — comment on the gist, or find me on freeq (`irc.freeq.at`) / Bluesky.*
