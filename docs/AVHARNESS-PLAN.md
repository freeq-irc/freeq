# Build plan: the AV harness (L1 + L2 + the debug endpoint)

Brief for an agent run. Read `docs/AV-MAP.md` first — it is the map this
harness exists to enforce — then `docs/AV-SESSION-AUDIT.md` §3 and
`docs/AV-TEST-PLAN.md` §1/§5 for the invariants and scenarios by name.

House rules: match the codebase's comment voice (say why, plain sentences);
every assertion names the invariant it enforces (I1–I6) and the scenario it
automates (§5.x); nothing is described as covered unless a test actually
fails when the behavior is broken (verify at least one negative per layer by
temporarily reverting a guard, like the smoke harness did).

## Deliverable 1 — L1: session-layer chaos suite (CI, headless)

New integration test: `freeq-server/tests/av_lifecycle.rs`. Pattern after
`tests/av_error_signal.rs` (real server process/instance + real `freeq-sdk`
clients over the WS IRC transport). **No media, no av-native feature needed**
— this layer proves the session state machine's temporal behavior, so it runs
in the default CI test job (which excludes the AV crates but NOT
freeq-server).

Scenarios, each a named test with explicit timing budgets:

1. `start_join_leave_converges` — A starts, B joins, C joins; roster over
   REST lists exactly {A,B,C} with instances (I2); one session id everywhere
   (I5). A leaves; roster drops A within 2 s (I4). Last leave ends the
   session; `av-state=ended` reaches B and C.
2. `blip_with_joiner_keeps_slot` — §5.2/F2: A in call; drop A's TCP abruptly
   (no QUIT); within the grace window B joins. Assert A's roster slot
   SURVIVES the join-time reap. Then let grace expire: A's slot drops and
   `av-state=left` broadcasts (I4, class C boundary). Use a short grace via
   env/config if one exists — if not, add `FREEQ_AV_GRACE_SECS` (test-only
   override, default 30) so the test doesn't sleep half a minute.
3. `dead_session_join_answers_error` — §5.3/F3: join a ULID that never
   existed and one that ended; both answer `+freeq.at/av-error=join-failed`
   with the av-id echoed (already partially covered in av_error_signal —
   extend, don't duplicate).
4. `concurrent_start_converges` — §5.5/F4: A and B send av-start in the same
   tick; exactly one session exists after; the loser got `start-collision`
   naming the winner's id (I5).
5. `restart_mid_call_one_session` — §5.6/B4: three clients in a call;
   SIGKILL the server process; restart on the same DB/data-dir; clients
   reconnect and re-join. Assert everyone lands in ONE session (same id
   resurrected or same new id — either is legal, split is not), and the old
   id, if dead, answers join-failed. This is the only unautomated CRITICAL
   from the July incident.
6. `rename_mid_call_updates_roster` — §5.4/F5: A renames (NICK) mid-call and
   re-sends av-join with the same instance; roster shows the new nick under
   the SAME instance within 2 s; no duplicate slot.
7. `token_minted_on_join` — F7 rail: every successful start/join receives
   `+freeq.at/av-token` + av-id; the REST fallback
   (`GET /api/v1/av/sessions/{id}/token` with the joiner's bearer) agrees.
8. `media_revocation_ordering` — F6 rail, signaling side: at grace expiry the
   roster leave and the revocation both happen; assert via the debug endpoint
   (deliverable 3) that no announced path remains for the departed instance.
   Skip cleanly (with a printed reason) if the binary lacks av-native.

## Deliverable 2 — L2: tone-mesh through the full stack

New binary: `freeq-av-client/src/bin/avharness.rs` (feature-gated as the
crate already is). Reuse the tone generator, Opus pipeline, and decode side
of `examples/av_cross_transport_e2e.rs` — but with the one difference that
makes it the real harness: agents go through the **full lifecycle** — IRC
connect (guest ok) → join channel → `av-start`/`av-join` → wait for
`+freeq.at/av-token` → dial `?jwt=…&inst=…` → publish/subscribe — never the
SFU shortcut.

Core loop:

- `--agents N` (default 4): agent k publishes a sine at `440 * (k+1)` Hz.
- After settle (`--settle-secs`, default 8): compute the full I1 matrix —
  agent k must detect agent j's tone (Goertzel bin at 440·(j+1) Hz above a
  noise floor) for every j ≠ k, and must NOT detect its own (I6).
- Print the matrix (✓/✗ grid, like the cross-transport example); any ✗ fails
  the run and names the pair and direction.

Chaos steps (`--chaos`, run serially, re-asserting the matrix after each):

1. `blip` — drop one agent's IRC socket, keep media; within grace the matrix
   must still be full (peers keep hearing it); after grace expiry the column
   must go silent for everyone within 5 s (revocation, C1).
2. `media-kill` — close one agent's media transport only; the agent's own
   UI-state says in-call but its column goes silent (C2 — currently
   UNAUDITED; whatever the harness finds here is a finding, not necessarily
   a failure — assert only that the matrix report NOTICES the silence).
3. `restart` — restart the server; all agents rejoin; full matrix within
   `--recover-secs` (default 30).
4. `collide` — two fresh agents av-start simultaneously in a new channel;
   one session; both tones cross.
5. `churn` — one agent leaves and rejoins 5× with fresh instances; final
   matrix full; roster holds exactly N rows (no ghost instances).

Runner: `scripts/avharness.sh` — builds the server with `--features
av-native`, starts it on loopback ports with a temp data-dir, runs L1's
`media_revocation_ordering` precondition, then the binary with default chaos,
tears down. One command, exit code is the verdict. Document at the top that
this is the launch gate for anything touching AV.

## Deliverable 3 — the class-A X-ray

`GET /api/v1/sessions/{id}?debug=1` adds `announced` — the SFU's current
broadcast paths under the session prefix — beside the roster, so
roster-vs-announcement divergence (class A) is one request during a live
incident. Requires av-native (absent → `"announced": null` and a note field).
Small handler change in `web.rs` reading from `av_sfu`'s state; add a test in
L1 (deliverable 1, scenario 8) and a line to `docs/AV-MAP.md` §7.

## CI wiring

- L1 runs automatically (it lives in freeq-server's default tests). Verify
  `cargo test -p freeq-server --test av_lifecycle` passes repeatedly
  (run 3×; these are timing tests — budgets must have slack, no flakes).
- L2 cannot run on ubuntu CI cheaply (audio deps, av-native build time). Add
  a `workflow_dispatch` + weekly-scheduled job `av-harness` on `macos-26`
  that runs `scripts/avharness.sh`. Do NOT add it to the per-push path.

## Verification before done

- L1: 3 consecutive green runs of the new test file; one deliberate breakage
  (e.g. comment out the grace-pending check in the reaper) makes
  `blip_with_joiner_keeps_slot` fail by name, then restore.
- L2: full run green locally (macOS, av-native); one deliberate breakage
  (e.g. skip token on dial with a local `FREEQ_AV_REQUIRE_TOKEN=1` server)
  fails the matrix.
- Full workspace suite + clippy + fmt with CI's exact invocations.
- Update `docs/AV-MAP.md` §6/§7 to reflect what now exists, and
  `docs/AV-TEST-PLAN.md` §5 rows with "automated: <test name>" where true.

Out of scope: L3 (Playwright cross-model probe — separate pass), Windows,
token-flip rehearsal itself, any SFU behavior change beyond the debug field.
