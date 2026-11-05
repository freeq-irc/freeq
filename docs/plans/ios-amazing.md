# Plan: Make the iOS client amazing — flagship-grade demo, mid-2026

**Branch:** `ios-amazing`
**Drafted:** 2026-05-17
**Predecessor:** `docs/plans/ios-catchup.md` (most of which has shipped — see "What already landed")

## 0. Demo goal

A single five-minute video shot on one iPhone (with a second device joining mid-demo) that shows, in order:

1. Cold launch → channels and DMs render from cache instantly, then reconnect goes green.
2. Sign in with Bluesky (already done) → signed-message lock badge appears on every send. Step-up flow for an image upload that requires elevated scope.
3. Start a video call in `#freeq` from the iPhone. A second device — web or another iPhone — joins via the in-channel "call in progress" speaker glyph. Both sides see actual camera frames (not placeholders).
4. While the call is live, post a coordination card from `freeq-cc` (the Claude Code agent), such as a task it posts; freeq-cc does not stream its replies, so a streaming reply needs another sender. The card renders as a rich card on iOS, not a wall of text.
5. Drop into a 1:1 DM with `yokota` (an agent), ask "/diagnose why I couldn't join #foo" and get a structured diagnostic reply rendered as a card.
6. Show federation — the same call/messages mirrored on a second freeq server via S2S.

Everything in §1–§3 is "must demo." §4–§6 are the differentiators that make people forward the video.

## 1. What already landed (do not re-do)

The 2026-05-13 batch and earlier shipped most of `ios-catchup.md`:

- ✅ Signed-message lock badge — `MessageListView.swift:537`
- ✅ Reaction toggle / `+freeq.at/unreact` — `AppState.swift:949` (out), `:1657` (in)
- ✅ AV lifecycle TAGMSGs (`+freeq.at/av-state`, `av-id`, `av-actor`) — `AppState.swift:1662-1691`, `av-join`/`av-leave` at `:336/:345`
- ✅ Inbound PIN/UNPIN handler — `AppState.swift:1497-1505`
- ✅ CHATHISTORY auto-fetch on scroll — `AppState.swift:397-404`
- ✅ Persistent buffer cache → instant cold launch — `b5ce9a8`, `4fae618`
- ✅ Proactive web-token refresh on foreground — `75ba865`
- ✅ Optimistic local reaction/delete updates — `f236df2`
- ✅ Step-up auth for blob upload — `82053a3`, `StepUpAuth.swift`
- ✅ Live Activity (Dynamic Island / lock screen) for active calls — `CallActivityAttributes.swift`

## 2. Phase 1 — Foundation (do first, blocks everything)

### 1.1 Rebuild `FreeqSDK.xcframework`

The xcframework is roughly two weeks behind `freeq-sdk-ffi`. Missing in the iOS-visible surface as a result:

- The full message-signing path (MSGSIG handshake, `+freeq.at/sig`) — server-side fallback is masking this on iOS, but client-side signing is the demo-able story.
- DPoP nonce retry for SASL (P1 just marked done in `CLAUDE.md`).
- `requestHistory(timestamp:)` overload (`9ee5fec`).
- Inbound streaming PRIVMSG / `+draft/edit` streaming tag plumbing (`5c6604d`) — needed for §4 demo.

**Action:** run `freeq-ios/build-rust.sh` after confirming it still works post the 2026-05-12 SDK reshuffle; regenerate `Generated/freeq.swift`; do a smoke pass on connect/SASL/PRIVMSG/AV-start before touching anything else.

**Acceptance:** the `Generated/freeq.swift` file diff shows the new SDK surface; one signed message is verifiable in the server logs as client-signed (not server-fallback-signed).

### 1.2 Wire `API-BEARER` into an `AgentToolsClient`

After SASL success the server emits `NOTICE * :API-BEARER <token>` (`4e37463`). The SDK already captures this; iOS needs a thin Swift wrapper to make authenticated calls to `/agent/tools/<capability>`. This unlocks §5 of the demo.

- Add `Models/AgentToolsClient.swift` with one method per capability we care about for the demo: `diagnoseJoinFailure`, `predictMessageOutcome`, `inspectMySession`. Bearer header from `freeq.apiBearer`.
- Surface it on `AppState` as `var agentTools: AgentToolsClient?` populated after the API-BEARER notice.

**Files:** new `Models/AgentToolsClient.swift`, edit `AppState.swift` (event handler for the API-BEARER NOTICE — currently it's likely being treated as a generic NOTICE).

### 1.3 Test net for the routing/auth/AV state machines

The only test file today is `BufferRoutingTests.swift`. Everything we ship in Phase 2/3 will touch the IRC event dispatch, the AV state machine, or the auth path. We need at least these new test files **before** we start cutting flagship features, otherwise every demo break will be a five-hour debug:

- `EventDispatchTests.swift` — fake the FFI events for PRIVMSG/TAGMSG/edit/delete/reaction/pin/AV-state and assert `AppState` mutations.
- `AvStateMachineTests.swift` — start, remote start, join, leave, double-leave, peer drop, late join after our own start, server says ended while we think we're in.
- `AuthRecoveryTests.swift` — 401, 5xx (verify we do NOT clear credentials per `e48d4ca`), 14-day grace window, broker DB wiped.

**Budget:** one focused day. Use the existing `BufferRoutingTests` style. Coverage target: every branch in the SwiftEventHandler.

## 3. Phase 2 — Make AV actually demo

This is the largest single piece of work and what people will actually remember.

### 2.1 Real video capture and rendering

`CallView.swift` is 122 lines of placeholder. The demo cannot ship until this renders real frames.

- Capture local camera via `AVCaptureSession`, preview in an `AVCaptureVideoPreviewLayer`-backed `UIViewRepresentable`.
- Remote frames: the `freeq-av-client` crate already speaks MoQ via the SFU at `/av/moq` (see `web.rs:216`). For iOS we either (a) call the same MoQ endpoint via Swift, or (b) wrap the existing Rust `freeq-av-client` in a UniFFI binding the same way we wrapped `freeq-sdk-ffi`. **Recommend (b)** — the protocol is non-trivial and we already have the Rust code.
- Add `freeq-av-ffi` crate alongside `freeq-sdk-ffi`. Expose: `startCall(channel) -> CallHandle`, `localVideoTrack() -> Stream<Frame>`, `remoteTracks() -> Stream<(participant_did, Stream<Frame>)>`.
- Render with `CVPixelBuffer` → `CAMetalLayer` for performance.

**Files:** new `freeq-av-ffi/`, new `freeq-ios/freeq/Views/VideoFeedView.swift`, rewrite `CallView.swift`.

**Risk:** highest in the plan. Time-box this to 3-4 days; if the FFI layer balloons, fall back to audio-only for the first demo and ship video in Phase 3.

### 2.2 Per-channel "call active" affordance

Today the speaker glyph in the topbar (`ChatDetailView.swift:121`) is gated on `isInCall` — i.e. only shows if **I'm** in a call. It should show whenever `activeAvSessions[channel] != nil`, with a tap-to-join action.

- Bind topbar speaker icon to `activeAvSessions[channel]`.
- Tapping when not in the call → `joinExistingCall(channel)` (already wired, just needs surface).
- Make the icon pulse (subtle) when participants > 1.

**Files:** `ChatDetailView.swift`, `SidebarView.swift` (also show a dot next to channels with active calls).

### 2.3 Inline call panel instead of modal

`CallView` is presented modally over chat. Web ships an inline panel (commit 721fd71 lifted the WIP). For iOS the right answer is probably a top-anchored mini-panel with a "expand" handle to go full-screen — matches the Picture-in-Picture muscle memory.

- Defer the inline-panel work until §2.1/§2.2 are solid. It's polish.

## 4. Phase 3 — Coordination cards & streaming agent UI

This is what makes the demo feel like a chat client from 2026, not 2006.

### 3.1 CoordinationCardView

The `+freeq.at/event`, `+freeq.at/payload`, `+freeq.at/task-id`, `+freeq.at/evidence-type` tags now relay over S2S (`b86f1f6`). Web renders these as cards (`CoordinationCards.tsx`). iOS sees the raw PRIVMSG body today.

- New `Views/CoordinationCardView.swift`. Switch on `event` type: `task.created`, `task.completed`, `evidence.attached`, `agent.spawned`, etc.
- Decide rendering: SwiftUI `GroupBox` with a header glyph, payload pretty-printed as key/value list, a "view details" button that opens the linked artifact.
- Wire into `MessageListView.swift` — when a message has these tags, render the card instead of (or above) the text body.

**Files:** new `Views/CoordinationCardView.swift`, edit `MessageListView.swift` row rendering.

### 3.2 Streaming reply UI

After the SDK rebuild, incoming `+freeq.at/streaming=1` PRIVMSGs followed by `+draft/edit` edits should produce a typing-cursor effect. The SDK already handles the edit chaining; iOS needs the visual.

- In `MessageListView.swift`, when a message is in `streaming` state, render a subtle blinking caret at the end and a faint background pulse.
- When the final edit clears the streaming tag, drop the effect.
- No protocol work — pure render.

### 3.3 Agent tools as slash commands

Wire `/diagnose`, `/predict`, `/whoami` slash commands to the `AgentToolsClient` from §1.2. Render replies as coordination cards from §3.1.

- Edit `ComposeView.swift:543-597` slash-command parser.
- Render the JSON response as a card with a friendly title.

## 5. Phase 4 — UX polish that closes the gap to web

Order by demo-visibility. These are independent items; pick based on time left.

| Item | Files | Effort | Demo value |
|---|---|---|---|
| Slash-command autocomplete (`/pins`, `/me`, `/topic`, `/nick`, `/diagnose`) | `ComposeView.swift` | S | M |
| QuickSwitcher (Cmd-K on iPad keyboard) | new `Views/QuickSwitcher.swift` | S | M |
| Format toolbar (bold/italic/code) | `ComposeView.swift` | S | L |
| Bookmarks panel | new `Views/BookmarksPanel.swift`, plus REST endpoint | M | S |
| Markdown rendering for message bodies | new `Views/MarkdownText.swift` (likely `swift-markdown` or `MarkdownUI`) | M | L |
| Sidebar: active-call dot, unread dot polish | `SidebarView.swift` | S | M |
| Agent manifest viewer (tap a bot's avatar → see delegation cert, creator, capabilities) | new `Views/AgentProfileSheet.swift` (extends `UserProfileSheet`) | M | L |
| Audit timeline (per-channel) | new `Views/AuditTimeline.swift`, uses `/api/v1/channels/{name}/audit` | M | M |

The Agent manifest viewer is unusually high-leverage for the demo because the actor/manifest endpoints already give us everything (we just used them in the yokota investigation earlier this session). A pretty card showing "Yokota — Chad Fowler's AI familiar — delegated via Bluesky on 2026-04-09" is exactly the screenshot people will repost.

## 6. Phase 5 — Demo prep (do last, time-box to a day)

- Seed two iOS devices and one web client with consistent test data.
- Pre-create the channels and the freeq-cc agent in `#freeq`.
- Record a fallback video for §3 in case live AV fails on demo day.
- Add a hidden `?demo=true` query / debug toggle that auto-mutes notifications and forces light/dark theme to the recorded look.

## 7. Risks and unknowns

- **AV video FFI complexity (§2.1).** Biggest unknown. If `freeq-av-client`'s MoQ stack doesn't trivially wrap into UniFFI (e.g. async streams of pixel buffers), we'll lose a week. Mitigation: spike `freeq-av-ffi` in a worktree for half a day before committing the rest of the plan to it.
- **Apple Push for incoming calls.** If we want a real "incoming call" ring like FaceTime, we need PushKit + CallKit + a server-side push from the AV session start. That's a separate plan; for the demo, the Live Activity is sufficient.
- **App Store review.** No new permissions beyond Camera/Mic (already declared for the existing CallView). Verify before submitting.
- **iCloud Keychain sync.** Already turned off in `6015367`. Don't re-enable.
- **Federation demo logistics.** Need a second freeq server peered to `irc.freeq.at` for §6 of the demo. Confirm one exists or stand one up — separate prep task, not blocking iOS code.

## 8. Suggested execution order

1. Phase 1.1 (xcframework rebuild) — half day
2. Phase 1.3 (test net) — one day
3. Phase 2.1 AV video spike — half day, decide path
4. Phase 1.2 (AgentToolsClient) — half day, in parallel with the spike
5. Phase 2.1 full implementation — 3 days
6. Phase 2.2 (per-channel call affordance) — half day
7. Phase 3.1 (CoordinationCardView) — one day
8. Phase 3.3 (slash → agent tools) + Phase 3.2 (streaming UI) — one day
9. Phase 4 polish — fill the remaining time, prioritize by the table
10. Phase 5 demo prep — final day

Roughly two weeks if Phase 2.1 lands cleanly; three weeks if the AV FFI gets ugly.

## 9. Open questions for Chad

- AV: are we committing to video for v1 of the demo, or is audio-only acceptable as a fallback if the FFI work blows out?
- Coordination cards: which event types are highest-priority for the demo? `task.created` from freeq-cc is the obvious one — anything else?
- Federation demo (§6): do we have a second peer server stood up, or should I plan to stand one up?
- Agent manifest viewer (§4): should it surface the unverified delegation state plainly (the yokota case) or hide it until we've fixed the verifier?
