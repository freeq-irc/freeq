# How iroh Does Group AV Sessions in freeq

A focused companion to `AV-ARCHITECTURE.md`. That doc explains the
browser path (MoQ over WebSocket, no iroh). This one explains the **iroh
path**: how a group call becomes a set of QUIC connections between peers,
who discovers whom, and where the server sits.

Everything here is behind the `av-native` feature.

---

## 1. One endpoint, many protocols

freeq runs **one** `iroh::Endpoint` per server. Its identity is a
persistent ed25519 key (`{data_dir}/iroh-key.secret`), so the endpoint ID
survives restarts. Everything iroh-shaped is multiplexed onto it by ALPN:

```
iroh::Endpoint  (QUIC, hole-punched, relay fallback)
  ├─ freeq/iroh/1   → IRC-over-QUIC client connections   (iroh.rs)
  ├─ freeq/s2s/1    → server-to-server federation        (s2s.rs)
  └─ iroh-live ALPNs → gossip + MoQ for AV rooms         (av_media.rs)
```

The ALPN list is registered **at bind time**, and all handlers are
mounted on a single `iroh::protocol::Router` in `iroh::spawn_router()`:

```rust
Router::builder(endpoint)
    .accept(ALPN,     IrohClientProtocol { state })
    .accept(S2S_ALPN, S2sProtocol { state })
// then, if av-native:
let builder = live.register_protocols(builder);
builder.spawn()
```

> **Load-bearing detail.** `iroh_live::Live::builder(...).with_router()`
> is deliberately *not* called. iroh-live's own router calls
> `endpoint.set_alpns(...)`, which would **replace** the freeq ALPNs and
> break every inbound IRC + S2S dial with TLS `no_application_protocol`.
> Instead `Live::register_protocols()` mounts gossip + MoQ onto freeq's
> shared `RouterBuilder`. See the comment in `av_media.rs`.

---

## 2. A group session = a Room = a ticket

`iroh_live::rooms::Room` is the group primitive. It is created by the
server when someone starts a call (`av_media.rs::create_room`):

```rust
let ticket = RoomTicket::generate();          // random capability
let room   = Room::new(&live, ticket).await?; // joins the gossip topic
let (events, handle) = room.split();          // inbound events / outbound control
```

- **`RoomTicket`** is the whole membership model: a random,
  unguessable token that doubles as the gossip topic id. Holding the
  ticket *is* the right to join. There is no per-room ACL below it —
  authorization happens above, in IRC.
- **`RoomHandle`** is the outbound half: `publish()`, `publish_producer()`,
  `set_display_name()`.
- **`RoomEvents`** is the inbound half: `PeerJoined`, `PeerLeft`,
  `BroadcastSubscribed`, …

The ticket string is persisted on the session row
(`av_sessions.iroh_ticket`) and handed to each joiner over IRC
(`connection/messaging.rs`, the `av-join` handler). So:

```
IRC (control plane)                     iroh (media plane)
────────────────────                    ──────────────────
TAGMSG +freeq.at/av-start   ──►  create_room() → RoomTicket
                            ◄──  ticket persisted + returned
TAGMSG +freeq.at/av-join    ──►  server sends the joiner the ticket
native client                    Room::new(&live, ticket) → joined
```

Control is IRC; membership is a ticket; media is QUIC. The three are
intentionally decoupled — the media backend is swappable.

---

## 3. Discovery inside a room: gossip, not a roster

Once two endpoints hold the same ticket they are on the same **gossip
topic**. That is how group membership propagates — there is no central
roster in the media plane:

1. A peer joins the topic and announces itself → every other member
   gets `RoomEvent::PeerJoined { remote, display_name }`.
2. Each peer publishes exactly **one broadcast** (its own mic/cam):
   `handle.publish(&display_name, &broadcast)`.
3. Every other peer learns of that broadcast and subscribes → they get
   `RoomEvent::BroadcastSubscribed { session, broadcast }`.
4. Leaving (or dying) produces `PeerLeft`, and the broadcast is
   unannounced.

So a room of N native peers is a **full mesh**: N−1 outbound
subscriptions per peer, each an iroh QUIC connection carrying MoQ
objects. The server is *not* in that path. Two native clients in the
same room talk directly, hole-punched, falling back to an n0 relay only
if the punch fails.

```
        Room ticket = gossip topic T
   ┌──────────┐  QUIC  ┌──────────┐
   │ native A │◄──────►│ native B │
   └────┬─────┘        └─────┬────┘
        │  QUIC      QUIC    │
        └────────┬───────────┘
            ┌────▼─────┐
            │ native C │      no server in the media path
            └──────────┘
```

### Broadcast naming

Media inside a session is addressed by path:

```
{session_id}/{nick}~{instance}      e.g.  01KN7X…/eliza~0a1b2c3d
```

`~{instance}` lets one identity join from two devices without a path
collision. `freeq-av`'s helpers (`broadcast_path`, `path_nick`,
`should_tap`) parse and filter these. `should_tap` is the join
gate every agent uses:

- skip our own exact broadcast (else we hear our own TTS),
- skip *any* broadcast whose nick is ours (second device),
- require the `{session_id}/` prefix — the trailing slash is
  load-bearing so session `sess` doesn't tap `sess2`,
- otherwise: subscribe.

---

## 4. The bridge: browsers and native peers in one call

Browsers can't speak iroh. They speak MoQ over WebSocket to the
`moq_relay::Cluster` SFU. To put both in the same call, the server joins
the room **as a participant** and forwards in both directions
(`av_bridge.rs`):

```
 Browser ──MoQ/WS──►┐                                ┌──► native peer
                    │   moq_relay::Cluster           │
 Browser ◄──MoQ/WS──┤          ▲   │                 │
                    │  MoQ→Room│   │Room→MoQ         │
                    │          │   ▼                 │
                    └───── freeq-server as a ────────┘
                            Room participant
                                (iroh QUIC + gossip)
```

- **MoQ → Room**: the bridge subscribes to cluster announcements,
  filters to `{session_id}/…`, and republishes each browser broadcast
  into the room via `room.publish_producer()`, forwarding tracks
  on demand (`dynamic.requested_track()` → `subscribe_track` →
  `forward_track`).
- **Room → MoQ**: on `BroadcastSubscribed` it builds a fresh
  `BroadcastProducer`, re-serializes the catalog (the `RemoteBroadcast`
  already consumed `catalog.json`), and publishes it into the cluster at
  `{session_id}/{broadcast_name}`.

Both directions are **Opus in hang/MoQ broadcasts**, so the bridge pipes
`BroadcastConsumer`s — no transcode.

**Loop prevention** is a single shared `HashSet<String>` of bridged
paths. Whichever direction bridges a path first records it; the other
direction skips it. Without this, browser audio would be forwarded into
the room, come back as a room broadcast, and be republished to the
cluster forever.

---

## 5. Two topologies, one session

| | Native ↔ Native | Anything ↔ Browser |
|---|---|---|
| transport | iroh QUIC (P2P, relay fallback) | MoQ over WebSocket (TLS/TCP) |
| topology | full mesh via gossip | star through `moq_relay::Cluster` |
| discovery | `RoomEvent` / MoQ announce | REST roster poll + MoQ announce |
| server role | not in media path | SFU, and bridge participant |
| membership | `RoomTicket` | per-session JWT (`?jwt=`) |

A mixed call is a mesh with one node (the server) that happens to also
be an SFU.

---

## 6. Agents: `freeq-av::AvSession`

Agents don't touch rooms directly; `freeq-av/src/session.rs` wraps the
whole thing:

```rust
let mut session = AvSession::connect(config, audio_source, make_video);
while let Some(mut p) = session.recv().await {
    while let Some(frame) = p.audio.recv().await { /* STT, record, meter */ }
}
```

It publishes one broadcast (Opus mic + optional H.264 tile), watches the
announce stream, and spawns one **tap** per remote participant. The
non-obvious behaviours, all learned from live failures:

- **Reconnect with backoff** (2,4,8,16,16 s); a session that ran >30 s
  before dropping resets the counter. Every reconnect re-announces all
  participants, so the same nick can surface more than once.
- **Re-tap on track end.** A track can stop while the participant stays
  in the call (mic restart, transport hiccup). The path stays announced,
  so a one-shot tap would go permanently deaf. The tap loops on
  `audio_ready`.
- **`audio_ready`, not `audio()`.** The latter is a one-shot catalog
  read and fails permanently if the Opus track lands a beat after the
  broadcast is announced.
- **Video freshness.** `VideoHandle::latest()` returns `None` after 10 s,
  so a camera turned off doesn't leave the agent describing a stale frame
  as live.
- **Unannounce aborts the tap**, freeing the path so a rejoin re-taps.

---

## 7. Limits and sharp edges

- **Mesh scaling.** Native rooms are N×N. Fine for a handful of peers;
  a 30-way native call would need the SFU path, not the mesh.
- **Ticket = capability.** Anyone holding a `RoomTicket` is in the room.
  Session authorization lives in IRC/JWT above it; don't leak tickets.
- **ALPN fragility.** Any code that calls `set_alpns` on the shared
  endpoint breaks IRC and S2S. Register protocols on the Router instead.
- **QUIC vs WebSocket.** Sustained media over MoQ-over-WebSocket
  degrades badly (`connection closed` floods); QUIC does not. See
  `AV-QUIC-MIGRATION.md`.
- **Catalog consumption.** `RemoteBroadcast::new()` eats `catalog.json`.
  The bridge works around it in both directions — don't "simplify" it.

---

## File map

| File | Role |
|---|---|
| `freeq-server/src/iroh.rs` | endpoint bind, ALPNs, unified Router |
| `freeq-server/src/av_media.rs` | `IrohLiveBackend` — room create/close, tickets |
| `freeq-server/src/av_bridge.rs` | MoQ ↔ Room bidirectional bridge |
| `freeq-server/src/av_sfu.rs` | `moq_relay::Cluster`, scoping, session JWTs |
| `freeq-server/src/connection/messaging.rs` | `av-start`/`av-join` → room + ticket |
| `freeq-av/src/session.rs` | `AvSession` — agent publish/subscribe |
| `freeq-av-client/src/main.rs` | reference native room client |
