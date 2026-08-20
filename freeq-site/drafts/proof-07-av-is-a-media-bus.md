# AV is a media bus, not a video-call feature

Adding calls to a chat system usually means adding a call *feature*: a button, a
room type, a server that now knows about meetings. freeq did something narrower,
and the narrowness is the whole point.

Starting a call is a message with tags on it. Here is one, sent by an ordinary
client:

```
→ @+freeq.at/av-start=;+freeq.at/av-instance=abcd1234;+freeq.at/av-title=standup TAGMSG #call
```

And here is what everyone in the room receives:

```
@time=2026-08-19T23:38:14.000Z;+freeq.at/av-state=started;+freeq.at/av-participants=1;+freeq.at/av-actor=chadfowler;+freeq.at/av-id=01M0E67FX2HKA1RVVJYRVT57GT;+freeq.at/av-instance=abcd1234;+freeq.at/av-title=standup :irc.freeq.at TAGMSG #call
```

```
:irc.freeq.at NOTICE chadfowler :AV session started: 01M0E67FX2HKA1RVVJYRVT57GT
:irc.freeq.at NOTICE chadfowler :AV ticket: webrtc://01M0E67FX2HKA1RVVJYRVT57GT
```

That is the entire involvement of the chat server in a call: it minted a session
id, told the room a call exists and who started it, and handed back a ticket. No
audio passes through it. A client that has never heard of `+freeq.at/av-` sees a
`TAGMSG` it ignores and a notice, and is otherwise unaffected — the same
graceful degradation every other capability gets.

## What the media side actually is

The media rides Media-over-QUIC. Each participant *publishes* one broadcast and
*subscribes* to everyone else's:

```
arbitrary audio source ─┐
                        ├─→ AvSession ─→ one decoded PCM stream per participant
arbitrary video source ─┘
```

Broadcasts are named, not enumerated by a server that owns the call:

```rust
pub fn broadcast_path(session_id: &str, nick: &str, instance: &str) -> String {
    format!("{session_id}/{nick}~{instance}")
}
```

The two halves of `AvSession` are worth stating plainly, because they are the
reason this is a bus and not a feature. **Publishing** takes an audio source and
a video source and pushes one broadcast. **Subscribing** watches the relay's
announcements and, for every other participant in this session, decodes their
audio into a stream of frames:

```rust
pub struct AvParticipant {
    pub audio: mpsc::Receiver<PcmFrame>,
    // …
}
```

One receiver per participant. Not a mixed room track — a separate decoded stream
per person, which is the difference between "we support calls" and "your program
can hear each participant individually".

## What that buys, mechanically

**A source is anything that produces samples.** The publishing side takes a
`PushAudioSource`: you push PCM into it. Speech synthesis is a source. A file is
a source. A generator is a source. Nothing in the session knows or cares whether
a microphone is involved, which is why an agent can speak in a call without
anyone building an agent-speaking feature.

**A sink is anything that consumes them.** Because you get one stream per
participant, transcription, recording, or analysis is an ordinary consumer of
those streams, and it knows who said what without diarisation — the streams are
already separated by identity.

**Reconnection is the session's problem, not yours.** The transport drops; the
session reconnects with backoff, ends every participant's stream, and
re-announces them fresh. Consumers see a clean restart rather than a silent
stall.

## The trust boundary, drawn honestly

```
identity, signalling, membership, policy      →  the IRC server sees these
audio and video bytes                          →  the media relay carries these
who is in the call, when, and for how long     →  both can infer this
message content in the channel                 →  the IRC server sees it (unless sealed)
```

Two services, two views, neither complete. The chat server never holds media;
the media relay never holds your identity or your messages. Metadata about the
call — that it happened, who was in it — is visible to both, and no arrangement
of this design hides it.

## Try it

**See it in 30 seconds.** The four lines at the top: a tag starts a call, the
room is told, a ticket comes back. That is the whole signalling protocol you have
to implement to interoperate.

**Run it in 5 minutes.** Start a server and drive the signalling by hand with the
[ninety-line client](https://github.com/freeq-irc/freeq/tree/main/examples/python-agent):

```bash
cargo run -p freeq-server -- --listen-addr 127.0.0.1:6889 --web-addr 127.0.0.1:6890 \
  --db-path /tmp/freeq/s.db --data-dir /tmp/freeq --server-name irc.freeq.at
```

```
@+freeq.at/av-start=;+freeq.at/av-instance=abcd1234;+freeq.at/av-title=standup TAGMSG #call
```

Watch a second client in the same channel receive the session announcement.

**Extend it in 30 minutes.** Write a sink. Take `AvSession`, subscribe, and do
something per participant with the PCM: level meters, a transcript, a recording
named by nick. The interface you are programming against is
[`freeq-av/src/session.rs`](https://github.com/freeq-irc/freeq/blob/main/freeq-av/src/session.rs),
and the useful realisation is that "join a meeting and process each person's
audio" is a small program rather than a partnership with a conferencing vendor.

## What this does not claim

**No call was recorded for this post.** What is captured above is the signalling,
end to end, on a server anyone can start. The media path is described from the
implementation, not demonstrated with audio — a session with real participants
needs a relay, and standing one up is not something this post walks you through.

**The relay is a third party.** Media does not flow peer-to-peer through some
magic; it goes to a MoQ relay and back out. That relay sees traffic patterns and
timing for everyone in the call, and freeq's identity guarantees say nothing
about it.

**Media is not sealed by the message encryption.** The DM ratchet and the group
scheme cover messages. Call audio is a separate path with separate properties,
and treating "our DMs are sealed" as "our calls are sealed" would be wrong.

**One decoded stream per participant is a property of the session API, not a
promise about scale.** Thirty participants means thirty decoders in your process.

## What is rough

`+freeq.at/av-` tags are consumed rather than relayed onward in some paths, so a
task or mutation message that carries one is refused rather than half-delivered.
That is deliberate, and it means the AV family does not compose with the others
on a single message.

The ticket in the notice is a bare session locator. Token minting for a relay
that requires authorisation is a separate REST call, and the two are not one
flow.

Video is one track per participant with no simulcast or layer selection, so a
client that wants a small tile decodes the same stream as one that wants a large
one.

## Come in

`#freeq` on `irc.freeq.at` is the channel. A plain client is asked to accept
the house rules on the way in — `POLICY #freeq ACCEPT`, then `JOIN #freeq`.

Source at [github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq). If
you build a sink that does something strange with per-participant audio, that
is the contribution this post is fishing for.

Next: a room that asks the outside world a question before it lets you in.
