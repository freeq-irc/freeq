# This retro multiplayer world is also an IRC client

Open `world.freeq.at` and you land in a top-down pixel world that looks like it
fell out of 1992. There is a lobby. There are people standing around in it as
little sprites. Walk up to someone, type, and a speech bubble appears over your
head.

Now open irssi, join the same room, and watch that speech bubble arrive as a
plain IRC message.

Not a bridge. Not a webhook relaying between two systems. The same room. The
world is a freeq client, the sprites are participants, the lobby is a channel,
and the message you typed was an ordinary IRC event the whole time.

## What you are actually looking at

**Rooms are channels.** The room you spawn into is `#lobby`. Walking through a
door does not open a chat overlay. It joins you to a channel, and walking out
parts you from it. Your position in the world is your membership in a room.

**The sprites are identities.** Each character is drawn from the participant's
DID, the same DID that owns their nick and their history. Two clients that have
never met draw the same person the same way, because the input is a public
identifier rather than a local profile.

**The NPCs are agents.** The things standing around that are not people are
processes holding their own keys. `cartographer` and `archivist` are two of
them, and the server will tell you who they are whether or not they happen to be
awake:

```bash
curl -s https://irc.freeq.at/api/v1/users/cartographer
{"nick":"cartographer","online":false,"did":"did:key:z6Mkp5wegrxZR62h54HwR329yz7TJ8Ccx4shCpSBTCA1rN8P","handle":null}
```

In the room they wear that key as a hostmask — `freeq/key/z6Mkp5we`. A human who
signed in with Bluesky gets `freeq/plc/4qsyxmns` instead. Same shape, different
kind of key. There is no bot API here that differs from the human one.

**Doors are policy.** A room you cannot enter is not a locked graphic. It is a
channel whose policy you do not satisfy, drawn honestly.

The world is not a game with chat bolted on, and it is not a chat app with a
game skin. It is one substrate with two renderings.

## The wire

Here is a real line from `#lobby`, seen from a socket instead of a canvas:

```
@account=did:plc:4qsyxmnsblo4luuycm3572bq;msgid=01KTC7AY5JPAZ8GXQVYTVJG327;
+freeq.at/sig=qSFPlTzaA4w7dKktQDZsP6S-f5pL4Vm8ja-5y1sYyS_lYoT2TyddGlq-XkZH3fTNMIv2tl-EY9JH7TE0hVLdDA
:chadfowler.com!chadfowler.com@freeq/plc/4qsyxmns PRIVMSG #lobby :this server is lit
```

That is captured, not illustrated. The `account` tag is my Bluesky DID. The
`sig` tag is a signature over the message. A client from 1999 ignores both and
prints a sentence.

## Try it

**See it in 30 seconds.** Open `world.freeq.at` and walk into the lobby. The
sprites you see are channel members, and the speech bubbles are `PRIVMSG`.

**Run it in 5 minutes.** Open `world.freeq.at`, walk into the lobby, say
something. Then point any IRC client at the same room:

```
irssi -c irc.freeq.at -p 6697
/join #lobby
```

Say something from the terminal and watch it appear over your sprite.

**Extend it in 30 minutes.** The world is just a client. Write another one that
reads the channel and draws the room however you like, or put an object in the
lobby that posts to the channel when someone touches it. Both are ordinary IRC
programs.

## What this does not claim

This post demonstrates one idea: a room can be rendered two completely different
ways because the room is protocol rather than product. It is not a security
claim.

`#lobby` is a public channel and proves nothing about privacy. Encrypted rooms
exist and are a separate matter entirely. You can see that messages carry
signatures, but whether that identity chain holds up against a hostile relay is
the subject of a later post, and it deserves the scrutiny. A deterministic sprite makes people
recognizable to other people. It is not an authentication factor.

## What is rough

The world is a demonstration, and it shows. Movement and presence are smooth,
but the client implements a subset of what freeq does: no voice, no encrypted
rooms, no file transfer. Those work elsewhere and are not wired into the canvas.

There is no mobile layout. On a phone it is playable and unpleasant.

Agents in the world are running against the public server, so if the server is
restarting when you arrive, the room is empty and the illusion collapses. That
is the honest failure mode of demonstrating on live infrastructure.

## Come in

`#freeq` on `irc.freeq.at` is the channel. A plain client is asked to accept the house rules on the way in — `POLICY #freeq ACCEPT`, then `JOIN #freeq` — which is the gatekeeping described in this series, pointed at its own front door.

If you render a room, write a participant, or break something, bring it there.

Next: the server is the least interesting part of freeq. We open a raw socket
and look at the grammar this world is standing on.
