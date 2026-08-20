# Two servers, one room, and no address between them

Everything so far happened on one server. This proof takes the room apart and
runs it on two machines that were never introduced.

Start a server. It prints a name for itself:

```
INFO freeq_server::iroh: Iroh endpoint ID: b6674b20e61d87c00f8a56f9608086391d501bf2a51c82382acc0a05f7ca2d5e
INFO freeq_server: Iroh ready. Connect with: --iroh-addr b6674b20e61d87c00f8a56f9608086391d501bf2a51c82382acc0a05f7ca2d5e
```

That string is a public key, not an address. There is no hostname in it, no
port, nothing a firewall can be configured around. Start a second server, tell
it that key, and the two of them work out how to reach each other:

```
INFO S2S Hello received — binding transport identity to server name
     peer=b6674b20e61d87c00f8a56f9608086391d501bf2a51c82382acc0a05f7ca2d5e
     server_name=a.freeq.test protocol_version=2 peer_trust=full
INFO S2S HelloAck: mutual authentication confirmed
     peer=b6674b20e61d87c00f8a56f9608086391d501bf2a51c82382acc0a05f7ca2d5e
     claimed=b6674b20e61d87c00f8a56f9608086391d501bf2a51c82382acc0a05f7ca2d5e trust=Some("full")
```

The peer is named by the key it proved it holds, and the name it claims for
itself is bound to that key rather than to DNS. Two servers, no address, no
inbound port configured on either.

## It refuses to be friendly by default

Point a server at a peer without also saying who is allowed to connect and it
will not start:

```
Error: S2S peers configured but --s2s-allowed-peers is empty. This would allow
any server to connect. Set --s2s-allowed-peers to the endpoint IDs of your
trusted peers.
```

Federation that defaults to open is federation that gets abused, so the failure
is loud and at startup, where mistakes are cheap.

## One room, two servers

`alice` connects to server A. `bob` connects to server B. Both join `#shared`,
which neither server was told about in advance:

```
bob@B sees:   @+freeq.at/origin=a.freeq.test;msgid=01M0E6CGNXBC5MN2EWC99BBX9Y;+freeq.at/sig=ed25519:fOYbQGVTrUhjYQb2buOPEw:r0DjoFhO4SgHWeriLWgnX4oyvB5HHhsDCmBKKjOvzklV_O7YHxIXTCcYBTqRcnvgl7dmWbr3UX9jE4S_9aTEDw :alice PRIVMSG #shared :morning from server A
alice@A sees: @msgid=01M0E6CM3NXF9MJ87RNHPNM45F;+freeq.at/sig=ed25519:vwsKzPyddg-gZYvqgV1iiA:UIj5T_Q6ivAU-SZjzPON0kOOXN1eiqMBpEwcznPKs6XUKqzMp2qfsKYCz3uUbkeph-dEMuiYUDl6t75pnbKBBw;+freeq.at/origin=b.freeq.test :bob PRIVMSG #shared :and from server B
```

Two things ride along that matter more than the delivery. `+freeq.at/origin`
names the server where the message was authored, so a relayed line is never
mistaken for a local one. And `+freeq.at/sig` is the author's own signature,
carried across the hop unchanged — the receiving server checks it against the
author's key rather than trusting the peer that handed it over. A hostile relay
in the middle can drop your message. It cannot write one in your name.

Ask each server who is in the room and they agree:

```
server A: @alice bob
server B: bob @alice
```

Same members, same op, two databases.

## Now break it

Kill server B while alice keeps talking:

```
server B: down 23:42:03
server B: back 23:42:17
```

B comes back and immediately asks what it missed:

```
INFO S2S catch-up requested   peer=b6674b20… since_ts=1787096540
INFO S2S catch-up: answering with events from the log
     asked_by=b6674b20… since_ts=1787096540 count=4 more=false
INFO S2S catch-up: applied replayed events  count=4 filed=0 conflicts=0 more=false
```

Four events replayed, no conflicts, and the link is live again:

```
@+freeq.at/origin=a.freeq.test;+freeq.at/sig=ed25519:fOYbQGVTrUhjYQb2buOPEw:qMtUKwtxXZxF-tCmQJ_eoEHaetJYs9Z5Yyrm_lYrSEexwb5ZiX6Q7kvwpICvwyYfwDLmd2HaMRGDAnruhSUKBA;msgid=01M0E6J3ZQGXJVM3KN63S8F8WM :alice3 PRIVMSG #shared :after the outage, live again
```

## What did not come back

Here is the part a demo would skip. Join `#shared` on server B after the outage
and ask for the room's history:

```
:b.freeq.test 353 bob2 = #shared @bob2
```

Nothing. The two messages alice sent while B was unreachable are on A, and they
stay on A. The catch-up reconciles the signed **event log** between peers; it
does not backfill a peer's chat scrollback for a room that had nobody in it
locally. Live traffic converges. Absent history does not.

That is a real limit, and it is the one worth understanding before you build on
this: what federates is participation, plus a log the two servers agree on. What
does not federate is the experience of having been there.

## What "decentralized" means here, exactly

Transport, discovery and delivery have no coordinator — two servers reach each
other by key, and neither is the other's home. Authority is a different
question, and it has owners: the channel's founder and its ops decide policy;
each identity is resolved through its own DID document; each server enforces its
own rules on the events it accepts from a peer, including refusing a mode change
or a kick from someone the peer says is an op but this server does not.

"No global coordinator, but scoped authorities" is the accurate sentence. Anyone
who tells you a system has neither is selling something.

## Try it

**See it in 30 seconds.** The two log lines at the top: a server naming itself
with a public key, and a peer binding that key to a claimed name.

**Run it in 5 minutes.** Two servers on one machine, dialing by key:

```bash
mkdir -p /tmp/fedA /tmp/fedB
cargo run -p freeq-server -- --listen-addr 127.0.0.1:7001 --db-path /tmp/fedA/a.db \
  --data-dir /tmp/fedA --server-name a.freeq.test --iroh
# note the endpoint ID it prints, then in another terminal:
cargo run -p freeq-server -- --listen-addr 127.0.0.1:7002 --db-path /tmp/fedB/b.db \
  --data-dir /tmp/fedB --server-name b.freeq.test --iroh \
  --s2s-allowed-peers <A's endpoint id> --s2s-peers <A's endpoint id>
```

Connect a client to each, join the same channel from both, and talk. Then kill
one and watch the other keep going.

**Extend it in 30 minutes.** Do it with a friend, on two machines, in two
countries, and check the harder claim: that neither of you opened a port. Then
try to make the servers disagree — set a mode on both sides during a partition
and see which one wins when they meet again.

## What this does not claim

Both servers in this capture ran on one laptop. What that proves is that a
server can be dialed by key with no address configured, that the peers
authenticate each other mutually, and that state converges. It does not prove
traversal of a hostile NAT, because there was no NAT between these two
processes. The transport underneath is iroh, whose whole business is that
traversal; this post is not the evidence for it.

Message delivery across the hop is not an anonymity property. Both servers see
who is talking in a shared channel and when. The signature stops a relay from
forging your words; it does nothing about metadata, and end-to-end encryption is
a separate mechanism with a separate post.

"Two databases agreed" is a claim about the events they exchanged, not about
everything either one holds. The history gap above is the honest edge of it.

## What is rough

Catch-up is bounded by a timestamp the returning peer supplies, and the answer
is capped per exchange. A peer that was away for a long time gets what fits and
asks again; there is no completion proof at the end of it.

The endpoint allowlist is checked on the accepting side, and a peer's trust
level is configured locally. Two operators who disagree about each other's trust
level have a working link with asymmetric rules, which is legible in the logs
and surprising in practice.

Rules text for a policy stays on the server where it was set; peers get the hash.
A federated reader can prove which rules were accepted, and has to fetch the
sentence from home.

## Come in

`#freeq-dev` on `irc.freeq.at`, and the source is at
[github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq). If you run a
node and it fails to converge with someone else's, that is the bug report we
most want.

Next: the conversation is the commit — signed intent, an agent that acts on it,
and a record of why a system changed.
