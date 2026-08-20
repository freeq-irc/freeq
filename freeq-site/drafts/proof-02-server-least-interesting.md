# The server is the least interesting part

A pixel world and a terminal shared one room in the last post. That only works
because of something boring: the server in the middle does very
little.

freeq is a shared environment where humans, agents, services, and media sources
participate as identifiable, programmable peers. IRC is its narrow waist, not
its product category. Identity, signing, policy, encryption, media, and
intelligence live at the edges.

This post is about the waist.

## What the server actually does

It accepts connections, relays events to the channels those events are addressed
to, and keeps enough state to answer who is here and what happened recently. It
does not decrypt anything. It does not mint identities. It does not decide what
a message means.

That sounds like an omission. It is the design. Every capability freeq adds is
carried as an IRCv3 message tag, and tags are data the server forwards rather
than features the server implements. Connect a raw socket and watch:

```
irssi -c irc.freeq.at -p 6697
/join #lobby
```

Or without a client at all:

```
openssl s_client -connect irc.freeq.at:6697 -quiet
NICK yourname
USER yourname 0 * :yourname
CAP REQ :message-tags
CAP END
JOIN #lobby
```

The server tells you what it knows how to carry:

```
:irc.freeq.at CAP * LS :sasl message-tags multi-prefix echo-message server-time
batch draft/chathistory account-notify account-tag extended-join away-notify
draft/read-marker draft/multiline=max-bytes=40000,max-lines=100 iroh=910a9acf...
```

Most of that is standard IRCv3. `sasl` carries one new mechanism,
`ATPROTO-CHALLENGE`, which is how a DID proves it holds a key. `iroh` advertises
a QUIC transport for server-to-server traffic. Nothing there is a freeq feature
in the sense of a thing the server does on your behalf.

## Tags are the extension point

Watch a busy channel and the tags stream past:

```
@+freeq.at/sig=WNXY9YUF7B-ZOfD7vPJuzLUTPaUl3L_UaOQZYAapSFzjt74YJU80BK0IF5Q7SunR7rijCkxfCZ6DoXyxQvk5CA;
msgid=01KXZ0NM839VVBXMAHC84B8QXV;account=did:key:z6MkpYk9z5Y8iCX4bfqtHuFekvWmzEyqQt89yecTqFNtxbTW
:chadfowler!chadfowler@freeq/key/z6MkpYk9 PRIVMSG #lobby :hello
```

```
@+freeq.at/reactions=🎉:chadmac;+freeq.at/sig=sSMmWIDdDz9w76-pp9cH1LFvlKSXkPUYiSZ7bvw2fPixX7Nn5w_Jz8t7A9tg_tkh_jI5Sh3KOiQvFpl9wb7TDA;
msgid=01KK7DHD8AVQW99HEGF2ZZNJCF :chadfowler.com!chadfowler.com@freeq/plc/4qsyxmns PRIVMSG #lobby :...
```

The `+freeq.at/` namespace is a public contract. `sig` carries authorship.
`reactions` carries who reacted with what. A reply carries `+reply` pointing at
another `msgid`. None of these required a server release, because the server was
already forwarding tags it does not interpret.

The consequence is the part worth sitting with. A 1999 client receives every one
of those lines. It ignores the tags and prints the sentence. Two people can sit
in one channel, one of them in a modern client seeing reactions and threaded
replies, the other in irssi seeing plain text, and neither is degraded into a
worse version of the other. Graceful degradation is not a compatibility
courtesy here. It is the test that keeps features from migrating into the
server.

## Why this matters for agents and media

If a capability has to be a server feature, then the server operator decides who
gets it, and every new capability is a negotiation with whoever runs the relay.

freeq puts them at the edges instead. An agent authenticates with the same SASL
mechanism a human uses and emits typed events as tags. A voice call sets some
channel metadata with an ordinary `TAGMSG` while the media travels separately
over MoQ. The server carries the metadata and never touches the audio. A client
that does not know about calls sees messages and is unharmed.

That is why the pixel world could exist without anyone adding a world-mode to
the server. It reads the same events every other client reads.

## Try it

**Run it in 5 minutes.** The `openssl s_client` sequence above. Join `#lobby`
and read the tags going by. That is the whole substrate, visible.

**Extend it in 30 minutes.** Add a client-side feature keyed on a tag, with zero
server changes. Pick an unused name in your own namespace, emit it from one
client, and render it in another. If it works, you have just extended the system
without asking permission from the thing in the middle. That exercise is the
thesis of this post.

## What this does not claim

A thin server is not a trustless one. The relay still sees plaintext in
unencrypted channels, still knows who is connected, and can still drop or delay
messages. Nothing in this post prevents that. What it changes is what the relay
can forge without being caught, and that argument depends on the signature
chain, which the next post takes apart and which is not finished.

"Nothing was forked" is a claim about the wire protocol, not about clients. A
client that wants to render task cards has to learn the tags.

## What is rough

The `+freeq.at/` namespace is a public contract by intention, and it is
versioned informally. It is documented in the repo and stable in practice, but
it has not been through the IRCv3 process.

`draft/chathistory` is exactly what the name says. Replay works and the
specification may move.

Federation over iroh converges and is tested, but it has not run between many
independent operators for long, so claims about the relay layer are strongest
for the single-server case today.

## Come in

`#freeq` on `irc.freeq.at` is the channel. A plain client is asked to accept the house rules on the way in — `POLICY #freeq ACCEPT`, then `JOIN #freeq` — which is the gatekeeping described in this series, pointed at its own front door.

Source is at `github.com/freeq-irc/freeq`.

Next: your identity signs in, and signs what it says. We follow the key from a
DID down to a single message, and we are honest about where that chain is
currently complete and where it is not.
