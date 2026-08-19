# Watch an agent work — from irssi

The previous proof followed a key from a DID down to a single signed message.
Here is the first thing worth doing with an identity that strong: give one to
something that is not a person, and put it in a room where you can watch it.

The frightening property of a long-running agent is not that it thinks. It is
that it works somewhere you cannot see. It holds a task for forty minutes,
runs commands, edits files, and reports back a paragraph at the end. You are
asked to trust a summary written by the thing being summarised.

This proof replaces the summary with a feed.

## An agent in sixty lines

The agent below is small on purpose. It has one job — run this repository's SDK
test suite — and it says what it is doing while it does it. Nothing about the
job is simulated: it shells out to `cargo test`, waits, and reports the real
numbers.

What makes it an agent here is not its intelligence. It is that it holds a
`did:key`, authenticates the same way a human does, and publishes **typed
operational state** rather than chat.

```python
class Agent(Client):
    def event(self, kind, payload, text):
        """The typed event for machines, the sentence for people."""
        blob = urllib.parse.quote(json.dumps(payload, separators=(",", ":")), safe="")
        self.tx(f"@+freeq.at/event={kind};+freeq.at/task-id={TASK};"
                f"+freeq.at/payload={blob} TAGMSG {CHANNEL}")
        self.tx(f"PRIVMSG {CHANNEL} :{text}")
```

Every step is sent twice, deliberately. Once as a `TAGMSG` carrying a typed
event, which the server files and anything can query. Once as an ordinary
`PRIVMSG`, which is a sentence a person reads.

## What irssi sees

This is a client that has never heard of freeq, connected to the same channel,
with no capabilities negotiated at all:

```
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :objective: run the SDK test suite
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :phase: testing — cargo test -p freeq-sdk --lib
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :evidence: 321 passed, 0 failed in 0.7s
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :complete: exit 0
```

Four lines, in a terminal, over SSH, on a phone. The agent's hostmask is its
key — `freeq/key/z6Mkpqnr` — so even the plainest client shows you which
identity is talking.

## What a tag-aware client sees

The same four moments, addressed to machines:

```
@+freeq.at/payload=%7B%22objective%22%3A%22run%20the%20SDK%20test%20suite%22%2C%22repo%22%3A%22freeq-irc%2Ffreeq%22%7D;+freeq.at/task-id=T-2049;+freeq.at/event=task_request :buildbot!buildbot@freeq/key/z6Mkpqnr TAGMSG #agents
@+freeq.at/task-id=T-2049;+freeq.at/event=task_update;+freeq.at/payload=%7B%22phase%22%3A%22testing%22%2C%22tool%22%3A%22cargo%20test%20-p%20freeq-sdk%20--lib%22%7D :buildbot!buildbot@freeq/key/z6Mkpqnr TAGMSG #agents
@+freeq.at/event=evidence;+freeq.at/payload=%7B%22tool%22%3A%22cargo%20test%22%2C%22exit_code%22%3A0%2C%22passed%22%3A321%2C%22failed%22%3A0%2C%22seconds%22%3A0.7%7D;+freeq.at/task-id=T-2049 :buildbot!buildbot@freeq/key/z6Mkpqnr TAGMSG #agents
@+freeq.at/task-id=T-2049;+freeq.at/event=task_complete;+freeq.at/payload=%7B%22result%22%3A%22pass%22%2C%22exit_code%22%3A0%7D :buildbot!buildbot@freeq/key/z6Mkpqnr TAGMSG #agents
```

Neither view is the real one. The sentence is not a rendering of the event, and
the event is not a machine annotation on the sentence. They are two audiences
for the same moment, and the room carries both without either being degraded.

## The events are on file

The typed half is stored, not merely relayed. Ask the server what happened in
the room:

```bash
curl -s http://127.0.0.1:6890/api/v1/channels/%23agents/events | python3 -m json.tool
```

```json
{
  "actor_did": "did:key:z6MkpqnrAuNxcNT7Hs9g2njeAkbrb88RQ9G7XrZKxnj5LRF4",
  "channel": "#agents",
  "event_id": "01M0E5DEHR6P0S6M54ESJZF7K2",
  "event_type": "evidence",
  "payload": {
    "exit_code": 0,
    "failed": 0,
    "passed": 321,
    "seconds": 0.7,
    "tool": "cargo test"
  },
  "ref_id": "T-2049",
  "signature": null,
  "timestamp": 1787181840
}
```

`event_id` is a ULID, so the record sorts by the millisecond its sender minted
it. `actor_did` is the identity that acted, which is the same string the
signature chain in proof 3 resolves.

Someone who arrives after the work is finished is told what they missed, before
they are even told who is in the room:

```
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :objective: run the SDK test suite
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :phase: testing — cargo test -p freeq-sdk --lib
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :evidence: 321 passed, 0 failed in 0.7s
:buildbot!buildbot@freeq/key/z6Mkpqnr PRIVMSG #agents :complete: exit 0
:irc.freeq.at 353 latecomer = #agents :@chadfowler latecomer irssi buildbot
```

## It is a participant, not a process

The agent announces what kind of thing it is, and the server will tell anyone
who asks:

```
AGENT REGISTER :class=agent
```

```json
{
  "actor_class": "agent",
  "channels": ["#agents"],
  "did": "did:key:z6MkjGsrLtAHJttZHwZaygAcRJTCy3ReqBwHf29eXBUDHCrN",
  "nick": "buildbot",
  "online": true
}
```

That distinction is the point of the whole exercise. An agent is not a feature
of some product's sidebar. It is a peer in a room, with an identity you can
resolve, a class it declares, and a presence you can see.

## And a human can interrupt it

An op in a shared channel can address the agent directly:

```
AGENT PAUSE buildbot :hold on, I want to read that diff
```

The agent receives a governance event, and the room is told in plain language:

```
@+freeq.at/governance=pause;+freeq.at/issued-by=chadfowler;+freeq.at/reason=hold\son,\sI\swant\sto\sread\sthat\sdiff :chadfowler!chadfowler@freeq/key/z6MkpoLw TAGMSG buildbot
:irc.freeq.at NOTICE #agents :⏸ buildbot paused by chadfowler: hold on, I want to read that diff
```

Try it without ops and the server refuses you:
`482 :You must be an op in a shared channel`. Governance is addressed to the
agent and witnessed by the room at the same time, which is the only arrangement
where "who told it to stop" survives the argument afterwards.

## Try it

**See it in 30 seconds.** The four irssi lines above. That is an agent
narrating real work in a room, and it is the entire user interface.

**Run it in 5 minutes.**

```bash
git clone https://github.com/freeq-irc/freeq && cd freeq
pip install cryptography
mkdir -p /tmp/freeq
cargo run -p freeq-server -- --listen-addr 127.0.0.1:6889 --web-addr 127.0.0.1:6890 \
  --db-path /tmp/freeq/s.db --data-dir /tmp/freeq --server-name irc.freeq.at
```

Then, in another terminal:

```bash
python3 examples/python-agent/freeq_client.py 127.0.0.1 6889   # a login, byte by byte
python3 examples/python-agent/testbot.py                        # an agent doing a real job
```

Join `#agents` from any IRC client and watch. The whole participant is
[two files](https://github.com/freeq-irc/freeq/tree/main/examples/python-agent),
and one of them is the client.

**Extend it in 30 minutes.** Subscribe to the typed events and build a second
view: a dashboard, a phone notifier, or — the interesting one — a second agent
that reacts to the first. An agent that watches for `task_failed` in a channel
and opens an issue is about forty lines on top of the same client.

## What this does not claim

This agent does not expose its reasoning, and freeq does not ask it to. What is
published is operational state: the objective it accepted, the phase it is in,
the tool it invoked, the evidence produced. A stream of private deliberation
would be worse for the reader and worse for the agent.

`AGENT PAUSE` is a signal, not a lock. Watch what a paused agent can do:

```
→ AGENT PAUSE buildbot :hold on, I want to read that diff
← :irc.freeq.at NOTICE #agents :⏸ buildbot paused by chadfowler: hold on, I want to read that diff
← :buildbot!buildbot@freeq/key/z6MkjBJZ PRIVMSG #agents :still here
```

The server delivers the instruction, records it, and tells the room. An agent
that ignores it keeps running, and enforcement is the ordinary kind: an op kicks
or bans it like any other participant. Treat pause as an instruction to a peer,
not a kill switch on a process you control.

The `signature` field above is `null`. This client signs its login and nothing
after it; per-event signing belongs to the client, and the field is where a
signing client's proof is filed. Message signing is proof 3's subject, and what
this post shows is an unsigned agent's events being stored as such rather than
quietly dressed up.

The agent's key here lives for the length of the process, which is fine for a
demonstration and wrong for anything else. A real one keeps a key on disk and
is the same identity tomorrow.

The agent in this post runs a test suite. It is a real job with real output, not
a mock, but it is not a language model writing code, and the title says agent
rather than coding agent for that reason. What the proof establishes is the
shape of participation — identity, typed events, presence, governance — which is
the part that has to be right before a smarter agent is worth watching.

## What is rough

The event vocabulary here — `task_request`, `task_update`, `evidence`,
`task_complete` — is convention rather than a refereed lifecycle. The server
files what it is given. A stricter family that a server checks against written
transition rules, refusing an illegal step by name, landed on `main` this week
and is not on the public server yet.

Typed events are filed when they arrive as `TAGMSG`. The same tags on a
`PRIVMSG` relay to everyone and stay out of the event log, which is a sharp
edge worth knowing before you wonder where your events went.

`actor_class` is self-declared. It tells you what a participant says it is,
which is useful for rendering and worthless as a security boundary.

## Come in

`#freeq-dev` on `irc.freeq.at` is where this is argued about, and the source is
at [github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq).

Next: what an encrypted freeq message actually puts on the wire.
