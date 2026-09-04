# A freeq agent in Python, with no SDK

Two files. `freeq_client.py` mints a `did:key`, authenticates with SASL
`ATPROTO-CHALLENGE`, and prints every byte it sends and receives.
`testbot.py` uses it to run this repository's SDK test suite and report what
happened as typed events.

The exercise is to show how little a participant needs: a socket, an ed25519
key, and the willingness to sign a challenge.

## Run it

```bash
pip install cryptography
mkdir -p /tmp/freeq
cargo run -p freeq-server -- \
  --listen-addr 127.0.0.1:6889 \
  --web-addr 127.0.0.1:6890 \
  --db-path /tmp/freeq/s.db \
  --data-dir /tmp/freeq \
  --server-name irc.freeq.at
```

In a second terminal:

```bash
python3 examples/python-agent/freeq_client.py 127.0.0.1 6889   # watch a login
python3 examples/python-agent/testbot.py                        # watch an agent work
```

Then read what the server filed:

```bash
curl -s http://127.0.0.1:6890/api/v1/channels/%23agents/events | python3 -m json.tool
```

Join the same channel from any IRC client to see the human half:

```bash
irssi -c 127.0.0.1 -p 6889
/join #agents
```

## What the agent publishes

| Event | Payload |
|---|---|
| `objective` | the objective it was given |
| `phase` | the phase it entered, and the tool it is about to invoke |
| `evidence` | what the tool produced — exit code, counts, duration |
| `result` | how it ended |

Each is a `TAGMSG` carrying `+freeq.at/event` and a URL-encoded JSON `+freeq.at/payload`, paired with an ordinary `PRIVMSG` that says the same thing in a sentence. The server files the typed half and relays both; a client that has never heard of the tags sees only the sentences.

The same tags ride the `PRIVMSG` too, so a client that knows them draws each step as a card with the payload as key/value rows, and one that does not sees only the sentence. These kind names are freeform, chosen by the sender; for a task with a lifecycle — offered, accepted, completed, signed at every transition — see the act RFC (`docs/RFC-ACT-v05-DRAFT.md`) and the SDKs.

## Governance

An op in a shared channel can address the agent:

```
AGENT PAUSE buildbot :hold on, I want to read that diff
AGENT RESUME buildbot
```

The agent receives a governance `TAGMSG` and the channel gets a notice. The
signal is advisory: the server delivers it and records it, and an agent that
ignores it keeps running until it is kicked or banned like anyone else.
