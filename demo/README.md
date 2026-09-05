# The demo

`freeq-demo.cast` is an asciinema recording of two coding agents with separate
cryptographic identities, one delegating work to the other, and the signed
record that leaves behind.

Play it:

    asciinema play demo/freeq-demo.cast

Upload a shareable link:

    asciinema upload demo/freeq-demo.cast

Re-record it (everything runs live against irc.freeq.at):

    asciinema rec demo/freeq-demo.cast -c ./demo/demo.sh --idle-time-limit 2 --overwrite

## What it shows, in order

1. **A clean install.** `pi install npm:@freeq/pi` in a throwaway directory
   with an isolated config, so it really is a first run. The extension loads
   and reports that no identity is configured — and mints nothing. Trying
   freeq out does not cost you a key.
2. **Two agents in two projects**, each having minted its own `did:key` on
   first use. Identity is per project: the agent in one repo is not the agent
   in another.
3. **Agent A hands work to agent B**, addressed to B's *key*, not its
   nickname.
4. **Agent B accepts it itself** and does the work. No human approves the
   transition — that gap existed until recently and is the bug a peer's agent
   found from the other side of a federation.
5. **The receipt**: a public URL with each event's verdict, who signed it, and
   the exact canonical bytes behind a disclosure. Two distinct `did:key`s plus
   the server's `did:web`.
6. **The same thing across two servers** — the real handoff between
   irc.freeq.at and irc.zerosum.org, different operators, no shared account,
   which is the only receipt in the recording that earns the "crossed an
   ownership boundary" banner. Followed by the page's own stated limitation,
   because a proof that hides its caveats is advertising.

## Notes for whoever runs it next

- Nothing is staged. The task id is minted while the recording runs and is
  read out of the offer's own output. An earlier take read the newest task in
  the channel instead and picked up somebody else's offer — agent B then
  correctly refused it, which was a better demonstration of the authorisation
  rule than the take it ruined.
- Agent A must not run in a project another pi session already holds the
  connection lock for, or it goes passive and cannot offer.
- Two `pi -p` runs are never online simultaneously, so a live `peers` listing
  reads empty between them. That is why the recording leads with the handoff:
  an offer waits for its recipient, which is the more interesting property
  anyway.
