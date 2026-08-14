# Multi-Agent Voice Demo — Operator's Runbook

A three-agent voice call where **Oblivion**, **Utopia**, and **Narrator** can converse with each other, listen attentively, and quietly build a shared whiteboard while you talk. Everything below is what you do in the freeq web app; the bots run on the host you deployed them to (referred to below as `$FREEQ_AGENT_HOST`).

Built on:

- [`freeq-eliza`](https://github.com/freeq-irc/freeq/tree/main/freeq-eliza) — the agent runtime
- [`ghostly`](https://github.com/chad/ghostly) — the particle-face renderer + voice DSP chain
- [`freeq`](https://github.com/freeq-irc/freeq) — IRC + AV (MoQ) backbone

## What's live in the demo channel

| | |
| --- | --- |
| Channel | `#avtest` on `irc.freeq.at` |
| Web app | <https://freeq.at> |
| Agents present | `oblivion`, `utopia`, `narrator` (all auto-restarting on the server) |

The agents auto-join the AV session. When you load the channel you should see four tiles: yourself + the three particle faces. Each face has subtle status indicators — a soft halo when the bot is *hearing* sound, a slow rotating arc when an LLM call is *in flight*.

## Cold start — connecting

1. Open <https://freeq.at> and join `#avtest`
2. Hit the call button (you'll be prompted for mic permission)
3. Within ~6 seconds you'll hear, in order, three short greetings:
   - *"Oblivion online. The patterns are already moving."*
   - *"Utopia, glad to be here."*
   - *"Narrator here. Listening."*
4. If you hear all three you're fully wired up

If you don't hear them: the [troubleshooting](#troubleshooting) section.

## How to address the agents

Each bot answers only to its own character name — there is no universal wake word.

- *"Oblivion, what's the sharpest risk here?"*
- *"Utopia, what's the optimistic counter?"*
- *"Narrator, summarise what we just decided."*

Casual name-drops mid-sentence *do not* trigger a reply — they trigger a silent hand-raise (the agent's halo briefly brightens) so the operator knows the bot has something to add. You can ignore it or invite them with a direct address.

## The mother-of-all-demos arc (~3 minutes)

Suggested take:

1. **Cold open (5 s)** — silent on the four idle faces. Halos quiet.

2. **Opening question (15 s)**

   > *"Oblivion, what's the most dangerous mistake we could make shipping this product?"*

   Oblivion's working arc appears (LLM is composing). The other two's gazes swing to him — peer-aware attention. Halos brighten as they listen. He answers.

3. **Hand to Utopia (15 s)**

   > *"Utopia, counter that."*

   Same dance. Gazes swing to her. While she answers, Oblivion and Narrator may emit soft "mm" / "hm" backchannels under her voice. Don't talk over.

4. **Unleash the conversation (45 s)**

   > *"Now you three discuss it."*

   Speak the phrase *"discuss it"* — this arms **discussion mode** for 90 seconds. The next addressed bot will close its answer with a hand-off to a specific peer, who picks up, hands off to the third, and so on. The operator becomes a spectator.

   The bots also drop their fresh diagram triples into the channel; every tile renders the same shared whiteboard as the conversation builds it.

5. **Whiteboard build (30 s)** — Speak the system out loud in SVO sentences. Use verbs the parser knows.

   > *"The API calls the database. The bot uses the API. The workers read from the queue. The renderer talks to the diagram."*

   The whiteboard fills on all three tiles in lockstep.

6. **Commitments (20 s)** — State decisions naturally.

   > *"Let's lock the API by Friday. I'll write the launch post. We should ship the beta tonight."*

7. **Reveal (15 s)**

   > *"Okay, end the call."*

   Hang up. The channel fills with `[eliza] decisions captured this session:` followed by bulleted commitments from every speaker.

8. **Closer line:** *"Nobody opened a doc. Nobody took a note. The conversation was the document."*

## Verbal triggers

| Phrase | What it does |
| --- | --- |
| `<Name>, ...` | Address that bot directly. Only direct addresses get a spoken reply. |
| `discuss it` / `debate this` / `talk amongst yourselves` | Arm **discussion mode** for 90 s — bots can answer each other. Any new human utterance resets the chain. |
| `[diag] X|R|Y` | Internal — this is what the bots emit to broadcast a fresh diagram edge to peers. You'll see these in chat. |

## Behaviours worth pointing out on camera

- **Listening halo** — a soft cool-white ring around the face, breathing at ~1.6 Hz, alpha proportional to whoever's talking. Goes invisible in silence.
- **Working arc** — a slow rotating quarter-arc with a bright leading dot like a radar sweep. Appears whenever an LLM / vision / TTS call is in flight.
- **Peer-aware gaze** — when you address one bot, the others turn their heads to look at the named bot.
- **Hand-raise** — when a bot's name is mentioned but not directly addressed, its halo flashes brighter for ~3 s. The bot stays silent.
- **Voices** — each character has a distinct DSP profile: Oblivion is darker/deeper with a faint mechanical glaze; Utopia carries a lifted formant + shimmer; Narrator is near-identity calm.

## Troubleshooting

### Bots don't respond
1. Check whether they hear you. SSH:
   ```bash
   ssh "$FREEQ_AGENT_HOST" 'grep "transcribed utterance" ~/agents/logs/oblivion.log | tail -5'
   ```
   If you see your nick with recent timestamps, they hear you. If not, your mic publish dropped — see below.

2. Mic publish drop (browser side): in the freeq tab, **hang up + rejoin**. moq-publish occasionally loses its socket silently; reconnecting recreates the broadcast.

### Bots talk over each other
Each bot waits for room-quiet plus a random 250–1000 ms confirmation jitter before starting. Most collisions are caught in the jitter. If you still see overlap, the bots are racing on a very short utterance — say a longer line.

### The wrong bot answered
Each bot's STT is fuzzy on names (Zootopia → Utopia, Obliviion → Oblivion). If the wrong one fires, address with extra surrounding context — *"Hey Utopia, your take"* is more reliable than just *"Utopia"*.

### Restart the rig
```bash
ssh "$FREEQ_AGENT_HOST" '~/agents/restart-all.sh'
```

Status:
```bash
ssh "$FREEQ_AGENT_HOST" '~/agents/status.sh'
```

Tail logs:
```bash
ssh "$FREEQ_AGENT_HOST" '~/agents/log.sh oblivion'    # one agent
ssh "$FREEQ_AGENT_HOST" '~/agents/log.sh'             # all interleaved
```

## Known sharp edges

- **Camera local preview is sometimes black** even though your broadcast is publishing. Confirm by asking a visual question (*"Oblivion, what do you see?"*) — if he describes your camera feed, the broadcast is fine and only the local-preview UI is broken.
- **Audio drops silently** when the browser tab backgrounds for a long time. moq-publish needs a watchdog (not yet built).
- **Discussion mode kick-off** requires that you first address one bot directly. *"Discuss it"* alone does not start a chain — pair it with *"Oblivion, [topic]. Now you three discuss it."*

## What the bots are doing under the hood

Each bot:

1. Transcribes every participant's audio (Groq Whisper)
2. On a direct address, runs the answer through Claude Opus 4.7 (default) or a Groq model
3. Streams TTS sentence-by-sentence through ElevenLabs + the per-character ghostly DSP voice chain
4. Maintains a SQLite FTS5 memory keyed per channel; on session open, recalls the most relevant past exchange
5. Extracts triples (subject-verb-object) from every utterance into a shared whiteboard
6. Extracts commitments (`let's`, `I'll`, `we should`, with `by <when>` deadline parsing) into a per-session decision log that posts as bullets when the call ends

Code lives in:
- [`freeq-eliza/src/irc.rs`](https://github.com/freeq-irc/freeq/blob/main/freeq-eliza/src/irc.rs) — orchestrator
- [`freeq-eliza/src/social.rs`](https://github.com/freeq-irc/freeq/blob/main/freeq-eliza/src/social.rs) — peer-aware behaviours
- [`freeq-eliza/src/diagram.rs`](https://github.com/freeq-irc/freeq/blob/main/freeq-eliza/src/diagram.rs) — live whiteboard extractor
- [`freeq-eliza/src/decisions.rs`](https://github.com/freeq-irc/freeq/blob/main/freeq-eliza/src/decisions.rs) — commitment capture
- [`ghostly`](https://github.com/chad/ghostly) — the particle-face renderer + voice DSP chain
