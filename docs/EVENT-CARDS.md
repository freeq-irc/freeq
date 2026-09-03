# Event cards

Two kinds of card, and the rules for both. Web, Android, macOS and iOS come
out identical in behaviour and vocabulary; each uses its own native mechanism
where this says so.

Design settled with nap 2026-09-02/03; the conversation record, with his words
quoted, is the card-design block in `docs/PHASE5-PLAN.md`.

## The generic event card

**Every `+freeq.at/event` message renders as one uniform generic card.** There
are no per-type faces and no name lists of any kind — the six retired task
names, `delegation_notice`, `status_update`, `society-question`, anything
unknown: all identical treatment.

Anatomy:

- a muted header strip: the type in lowercase monospace behind a leading `◇`,
  the time at the right
- a body carrying the sender's text as sent
- the payload as always-visible key/value rows

Grayscale only. A generic card never wears colour and never has an edge.

A bare TAGMSG event with no message row draws nothing — there is no row to
card.

### The payload rule

The payload tag is JSON by convention only; nothing enforces it. So:

| what the tag holds | what the card shows |
|---|---|
| a JSON object | one row per top-level key, in document order |
| a JSON array or scalar | one row keyed `payload` with the compact JSON |
| anything that does not parse | one row keyed `payload` with the raw decoded string |
| nothing | no rows |

The tag is percent-decoded first, and percent-decoding is not form decoding —
a `+` stays a plus. Malformed escaping keeps the bytes that arrived rather
than dropping them. A genuinely long value clips or scrolls inside its own
row; the card never grows unbounded.

Implementations: `freeq-app/src/lib/event-payload.ts`,
`freeq-android/.../model/EventCardPayload.kt`, and `EventCardPayload` in each
Apple `Models/CoordinationCard.swift`.

## The act card

Act cards are the special class. Everything the act cards already carry stays
— verb glyph, uppercase headline word, task id chip, prev/next footer, system
lines for `confirm`, `expire` and `auto-accept` — plus the seal and the colour
law below.

### The seal

A monochrome seal icon in the header: SF Symbol `checkmark.seal` on Apple,
Material `verified` on Android, an inline SVG rosette on web. Monochrome
always — a muted foreground colour, never the card's hue and never green. A
coloured seal would either fight the card's hue or borrow verdict-green, and
the seal is a statement about the rules, not about the outcome.

Click or tap opens a disclosure — an expanding panel on web, a popover on
Apple, an expandable panel on Android — carrying:

- the header `<KIND>: Rules Enforced`, with the kind uppercased from the
  event's own `act` tag (`HANDOFF: Rules Enforced`, `BOUNTY: Rules Enforced`,
  future kinds automatically)
- one plain-language sentence stating what the server enforced on this step
- a link `View full history` opening the task timeline

Only web has a task timeline surface, so only web shows the link.

The sentence is selected mechanically from the `who` of the transition row the
event's verb matched in `spec/act-transitions.json`. An opening verb has no
transition row of its own and takes the `opener` sentence. A `system` row
never cards, and a verb the rules file does not name has no rule about a
person to state, so neither gets a sentence.

**The sentences themselves live in one place: `spec/act-card-copy.json`.**
Each client bundles that file byte-identical and pins the copy with a test;
none of them holds the prose. The header format and the link text live there
too.

| client | bundled copy | loader |
|---|---|---|
| web | `freeq-app/src/lib/act-card-copy.json` | `src/lib/seal-panel-copy.ts` |
| Android | `freeq/src/main/resources/act-card-copy.json` | `model/SealPanelCopy.kt` |
| macOS | `freeq-macos/freeq-macos/Models/act-card-copy.json` | `SealPanelCopy` in `Models/ActVerbs.swift` |
| iOS | `freeq-ios/freeq/Models/act-card-copy.json` | `SealPanelCopy` in `Models/ActVerbs.swift` |

### The colour law

One hue per card. The hue is the **register** of the state the event lands the
task in, read from `spec/act-transitions.json`'s `to` fields:

| register | hue | lands in | verbs |
|---|---|---|---|
| new | purple | `open`, `offered` | `offer` |
| in progress | blue | `assigned`, `under_review`, **and every additive step** (a verb whose `from` equals its `to`) | `accept`, `claim`, `award`, `submit`, `revise`, `progress`, `bid` |
| ended well | green | `completed`, `accepted` | `complete`, `accept-work` |
| did not end well | red | `failed`, `forfeited`, `cancelled`, `declined` | `fail`, `forfeit`, `cancel`, `decline` |
| neutral end (fallback) | yellow | no state: a verb the rules file does not name | — |

`confirm`, `expire` and `auto-accept` are `system` rows: system lines, no
card, no colour. A verb the rules file does not name defaults to the neutral
end.

The hue paints the headline word, a 3px left edge, and the border wash.
**Every act card carries the edge** — it is the hue rail and it is also the
act-vs-generic tell, since a generic card never has one.

This is a verb→register table per client, row-identical across the four,
derived from the rules file and covered by a test that reads the rules file
itself. It is state-machine data, not name special-casing: the no-lists rule
bans carding decisions by event-type name, never rules-file-derived tables.

#### Values — each app's own tokens

| register | web | Android | macOS | iOS |
|---|---|---|---|---|
| new | `--color-purple` | `FreeqColors.accent` | `Theme.purple` | `Theme.iris` |
| in progress | `--color-blue` | `FreeqColors.blue` | `Theme.blue` | `Theme.blue` |
| ended well | `--color-success` | `FreeqColors.success` | `Theme.success` | `Theme.success` |
| did not end well | `--color-danger` | `FreeqColors.danger` | `Theme.danger` | `Theme.danger` |
| neutral end | `--color-warning` | `FreeqColors.warning` | `Theme.warning` | `Theme.warning` |

Android and iOS had no blue token. One was added to each, the web token's value, on nap's word (2026-09-03): `FreeqColors.blue` in `ui/theme/Theme.kt` and `Theme.blue` in `freeq-ios/freeq/Theme.swift`.

Exact tint and wash percentages tune on-device under nap's visual pass.

## Sources

- **The register vocabulary is Atlassian's lozenge**, chosen 2026-09-03 (nap:
  "atlassian seems to be the better fit"). Verified at the published package
  `@atlaskit/lozenge@15.4.1`: `dist/types/lozenge.d.ts:7` lists the
  appearances `default|inprogress|moved|new|removed|success` and
  `dist/cjs/lozenge.js:47-59` maps them to the semantic registers
  `neutral/information/warning/danger/success/discovery`. Reproducible with
  `npm pack @atlaskit/lozenge`.
- **Two amendments to that vocabulary, both nap's**, recorded the same day: the neutral register is **yellow, not gray** ("i told you no grey", and "we should still have a 'default' / neutral state, which should not be gray. yrllow perhaps."); and every not-done ending is red ("why wouldn't cancelled or declined be red?", "we can move the neutral not-done-end states to red i suppose", "forfeited is red isn't it? how is that different than the other 'did not end well' endings?").
- **The values are each app's own semantic tokens.** The one colour introduced is the blue token above. Known pre-existing palette fact: the web's `--color-success` is byte-identical to `--color-accent`, so a green ending shares its hue with links and buttons there.
