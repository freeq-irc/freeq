You are picking ONE file in the freeq repository whose risk-to-coverage ratio is
worst — high-churn / high-complexity but undertested — and that you can
meaningfully add tests for in a single focused change.

This step is **read-only**. Do not edit any files. Investigate, then report a choice.

## How to choose

1. Run the repo's own hotspot analysis and read the curated list:
   - `bash scripts/hotspots.sh --top 25` — high "gamma" = high risk.
   - The "Hotspot Analysis" section of `CLAUDE.md` names specific UNDERTESTED
     files (e.g. `irc/client.ts`, `MessageList.tsx`, `sdk/client.rs`). Prefer
     these — they are explicitly flagged as needing tests.
2. For your top candidates, gauge existing coverage: look for a sibling test
   module / `#[cfg(test)]` block / `*.test.ts(x)` file and how much it covers.
3. Stay inside the CI-covered surface. AVOID the heavy AV crates that CI
   excludes: `freeq-av`, `freeq-eliza`, `freeq-av-client`, `freeq-av-image`.
   Good targets live in `freeq-server`, `freeq-sdk`, `freeq-sdk-ffi`,
   `freeq-app`, `freeq-tui`, `freeq-windows-core`, or `freeq-bots`.
4. Pick something with a clear, pure-ish functional core you can pin with
   tests without standing up a network/server — the highest-signal, lowest-
   flake tests.

## Report

State clearly:
- The exact file you chose and its language/crate.
- Why it's high-risk and undertested (cite the hotspot score or CLAUDE.md).
- 3–6 specific behaviors/edge cases you intend to pin with tests.
- The existing test convention you'll follow (point to a sibling test file).

Do not write tests yet — the next step does that.
