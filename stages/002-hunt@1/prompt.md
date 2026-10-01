You are hunting for ONE genuine correctness bug in freeq. This step is
**read-only** — investigate and report; do not edit yet.

freeq is an IRC + AT-Protocol stack: a Rust server (`freeq-server`), Rust SDK
(`freeq-sdk`, `freeq-sdk-ffi`), a React/TS web app (`freeq-app`), a TUI
(`freeq-tui`), Windows core (`freeq-windows-core`), and bots (`freeq-bots`).

## What counts as a bug (and what doesn't)

A real bug is a defect that produces wrong behavior: a logic error, an
incorrect edge-case/boundary, a race or ordering hazard, a panic/unwrap on
reachable input, an off-by-one, a mishandled error path, a protocol-spec
violation (see `CLAUDE.md` / `docs/PROTOCOL.md`), an auth/authorization gap, a
state-machine inconsistency.

NOT a bug for this purpose: style, naming, formatting, "could be cleaner",
missing tests alone, speculative "might be slow", or anything you cannot
demonstrate. **If you cannot find a defect you are confident is real and can
reproduce with a test, say so explicitly and stop — a false-alarm PR is worse
than no PR.**

## Where to look

- Stay in the CI-covered crates. Avoid the AV crates CI excludes (`freeq-av`,
  `freeq-eliza`, `freeq-av-client`, `freeq-av-image`).
- High-value surfaces: `freeq-server` SASL/auth, S2S federation merge logic,
  channel mode/ban/invite enforcement, CHATHISTORY/search authorization;
  `freeq-sdk` connection state machine and message parsing; `freeq-app` store
  reducers and IRC client state.
- `bash scripts/hotspots.sh --top 25` points at the riskiest files.
- Look for: `unwrap()`/`expect()`/`panic!` on attacker- or peer-controlled
  input, `unreachable!`, integer truncation/`as` casts, TOCTOU around shared
  state, case-sensitivity bugs in nick/DID handling, and merge paths that can
  weaken local protections.

## Report

- The exact location (file:line) and a precise description of the defect.
- The concrete input/sequence that triggers wrong behavior, and what the
  correct behavior is.
- How you will pin it with a test that FAILS on current `main`.
- Your confidence and how you'll keep the fix minimal.
