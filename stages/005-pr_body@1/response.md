I can't write this PR body yet. Nothing in this conversation shows me adding tests: I have no `git diff --stat` or `git diff` output, and I haven't run `.fabro/verify.sh`. Describing specific tests or claiming the verify script passes would be fabrication.

If you paste the diff (or the `--stat` and the test file contents) and the verify output, I'll write it against what actually changed. Below is a skeleton with only the facts I can source from CLAUDE.md. Everything in `<…>` needs to be filled from the real diff.

---

## Summary
Adds unit tests for `<file/area>`, which CLAUDE.md flags as `<UNDERTESTED / ZERO unit tests>` (hotspot gamma `<score>`). `<One sentence on why that matters, e.g. connection state machine / message rendering logic changes frequently with no coverage.>`

## What's tested
- `<behavior or edge case 1>`
- `<behavior or edge case 2>`
- `<error / malformed-input case>`

## Notes
- `<Tests-only. | Describes the exact testability seam added (e.g. a `pub(crate)` visibility change or extracted helper), and why it doesn't change behavior.>`
- `.fabro/verify.sh` (rustfmt + check + clippy `-D warnings` + test, CI-mirrored) `<passes / not yet run>`.

---

Reference points from CLAUDE.md if they apply: `sdk/client.rs` (gamma 104, zero unit tests on the connection state machine), `irc/client.ts` (gamma 133), `MessageList.tsx` (gamma 103). If the tests are TypeScript, the verify script as described only covers Rust, so I'd need to know how the vitest run was verified before stating it.