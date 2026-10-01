Now prove and fix the bug you identified.

## Order of operations (regression-test-first)

1. **Write a test that reproduces the bug and FAILS on the current code.** Run
   it, and confirm it fails for the *right reason* (the defect), not a typo.
   This is the proof the bug is real — without a failing test, stop and
   reconsider whether it's actually a bug.
2. **Make the minimal fix.** Change as little production code as possible to
   correct the behavior. No refactors, no drive-by cleanups, no reformatting
   unrelated code. Preserve public API and existing behavior everywhere else.
3. **Confirm the test now passes** and that you haven't broken neighbors.

## Constraints

- Keep the diff surgical and easy to review: ideally one root-cause fix + its
  regression test.
- Honor `-D warnings`: no new clippy warnings, no `#[allow]` to dodge them,
  rustfmt-clean.
- If, while fixing, you discover the "bug" isn't actually wrong (the behavior
  is intended elsewhere), back out and clearly report that the hunt was a false
  alarm rather than forcing a change.

## Build discipline (important — the workspace is large)

- **Iterate with TARGETED commands** while developing: `cargo test -p <crate>
  <test_name>`, `cargo check -p <crate>`, `cargo clippy -p <crate>`. A full
  workspace build is slow; don't run it repeatedly.
- **Do NOT touch build configuration** to speed things up — no
  `.cargo/config.toml`, no `[profile.*]` / `debuginfo` / `strip` edits, no
  `CARGO_*` changes. The environment is already tuned. Let slow compiles run.

## Self-verify once, at the end (required)

When the regression test fails-before / passes-after and your fix is in, first
**auto-format and lint-fix** (the gate enforces both):

```
cargo fmt --all                 # gate runs `cargo fmt --all -- --check`
cargo clippy -p <crate> --tests # fix warnings, never silence with #[allow]
```

Then run the full gate **exactly once** to confirm it's green:

```
bash .fabro/verify.sh
```

Don't loop the full gate. The next node runs this same gate authoritatively; a
failure there produces no PR.
