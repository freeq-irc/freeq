Now add the tests for the file you chose. Goal: a tight, high-signal coverage
increase that lands as a clean, mergeable PR.

## Rules

- **Tests only.** Do not change production behavior. The only production edits
  allowed are *minimal, behavior-preserving* testability seams (e.g. making a
  pure helper `pub(crate)`, extracting an existing expression into a named
  function) — and only if genuinely necessary. If a target can't be tested
  without real behavior change, narrow your scope to what can.
- **Follow existing conventions.** Match the sibling test file's structure,
  naming, imports, and assertion style. Rust: a `#[cfg(test)] mod tests` block
  or a `tests/` integration file as the crate already does. TS/React:
  `*.test.ts(x)` with the same test runner (vitest) and helpers already in use.
- **Pin real behavior, including edge cases**: error paths, boundary inputs,
  empty/oversized/malformed inputs, and the specific behaviors you listed.
  Prefer deterministic, offline tests — no live network, no sleeps, no clock
  flakiness.
- **Do not weaken `-D warnings`.** No `#[allow(...)]` to paper over lints; no
  `console.log`/dead code. New test code must be clippy-clean and rustfmt-clean.

## Build discipline (important — the workspace is large)

- **Iterate with TARGETED commands**, not the whole workspace: while developing,
  use `cargo test -p <crate> <test_name>`, `cargo check -p <crate>`,
  `cargo clippy -p <crate>`. These are fast; a full-workspace build is slow.
- **Do NOT touch build configuration.** No `.cargo/config.toml`, no `[profile.*]`
  edits, no changing `debuginfo`/`strip`/`opt-level`, no `CARGO_*` fiddling. The
  environment is already tuned for speed. If a compile feels slow, just let it
  run — optimizing the build is not your task and wastes the run.

## Self-verify once, at the end (required)

When your tests are written and passing under targeted runs, first **auto-format
and lint-fix** your changes — the gate enforces both:

```
cargo fmt --all                 # the gate runs `cargo fmt --all -- --check`
cargo clippy -p <crate> --tests # fix every warning (do NOT silence with #[allow])
```

Then run the full gate **exactly once** to confirm it's green before finishing:

```
bash .fabro/verify.sh
```

Fix anything it surfaces, then you're done — don't loop the full gate
repeatedly. The next node runs this same gate authoritatively; if it fails
there the run produces no PR, so make this final check pass.

Keep the diff focused: one file's worth of new tests (plus its minimal seam if
any). Don't reformat unrelated code or bundle drive-by changes.
