Write the pull-request description for the test coverage you just added. Fabro
opens the PR from your branch; this is its body. Base it strictly on what you
actually changed (`git diff --stat` and `git diff`).

Use this structure, in GitHub-flavored markdown:

## Summary
One or two sentences: which file/area gained coverage and why it mattered
(cite the hotspot score or the CLAUDE.md flag).

## What's tested
A bulleted list of the behaviors/edge cases now pinned by tests.

## Notes
- Confirm this is tests-only, or describe precisely any minimal testability
  seam you added and why it's behavior-preserving.
- State that `.fabro/verify.sh` (rustfmt + check + clippy -D warnings + test,
  CI-mirrored) passes.

Keep it factual and concise. No marketing language. Do not claim anything you
didn't verify.
