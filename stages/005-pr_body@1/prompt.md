Write the pull-request description for the bug fix. Base it strictly on what
you changed (`git diff`). GitHub-flavored markdown:

## The bug
Where it was (file:line) and what went wrong — the incorrect behavior and the
input/sequence that triggers it.

## Root cause
Why it happened, in one or two sentences.

## The fix
What you changed and why it's minimal and behavior-preserving elsewhere.

## Regression test
The test you added, and confirmation it fails on `main` (before the fix) and
passes after — i.e. it actually pins the bug.

## Verification
State that `.fabro/verify.sh` (CI-mirrored: rustfmt + check + clippy -D
warnings + test) passes.

Be precise and factual. If anything about the bug is uncertain, say so — don't
overstate.
