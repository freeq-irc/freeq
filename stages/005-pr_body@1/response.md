I can't write this PR description yet, because nothing in this conversation gives me a diff to base it on. I haven't made any changes, run `git diff`, or looked at a bug, so the description would be fabricated. That includes the file:line, the root cause, the regression test, the fail-on-`main` confirmation, and the `.fabro/verify.sh` result.

I also haven't run `.fabro/verify.sh` or a test against `main`, so I can't say either one passes or fails.

To get an accurate description, I need one of these:

1. **The diff.** Paste the output of `git diff main...HEAD`, or give me the branch name and tool access so I can run it myself.
2. **Verification output.** Either let me run these, or paste their results:
   - `.fabro/verify.sh`
   - the new test run against `main` without the fix (e.g. `git stash` the source change, keep the test) to confirm it fails
   - the same test with the fix applied to confirm it passes

Once I have those, I'll fill in this structure from the diff alone:

```markdown
## The bug
<file:line, incorrect behavior, triggering input/sequence>

## Root cause
<1–2 sentences>

## The fix
<what changed, why it's minimal, why behavior elsewhere is preserved>

## Regression test
<test name/location; fails on main before the fix, passes after>

## Verification
<.fabro/verify.sh result: rustfmt + check + clippy -D warnings + test>
```

Anything the diff doesn't establish, such as whether other call sites share the same flaw, I'll mark as uncertain rather than assert.