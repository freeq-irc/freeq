#!/usr/bin/env python3
"""Artifact-package checklist for freeq launch posts.

"The post is not the product — the executable proof is." Every flagship /
experiment post ships an artifact package. This reports what's present and
what's missing so nothing publishes half-built. It is a checklist (warn), not
a hard gate: field-notes may legitimately skip the demo clip, but the
"what this does NOT claim / protect" section and at least one *checkable*
artifact (a runnable command or a real wire/signature example) are never
optional.

Usage: python3 check_artifact_package.py blog/post.md [more.md ...]
"""
import re
import sys

CHECKS = [
    ("a 'What is rough' section (honest limitations)",
     lambda t: re.search(r"what is rough|what.s rough", t, re.I)),
    ("hands-on ladder (See it / Run it / Extend it)",
     lambda t: re.search(r"see it|run it|extend it", t, re.I)),
    ("a runnable command or code block",
     lambda t: "```" in t),
    ("a real wire/event/signature example (not pseudo-output)",
     lambda t: re.search(r"did:|ed25519|ircv3|\+freeq|ATPROTO|sasl", t, re.I)),
    ("a 'what this does NOT claim / protect' section",
     lambda t: re.search(r"does ?n.?t (claim|protect)|not claim|what this (is not|does not)|limitations", t, re.I)),
    # The funnel target. `#freeq` is the room the series sends people to; the
    # older `#freeq-dev` still counts so an unrevised draft is not silently
    # judged against a channel name that changed under it.
    ("community-channel entry point",
     lambda t: re.search(r"#freeq\b|#freeq-dev\b|builder|irc\.freeq\.at/join|join/#", t, re.I)),
]
NEVER_OPTIONAL = {
    "a 'what this does NOT claim / protect' section",
}

# Placeholders that must never survive to publication. A regex can't tell real
# captured bytes from invented ones, so it flags the tells instead: repeated
# x's, elisions, dead links, and explicit TODO/VERIFY markers.
PLACEHOLDERS = [
    (r"xxxx+", "xxxx… — placeholder identifier, paste the real value"),
    (r"<!--\s*(?:TODO|VERIFY|FIXME)", "TODO/VERIFY marker still in the post"),
    (r"\b(?:TODO|FIXME)\b", "TODO/FIXME marker still in the post"),
    (r"\]\(#\)", "dead link `](#)` — the clip/asset is not wired up"),
    (r"sig=\.\.\.|=\s*\.\.\.\s*$", "elided value (`...`) — real captures do not elide"),
    (r"\byour-(?:did|nick|channel)\b", "placeholder token"),
    (r"\bexample\.com\b", "example.com — use the real host"),
    (r"lorem ipsum", "lorem ipsum"),
]


def main() -> int:
    files = sys.argv[1:]
    hard_missing = 0
    for f in files:
        t = open(f).read()
        print(f"=== {f} ===")
        missing = []
        for name, fn in CHECKS:
            ok = bool(fn(t))
            print(f"  [{'x' if ok else ' '}] {name}")
            if not ok:
                missing.append(name)
        checkable = re.search(r"```", t) or re.search(r"did:|ed25519|ircv3|\+freeq", t, re.I)
        if not checkable:
            print("  [!] no checkable artifact at all (no command, no real wire example) — required")
            hard_missing += 1
        for m in missing:
            if m in NEVER_OPTIONAL:
                print(f"  [!] REQUIRED and missing: {m}")
                hard_missing += 1
        for i, line in enumerate(t.splitlines(), 1):
            for pat, why in PLACEHOLDERS:
                mm = re.search(pat, line, re.I)
                if mm:
                    print(f'  [!] line {i}: placeholder "{mm.group(0)}" — {why}')
                    hard_missing += 1
        if missing:
            print(f"  -> missing: {', '.join(missing)}")
        print()
    if hard_missing:
        print(f"FAIL: {hard_missing} required artifact-package piece(s) missing.")
        return 1
    print("OK: every post has its non-optional pieces (review the warn list before publishing).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
