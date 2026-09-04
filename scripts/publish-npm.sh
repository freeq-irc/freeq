#!/usr/bin/env bash
#
# Publish the four @freeq packages to npm, in dependency order.
#
# The problem this solves: in the repo the packages depend on each other by
# `file:../sibling`, which is what makes local development and CI work without
# a registry. That path is meaningless on a consumer's machine, so it must
# become a version range in the published tarball — and must NOT be committed,
# or every `npm ci` here breaks until the packages exist on npm.
#
# So the swap happens here, around the publish, and is always undone. The trap
# fires on failure and on Ctrl-C, because a half-published repo left with
# version ranges in it is a repo whose next install fails for reasons nobody
# will connect to this script.
#
# Usage:
#   scripts/publish-npm.sh --dry-run     # rehearse; publishes nothing
#   scripts/publish-npm.sh               # for real
#
set -euo pipefail
cd "$(dirname "$0")/.."

DRY=""
[[ "${1:-}" == "--dry-run" ]] && DRY="--dry-run"

# Dependency order. sdk has no siblings; bot-kit needs sdk; mcp and pi need
# both. npm resolves a dependency at install time, not publish time, so a
# consumer of pi installed minutes after pi went up still needs bot-kit to be
# there — hence the order, not just the convention.
PKGS=(freeq-sdk-js freeq-bot-kit-js freeq-mcp freeq-pi)

# Read each package's own version rather than pinning one here. A hardcoded
# version silently skips a package that has moved on - which is exactly what a
# patch release is - and "already published, skipping" is the least helpful
# possible way to learn that.
pkg_version() { node -e "process.stdout.write(require('./$1/package.json').version)"; }

restore() {
  git checkout -- freeq-bot-kit-js/package.json freeq-mcp/package.json freeq-pi/package.json 2>/dev/null || true
  echo "→ restored file: dependencies in the working tree"
}
trap restore EXIT INT TERM

echo "── preflight ─────────────────────────────────────────"
who=$(npm whoami 2>/dev/null || true)
[[ -n "$who" ]] || { echo "not logged in to npm — run: npm login"; exit 1; }
echo "npm user: $who"

if ! npm org ls freeq >/dev/null 2>&1; then
  cat <<'MSG'

The @freeq scope does not exist yet, or you are not a member.

Create it (free for public packages):
    https://www.npmjs.com/org/create      → organisation name: freeq

Then run this script again. Nothing has been published.
MSG
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree is dirty — commit or stash first, so the restore is clean"
  exit 1
fi

echo
echo "── rewriting sibling deps ───────────────────────────"
python3 - "$(pkg_version freeq-sdk-js)" <<'PY'
import json, pathlib, sys
version = sys.argv[1]
for d in ("freeq-bot-kit-js", "freeq-mcp", "freeq-pi"):
    p = pathlib.Path(d) / "package.json"
    j = json.loads(p.read_text())
    for field in ("dependencies", "peerDependencies"):
        for k, v in list(j.get(field, {}).items()):
            if str(v).startswith("file:"):
                j[field][k] = f"^{version}"
                print(f"  {d}: {k} -> ^{version}")
    p.write_text(json.dumps(j, indent=2) + "\n")
PY

echo
echo "── building ─────────────────────────────────────────"
for p in "${PKGS[@]}"; do
  ( cd "$p" && npm run build >/dev/null ) && echo "  built $p"
done

echo
echo "── publishing ───────────────────────────────────────"
for p in "${PKGS[@]}"; do
  name=$(node -e "process.stdout.write(require('./$p/package.json').name)")
  v=$(pkg_version "$p")
  if npm view "$name@$v" version >/dev/null 2>&1; then
    echo "  $name@$v already published — skipping"
    continue
  fi
  echo "  publishing $name@$v"
  ( cd "$p" && npm publish --access public $DRY )
done

echo
if [[ -n "$DRY" ]]; then
  echo "dry run complete — nothing was published."
else
  echo "published. Verify the on-ramp from a CLEAN directory, not this one:"
  echo "    cd \$(mktemp -d) && npm init -y >/dev/null && pi install npm:@freeq/pi && pi -p 'say READY'"
fi
