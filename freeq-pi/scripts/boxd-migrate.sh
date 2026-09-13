#!/usr/bin/env bash
#
# Move a pi session onto a boxd.sh VM, with a freeq identity the VM owns and
# the owner has signed for.
#
# The interesting part is the identity, not the file copying. A cloud VM must
# not hold the owner's delegation-signing key, and it must not hold a copy of
# the laptop's agent key either — two machines answering to one DID is a
# broken participant, not redundancy. So the VM mints its OWN did:key, we sign
# its certificate here with the owner's creator key, and only the signed
# certificate travels. That is what gets the agent into an +i channel the
# owner is in: freeq admits an agent on a *verified* delegation
# (freeq-server/src/connection/channel.rs), and an unsigned cert grants
# nothing.
#
#   ./scripts/boxd-migrate.sh --vm my-box --channel '#my-room'
#
# Idempotent: safe to re-run against an existing VM. Keys are loaded, not
# regenerated; a cert that is already signed is left alone.
#
set -euo pipefail

VM=""
CHANNEL=""
NICK=""
SESSION="${PI_SESSION_FILE:-}"
REPO=""
START=1
DRY=0
REMOTE_HOME="/home/boxd"

usage() {
  cat <<'EOF'
usage: boxd-migrate.sh [options]

  --vm NAME         boxd machine name           (default: pi-<project>)
  --channel '#c'    channel the VM agent joins  (default: first in freeq.json)
  --nick NICK       base nick on the VM         (default: <local nick>-boxd)
  --session FILE    session .jsonl to carry     (default: $PI_SESSION_FILE;
                                                 "none" to start fresh)
  --repo DIR        repo to mirror on the VM    (default: git root of cwd)
  --no-start        provision only, do not launch pi
  --dry-run         print what would happen
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM="$2"; shift 2;;
    --channel) CHANNEL="$2"; shift 2;;
    --nick) NICK="$2"; shift 2;;
    --session) SESSION="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    --no-start) START=0; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v boxd >/dev/null || die "boxd CLI not found (curl -fsSL https://boxd.sh/downloads/install.sh | sh)"
command -v node >/dev/null || die "node not found"
command -v python3 >/dev/null || die "python3 not found"

# boxd renamed its verbs between versions: `boxd exec` on newer builds,
# `boxd machine exec` on older ones. Probe once rather than guess.
if boxd exec --help >/dev/null 2>&1; then BX=(boxd); else BX=(boxd machine); fi
bx()      { "${BX[@]}" "$@"; }
vmexec()  { "${BX[@]}" exec "$VM" -- "$1"; }
vmput()   { "${BX[@]}" cp - "$VM:$1" >/dev/null; }   # stdin -> remote file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$HOME/.pi/agent"
FREEQ_JSON="$AGENT_DIR/freeq.json"
[ -f "$FREEQ_JSON" ] || die "$FREEQ_JSON not found — run /freeq login <did> in pi first"

OWNER_DID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("ownerDid",""))' "$FREEQ_JSON")
[ -n "$OWNER_DID" ] || die "no ownerDid in freeq.json — run /freeq login <did> in pi first"

REPO="${REPO:-$(git rev-parse --show-toplevel 2>/dev/null || true)}"
[ -n "$REPO" ] || die "not in a git repo and --repo not given"
PROJECT="$(basename "$REPO")"
ORIGIN="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
[ -n "$ORIGIN" ] || die "$REPO has no origin remote; the VM needs somewhere to clone from"
# owner/name, whatever URL form origin uses
SLUG="$(printf '%s' "$ORIGIN" | sed -E 's#^git@[^:]+:##; s#^[a-z+]+://[^/]+/##; s#\.git$##')"
BRANCH="$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"

VM="${VM:-pi-$PROJECT}"
if [ -z "$CHANNEL" ]; then
  CHANNEL=$(python3 -c 'import json,sys;c=json.load(open(sys.argv[1])).get("channels") or [];print(c[0] if c else "")' "$FREEQ_JSON")
fi
[ -n "$CHANNEL" ] || die "no channel given and none in freeq.json"
if [ -z "$NICK" ]; then
  BASENICK=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("nick") or "pi")' "$FREEQ_JSON")
  NICK="${BASENICK}-boxd"
fi
PROVIDER=$(python3 -c 'import json,sys,os
p=sys.argv[1]
print((json.load(open(p)).get("defaultProvider") if os.path.exists(p) else "") or "")' "$AGENT_DIR/settings.json" 2>/dev/null || true)
PROVIDER="${PI_PROVIDER:-${PROVIDER:-anthropic}}"
case "$PROVIDER" in
  anthropic) KEY_ENV=ANTHROPIC_API_KEY;;
  openai)    KEY_ENV=OPENAI_API_KEY;;
  google)    KEY_ENV=GEMINI_API_KEY;;
  *)         KEY_ENV="";;
esac

say "vm=$VM project=$PROJECT repo=$SLUG@$BRANCH channel=$CHANNEL nick=$NICK owner=$OWNER_DID"
if [ "$DRY" = 1 ]; then echo "(dry run — nothing done)"; exit 0; fi

# ── 1. the machine ──────────────────────────────────────────────────────────
if bx get "$VM" >/dev/null 2>&1; then
  say "machine $VM exists"
  bx start "$VM" >/dev/null 2>&1 || true
else
  say "creating machine $VM (auto-suspend off — an idle agent still has to be reachable)"
  bx new "$VM" --auto-suspend-timeout=0 --auto-hibernate-timeout=0 >/dev/null
fi

# ── 2. pi on the machine ────────────────────────────────────────────────────
say "installing pi"
vmexec 'command -v pi >/dev/null && exit 0
        sudo npm i -g @earendil-works/pi-coding-agent >/dev/null 2>&1 || npm i -g @earendil-works/pi-coding-agent >/dev/null 2>&1
        # npm under nvm puts pi outside the non-interactive PATH; link it.
        P=$(ls -d $HOME/.nvm/versions/node/*/bin/pi 2>/dev/null | head -1)
        [ -n "$P" ] && sudo ln -sf "$P" /usr/local/bin/pi
        pi --version >/dev/null'

# ── 3. the repo, including work that is not pushed yet ──────────────────────
say "cloning $SLUG"
vmexec "git config --global user.name \"$(git config user.name)\" || true
        git config --global user.email \"$(git config user.email)\" || true
        mkdir -p ~/src && cd ~/src
        [ -d '$PROJECT' ] || gh repo clone '$SLUG' '$PROJECT' -- --depth=100
        cd '$PROJECT' && git fetch --quiet origin '$BRANCH' && git checkout --quiet '$BRANCH' && git pull --quiet --ff-only || true"

UPSTREAM="origin/$BRANCH"
if git -C "$REPO" rev-parse --verify --quiet "$UPSTREAM" >/dev/null && \
   [ -n "$(git -C "$REPO" log --oneline "$UPSTREAM..HEAD" 2>/dev/null)" ]; then
  say "carrying $(git -C "$REPO" rev-list --count "$UPSTREAM..HEAD") unpushed commit(s) as patches (nothing is pushed)"
  git -C "$REPO" format-patch "$UPSTREAM..HEAD" --stdout | vmput "$REMOTE_HOME/.pi-migrate.patch"
  vmexec "cd ~/src/'$PROJECT' && git am --3way < ~/.pi-migrate.patch 2>/dev/null || git am --abort 2>/dev/null || true"
fi

# ── 4. credentials, skills, settings, session ───────────────────────────────
# Before installing @freeq/pi, not after: `pi install` records the package in
# settings.json, and writing settings afterwards would erase the entry and
# leave the VM with no extension loaded.
if [ -n "$KEY_ENV" ] && [ -n "${!KEY_ENV:-}" ]; then
  say "transferring the $PROVIDER API key (stdin, never in argv)"
  printf '%s' "${!KEY_ENV}" | vmput "$REMOTE_HOME/.pi-model-key"
  vmexec "chmod 600 ~/.pi-model-key
          grep -q pi-model-key ~/.bashrc || printf '\nexport $KEY_ENV=\$(cat \$HOME/.pi-model-key)\n' >> ~/.bashrc"
else
  say "WARNING: no API key found in \$$KEY_ENV — set one on the VM yourself"
fi
if [ -f "$AGENT_DIR/auth.json" ]; then
  vmexec 'mkdir -p ~/.pi/agent'
  vmput "$REMOTE_HOME/.pi/agent/auth.json" < "$AGENT_DIR/auth.json"
  vmexec 'chmod 600 ~/.pi/agent/auth.json'
fi

if [ -d "$AGENT_DIR/skills" ]; then
  say "copying skills"
  tar czf - -C "$AGENT_DIR" skills 2>/dev/null | vmput "$REMOTE_HOME/.pi-skills.tgz"
  vmexec 'mkdir -p ~/.pi/agent && tar xzf ~/.pi-skills.tgz -C ~/.pi/agent && rm ~/.pi-skills.tgz'
fi

say "writing settings.json and freeq.json"
python3 - "$AGENT_DIR/settings.json" "$PROVIDER" "${PI_MODEL:-}" <<'PY' | vmput "$REMOTE_HOME/.pi/agent/settings.json"
import json, os, sys
path, provider, model = sys.argv[1], sys.argv[2], sys.argv[3]
s = json.load(open(path)) if os.path.exists(path) else {}
# Packages are paths on THIS machine; the VM got its own install in step 4.
s.pop("packages", None)
s["defaultProvider"] = provider
if model:
    s["defaultModel"] = model
print(json.dumps(s, indent=2))
PY

python3 - "$FREEQ_JSON" "$CHANNEL" "$NICK" <<'PY' | vmput "$REMOTE_HOME/.pi/agent/freeq.json"
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["channels"] = [sys.argv[2]]
cfg["nick"] = sys.argv[3]
# The VM is a different installation: let it derive its own slug, and drop
# per-project channel overrides that belong to the laptop's directories.
cfg.pop("install", None)
cfg.pop("projects", None)
print(json.dumps(cfg, indent=2))
PY

# ── 5. @freeq/pi ────────────────────────────────────────────────────────────
# If we are migrating the freeq repo itself, install the checkout so the VM
# runs the same code as this session — including anything not yet published.
if [ -f "$REPO/freeq-pi/package.json" ]; then
  say "building @freeq/pi from the checkout"
  vmexec "cd ~/src/'$PROJECT'/freeq-pi && npm install --silent && npm run build --silent && pi install \"\$(pwd)\" >/dev/null"
  PKG_DIR="$REMOTE_HOME/src/$PROJECT/freeq-pi"
else
  say "installing @freeq/pi from npm"
  vmexec 'pi install npm:@freeq/pi >/dev/null'
  PKG_DIR="$REMOTE_HOME/.pi/agent/npm/node_modules/@freeq/pi"
fi

if [ -n "$SESSION" ] && [ "$SESSION" != "none" ] && [ -f "$SESSION" ]; then
  say "carrying the session history ($(wc -l < "$SESSION" | tr -d ' ') entries)"
  SDIR="--$(printf '%s' "$REMOTE_HOME/src/$PROJECT" | sed 's#/#-#g; s#^-##')--"
  vmexec "mkdir -p '$REMOTE_HOME/.pi/agent/sessions/$SDIR'"
  # The session header records the cwd it was created in; rewrite it so the
  # VM's copy belongs to the VM's checkout and `pi -c` finds it.
  python3 - "$SESSION" "$REMOTE_HOME/src/$PROJECT" <<'PY' | vmput "$REMOTE_HOME/.pi/agent/sessions/$SDIR/$(basename "$SESSION")"
import json, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
if lines:
    try:
        head = json.loads(lines[0])
        if head.get("type") == "session":
            head["cwd"] = sys.argv[2]
            lines[0] = json.dumps(head)
    except Exception:
        pass
print("\n".join(lines))
PY
fi

# ── 6. identity: minted on the VM, signed here ──────────────────────────────
say "minting the VM's own did:key"
MINT=$(vmexec "cd '$PKG_DIR' && node scripts/mint-identity.mjs --owner '$OWNER_DID' --project '$PROJECT'" | tr -d '\r' | grep '^{' | tail -1)
BOT_DID=$(printf '%s' "$MINT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["did"])')
CERT_PATH=$(printf '%s' "$MINT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["certPath"])')
SIGNED=$(printf '%s' "$MINT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["signed"])')
say "VM agent is $BOT_DID"

if [ "$SIGNED" != "True" ]; then
  say "signing its delegation here (the creator seed stays on this machine)"
  TMP_CERT=$(mktemp)
  bx cp "$VM:$CERT_PATH" "$TMP_CERT" >/dev/null
  node "$SCRIPT_DIR/sign-delegation.mjs" --cert "$TMP_CERT" --owner "$OWNER_DID" >/dev/null
  vmput "$CERT_PATH" < "$TMP_CERT"
  vmexec "chmod 600 '$CERT_PATH'"
  rm -f "$TMP_CERT"
fi

# The cert is only worth anything if the server knows the key that signed it.
PUB=$(node -e '
import("'"$SCRIPT_DIR"'/../dist/owner-key.js").then(async (m) => {
  const seed = await m.loadOrCreateCreatorSeed(m.creatorKeyPath(process.env.HOME + "/.freeq", process.argv[1]));
  console.log(m.creatorPublicKeyB64(seed));
});' "$OWNER_DID")
SERVER_HOST=$(python3 -c 'import json,sys,urllib.parse
u=urllib.parse.urlparse(json.load(open(sys.argv[1]))["server"]);print(u.hostname)' "$FREEQ_JSON")
REGISTERED=$(curl -fsS "https://$SERVER_HOST/api/v1/signing-keys/$OWNER_DID" 2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("public_key",""))
except Exception: print("")')
if [ "$REGISTERED" != "$PUB" ]; then
  cat <<EOF

  ┌─ one-time, and only you can do it ──────────────────────────────────────
  │ The server must know the key that signed this delegation. Paste this
  │ into any freeq client logged in as $OWNER_DID:
  │
  │     /raw MSGSIG $PUB
  │
  │ It is an ed25519 PUBLIC key — nothing secret. Until it is registered,
  │ the cert is "stored (unverified)" and grants the agent nothing.
  └──────────────────────────────────────────────────────────────────────────

EOF
  read -r -p "  press enter once you have pasted it (or ctrl-c to do it later) " _ || true
fi

# ── 7. run it ───────────────────────────────────────────────────────────────
if [ "$START" = 1 ]; then
  say "starting pi in tmux session 'pi'"
  RESUME="-c"
  if [ -z "$SESSION" ] || [ "$SESSION" = "none" ]; then RESUME=""; fi
  vmexec "tmux has-session -t pi 2>/dev/null && tmux kill-session -t pi
          tmux new-session -d -s pi -x 200 -y 50 \"bash -lc 'cd ~/src/$PROJECT && pi $RESUME; exec bash'\"
          sleep 8
          # pi asks about trusting the project folder on first run in a dir.
          tmux send-keys -t pi Enter
          sleep 20"
  # JOIN and PROVENANCE race on connect: a join sent before the server has
  # verified the cert is refused with +i. Asking again once we are online is
  # the reliable order.
  say "joining $CHANNEL"
  vmexec "tmux send-keys -t pi '/freeq join $CHANNEL' Enter; sleep 12; tmux capture-pane -p -t pi | tail -6"
  echo
  say "attach with:  boxd connect $VM   then:  tmux attach -t pi"
else
  say "provisioned; start it with: ${BX[*]} exec $VM -- 'tmux new-session -d -s pi \"bash -lc \\\"cd ~/src/$PROJECT && pi -c\\\"\"'"
fi
