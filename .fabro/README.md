# Fabro — agents improving freeq around the clock

This directory configures [Fabro](https://fabro.sh) to run AI-agent workflows
that improve freeq, each opening a **ready-for-review PR** you merge by hand.
Workflows are version-controlled DOT graphs — the process is code, reviewable
and forkable like anything else in the repo.

Two ways work reaches it:

- **Nightly upkeep** — scheduled workflows (below) run on their own.
- **Handoff** — you plan on the laptop, hand the plan to the `feature`
  workflow, close the lid; it keeps going on the boxd VM.

Either way, run lifecycle lands in **#freeq-dev** on irc.freeq.at (started,
finished + PR link, failed + reason, waiting for your approval), and you can
drive Fabro back from any freeq client — including your phone.

## Driving it from freeq

The `fabro` bot in #freeq-dev takes commands from its owner only (checked
against the sender's server-verified DID; everyone else is ignored). Address
it in the channel, or DM it without the prefix:

| Command | Does |
|---|---|
| `fabro status` | Active runs, and any gate waiting on you |
| `fabro run bug-hunt` | Fire an upkeep automation now, from `main` |
| `fabro run feature <goal…>` | Start a workflow with a goal (handoff from your phone) |
| `fabro approve [id]` / `fabro deny [id]` | Answer a waiting yes/no gate — id optional if only one waits |
| `fabro answer <id> <choice or text>` | Multiple-choice / freeform gates |
| `fabro cancel <id>` | Cancel a run |
| `fabro help` | This list |

`id` is the 6-character tag every notification carries, e.g. `[ndb1qw]`.
Approval pings include the gate's actual question and the reply to send.

## The workflows

| Workflow | What it does | Schedule (UTC) |
|---|---|---|
| [`test-coverage`](workflows/test-coverage/) | Picks a high-risk, undertested file (`scripts/hotspots.sh` + the CLAUDE.md hotspot list) and adds focused tests. | Nightly 02:00 |
| [`bug-hunt`](workflows/bug-hunt/) | Finds one genuine correctness bug, pins it with a failing regression test, fixes it minimally. Opus for the hunt. | Nightly 04:00 |
| [`dep-audit`](workflows/dep-audit/) | Runs `cargo audit` + `npm audit`, patches one advisory with the smallest viable bump. | Mon 06:00 |
| [`feature`](workflows/feature/) | Long-horizon: explore → plan → 3 parallel plan reviews → **your approval** → implement → CI gate → 2 parallel code reviews → address → CI gate → PR. Driven by `--goal`/`--goal-file`. | On demand |

The upkeep workflows share one shape: **select/hunt/audit (read-only) →
implement → CI gate → PR body**. The CI gate ([`verify.sh`](verify.sh)) mirrors
`.github/workflows/ci.yml` (rustfmt + `cargo check`/`clippy -D warnings`/`test`
with CI's AV-crate exclusions, plus `freeq-app` vitest when the app changed).
It's a `goal_gate`: **a failed gate opens no PR**, and routes back to the
implementer for up to 2 bounded retries first.

## PR policy and models

Set in [`project.toml`](project.toml): PRs open **ready for review**,
squash-merge, **never auto-merged**. Every node names its model —
`claude-sonnet-5-5`, or `claude-opus-5-5` for hunt/explore/plan/implement.
The run-level default stays `claude-sonnet-4-6` because Fabro writes the PR
title/body with a forced tool call, which the 5.5 family rejects. Fabro 0.254
(the latest stable) predates the 5.5 family, so both are declared as custom
models on the executor ([`executor/models.toml`](executor/models.toml)).

## Handoff from the laptop

[`scripts/fabro-remote`](../scripts/fabro-remote) is `fabro` pointed at the VM:
it opens an SSH tunnel to the server (which only listens on the VM's loopback)
and logs in with the VM's dev token on first use.

```bash
# plan interactively (Claude Code / pi), save it, then:
scripts/fabro-remote run .fabro/workflows/feature/workflow.toml \
  --goal-file docs/plans/my-feature.md --detach

scripts/fabro-remote ps                 # what's running
scripts/fabro-remote attach <run-id>    # follow along / answer the approval gate
scripts/fabro-remote inspect <run-id>
scripts/fabro-remote --close            # drop the tunnel
```

While the tunnel is up the web UI is at http://127.0.0.1:32277. The run clones
**GitHub**, not your working tree — push the branch it should start from
first. The goal file travels with the run, so the plan itself needn't be
committed. Workflow config (`.fabro/`) is taken from your local checkout.

## Where it runs

An always-on **boxd VM**, `fabro-freeq` (4 vCPU / 16 GB, auto-suspend and
auto-hibernate off so cron fires), runs:

| Service | What |
|---|---|
| `fabro-server` | Fabro 0.254, `127.0.0.1:32276`, automations in `~/.fabro/automations/` |
| `sccache-webdav` | Disk-backed compiler cache on the docker bridge, `172.17.0.1:8090` |
| `freeq-fabro` | [`freeq-fabro/`](../freeq-fabro/) relay bot: Fabro HTTP hooks → #freeq-dev |

Runs execute in Docker (`freeq-fabro:tools`, [`Dockerfile.tools`](Dockerfile.tools):
toolchain only, no baked source). The docker provider is clone-based: each run
gets a fresh clone on `fabro/run/<id>`, and Fabro owns branch → commit → push
→ PR.

**Why Docker inside boxd, not a boxd fork per run?** Fabro only executes runs
on its built-in providers (`local`/`docker`/`daytona`); automations and
auto-PRs both require a clone-based one (`local` is rejected for both), and
sandbox-driver plugins can't execute runs yet. When they can, a boxd plugin
forking a warm golden VM per run is the better shape.

**Warm builds.** Containers start cold and the docker provider has no volume
mounts, so `RUSTC_WRAPPER=sccache` caches compiled crates in the host's WebDAV
store (`CARGO_INCREMENTAL=0`, which sccache needs). Entries untouched for 14
days are pruned. Debug symbols stay off (`CARGO_PROFILE_*_DEBUG=0`) — debug=2
once blew the disk and bus-errored the linker.

**Scheduled runs see `main` on GitHub.** An automation fire clones
`freeq-irc/freeq@main`, so config changes here only affect nightly runs once
pushed (laptop handoffs use your local `.fabro/`).

## Executor setup

1. `boxd new --name=fabro-freeq --vcpu 4 --auto-suspend-timeout=0 --auto-hibernate-timeout=0`
2. On the VM: install Fabro (`curl -fsSL https://fabro.sh/install.sh | bash`),
   Docker, Node 22+; clone freeq to `~/freeq`.
3. `fabro install` (GitHub token strategy), `fabro secret set ANTHROPIC_API_KEY …`.
4. Run `fabro server start --foreground` under systemd as `fabro-server`.
5. `bash .fabro/executor/provision.sh` — idempotent; installs the cache,
   custom models, automations, run image, and the relay bot (config in
   `~/.config/freeq-fabro.env`, log in `~/.config/freeq-fabro.log`). Re-run
   after pulling changes to `.fabro/` or `freeq-fabro/`.

## Running on the VM directly

```bash
fabro run .fabro/workflows/test-coverage/workflow.toml --detach
fabro run .fabro/workflows/test-coverage/workflow.toml --dry-run   # simulated LLM, no spend
fabro preflight .fabro/workflows/bug-hunt/workflow.toml
fabro events <run-id> / fabro logs <run-id> / fabro inspect <run-id>
```

`--dry-run` only works from the VM's own checkout: it forces the `local`
provider, which runs in the submitting client's directory.
