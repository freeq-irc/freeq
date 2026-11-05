# Fabro revival plan (2026-09-29)

Goal: nightly upkeep + laptop→cloud handoff for freeq, running on boxd so the
laptop can close and work keeps going. Run lifecycle notifications land in
**#freeq-dev** on irc.freeq.at.

## Decisions

- **Docker stays (for now).** Fabro only *executes* runs on its built-in
  providers (`local`, `docker`, `daytona`). Automations (cron) and auto-PRs
  both require a clone-based provider — `local` is rejected for both. Fabro
  has a sandbox-driver plugin protocol, but plugins are currently only used to
  *inspect* sandboxes, not run them ("Runs execute only on the built-in
  providers for now"). So "one boxd fork per run" would mean re-implementing
  scheduling, branching, and PR creation outside Fabro. Revisit when Fabro
  lets plugins execute runs — a `sandbox-driver-boxd` plugin forking a warm
  golden VM per run is then the ideal shape.
- **boxd's role:** the always-on host. Resize `fabro-freeq` to 4 vCPU / 16 GB
  (boxd supports resize now), disable auto-suspend/hibernate so cron fires.
- **Warm builds without volume mounts:** Fabro's docker provider has no mount
  support, so cache compiler output via **sccache → a disk-backed WebDAV
  store on the VM host** (reachable from run containers over the docker bridge). Turns 20–30 min
  cold builds into mostly-cache-hit builds.
- **Notifications:** new `freeq-fabro/` package — a small bot-kit daemon
  (did:key, owner = did:plc:4qsyxmnsblo4luuycm3572bq) that stays in
  #freeq-dev and listens on 127.0.0.1 for Fabro HTTP hooks
  (run_start / run_complete / run_failed, plus human-gate questions).
  Approvals-over-freeq is a follow-up on the same bot.
- **Models:** Sonnet 5.5 default, Opus 5.5 for hunt/plan/implement nodes.

## Steps

- [x] 1. Wake `fabro-freeq`; inventory (fabro version, systemd unit, docker
      image, repo checkout, secrets present, disk).
- [x] 2. ~~Resize to 4×16G~~ (already 4×16G); auto-suspend/hibernate off.
- [x] 3. ~~Upgrade Fabro~~ — stayed on 0.254 (latest stable); 5.5 models
      added as custom catalog entries instead.
- [x] 4. Update `.fabro/` config: models, resources, sccache env, image.
- [x] 5. sccache + WebDAV store on VM; rebuild `freeq-fabro:tools`.
- [ ] 6. Manual `test-coverage` run → confirm green PR, measure build time.
- [x] 7. `freeq-fabro` notifier bot + hooks; systemd on VM; verify a
      message lands in #freeq-dev.
- [x] 8. Laptop handoff: point laptop CLI at the VM server; document
      "plan here, run there" flow.
- [ ] 9. Enable nightly schedules (test-coverage 02:00, bug-hunt 04:00 UTC,
      dep-audit Mon 06:00 UTC) — enabled in repo; live after push + provision.
- [x] 10. Update `.fabro/README.md`; commit.

## Log

- 2026-09-29 — VM `fabro-freeq` was hibernated (auto-hibernate 4h); woke it,
  set auto-hibernate off. Already 4 vCPU / 16 GB — no resize needed.
- Fabro: latest *stable* is still 0.254 (June); everything since is nightly.
  Stayed on 0.254. Its catalog stops at opus-4-8/sonnet-4-6 → declared
  claude-opus-5-5 / claude-sonnet-5-5 as custom models (`executor/models.toml`).
- Cache: chose sccache → **WebDAV on disk** (rclone) over Redis — Redis would
  hold the cache in the RAM the builds need. Verified from a run container.
- Relay: `freeq-fabro/` bot. #freeq-dev has a join policy (477) — bot accepts
  it (`FREEQ_ACCEPT_POLICY=1`, owner opted in); joined as role `member`.
  Verified start/finish lines posting from a dry run.
- Hooks in 0.254 are `[[run.hooks]]` with no `type` field (inferred from `url`).
- Automations: 0.254 loads them from `~/.fabro/automations/`, not the repo —
  they were never registered in June, so schedules could never have fired.
  provision.sh now installs them. Schedules enabled in the repo; they fire
  with whatever config is on GitHub `main`.
- Laptop access: SSH tunnel (`scripts/fabro-remote`), not the public boxd
  proxy — exposing the control plane publicly is an open decision.
- **Blocker:** the VM's ANTHROPIC_API_KEY hit its monthly usage limit
  (resets 2026-10-01 00:00 UTC). Step 6 (a real green run) waits on that.
- Real laptop-launched run (01M3QG67…): docker sandbox, clone, run branch push,
  hooks, Sonnet 5.5 selection all worked; LLM stages failed on the usage limit.
- **Found + fixed:** that run still ended SUCCEEDED — unconditional edges let
  failed agent stages fall through to the CI gate, which passed on unchanged
  main. An outage would have looked like a quiet night. 0.254 ignores
  graph-level `on_failure="exit"` and rejects all-conditional edges, so each
  working stage now advances on `outcome=succeeded` and otherwise drops to an
  `abort` goal gate. Verified: run 01M3QHMC… ended FAILED in ~1 min and
  #freeq-dev got the FAILED line.
- Build timing (CI gate, 4 vCPU): cold 12.7 min → 9.5 min with a warm
  sccache; compile is ~4 min cold, the rest is the test suite.

## Paused (2026-10-03)

`fabro-server` and `freeq-fabro` are stopped and disabled on the VM at the
owner's request — no scheduled runs, no bot. The VM itself still runs
(with `sccache-webdav`). To resume: push the pending commits, then on the VM
`sudo systemctl enable --now fabro-server freeq-fabro` (re-running
`provision.sh` also re-enables the bot).

## Open

- Push to GitHub (needs your OK) so nightly runs pick up this config.
- Approvals over freeq (reply in #freeq-dev → Fabro submit-answer API).
- Public web UI (boxd proxy + real auth) if phone access matters.
