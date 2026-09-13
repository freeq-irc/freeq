# Migrate this pi session to a boxd VM, joined to #chad-compute

Goal: this session (project `freeq`, running on the laptop) continues on a
boxd.sh VM, where pi runs with `@freeq/pi`, holds its **own** `did:key`
identity, and joins `#chad-compute` under a delegation certificate **signed by
the owner's creator key** (owner DID `did:plc:4qsy…`), so the server reports
provenance as verified rather than "declarative only".

## Design decisions

- **The creator seed never leaves the laptop.** bot-kit will sign a cert at
  connect time if given `creatorKeyPath`, but that would mean shipping the
  owner's delegation-signing key to a cloud VM. Instead: the VM mints its own
  agent key, we read only its *public* `did:key`, sign the cert here, and
  upload the signed `delegation.json`. `loadOrMintDelegation` keeps an existing
  signed cert untouched.
- **New identity on the VM, not a copy of the laptop's.** Agent identity is
  per-installation × per-project. Copying `agent.key` would put the same DID on
  two machines. The VM is a different participant, delegated by the same owner.
- **Session *history* is what migrates**, i.e. the session `.jsonl` plus repo
  checkout and settings — not the laptop's keys.

## Steps

- [x] 1. Plan file
- [x] 2. Owner creator key exists locally (`~/.freeq/owner/<did>/creator.key`, 0600)
- [x] 3. Register its public half under the owner DID via `MSGSIG` (one line
      pasted into a client already authenticated as the owner) — verified via
      `/api/v1/signing-keys/<did>` (kid `2Vd1oFdI…`)
- [x] 4. `boxd new --name=chad-compute`, auto-suspend disabled
- [x] 5. Node 22 + pi installed on the VM
- [x] 6. Repo cloned on the VM; model API key + session `.jsonl` transferred
- [x] 7. `@freeq/pi` installed on the VM; `freeq.json` written with ownerDid,
      nick `pi-chad-boxd`, channels `["#chad-compute"]`
- [x] 8. VM mints agent key → we sign its cert locally → upload `delegation.json`
- [x] 9. pi runs on the VM in tmux, resumes the migrated session, joins
      `#chad-compute`, and the server reports **Provenance verified**

## Verification

- `boxd exec chad-compute -- 'tmux ls'` shows the session
- freeq `#chad-compute` shows `pi-chad-boxd` joined
- the VM's connection log contains `Provenance verified`

## Reusable form

The one-off is now a skill shipped with `@freeq/pi`, so any pi session with the
package installed can do this without rediscovering the identity rules:

- `freeq-pi/skills/boxd-migrate/SKILL.md` — when to use it, why the VM mints
  its own key, and the manual `MSGSIG` step
- `freeq-pi/scripts/boxd-migrate.sh` — the whole move, idempotent
- `freeq-pi/scripts/mint-identity.mjs` — mint an identity without connecting
  (on the machine being provisioned)
- `freeq-pi/scripts/sign-delegation.mjs` — sign a cert with the owner's
  creator key (on the owner's machine)

Validated end to end on a throwaway VM (`pi-migrate-test`, since destroyed),
which is how the settings/`pi install` ordering bug was found.

## Status

DONE — 2026-09-13. VM `chad-compute`, agent nick `pi-chad-boxd`,
bot DID `did:key:z6MkpLMR…`, cert signed by the owner creator key and
accepted by the server ("Provenance verified"). pi resumes the migrated
session in tmux session `pi`.
