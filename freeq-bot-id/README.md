# freeq-bot-id

CLI utility for minting and managing freeq bot identities.

This is the **Rust-side identity utility**: it generates the ed25519 keypair (did:key or did:web), persists the seed at `~/.freeq/bots/<name>/key.ed25519` with mode 0600, and optionally writes a delegation certificate naming a creator DID as the bot's owner, which the owner proves with an agent record (`register`, below).

## Who uses this

- **Rust bot authors** — your typical setup is a one-shot `freeq-bot-id create --name X`, then your bot reads the persisted seed in code via `freeq_sdk::auth::KeySigner::from_seed(...)`. The Rust SDK has the cryptographic primitives (`PrivateKey::generate_ed25519`, `PrivateKey::ed25519_from_bytes`) but no "load-or-create at the right path with the right perms" helper — this CLI is that helper.

- **TypeScript bot authors** — you don't need this. [`@freeq/bot-kit`](../freeq-bot-kit-js/)'s `FreeqBot.create({name, ownerDid, ...})` handles identity persistence internally on first run. The on-disk layout matches what `freeq-bot-id` writes, so a Rust bot and a TS bot can interoperate on the same keys.

## Install

```bash
cargo install --path freeq-bot-id
```

## Subcommands

```bash
# Mint a fresh bot identity (writes seed + DID document under ~/.freeq/bots/<name>/)
freeq-bot-id create --name myagent

# Quick did:key one-liner (no delegation, just generates and prints)
freeq-bot-id did-key --name myagent

# Inspect an existing identity
freeq-bot-id info --name myagent

# Record bots as yours (run by the owner, not on the bot's machine)
freeq-bot-id register --owner alice.bsky.social did:key:z6Mk... --name helper
freeq-bot-id register --owner alice.bsky.social did:key:z6Mk... did:key:z6Mk...
```

For did:web identities (org-scoped), pass `--domain example.com` to `create`.

## Registering bots as yours

A bot names its owner in the certificate it presents when it connects
(`create --creator-did <owner DID>` writes one, unsigned). The server proves
that claim by reading the owner's account for an `at.freeq.agentKey` record
naming the bot. `register` writes those records:

1. It opens your browser once to sign in, asking to create identity records
   in your account (`atproto repo:at.freeq.deviceKey?action=create
   repo:at.freeq.agentKey?action=create`).
2. It loads this machine's device key from its own file,
   `<config dir>/freeq-bot-id/<handle>.device-key.json` (on Linux
   `~/.config/freeq-bot-id/`, on macOS `~/Library/Application Support/freeq-bot-id/`),
   or makes one. A key past its 90-day lifetime, or signed out from another
   device, is replaced.
3. If your account has no live record for that key, it publishes one, so the
   machine shows in your Devices list as `freeq-bot-id on <machine name>`.
4. It writes one agent record per bot DID, signed by that key, and prints
   each record's URI. `--name` names the bot in your Agents list; it takes
   one DID. A bot registered without a name is listed by its DID.

The sign-in is not saved: nothing that can write to your account is left on
the machine after the run. Nothing is written on the bot's machine either;
the bot keeps presenting the same unsigned certificate. The web app's
Settings → Agents does the same from a browser, and removes a bot.

### Deprecated: a signed certificate

Adding `--creator-key <path>` to `create` signs the certificate with
a key of the owner's, which the owner must have registered with the server
(`MSGSIG`). It is deprecated and to be removed in a later release, when signed
certificates stop counting; every server in use now reads agent records.
The key lives on the bot's machine and counts as one of the owner's signing
keys, and a certificate signed while the key was valid cannot be withdrawn.
`create` warns when it signs one. Use `register`, then set `"signature":
null` in the bot's `identity.json` and in its `delegation.json` (did:key) or
the `did.json` you serve (did:web).

## File layout

```
~/.freeq/bots/<name>/
├── key.ed25519        # 32-byte seed (mode 0600)
├── did-document.json  # DID document (did:web only)
└── delegation.json    # FreeqBotDelegation/v1 cert (when --creator-did given)

<config dir>/freeq-bot-id/<handle>.device-key.json   # the owner's device key (register)
```

## Scope

Compatibility with `@freeq/bot-kit`'s file layout is intentional. TS bots created via `FreeqBot.create({name: 'X'})` write files at `~/.freeq/bots/X/agent.key` and `~/.freeq/bots/X/delegation.json`; the seed format and cert schema are interchangeable with what this CLI produces. A bot can be moved from Rust to TS (or vice versa) without re-minting its DID.

## See also

- [`@freeq/bot-kit`](../freeq-bot-kit-js/) — TS bot framework that subsumes this utility for TS workflows
- [`freeq-sdk`](../freeq-sdk/) — Rust SDK whose `auth::KeySigner` consumes the seed file this writes
- [`docs/agents.md`](../docs/agents.md) — full agent-protocol reference, including identity + provenance details
