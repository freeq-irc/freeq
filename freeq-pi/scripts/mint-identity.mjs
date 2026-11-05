#!/usr/bin/env node
/**
 * Mint this installation's freeq identity WITHOUT connecting.
 *
 * `FreeqBot.create()` normally does this on first connect, which is fine on a
 * laptop. When provisioning a machine, mint first so the owner can claim the
 * DID before the agent connects: the owner adds it as one of their agents,
 * in the freeq web app's Settings → Agents or with
 * `freeq-bot-id register --owner <handle> <did>`, and the server proves the
 * unsigned certificate from that record. Nothing of the owner's comes here.
 *
 * Deprecated; to be removed in a later release: let the owner sign the cert
 * elsewhere (`sign-delegation.mjs`) and drop the signed cert back in place
 * before connecting.
 *
 * Run it ON the machine being provisioned, from the freeq-pi package dir:
 *
 *     node scripts/mint-identity.mjs --owner did:plc:… --project freeq
 *
 * Idempotent: an existing key is loaded, not replaced, and an existing SIGNED
 * cert is left alone (`signed` says so; signed certificates will stop counting
 * in a later release, and boxd-migrate.sh says what to delete). Prints JSON on
 * stdout:
 *
 *     {"botName","did","seedPath","certPath","signed":false}
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const { loadOrCreateIdentity, loadOrMintDelegation } = await import("@freeq/bot-kit");
const { deriveInstallSlug, resolveBotName } = await import("@freeq/harness-kit/identity");

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

const ownerDid = arg("owner");
if (!ownerDid || !/^did:[a-z0-9]+:.+/.test(ownerDid)) {
  console.error("usage: mint-identity.mjs --owner did:plc:… [--project NAME] [--root DIR]");
  process.exit(2);
}
// The project is the git root's basename — the same input `collectSessionMeta`
// gives the connection, so the name minted here is the name it connects under.
const project = arg("project") || undefined;
const root = arg("root") || join(homedir(), ".freeq", "bots");
const slug = arg("install") || deriveInstallSlug();

const botName = resolveBotName(slug, project, (n) => existsSync(join(root, n)));
const dir = join(root, botName);
const seedPath = join(dir, "agent.key");
const certPath = join(dir, "delegation.json");

const identity = await loadOrCreateIdentity({ seedPath });
// No creatorKeyPath: the seed that signs this stays on the owner's machine.
const cert = await loadOrMintDelegation({ certPath, agentDid: identity.did, ownerDid });

console.log(
  JSON.stringify({
    botName,
    install: slug,
    did: identity.did,
    fresh: identity.isFresh,
    seedPath,
    certPath,
    signed: Boolean(cert.signature),
  }),
);
