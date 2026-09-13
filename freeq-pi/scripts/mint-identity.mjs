#!/usr/bin/env node
/**
 * Mint this installation's freeq identity WITHOUT connecting.
 *
 * `FreeqBot.create()` normally does this on first connect, which is fine on a
 * laptop but wrong when provisioning a machine: the cert has to be signed by
 * the owner's creator key, that key must never leave the owner's machine, and
 * the agent must not connect with an unsigned cert first (an unsigned cert
 * grants nothing — no +i channel, no provenance badge).
 *
 * So: mint here, print the did:key, let the owner sign the cert elsewhere
 * (`sign-delegation.mjs`), drop the signed cert back in place, then connect.
 *
 * Run it ON the machine being provisioned, from the freeq-pi package dir:
 *
 *     node scripts/mint-identity.mjs --owner did:plc:… --project freeq
 *
 * Idempotent: an existing key is loaded, not replaced, and an existing SIGNED
 * cert is left alone. Prints JSON on stdout:
 *
 *     {"botName","did","seedPath","certPath","signed":false}
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const { loadOrCreateIdentity, loadOrMintDelegation } = await import("@freeq/bot-kit");
const { deriveInstallSlug, resolveBotName } = await import("../dist/identity.js");

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
