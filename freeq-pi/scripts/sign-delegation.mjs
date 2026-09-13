#!/usr/bin/env node
/**
 * Sign a delegation cert with the OWNER's creator key — on the owner's
 * machine, never on the machine being provisioned.
 *
 * bot-kit will happily sign at connect time given `creatorKeyPath`, but that
 * means putting the owner's delegation-signing seed on whatever box the agent
 * runs on. A cloud VM does not need that key; it needs the *result*. This
 * script is the split: cert in, signed cert out, seed stays home.
 *
 *     node scripts/sign-delegation.mjs --cert ./delegation.json           \
 *          [--owner did:plc:…] [--key ~/.freeq/owner/<did>/creator.key]   \
 *          [--out ./delegation.signed.json]
 *
 * With no --key, the creator key for --owner (or the cert's creator_did) is
 * loaded from the standard location, and CREATED there if absent — in which
 * case the `MSGSIG` line that registers its public half is printed on stderr.
 * Until that line is pasted into a client authenticated as the owner, the
 * server stores the cert as unverified and grants it nothing.
 *
 * Prints the signed cert to --out (default: in place).
 */

import { readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";

const { signDelegation } = await import("@freeq/bot-kit");
const { creatorKeyPath, loadOrCreateCreatorSeed, creatorPublicKeyB64 } = await import(
  "../dist/owner-key.js"
);

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

const certFile = arg("cert");
if (!certFile) {
  console.error("usage: sign-delegation.mjs --cert FILE [--owner DID] [--key PATH] [--out FILE]");
  process.exit(2);
}
const cert = JSON.parse(await readFile(certFile, "utf8"));
if (cert.type !== "FreeqBotDelegation/v1") {
  console.error(`${certFile}: not a FreeqBotDelegation/v1 cert`);
  process.exit(1);
}
const ownerDid = arg("owner", cert.creator_did);
if (!ownerDid) {
  console.error("cert has no creator_did and --owner was not given");
  process.exit(1);
}
if (cert.creator_did !== ownerDid) {
  console.error(`cert creator_did is ${cert.creator_did}, refusing to sign as ${ownerDid}`);
  process.exit(1);
}

const keyPath = arg("key", creatorKeyPath(`${homedir()}/.freeq`, ownerDid));
const seed = await loadOrCreateCreatorSeed(keyPath);
const pub = creatorPublicKeyB64(seed);

const signed = await signDelegation(cert, seed);
await writeFile(arg("out", certFile), JSON.stringify(signed, null, 2) + "\n", { mode: 0o600 });

console.error(`signed ${cert.bot_did} for ${ownerDid}`);
console.error(`creator public key: ${pub}`);
console.error(
  `if the server has never seen it, paste this into a client logged in as ${ownerDid}:\n` +
    `    /raw MSGSIG ${pub}`,
);
console.log(JSON.stringify({ botDid: cert.bot_did, ownerDid, creatorPublicKey: pub }));
