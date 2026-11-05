/**
 * Proving that this installation acts for its owner.
 *
 * A delegation certificate names an owner, but on its own that is a string
 * the agent chose. The server proves it by reading the owner's account for
 * an `at.freeq.agentKey` record naming this installation's DID; the owner
 * writes that record from their own device, in the web app's Settings →
 * Agents or with `freeq-bot-id register`. Nothing of the owner's is kept on
 * this machine. Until the record exists the server stores the certificate
 * as unverified, and every feature that trusts delegation refuses it.
 *
 * THE DEPRECATED WAY. An installation can instead sign its certificate
 * with a creator key kept here (`creatorKeyPath`), whose public half the
 * owner registers with the server by sending `MSGSIG <pubkey>` from a
 * session signed in as them. Every server in use now reads agent records,
 * and signed certificates will stop counting in a later release, when this way is
 * removed. Until then an installation that has such a key keeps signing
 * with it and is warned once per process (`signedCertificateLine`); the key
 * functions below stay for that, and for the helper scripts.
 */

import { mkdir, readFile, writeFile, chmod, access } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createPrivateKey, randomBytes } from "node:crypto";
import { PI_NAMES, type HarnessNames } from "./names.js";

/** Where the owner's creator seed lives, per owner DID. Mode 0600. */
export function creatorKeyPath(root: string, ownerDid: string): string {
  // DIDs contain ':' which is awkward in paths on some filesystems.
  const safe = ownerDid.replace(/[^a-zA-Z0-9]+/g, "_");
  return join(root, "owner", safe, "creator.key");
}

/** Load the seed if present, else mint and persist one. Returns the seed. */
export async function loadOrCreateCreatorSeed(path: string): Promise<Uint8Array> {
  try {
    await access(path);
    const buf = await readFile(path);
    if (buf.length !== 32) {
      throw new Error(`${path} is ${buf.length} bytes, expected a 32-byte ed25519 seed`);
    }
    return new Uint8Array(buf);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  const seed = new Uint8Array(randomBytes(32));
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, seed, { mode: 0o600 });
  await chmod(path, 0o600);
  return seed;
}

/** The public key in the form `MSGSIG` takes: base64url of the raw 32 bytes. */
export function creatorPublicKeyB64(seed: Uint8Array): string {
  // PKCS#8 wrapper for an Ed25519 seed (RFC 8410). Node derives the public
  // half; asking for JWK gives it back as raw base64url — exactly what
  // MSGSIG wants — with no multibase decoding in between.
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seed),
  ]);
  const jwk = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }).export({
    format: "jwk",
  }) as { x?: string };
  if (!jwk.x) throw new Error("could not derive the Ed25519 public key from the seed");
  return jwk.x;
}

export interface AuthorizeInstructions {
  ownerDid: string;
  creatorKeyPath: string;
  publicKey: string;
  /** The one line to paste into an authenticated client. Public material only. */
  pasteLine: string;
  /** What to tell the user. */
  steps: string[];
}

/**
 * `/freeq authorize --sign-cert`, deprecated: make sure the creator key
 * exists, and say what to paste where. Pure and local — no network. To be
 * removed in a later release, when signed certificates stop counting.
 */
export async function authorizeInstructions(opts: {
  ownerDid: string;
  root: string;
  names?: HarnessNames;
}): Promise<AuthorizeInstructions> {
  const names = opts.names ?? PI_NAMES;
  const keyPath = creatorKeyPath(opts.root, opts.ownerDid);
  const seed = await loadOrCreateCreatorSeed(keyPath);
  const publicKey = creatorPublicKeyB64(seed);
  const pasteLine = `/raw MSGSIG ${publicKey}`;
  return {
    ownerDid: opts.ownerDid,
    creatorKeyPath: keyPath,
    publicKey,
    pasteLine,
    steps: [
      `1. In the freeq web client (or any client logged in as ${opts.ownerDid}), paste this into the message box:`,
      `      ${pasteLine}`,
      `   It is a public key. Nothing secret is being sent.`,
      `2. Back here, run:  ${names.hint("authorize verify")}`,
      `   ${names.name} will reconnect with a signed delegation and confirm the server accepted it.`,
    ],
  };
}

/** Whether this process has warned about a signed certificate yet. Once per
 *  process, like the SDK's deprecation warnings: a reconnect builds a new
 *  connection, so a per-connection set would warn again. */
let signedCertificateWarned = false;

/** True the first time it is called in this process, false after. Both the
 *  connection's warning and `/freeq authorize --sign-cert`'s call it. */
export function firstSignedCertificateWarning(): boolean {
  if (signedCertificateWarned) return false;
  signedCertificateWarned = true;
  return true;
}

/**
 * What to say when this installation's certificate is signed with a creator
 * key: that signed certificates will stop counting in a later release, how to add
 * the agent record instead, and what to delete so an unsigned certificate is
 * made at the next start. Without `certPath` (the signer, which may be
 * signing a copy) it names the signed certificate on the bot's machine.
 * bot-kit says the same sentence in its own copy; it cannot import this.
 */
export function signedCertificateLine(opts: { botDid: string; certPath?: string; keyPath?: string }): string {
  const certificate = opts.certPath
    ? `the certificate at ${opts.certPath}`
    : "the signed certificate on the bot's machine";
  const toDelete = opts.keyPath
    ? `the creator key at ${opts.keyPath} if it exists, and ${certificate}`
    : certificate;
  return (
    "This bot's certificate is signed with a creator key. Signed certificates will stop counting in a later release; " +
    "every server now reads agent records instead. Add this agent under Settings → Agents in the freeq web app, " +
    `or with \`freeq-bot-id register --owner <handle> ${opts.botDid}\`, then delete ${toDelete}, ` +
    "so an unsigned certificate is made at the next start."
  );
}

export interface AgentInstructions {
  ownerDid: string;
  botDid: string;
  /** What to tell the user. */
  steps: string[];
}

/**
 * What `/freeq authorize` says: this installation's DID and the two places
 * the owner can add it as one of their agents, and, when its certificate is
 * signed (`signature`), the deprecation line naming what to delete. Local
 * only: nothing is made or sent.
 */
export async function agentInstructions(opts: {
  ownerDid: string;
  botDid: string;
  root: string;
  /** The loaded certificate's signature; set means it is signed. */
  signature?: string | null;
  /** Where bot-kit keeps this installation's state, holding delegation.json. */
  stateDir?: string;
  names?: HarnessNames;
}): Promise<AgentInstructions> {
  const names = opts.names ?? PI_NAMES;
  const steps = [
    `This installation's DID: ${opts.botDid}`,
    "",
    `To prove it acts for you, add it as one of your agents, signed in as ${opts.ownerDid}:`,
    "  - in the freeq web app: Settings → Agents → + Add an agent, with the DID above; or",
    `  - from a terminal: freeq-bot-id register --owner <your handle> ${opts.botDid}`,
    "",
    `Then run:  ${names.hint("authorize verify")}`,
  ];
  if (opts.signature) {
    let keyPath: string | undefined = creatorKeyPath(opts.root, opts.ownerDid);
    try {
      await access(keyPath);
    } catch {
      // No creator key here (a copied certificate): only the file to delete.
      keyPath = undefined;
    }
    steps.push(
      "",
      signedCertificateLine({
        botDid: opts.botDid,
        certPath: opts.stateDir ? join(opts.stateDir, "delegation.json") : undefined,
        keyPath,
      }),
    );
  }
  return { ownerDid: opts.ownerDid, botDid: opts.botDid, steps };
}

/** What an unverified certificate means now: the owner's record is not there yet. */
function waitingForRecord(names: HarnessNames): string {
  return (
    `Not verified yet: the server found no agent record naming this installation. Add its DID (shown by ${names.hint("authorize")}) in the freeq web app under Settings → Agents, or with freeq-bot-id register, then run ${names.hint("authorize verify")} again.`
  );
}

/**
 * Read the server's verdict on this installation's certificate. After
 * reconnecting, the PROVENANCE reply is "Provenance verified: …",
 * "Provenance stored (unverified): …", or a rejection. An unverified reply
 * comes first; a verified one can follow once the server has read the
 * owner's records.
 */
export function interpretProvenanceNotice(
  notice: string | undefined,
  names: HarnessNames = PI_NAMES,
): {
  verified: boolean;
  message: string;
} {
  if (!notice) {
    return {
      verified: false,
      message:
        "No provenance reply seen yet. Reconnect and try again; if it persists, the cert may not have been re-sent.",
    };
  }
  if (/^Provenance verified/i.test(notice)) {
    return { verified: true, message: "Delegation verified — this installation provably acts for you." };
  }
  if (/^Provenance stored \(unverified\)/i.test(notice)) {
    return { verified: false, message: waitingForRecord(names) };
  }
  return { verified: false, message: `Server said: ${notice}` };
}

/**
 * Wait for the server's verdict: poll `read` (the latest PROVENANCE reply)
 * until it says verified or rejected, or `timeoutMs` passes, and return the
 * last reply seen. The unverified reply comes first and a verified one may
 * follow, so it is not an answer on its own.
 */
export async function waitForProvenance(
  read: () => string | undefined,
  opts: { timeoutMs: number; pollMs: number },
): Promise<string | undefined> {
  const deadline = Date.now() + opts.timeoutMs;
  let notice = read();
  while (Date.now() < deadline) {
    if (notice && /^Provenance (verified|rejected)/i.test(notice)) return notice;
    await new Promise((r) => setTimeout(r, opts.pollMs));
    notice = read();
  }
  return notice;
}
