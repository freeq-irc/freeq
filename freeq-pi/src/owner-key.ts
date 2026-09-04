/**
 * The owner's signing key — what makes "this agent acts for me" provable.
 *
 * A delegation certificate names an owner, but until the owner's key signs
 * it, that is a string the agent chose. The server stores such a cert as
 * `_verified: false, "Cert has no signature; declarative only"`, and every
 * downstream feature that trusts delegation (channel access for an owner's
 * agent, provenance badges, handoff authority) correctly refuses it.
 *
 * This module gives the owner a persistent ed25519 key on this machine.
 * bot-kit signs the installation's certificate with it (`creatorKeyPath`),
 * and the server verifies that signature against a key registered under the
 * owner's DID.
 *
 * REGISTERING THE KEY — WHY THERE IS NO PASSWORD PROMPT. Putting a key on
 * file under your DID takes exactly one `MSGSIG <pubkey>` on a session that is
 * already authenticated as you. You have one of those open whenever the web
 * client is logged in, and it has a `/raw` command. So the ceremony is:
 *
 *     pi prints:   /raw MSGSIG <your-public-key>
 *     you paste it into the web client, in any channel
 *     pi reconnects, presents the signed cert, and the server says verified
 *
 * Nothing secret moves. The line you paste is a public key. pi never sees a
 * password, never talks to your PDS, and never holds anything that could act
 * as you — only the creator seed, which signs certificates and nothing else.
 *
 * The earlier design asked for an AT Protocol app password to do this
 * through `pds-session` SASL. That was a second credential to protect for a
 * one-time job, and it is gone.
 */

import { mkdir, readFile, writeFile, chmod, access } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createPrivateKey, randomBytes } from "node:crypto";

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
 * Step one of the ceremony: make sure the key exists, and say what to paste
 * where. Pure and local — no network.
 */
export async function authorizeInstructions(opts: {
  ownerDid: string;
  root: string;
}): Promise<AuthorizeInstructions> {
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
      `2. Back here, run:  /freeq authorize verify`,
      `   pi will reconnect with a signed delegation and confirm the server accepted it.`,
    ],
  };
}

/**
 * Has the server got a key on file for this owner that verifies our cert?
 * Answered by the server itself: after reconnecting, the PROVENANCE reply is
 * either "Provenance verified" or says why not. Callers pass in whatever
 * the connection layer observed.
 */
export function interpretProvenanceNotice(notice: string | undefined): {
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
  if (/Provenance verified/i.test(notice)) {
    return { verified: true, message: "Delegation verified — this installation provably acts for you." };
  }
  if (/No registered MSGSIG key/i.test(notice)) {
    return {
      verified: false,
      message:
        "The server has no signing key on file for your DID yet. Paste the /raw MSGSIG line into a client logged in as you, then run /freeq authorize verify again.",
    };
  }
  if (/did not verify against/i.test(notice)) {
    return {
      verified: false,
      message:
        "A key is on file for your DID, but not this one. Paste the /raw MSGSIG line from /freeq authorize (it must be this machine's key), then verify again.",
    };
  }
  if (/no signature/i.test(notice)) {
    return {
      verified: false,
      message:
        "The cert went out unsigned — the creator key was not found at connect time. Run /freeq authorize to create it, then verify again.",
    };
  }
  return { verified: false, message: `Server said: ${notice}` };
}
