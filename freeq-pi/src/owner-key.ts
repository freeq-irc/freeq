/**
 * The owner's signing key — what makes "this agent acts for me" provable.
 *
 * A delegation certificate names an owner, but until the owner's key signs
 * it, that is a string the agent chose. The server stores such a cert as
 * `_verified: false, "Cert has no signature; declarative only"`, and every
 * downstream feature that trusts delegation (channel access for an owner's
 * agent, provenance badges, handoff authority) correctly refuses it.
 *
 * This module gives the owner a persistent ed25519 key on this machine and
 * registers its public half under the owner's DID on the server. bot-kit then
 * signs the installation's certificate with it (`creatorKeyPath`), and the
 * server verifies that signature against the registered key.
 *
 * Registering the key requires proving you *are* the owner once. That is done
 * with an AT Protocol app password: `createSession` on the owner's PDS yields
 * an access token, the server checks it against the PDS via the `pds-session`
 * SASL method, and on that authenticated session a single `MSGSIG` puts the
 * key on file. The app password is used for that one exchange and never
 * stored — after this the extension holds only the creator seed, and the
 * seed only ever signs certificates.
 *
 * Why a persistent key rather than the web client's: the web client registers
 * a fresh MSGSIG key per browser session. A certificate is signed once and
 * presented for months. The server now verifies against every key an owner
 * has registered (not just the newest), so this would work either way — but a
 * key that exists for exactly this purpose is easier to reason about, easier
 * to revoke, and does not depend on a browser tab that happened to be open.
 */

import { mkdir, readFile, writeFile, chmod, access } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

import { createPrivateKey } from "node:crypto";

import { FreeqClient } from "@freeq/sdk";

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

export interface AuthorizeOptions {
  /** Owner handle (`alice.bsky.social`) or DID. */
  identifier: string;
  /** App password, used once and discarded. */
  appPassword: string;
  /** freeq server WebSocket URL. */
  server: string;
  /** Root of `~/.freeq`, for the seed path. */
  root: string;
  /** Optional: resolve a handle to its DID + PDS. Defaults to the public resolver. */
  resolve?: (identifier: string) => Promise<{ did: string; pdsUrl: string }>;
  /** Optional: override the PDS session exchange (tests). */
  createSession?: (pdsUrl: string, identifier: string, appPassword: string) => Promise<string>;
  /** Optional: override the freeq client factory (tests). */
  clientFactory?: (opts: ConstructorParameters<typeof FreeqClient>[0]) => FreeqClient;
  /** Report progress in words a human can act on. */
  onProgress?: (line: string) => void;
}

export interface AuthorizeResult {
  ownerDid: string;
  creatorKeyPath: string;
  publicKey: string;
}

/** Resolve a handle or DID to `{ did, pdsUrl }` via the public directory. */
async function defaultResolve(identifier: string): Promise<{ did: string; pdsUrl: string }> {
  let did = identifier;
  if (!identifier.startsWith("did:")) {
    const r = await fetch(
      `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(identifier)}`,
    );
    if (!r.ok) throw new Error(`Could not resolve handle ${identifier}: HTTP ${r.status}`);
    did = ((await r.json()) as { did: string }).did;
  }
  const docUrl = did.startsWith("did:plc:")
    ? `https://plc.directory/${did}`
    : `https://${did.replace(/^did:web:/, "")}/.well-known/did.json`;
  const doc = (await (await fetch(docUrl)).json()) as {
    service?: Array<{ id: string; serviceEndpoint: string }>;
  };
  const pds = doc.service?.find((s) => s.id.endsWith("#atproto_pds"))?.serviceEndpoint;
  if (!pds) throw new Error(`DID document for ${did} names no PDS`);
  return { did, pdsUrl: pds.replace(/\/$/, "") };
}

/** `com.atproto.server.createSession` → access JWT. */
async function defaultCreateSession(
  pdsUrl: string,
  identifier: string,
  appPassword: string,
): Promise<string> {
  const r = await fetch(`${pdsUrl}/xrpc/com.atproto.server.createSession`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier, password: appPassword }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(
      r.status === 401
        ? "The PDS rejected that app password."
        : `createSession failed: HTTP ${r.status} ${body.slice(0, 120)}`,
    );
  }
  const j = (await r.json()) as { accessJwt: string };
  return j.accessJwt;
}

/**
 * Prove ownership once, and put the creator key on file under the owner's
 * DID. After this, the installation's delegation can be signed and verified.
 */
export async function authorizeOwner(opts: AuthorizeOptions): Promise<AuthorizeResult> {
  const say = opts.onProgress ?? (() => {});
  const resolve = opts.resolve ?? defaultResolve;
  const createSession = opts.createSession ?? defaultCreateSession;

  say(`resolving ${opts.identifier}…`);
  const { did, pdsUrl } = await resolve(opts.identifier);

  const keyPath = creatorKeyPath(opts.root, did);
  const seed = await loadOrCreateCreatorSeed(keyPath);
  const publicKey = creatorPublicKeyB64(seed);

  say(`signing in to ${pdsUrl} as ${did}…`);
  const accessJwt = await createSession(pdsUrl, opts.identifier, opts.appPassword);

  say("registering the signing key with freeq…");
  const make =
    opts.clientFactory ?? ((o: ConstructorParameters<typeof FreeqClient>[0]) => new FreeqClient(o));
  const client = make({
    url: opts.server,
    nick: "owner-authorize",
    // We are registering our own key, so the SDK's auto-generated one would
    // only add noise under the owner's DID.
    autoMsgSig: false,
    skipInitialBrokerRefresh: true,
    sasl: { did, pdsUrl, method: "pds-session", token: accessJwt },
  } as ConstructorParameters<typeof FreeqClient>[0]);

  const registered = new Promise<void>((resolveP, rejectP) => {
    const timer = setTimeout(
      () => rejectP(new Error("timed out waiting for the server to accept the key")),
      15_000,
    );
    client.on("systemMessage", (_from: string, text: string) => {
      if (/MSGSIG OK/i.test(text)) {
        clearTimeout(timer);
        resolveP();
      } else if (/MSGSIG/i.test(text) && /fail|error|invalid/i.test(text)) {
        clearTimeout(timer);
        rejectP(new Error(text));
      }
    });
    client.on("authError", (err: string) => {
      clearTimeout(timer);
      rejectP(new Error(`freeq refused the owner session: ${err}`));
    });
    client.on("registered", () => {
      client.raw(`MSGSIG ${publicKey}`);
    });
  });

  client.connect();
  try {
    await registered;
  } finally {
    try {
      client.quit("owner key registered");
    } catch {
      /* already gone */
    }
  }

  say(`registered. ${did} can now sign delegations from this machine.`);
  return { ownerDid: did, creatorKeyPath: keyPath, publicKey };
}
