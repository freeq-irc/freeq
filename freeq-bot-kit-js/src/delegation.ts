// FreeqBotDelegation/v1 cert. The server (connection/provenance.rs) proves
// it one of two ways.
//
// Unsigned (no `creatorKeyPath`, signature: null): the owner's agent record
// proves it. The owner adds the bot's DID in the freeq web app under
// Settings → Agents, or with `freeq-bot-id register --owner <handle>
// <bot-did>`, which publishes an at.freeq.agentKey record on their account.
// On each PROVENANCE the server first answers "Provenance stored
// (unverified): …", reads the owner's records, and if a live record names
// the bot, marks the cert verified and sends "Provenance verified: …". A bot
// whose record is added later is verified when it next connects, so it is
// restarted after adding it. No key of the owner's is kept with the bot.
//
// Signed (deprecated; signed certificates will stop counting in a later release,
// and the signing is removed then): with the creator's ed25519 key
// (`creatorKeyPath`, a 32-byte seed file — the same format
// `freeq-bot-id --creator-key` reads) the cert is JCS-canonicalized
// (RFC 8785) with the `signature` field omitted and ed25519-signed, exactly
// mirroring freeq-bot-id/src/main.rs. The server verifies it against the
// creator's registered MSGSIG public keys, so the creator must have
// registered that key's public half via MSGSIG.

import { importDidKey } from "@freeq/sdk";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface DelegationCert {
  /** Always "FreeqBotDelegation/v1". Server's verifier dispatches on this. */
  type: "FreeqBotDelegation/v1";
  /** Bot's DID — must match the SASL-authenticated session DID, server checks. */
  bot_did: string;
  /** Multibase ed25519 pubkey of the bot (the part after "did:key:"). */
  bot_public_key: string;
  /** Owner's DID, typically did:plc:… */
  creator_did: string;
  /** ISO-8601 timestamp the cert was minted. */
  created_at: string;
  /** Who can revoke this binding. Same as creator_did in v1.0. */
  revocation_authority: string;
  /**
   * Base64url ed25519 signature over the JCS-canonical form of the cert with
   * this field omitted. Signed by the creator's key when one is provided
   * (see `signDelegation` / `creatorKeyPath`); null otherwise, in which
   * case the server proves the cert from the owner's agent record.
   */
  signature: string | null;
}

/**
 * RFC 8785 (JCS) canonicalization, restricted to the value shapes a
 * delegation cert can contain: objects, arrays, strings, booleans, null,
 * and safe integers. Must produce byte-identical output to
 * `freeq_sdk::canonical::canonicalize` on the Rust side — key order sorted
 * by UTF-16 code units, no whitespace, JSON string escaping.
 */
export function canonicalizeForSigning(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new Error(`canonicalizeForSigning: non-integer number ${value} unsupported`);
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map(canonicalizeForSigning).join(",")}]`;
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      const body = keys
        .map((k) => `${JSON.stringify(k)}:${canonicalizeForSigning(obj[k])}`)
        .join(",");
      return `{${body}}`;
    }
    default:
      throw new Error(`canonicalizeForSigning: unsupported type ${typeof value}`);
  }
}

/**
 * Sign a cert with the creator's ed25519 seed (32 bytes — the same file
 * format `freeq-bot-id --creator-key` reads). Returns a NEW cert with the
 * signature attached. The creator must have registered this key's public
 * half with the server via MSGSIG for verification to succeed.
 */
export async function signDelegation(
  cert: DelegationCert,
  creatorSeed: Uint8Array,
): Promise<DelegationCert> {
  // Canonical form: the cert WITHOUT the signature field, matching both
  // freeq-bot-id sign-time behavior and the server's verify-time removal.
  const { signature: _omit, ...unsigned } = cert;
  const canonical = canonicalizeForSigning(unsigned);
  const key = await importDidKey(creatorSeed);
  const signature = await key.signer(new TextEncoder().encode(canonical));
  return { ...cert, signature };
}

export interface BuildDelegationOptions {
  /** Bot's did:key — must start with "did:key:". */
  agentDid: string;
  /** Owner's DID, typically did:plc:… */
  ownerDid: string;
}

/** Build a fresh cert. Does NOT persist. */
export function buildDelegation(opts: BuildDelegationOptions): DelegationCert {
  const { agentDid, ownerDid } = opts;
  const bot_public_key = agentDid.replace(/^did:key:/, "");
  if (bot_public_key === agentDid) {
    throw new Error(
      `agentDid does not start with did:key: — got ${agentDid}. v1.0 only supports did:key bots.`,
    );
  }
  return {
    type: "FreeqBotDelegation/v1",
    bot_did: agentDid,
    bot_public_key,
    creator_did: ownerDid,
    created_at: new Date().toISOString(),
    revocation_authority: ownerDid,
    signature: null,
  };
}

export interface LoadDelegationOptions {
  /** Absolute path to the cert file. */
  certPath: string;
}

export async function loadDelegation(
  opts: LoadDelegationOptions,
): Promise<DelegationCert | null> {
  const { certPath } = opts;
  let raw: string;
  try {
    raw = await readFile(certPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  let parsed: DelegationCert;
  try {
    parsed = JSON.parse(raw) as DelegationCert;
  } catch {
    throw new Error(
      `${certPath} is not valid JSON. Delete it to regenerate, or fix the file.`,
    );
  }
  if (parsed.type !== "FreeqBotDelegation/v1") {
    throw new Error(
      `${certPath} has type ${parsed.type}; expected FreeqBotDelegation/v1.`,
    );
  }
  return parsed;
}

export interface LoadOrMintDelegationOptions {
  /** Absolute path to the cert file. The parent directory is created if needed. */
  certPath: string;
  agentDid: string;
  ownerDid: string;
  /**
   * Path to the creator's ed25519 seed (32 bytes, mode 0600 — the file
   * `freeq-bot-id --creator-key` reads). When set, freshly minted certs are
   * signed, and an existing UNSIGNED cert is upgraded in place (signed and
   * rewritten). The creator must have registered this key via MSGSIG.
   * Deprecated; to be removed in a later release.
   */
  creatorKeyPath?: string;
}

async function readCreatorSeed(path: string): Promise<Uint8Array> {
  const buf = await readFile(path);
  if (buf.length !== 32) {
    throw new Error(
      `${path} is ${buf.length} bytes, expected 32 (ed25519 seed for delegation signing).`,
    );
  }
  return new Uint8Array(buf);
}

/** Mint a new cert if none exists, otherwise return the existing one
 *  (upgrading it to signed when a creator key is provided). */
export async function loadOrMintDelegation(
  opts: LoadOrMintDelegationOptions,
): Promise<DelegationCert> {
  const { certPath, agentDid, ownerDid, creatorKeyPath } = opts;
  const existing = await loadDelegation({ certPath });
  if (existing) {
    // Sanity: an existing cert must match the current agent + owner identity.
    // Mismatch usually means the user changed handle or regenerated the seed.
    if (existing.bot_did !== agentDid) {
      throw new Error(
        `Stored delegation bot_did (${existing.bot_did}) does not match current agent (${agentDid}). Delete ${certPath} to regenerate.`,
      );
    }
    if (existing.creator_did !== ownerDid) {
      throw new Error(
        `Stored delegation creator_did (${existing.creator_did}) does not match current owner (${ownerDid}). Delete ${certPath} to regenerate.`,
      );
    }
    if (!existing.signature && creatorKeyPath) {
      const signed = await signDelegation(existing, await readCreatorSeed(creatorKeyPath));
      await writeFile(certPath, JSON.stringify(signed, null, 2) + "\n", { mode: 0o600 });
      return signed;
    }
    return existing;
  }

  let cert = buildDelegation({ agentDid, ownerDid });
  if (creatorKeyPath) {
    cert = await signDelegation(cert, await readCreatorSeed(creatorKeyPath));
  }
  await mkdir(dirname(certPath), { recursive: true, mode: 0o700 });
  await writeFile(certPath, JSON.stringify(cert, null, 2) + "\n", { mode: 0o600 });
  return cert;
}
