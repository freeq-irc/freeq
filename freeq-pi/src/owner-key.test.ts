import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  authorizeInstructions,
  creatorKeyPath,
  creatorPublicKeyB64,
  interpretProvenanceNotice,
  loadOrCreateCreatorSeed,
} from "./owner-key.js";

describe("the owner's creator key", () => {
  it("is minted once, mode 0600, and reused after", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const path = creatorKeyPath(root, "did:plc:alice");
    const a = await loadOrCreateCreatorSeed(path);
    const b = await loadOrCreateCreatorSeed(path);
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
    // The seed signs anything the owner is; nobody else on the box reads it.
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("derives a base64url raw public key, which is what MSGSIG takes", () => {
    const seed = new Uint8Array(32).fill(7);
    const pk = creatorPublicKeyB64(seed);
    expect(pk).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes, unpadded
    expect(creatorPublicKeyB64(seed)).toBe(pk); // deterministic
  });

  it("keeps DIDs from colliding on disk", () => {
    expect(creatorKeyPath("/r", "did:plc:a")).not.toBe(creatorKeyPath("/r", "did:plc:b"));
    expect(creatorKeyPath("/r", "did:plc:a")).not.toContain(":");
  });
});

describe("the ceremony", () => {
  it("is a public key to paste and nothing else - no password, no network", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const ins = await authorizeInstructions({ ownerDid: "did:plc:alice", root });

    const seed = new Uint8Array(await readFile(ins.creatorKeyPath));
    const pub = creatorPublicKeyB64(seed);
    expect(ins.publicKey).toBe(pub);
    expect(ins.pasteLine).toBe(`/raw MSGSIG ${pub}`);

    // What the user is shown must never contain the private half.
    const shown = ins.steps.join("\n");
    expect(shown).toContain(ins.pasteLine);
    expect(shown).not.toContain(Buffer.from(seed).toString("base64url"));
    expect(shown).not.toContain(Buffer.from(seed).toString("hex"));
    expect(shown.toLowerCase()).not.toMatch(/password/);
  });

  it("is idempotent: running it twice shows the same key", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const a = await authorizeInstructions({ ownerDid: "did:plc:alice", root });
    const b = await authorizeInstructions({ ownerDid: "did:plc:alice", root });
    expect(a.pasteLine).toBe(b.pasteLine);
  });
});

describe("reading the server's verdict", () => {
  it("recognises success", () => {
    const v = interpretProvenanceNotice("Provenance verified: Verified against creator key for did:plc:alice");
    expect(v.verified).toBe(true);
  });

  it("tells the user exactly which step is missing", () => {
    expect(
      interpretProvenanceNotice(
        "Provenance stored (unverified): No registered MSGSIG key for did:plc:alice; creator must register one before signing",
      ).message,
    ).toMatch(/Paste the \/raw MSGSIG line/);

    expect(
      interpretProvenanceNotice(
        "Provenance stored (unverified): Signature did not verify against any of the creator's 2 registered key(s)",
      ).message,
    ).toMatch(/not this one/);

    expect(
      interpretProvenanceNotice("Provenance stored (unverified): Cert has no signature; declarative only")
        .message,
    ).toMatch(/unsigned/);
  });

  it("never claims success on silence", () => {
    expect(interpretProvenanceNotice(undefined).verified).toBe(false);
  });
});
