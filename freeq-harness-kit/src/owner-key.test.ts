import { describe, it, expect } from "vitest";
import { access, mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  agentInstructions,
  authorizeInstructions,
  creatorKeyPath,
  creatorPublicKeyB64,
  interpretProvenanceNotice,
  loadOrCreateCreatorSeed,
  signedCertificateLine,
  waitForProvenance,
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

describe("authorize", () => {
  const BOT = "did:key:z6MkwVDfCg9LbbY6xjH3EZk8YSFQZujV5Y4y1ZWeER9tDiN3";

  it("prints this installation's DID and where to add it, and no line to paste", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const ins = await agentInstructions({ ownerDid: "did:plc:alice", botDid: BOT, root });
    const shown = ins.steps.join("\n");

    expect(shown).toContain(BOT);
    expect(shown).toContain("Settings → Agents");
    expect(shown).toContain(`freeq-bot-id register --owner <your handle> ${BOT}`);
    expect(shown).toContain("/freeq authorize verify");
    expect(shown).not.toMatch(/MSGSIG|\/raw|paste/i);
    expect(shown.toLowerCase()).not.toMatch(/password/);
  });

  it("no longer points at --sign-cert", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const ins = await agentInstructions({ ownerDid: "did:plc:alice", botDid: BOT, root });
    expect(ins.steps.join("\n")).not.toMatch(/sign-cert|doesn't read agent records/);
    expect(ins.steps.at(-1)).toBe("Then run:  /freeq authorize verify");
  });

  it("makes no creator key", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    await agentInstructions({ ownerDid: "did:plc:alice", botDid: BOT, root });
    await expect(access(creatorKeyPath(root, "did:plc:alice"))).rejects.toThrow();
  });

  it("prints the deprecation line when told the certificate is signed", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const keyPath = creatorKeyPath(root, "did:plc:alice");
    const stateDir = join(root, "bots", "pi-x");
    const certPath = join(stateDir, "delegation.json");

    // A creator key alone, with an unsigned certificate, says nothing more.
    await loadOrCreateCreatorSeed(keyPath);
    const unsigned = await agentInstructions({ ownerDid: "did:plc:alice", botDid: BOT, root, signature: null, stateDir });
    expect(unsigned.steps.at(-1)).toBe("Then run:  /freeq authorize verify");

    const signed = await agentInstructions({ ownerDid: "did:plc:alice", botDid: BOT, root, signature: "sig", stateDir });
    expect(signed.steps.at(-1)).toBe(signedCertificateLine({ botDid: BOT, certPath, keyPath }));
    expect(signed.steps.at(-1)).toBe(
      "This bot's certificate is signed with a creator key. Signed certificates will stop counting in a later release; " +
        "every server now reads agent records instead. Add this agent under Settings → Agents in the freeq web app, " +
        `or with \`freeq-bot-id register --owner <handle> ${BOT}\`, then delete the creator key at ${keyPath} if it exists, ` +
        `and the certificate at ${certPath}, so an unsigned certificate is made at the next start.`,
    );
    expect(signed.steps.join("\n")).not.toMatch(/MSGSIG|\/raw/);

    // A copied certificate, with no creator key on this machine.
    const other = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const copied = await agentInstructions({ ownerDid: "did:plc:alice", botDid: BOT, root: other, signature: "sig", stateDir });
    expect(copied.steps.at(-1)).toBe(signedCertificateLine({ botDid: BOT, certPath }));
    expect(copied.steps.at(-1)).toContain(`then delete the certificate at ${certPath}, so`);
  });

  it("names the signed certificate on the bot's machine when given no path", () => {
    expect(signedCertificateLine({ botDid: BOT, keyPath: "/k" })).toContain(
      "then delete the creator key at /k if it exists, and the signed certificate on the bot's machine, so",
    );
  });
});

describe("authorize --sign-cert, deprecated", () => {
  it("makes the creator key and prints the line to paste, a public key and nothing else", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    const ins = await authorizeInstructions({ ownerDid: "did:plc:alice", root });

    const seed = new Uint8Array(await readFile(ins.creatorKeyPath));
    const pub = creatorPublicKeyB64(seed);
    expect(ins.publicKey).toBe(pub);
    expect(ins.pasteLine).toBe(`/raw MSGSIG ${pub}`);

    const shown = ins.steps.join("\n");
    expect(shown).toContain(ins.pasteLine);
    expect(shown).toContain("/freeq authorize verify");
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
  it("recognises success, by a signed certificate or by the owner's record", () => {
    expect(
      interpretProvenanceNotice("Provenance verified: Verified against creator key for did:plc:alice").verified,
    ).toBe(true);
    expect(
      interpretProvenanceNotice(
        "Provenance verified: Owner's agent record at://did:plc:alice/at.freeq.agentKey/3k names this bot",
      ).verified,
    ).toBe(true);
  });

  it("reads an unsigned certificate as waiting for the owner's record, and never asks to paste", () => {
    for (const notice of [
      "Provenance stored (unverified): Cert has no signature; declarative only",
      "Provenance stored (unverified): No registered MSGSIG key for did:plc:alice; creator must register one before signing",
      "Provenance stored (unverified): Signature did not verify against any of the creator's 2 registered key(s)",
    ]) {
      const v = interpretProvenanceNotice(notice);
      expect(v.verified).toBe(false);
      expect(v.message).toMatch(/Settings → Agents/);
      expect(v.message).toMatch(/freeq-bot-id register/);
      expect(v.message).not.toContain("sign-cert");
      expect(v.message).not.toMatch(/MSGSIG|\/raw|paste/i);
    }
  });

  it("never claims success on silence", () => {
    expect(interpretProvenanceNotice(undefined).verified).toBe(false);
  });
});

describe("waiting for the verdict", () => {
  it("waits past the unverified notice for the verified one that follows", async () => {
    const seen = [
      undefined,
      "Provenance stored (unverified): Cert has no signature; declarative only",
      "Provenance stored (unverified): Cert has no signature; declarative only",
      "Provenance verified: Owner's agent record at://did:plc:alice/at.freeq.agentKey/3k names this bot",
    ];
    let i = 0;
    const notice = await waitForProvenance(() => seen[Math.min(i++, seen.length - 1)], {
      timeoutMs: 1_000,
      pollMs: 1,
    });
    expect(notice).toMatch(/^Provenance verified/);
  });

  it("returns the last notice when nothing verifies in time", async () => {
    const unverified = "Provenance stored (unverified): Cert has no signature; declarative only";
    const notice = await waitForProvenance(() => unverified, { timeoutMs: 30, pollMs: 5 });
    expect(notice).toBe(unverified);
  });

  it("stops at a rejection", async () => {
    const rejected = "Provenance rejected: Cert bot_did (x) does not match the authenticated session DID (y)";
    const started = Date.now();
    expect(await waitForProvenance(() => rejected, { timeoutMs: 5_000, pollMs: 5 })).toBe(rejected);
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});
