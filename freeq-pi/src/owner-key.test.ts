import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";

import {
  authorizeOwner,
  creatorKeyPath,
  creatorPublicKeyB64,
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
    // The seed can sign anything the owner is; it must not be readable by
    // anyone else on the machine.
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("derives a base64url raw public key, which is what MSGSIG takes", () => {
    const seed = new Uint8Array(32).fill(7);
    const pk = creatorPublicKeyB64(seed);
    // 32 bytes → 43 base64url chars, unpadded, no +/=.
    expect(pk).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(creatorPublicKeyB64(seed)).toBe(pk); // deterministic
  });

  it("keeps DIDs from colliding on disk", () => {
    expect(creatorKeyPath("/r", "did:plc:a")).not.toBe(creatorKeyPath("/r", "did:plc:b"));
    expect(creatorKeyPath("/r", "did:plc:a")).not.toContain(":");
  });
});

/** A freeq client that answers MSGSIG the way the server does. */
class FakeClient extends EventEmitter {
  sent: string[] = [];
  opts: Record<string, unknown>;
  constructor(opts: Record<string, unknown>) {
    super();
    this.opts = opts;
  }
  connect() {
    queueMicrotask(() => this.emit("registered", "owner-authorize"));
  }
  raw(line: string) {
    this.sent.push(line);
    if (line.startsWith("MSGSIG ")) {
      queueMicrotask(() => this.emit("systemMessage", "server", "MSGSIG OK"));
    }
  }
  quit() {}
}

describe("authorizeOwner", () => {
  it("proves ownership once and registers the key under the owner's DID", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    let made: FakeClient | undefined;
    const sessions: Array<[string, string, string]> = [];

    const result = await authorizeOwner({
      identifier: "alice.test",
      appPassword: "app-pass-used-once",
      server: "wss://test/irc",
      root,
      resolve: async () => ({ did: "did:plc:alice", pdsUrl: "https://pds.test" }),
      createSession: async (pds, id, pw) => {
        sessions.push([pds, id, pw]);
        return "access-jwt";
      },
      clientFactory: (o) => {
        made = new FakeClient(o as Record<string, unknown>);
        return made as unknown as ReturnType<NonNullable<typeof made>["constructor"]> as never;
      },
    });

    // One PDS exchange, with the password, and never again.
    expect(sessions).toEqual([["https://pds.test", "alice.test", "app-pass-used-once"]]);

    // The freeq session is the OWNER's, via pds-session, not the agent's.
    const sasl = made!.opts.sasl as { did: string; method: string; token: string };
    expect(sasl).toMatchObject({ did: "did:plc:alice", method: "pds-session", token: "access-jwt" });
    // The SDK's throwaway per-session key is suppressed: only ours goes on file.
    expect(made!.opts.autoMsgSig).toBe(false);

    // Exactly one MSGSIG, and it is the persisted seed's public key.
    const seed = await readFile(result.creatorKeyPath);
    const msgsig = made!.sent.filter((l) => l.startsWith("MSGSIG "));
    expect(msgsig).toEqual([`MSGSIG ${creatorPublicKeyB64(new Uint8Array(seed))}`]);

    expect(result.ownerDid).toBe("did:plc:alice");
    expect(result.publicKey).toBe(creatorPublicKeyB64(new Uint8Array(seed)));
  });

  it("does not persist the app password anywhere", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    await authorizeOwner({
      identifier: "alice.test",
      appPassword: "hunter2-secret",
      server: "wss://test/irc",
      root,
      resolve: async () => ({ did: "did:plc:alice", pdsUrl: "https://pds.test" }),
      createSession: async () => "jwt",
      clientFactory: (o) => new FakeClient(o as Record<string, unknown>) as never,
    });
    const { execSync } = await import("node:child_process");
    const grep = execSync(`grep -rl "hunter2-secret" "${root}" || true`).toString().trim();
    expect(grep).toBe("");
  });

  it("surfaces a rejected app password in words", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-owner-"));
    await expect(
      authorizeOwner({
        identifier: "alice.test",
        appPassword: "wrong",
        server: "wss://test/irc",
        root,
        resolve: async () => ({ did: "did:plc:alice", pdsUrl: "https://pds.test" }),
        createSession: async () => {
          throw new Error("The PDS rejected that app password.");
        },
      }),
    ).rejects.toThrow(/rejected that app password/);
  });
});
