/**
 * `defaultCreateClient` with bot-kit replaced by a recording fake: which
 * owner the certificate is minted for, when a self-owned cert is replaced,
 * and that guests are only ever explicit.
 */

import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { defaultCreateClient, type BotKitModule } from "./session.js";

function fakeKit(opts: { cert?: { creator_did: string; signature: string | null } | null } = {}) {
  const calls: { create?: Record<string, unknown>; seedPath?: string; certPath?: string } = {};
  const kit: BotKitModule = {
    async loadOrCreateIdentity({ seedPath }) {
      calls.seedPath = seedPath;
      return { did: "did:key:zagent" };
    },
    async loadDelegation({ certPath }) {
      calls.certPath = certPath;
      return opts.cert ?? null;
    },
    FreeqBot: {
      async create(o) {
        calls.create = o as unknown as Record<string, unknown>;
        return {
          client: { nick: o.nick },
          identity: { did: "did:key:zagent" },
          rooms: {} as never,
          start: async () => undefined,
          stop: async () => undefined,
        };
      },
    },
  };
  return { kit, calls };
}

describe("defaultCreateClient", () => {
  it("is a self-owned did:key with no configuration at all", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-mcp-"));
    const { kit, calls } = fakeKit();
    const made = await defaultCreateClient(loadConfig({}), "mcp-abc", { botKit: async () => kit, root });
    expect(made.mode).toBe("authenticated");
    expect(made.selfOwned).toBe(true);
    expect(made.did).toBe("did:key:zagent");
    expect(made.start).toBeTypeOf("function");
    expect(made.rooms).toBeDefined();
    // The delegation names the agent itself as creator/owner.
    expect(calls.create).toMatchObject({ name: "mcp-abc", nick: "mcp-abc", ownerDid: "did:key:zagent", root });
    expect(calls.seedPath).toBe(join(root, "mcp-abc", "agent.key"));
  });

  it("binds to FREEQ_OWNER_DID when set", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-mcp-"));
    const { kit, calls } = fakeKit();
    const made = await defaultCreateClient(
      loadConfig({ FREEQ_OWNER_DID: "did:plc:owner", FREEQ_CHANNELS: "#a" }),
      "mcp-abc",
      { botKit: async () => kit, root },
    );
    expect(made.selfOwned).toBe(false);
    expect(calls.create).toMatchObject({ ownerDid: "did:plc:owner", channels: ["#a"] });
  });

  it("replaces a stale self-owned certificate when an owner is configured later", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-mcp-"));
    const certPath = join(root, "mcp-abc", "delegation.json");
    await mkdir(join(root, "mcp-abc"), { recursive: true });
    await writeFile(certPath, "{}");
    const { kit } = fakeKit({ cert: { creator_did: "did:key:zagent", signature: null } });
    await defaultCreateClient(loadConfig({ FREEQ_OWNER_DID: "did:plc:owner" }), "mcp-abc", {
      botKit: async () => kit,
      root,
    });
    await expect(readFile(certPath)).rejects.toThrow(/ENOENT/);
  });

  it("leaves a certificate bound to someone else alone", async () => {
    const root = await mkdtemp(join(tmpdir(), "freeq-mcp-"));
    const certPath = join(root, "mcp-abc", "delegation.json");
    await mkdir(join(root, "mcp-abc"), { recursive: true });
    await writeFile(certPath, "{}");
    const { kit } = fakeKit({ cert: { creator_did: "did:plc:someone", signature: null } });
    await defaultCreateClient(loadConfig({ FREEQ_OWNER_DID: "did:plc:owner" }), "mcp-abc", {
      botKit: async () => kit,
      root,
    });
    expect(await readFile(certPath, "utf8")).toBe("{}");
  });

  it("is a guest only when FREEQ_GUEST is set, and never touches bot-kit then", async () => {
    let loaded = false;
    const made = await defaultCreateClient(loadConfig({ FREEQ_GUEST: "1" }), "mcp-abc", {
      botKit: async () => {
        loaded = true;
        throw new Error("should not load");
      },
    });
    expect(made.mode).toBe("guest");
    expect(made.rooms).toBeUndefined();
    expect(loaded).toBe(false);
  });
});
