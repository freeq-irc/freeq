import { describe, it, expect } from "vitest";
import { botName, projectBotName, projectNick, projectSlug,
  legacyProjectSlug,
  resolveBotName,
  SLUG_MAX,
} from "./identity.js";

describe("per-project identities", () => {
  it("gives each project its own state dir and nick, under the same owner", () => {
    const music = projectBotName("abcd1234", "music");
    const work = projectBotName("abcd1234", "freeq");
    expect(music).not.toBe(work);
    expect(music).toBe("pi-abcd1234-music");
    expect(projectNick("chad-bot", "music")).toBe("chad-bot-music");
    expect(projectNick("chad-bot", "freeq")).toBe("chad-bot-freeq");
  });

  it("is stable across restarts: the same project always derives the same identity", () => {
    expect(projectBotName("abcd1234", "freeq")).toBe(projectBotName("abcd1234", "freeq"));
    expect(projectNick("chad-bot", "freeq")).toBe(projectNick("chad-bot", "freeq"));
  });

  it("falls back to the installation identity when there is no project", () => {
    expect(projectBotName("abcd1234", undefined)).toBe(botName("abcd1234"));
    expect(projectNick("chad-bot", undefined)).toBe("chad-bot");
  });

  it("keeps a long project name distinct without making it unreadable", () => {
    // Was: anything over 12 chars became 8 hex. That is unique and stable and
    // tells the owner nothing, and most repository names are longer than 12.
    // Now the stem survives and four hex of the FULL name keeps it distinct.
    const a = projectSlug("a-very-long-project-name-indeed")!;
    const b = projectSlug("a-very-long-project-name-indeed-2")!;
    expect(a).not.toBe(b);
    expect(a.startsWith("a-very-long")).toBe(true);
    expect(a.length).toBeLessThanOrEqual(SLUG_MAX);
  });

  it("keeps the project visible in the nick even when the base is long", () => {
    const nick = projectNick("a-ridiculously-long-installation-nick", "music");
    expect(nick.endsWith("-music")).toBe(true);
    expect(nick.length).toBeLessThanOrEqual(30);
  });

  it("never produces an invalid IRC nick", () => {
    for (const p of ["My Project!!!", "../../etc", "😀", "", "a b c"]) {
      const nick = projectNick("chad-bot", p || undefined);
      expect(nick).toMatch(/^[A-Za-z[\]{}\\^`|][A-Za-z0-9_\-[\]{}\\^`|]*$/);
    }
  });
});

describe("readable project slugs", () => {
  it("uses the name itself when it fits", () => {
    // The old rule hashed anything over 12 characters, so 'my-new-project'
    // became '278cc566' — the first thing a stranger saw of their own agent.
    expect(projectSlug("freeq")).toBe("freeq");
    expect(projectSlug("my-new-project")).toBe("my-new-project");
    expect(projectSlug("Freeq Fabric")).toBe("freeq-fabric");
  });

  it("truncates long names readably and keeps them distinct", () => {
    const a = projectSlug("some-really-long-project-name")!;
    const b = projectSlug("some-really-long-project-other")!;
    expect(a.startsWith("some-really")).toBe(true);
    expect(a.length).toBeLessThanOrEqual(SLUG_MAX);
    // The hash is over the FULL name, so a shared prefix does not collide.
    expect(a).not.toBe(b);
  });

  it("keeps an identity that already exists under the old name", () => {
    // A slug names a keypair and a registered nick. Renaming on upgrade would
    // bring the agent back as a stranger with a new DID.
    const legacy = `pi-inst-${legacyProjectSlug("my-new-project")}`;
    expect(resolveBotName("inst", "my-new-project", (n) => n === legacy)).toBe(legacy);
    // With nothing on disk, new projects get the readable form.
    expect(resolveBotName("inst", "my-new-project", () => false)).toBe("pi-inst-my-new-project");
  });
});
