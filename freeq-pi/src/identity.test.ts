import { describe, it, expect } from "vitest";
import { botName, projectBotName, projectNick, projectSlug } from "./identity.js";

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

  it("hashes an awkward project name rather than colliding on the sanitised form", () => {
    // "My Project!!!" and "my-project" would sanitise to the same slug.
    const a = projectSlug("a-very-long-project-name-indeed");
    const b = projectSlug("a-very-long-project-name-indeed-2");
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[0-9a-f]{8}$/);
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
