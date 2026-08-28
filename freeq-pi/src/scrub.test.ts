import { describe, it, expect } from "vitest";
import { homedir } from "node:os";
import { scrubOutbound } from "./scrub.js";

describe("the M0 regression — absolute paths", () => {
  it("redacts the exact leak that reached public channel history", () => {
    // Verbatim shape of the M0 answer: "…rooted at /Users/chad/src/freeq".
    const leaked = "The repo is freeq (working dir freeq-pi is a subdirectory of the repo rooted at /Users/chad/src/freeq)";
    const { text, hits } = scrubOutbound(leaked);
    expect(text).not.toContain("/Users/chad");
    expect(hits.length).toBeGreaterThan(0);
    // Message stays intelligible.
    expect(text).toContain("freeq");
  });

  it("redacts the running user's home directory by name", () => {
    const { text, hits } = scrubOutbound(`config lives at ${homedir()}/.config/app.json`);
    expect(text).not.toContain(homedir());
    expect(hits).toContain("home-path");
  });

  it("keeps the final segment so the message still makes sense", () => {
    const { text } = scrubOutbound("run /Users/someone/src/proj/deploy.sh now");
    expect(text).toContain("deploy.sh");
    expect(text).not.toContain("/Users/someone");
  });

  it("handles Windows and UNC paths", () => {
    expect(scrubOutbound("see C:\\Users\\bob\\secrets.txt").text).not.toContain("bob");
    expect(scrubOutbound("at \\\\fileserver\\share").text).not.toContain("fileserver");
  });

  it("leaves system paths and relative paths alone", () => {
    for (const ok of [
      "check /usr/local/bin for the binary",
      "logs are in /var/log/syslog",
      "edit src/config.ts in this repo",
      "the file ./deploy/deploy.sh",
    ]) {
      expect(scrubOutbound(ok).text).toBe(ok);
    }
  });

  it("does not mangle URLs", () => {
    const url = "docs at https://example.com/a/b/c";
    expect(scrubOutbound(url).text).toContain("https://example.com/a/b/c");
  });
});

describe("secrets", () => {
  const cases: Array<[string, string, string]> = [
    ["github token", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_"],
    ["slack token", "xoxb-123456789012-abcdefghijkl", "xoxb-"],
    ["aws key id", "key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"],
    ["openai key", "sk-abcdefghijklmnopqrstuvwxyz012345", "sk-abcdefghij"],
    ["anthropic key", "sk-ant-abcdefghijklmnopqrstuvwxyz01", "sk-ant-"],
    ["jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "eyJhbGci"],
  ];

  for (const [name, input, needle] of cases) {
    it(`redacts a ${name}`, () => {
      const { text, hits } = scrubOutbound(input);
      expect(text).not.toContain(needle);
      expect(text).toMatch(/\[redacted:/);
      expect(hits.length).toBeGreaterThan(0);
    });
  }

  it("redacts a private key block entirely", () => {
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\ndef456\n-----END OPENSSH PRIVATE KEY-----";
    const { text } = scrubOutbound(`here: ${pem}`);
    expect(text).not.toContain("abc123");
    expect(text).toContain("[redacted:private-key]");
  });

  it("redacts credentials embedded in URLs but keeps the host", () => {
    const { text } = scrubOutbound("postgres://admin:hunter2@db.example.com:5432/app");
    expect(text).not.toContain("hunter2");
    expect(text).toContain("db.example.com");
  });

  it("redacts secret-shaped env assignments", () => {
    for (const input of [
      "DATABASE_PASSWORD=hunter2",
      "API_TOKEN: abc123def456",
      'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG"',
    ]) {
      const { text } = scrubOutbound(input);
      expect(text).toMatch(/\[redacted:secret\]/);
      expect(text).not.toMatch(/hunter2|abc123def456|wJalrXUtnFEMI/);
    }
  });

  it("redacts bearer tokens", () => {
    const { text } = scrubOutbound("Authorization: Bearer abcdefghijklmnopqrstuv");
    expect(text).not.toContain("abcdefghijklmnopqrstuv");
  });

  it("leaves ordinary env vars alone", () => {
    for (const ok of ["NODE_ENV=production", "PORT=8080", "LOG_LEVEL=debug"]) {
      expect(scrubOutbound(ok).text).toBe(ok);
    }
  });
});

describe("general behaviour", () => {
  it("is a no-op on clean text and reports no hits", () => {
    const clean = "The auth refactor changed AuthProvider to take a Session object.";
    const { text, hits } = scrubOutbound(clean);
    expect(text).toBe(clean);
    expect(hits).toEqual([]);
  });

  it("handles empty input", () => {
    expect(scrubOutbound("").text).toBe("");
  });

  it("redacts multiple categories in one message and reports each", () => {
    const { text, hits } = scrubOutbound(
      "deploy from /Users/x/src/app with ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    );
    expect(text).not.toContain("/Users/x");
    expect(text).not.toContain("ghp_");
    expect(hits).toContain("github-token");
    expect(hits.some((h) => h.includes("path"))).toBe(true);
  });

  it("is idempotent", () => {
    const once = scrubOutbound("token ghp_abcdefghijklmnopqrstuvwxyz0123456789 at /Users/x/y/z").text;
    expect(scrubOutbound(once).text).toBe(once);
  });
});
