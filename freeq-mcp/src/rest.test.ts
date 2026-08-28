import { describe, expect, it, vi } from "vitest";
import { FreeqRest, channelPath } from "./rest.js";

function fakeFetch(
  handler: (url: string, init: RequestInit) => { status?: number; body?: string; ct?: string },
) {
  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const { status = 200, body = "{}", ct = "application/json" } = handler(url, init ?? {});
    return new Response(body, { status, headers: { "content-type": ct } });
  }) as unknown as typeof fetch;
}

function rest(fetchImpl: typeof fetch, token?: string) {
  return new FreeqRest({ baseUrl: "https://irc.test", bearerToken: token, fetchImpl });
}

describe("channelPath", () => {
  it("percent-encodes the hash and supplies a missing one", () => {
    expect(channelPath("#general")).toBe("%23general");
    expect(channelPath("general")).toBe("%23general");
    expect(channelPath("&local")).toBe("%26local");
  });
});

describe("url construction", () => {
  it("builds history urls with clamped params", async () => {
    const seen: string[] = [];
    const r = rest(fakeFetch((url) => (seen.push(url), { body: "[]" })));
    await r.history("general", { limit: 10, before: 1234 });
    expect(seen[0]).toBe("https://irc.test/api/v1/channels/%23general/history?limit=10&before=1234");
  });

  it("omits absent query params rather than sending empty ones", async () => {
    const seen: string[] = [];
    const r = rest(fakeFetch((url) => (seen.push(url), { body: "[]" })));
    await r.history("#dev");
    expect(seen[0]).toBe("https://irc.test/api/v1/channels/%23dev/history");
  });

  it("encodes search queries, including the channel's hash", async () => {
    const seen: string[] = [];
    const r = rest(fakeFetch((url) => (seen.push(url), { body: "[]" })));
    await r.search({ channel: "general", q: "deploy failed", limit: 5 });
    expect(seen[0]).toContain("channel=%23general");
    expect(seen[0]).toContain("q=deploy+failed");
    expect(seen[0]).toContain("limit=5");
  });

  it("encodes msgids and nicks that contain url-unsafe characters", async () => {
    const seen: string[] = [];
    const r = rest(fakeFetch((url) => (seen.push(url), { body: "{}" })));
    await r.whois("weird nick/../x");
    expect(seen[0]).toBe("https://irc.test/api/v1/users/weird%20nick%2F..%2Fx/whois");
  });
});

describe("auth", () => {
  it("sends no authorization header when there is no token", async () => {
    let headers: Record<string, string> = {};
    const r = rest(
      fakeFetch((_url, init) => {
        headers = init.headers as Record<string, string>;
        return { body: "{}" };
      }),
    );
    await r.health();
    expect(headers.authorization).toBeUndefined();
  });

  it("uses a bearer token learned after construction", async () => {
    let headers: Record<string, string> = {};
    const r = rest(
      fakeFetch((_url, init) => {
        headers = init.headers as Record<string, string>;
        return { body: "{}" };
      }),
    );
    expect(r.hasBearerToken).toBe(false);
    r.setBearerToken("sess-123");
    expect(r.hasBearerToken).toBe(true);
    await r.health();
    expect(headers.authorization).toBe("Bearer sess-123");
  });
});

describe("error explanation", () => {
  // A bare status code is a dead end for a caller that can't see the spec.
  const cases: Array<[number, string]> = [
    [401, "bearer token"],
    [403, "Invite-only"],
    [404, "does not exist"],
    [429, "rate limited"],
    [503, "without persistence"],
  ];

  for (const [status, needle] of cases) {
    it(`explains ${status} in actionable terms`, async () => {
      const r = rest(fakeFetch(() => ({ status, body: "nope" })));
      await expect(r.history("#x")).rejects.toThrow(new RegExp(needle, "i"));
    });
  }

  it("includes the server's own message", async () => {
    const r = rest(fakeFetch(() => ({ status: 403, body: "channel is +k" })));
    await expect(r.history("#x")).rejects.toThrow(/channel is \+k/);
  });

  it("attaches the status code for callers that branch on it", async () => {
    const r = rest(fakeFetch(() => ({ status: 404, body: "" })));
    await r.history("#x").catch((err) => expect(err.status).toBe(404));
  });

  it("reports non-JSON responses as their text, not a parse error", async () => {
    const r = rest(fakeFetch(() => ({ body: "<html>gateway</html>", ct: "text/html" })));
    await expect(r.health()).rejects.toThrow(/was not JSON: <html>gateway/);
  });

  it("names the url when the transport itself fails", async () => {
    const boom = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    await expect(rest(boom).health()).rejects.toThrow(
      /GET https:\/\/irc.test\/api\/v1\/health failed: ECONNREFUSED/,
    );
  });
});

describe("assistance interface", () => {
  it("posts to /agent/tools/<tool> with a JSON body", async () => {
    let seenUrl = "";
    let seenBody = "";
    const r = rest(
      fakeFetch((url, init) => {
        seenUrl = url;
        seenBody = init.body as string;
        return { body: '{"ok":true}' };
      }),
    );
    await r.assist("diagnose_join_failure", { channel: "#x" });
    expect(seenUrl).toBe("https://irc.test/agent/tools/diagnose_join_failure");
    expect(JSON.parse(seenBody)).toEqual({ channel: "#x" });
  });
});
