import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { findRunPr } from "./pr.js";
import { createRelay, handleHook } from "./relay.js";

describe("handleHook", () => {
  it("looks up the PR only for run_complete", async () => {
    const lookups: string[] = [];
    const posted: string[] = [];
    const opts = {
      post: (l: string) => posted.push(l),
      findPr: async (id: string) => { lookups.push(id); return "https://gh/pr/1"; },
    };
    await handleHook({ event: "run_start", run_id: "A", workflow_name: "w" }, opts);
    await handleHook({ event: "run_complete", run_id: "B", workflow_name: "w" }, opts);
    expect(lookups).toEqual(["B"]);
    expect(posted[1]).toBe("fabro: w [b] finished green — PR https://gh/pr/1");
  });
});

describe("createRelay", () => {
  let close = (): void => {};
  afterEach(() => close());

  async function start(post: (l: string) => void): Promise<string> {
    const server = createRelay({ post });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    close = () => server.close();
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it("answers 204 and posts the formatted line", async () => {
    const posted: string[] = [];
    const base = await start((l) => posted.push(l));
    const res = await fetch(`${base}/hook`, {
      method: "POST",
      body: JSON.stringify({ event: "run_failed", run_id: "R", workflow_name: "dep-audit", failure_reason: "verify failed" }),
    });
    expect(res.status).toBe(204);
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toEqual(["fabro: dep-audit [r] FAILED: verify failed — fabro inspect R"]);
  });

  it("404s other paths and tolerates junk bodies", async () => {
    const posted: string[] = [];
    const base = await start((l) => posted.push(l));
    expect((await fetch(`${base}/nope`, { method: "POST" })).status).toBe(404);
    expect((await fetch(`${base}/hook`, { method: "POST", body: "not json" })).status).toBe(204);
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toEqual([]);
  });
});

describe("findRunPr", () => {
  const reply = (body: unknown, ok = true) =>
    ({ ok, json: async () => body }) as unknown as Response;

  it("polls until the run branch has a PR", async () => {
    const urls: string[] = [];
    const replies = [reply([]), reply({}, false), reply([{ html_url: "https://github.com/freeq-irc/freeq/pull/77" }])];
    const url = await findRunPr("RUN1", {
      repo: "freeq-irc/freeq",
      fetch: (async (u: string) => { urls.push(u); return replies.shift()!; }) as typeof fetch,
      delayMs: 0,
    });
    expect(url).toBe("https://github.com/freeq-irc/freeq/pull/77");
    expect(urls).toHaveLength(3);
    expect(urls[0]).toContain(encodeURIComponent("freeq-irc:fabro/run/RUN1"));
  });

  it("gives up quietly when the API keeps failing", async () => {
    const url = await findRunPr("RUN2", {
      repo: "o/r", attempts: 2, delayMs: 0,
      fetch: (async () => { throw new Error("offline"); }) as typeof fetch,
    });
    expect(url).toBeUndefined();
  });
});
