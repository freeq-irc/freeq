import { describe, expect, it } from "vitest";
import { FabroApi, isActive, shortId } from "./fabro-api.js";

function api(reply: (url: string, init: RequestInit) => { status?: number; body: unknown }) {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    const { status = 200, body } = reply(url, init);
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return new Response(status === 204 ? null : text, { status });
  }) as typeof fetch;
  return { client: new FabroApi("http://fabro/", async () => "tok", f), seen };
}

describe("FabroApi", () => {
  it("maps the run list the server returns (0.254 shape)", async () => {
    const { client, seen } = api(() => ({
      body: { data: [{
        id: "01M3QHMC0RTP0PJDFHZ7NDB1QW",
        workflow: { slug: "test-coverage", graph_name: "TestCoverage" },
        lifecycle: { status: { kind: "failed", reason: "workflow_error" } },
        pull_request: null,
      }], meta: { total: 1 } },
    }));
    expect(await client.listRuns()).toEqual([
      { id: "01M3QHMC0RTP0PJDFHZ7NDB1QW", workflow: "test-coverage", status: "failed", prUrl: undefined },
    ]);
    expect(seen[0].url).toBe("http://fabro/api/v1/runs?page%5Blimit%5D=50");
    expect((seen[0].init.headers as Record<string, string>).authorization).toBe("Bearer tok");
  });

  it("posts answers as JSON to the question's endpoint", async () => {
    const { client, seen } = api(() => ({ status: 204, body: "" }));
    await client.answer("RUN", "q/1", { kind: "yes" });
    expect(seen[0].url).toBe("http://fabro/api/v1/runs/RUN/questions/q%2F1/answer");
    expect(seen[0].init.method).toBe("POST");
    expect(seen[0].init.body).toBe('{"kind":"yes"}');
  });

  it("surfaces the server's error message", async () => {
    const { client } = api(() => ({ status: 409, body: { message: "run is not cancellable" } }));
    await expect(client.cancel("RUN")).rejects.toThrow("POST /runs/RUN/cancel → 409: run is not cancellable");
  });

  it("finds the new run id however the trigger response wraps it", async () => {
    for (const body of [{ id: "A" }, { run_id: "B" }, { data: { id: "C" } }]) {
      const { client } = api(() => ({ status: 201, body }));
      expect(await client.triggerAutomation("bug-hunt")).toMatch(/^[ABC]$/);
    }
  });
});

describe("helpers", () => {
  it("shortId is the lowercased ULID tail", () => expect(shortId("01M3QHMC0RTP0PJDFHZ7NDB1QW")).toBe("ndb1qw"));
  it("isActive covers waiting and running, not terminal", () => {
    expect(["running", "blocked", "paused"].every(isActive)).toBe(true);
    expect(["succeeded", "failed", "dead"].some(isActive)).toBe(false);
  });
});
