/**
 * `/freeq doctor`: the kit's setup check, with pi's own line (whether this
 * window holds the connection or is passive) at the end.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { baseConfig, startPi, type FetchHandler } from "./fake-pi.js";

const api: FetchHandler = (url) =>
  url.endsWith("/api/v1/health")
    ? { status: 200, body: { server_name: "test", version: "0.9.0" } }
    : url.includes("/api/v1/actions")
      ? { status: 200, body: { tasks: [] } }
      : { status: 404 };

describe("/freeq doctor", () => {
  it("checks the setup and says this window holds the connection", async () => {
    const h = await startPi({ config: baseConfig(), fetch: api });
    h.bot.emit("channelJoined", "#work");
    h.notices.length = 0;
    await h.command("doctor");
    expect(h.noticeTexts()).toMatchInlineSnapshot(`
      [
        "warning: freeq doctor
        ⚠ identity: none yet at <home>/.freeq/bots/pi-test1234-proj/agent.key — made on the first connect in this project
        ⚠ ownership: no identity to ask the server about
        ✓ owner: did:plc:owner
        ✓ config: <root>/agent/freeq.json
        ✓ server: ws://test.invalid/irc (test 0.9.0)
        ✓ connection: online: pi-test1234-proj (did:key:zSelf) · proj · test-model
        ✓ channels: joined #work
        ✓ this window: holds the connection

      No problems, 2 warnings.",
      ]
    `);
  });

  it("says so when another pi session holds the connection", async () => {
    const h = await startPi({ config: baseConfig(), fetch: api, start: false });
    // A live process that is not this one holds the project's lock.
    writeFileSync(
      join(h.agentDir, "freeq-connection-proj.lock"),
      JSON.stringify({ pid: process.ppid, at: 0, label: "/elsewhere/proj" }),
    );
    await h.fire("session_start");
    h.notices.length = 0;
    await h.command("doctor");
    const text = h.lastNotice()!.text;
    expect(text).toContain("⚠ connection: passive — another pi session in this project holds it (/freeq takeover)");
    expect(text).toContain("⚠ this window: passive — another pi session holds the connection (/freeq takeover)");
  });

  it("is offered by autocomplete", async () => {
    const h = await startPi({ hasUI: true });
    const provider = h.autocomplete[0]!({
      getSuggestions: async () => null,
      applyCompletion: () => ({ lines: [], cursorLine: 0, cursorCol: 0 }),
    });
    const r = await provider.getSuggestions(["/freeq doc"], 0, 10, { signal: new AbortController().signal });
    expect(r.items.map((i: { value: string }) => i.value)).toEqual(["doctor"]);
  });
});
