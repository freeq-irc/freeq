// The control socket's action dispatch: what each owner-authorized action
// does to the IRC client underneath.
//
// The distinction these tests hold: a message under the agent's name goes
// through the client's signed send path, and only the control verbs are
// written as raw lines. A hand-built `PRIVMSG` line bypasses the session key
// the client armed at connect, so the message arrives with the server
// vouching for it instead of the agent's own device — which is exactly the
// claim freeqcc exists to make.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createConnection } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { TokenStore, startControlServer, type ControlServerHandle, type IrcSink } from "./control.js";

interface Recorded {
  raw: string[];
  say: Array<[string, string]>;
  notice: Array<[string, string]>;
}

function recorder(): { sink: IrcSink; calls: Recorded } {
  const calls: Recorded = { raw: [], say: [], notice: [] };
  return {
    calls,
    sink: {
      raw: (line) => calls.raw.push(line),
      say: (target, text) => calls.say.push([target, text]),
      notice: (target, text) => calls.notice.push([target, text]),
      nick: "agent",
    },
  };
}

const ACTIONS = [
  "join",
  "part",
  "privmsg-user",
  "privmsg-channel",
  "notice-user",
  "notice-channel",
  "nick",
];

describe("control socket actions", () => {
  let dir: string;
  let sockPath: string;
  let server: ControlServerHandle;
  let store: TokenStore;
  let rec: ReturnType<typeof recorder>;
  let token: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "freeqcc-control-"));
    sockPath = join(dir, "control.sock");
    store = new TokenStore();
    rec = recorder();
    server = await startControlServer({
      store,
      sink: rec.sink,
      socketPath: sockPath,
      log: () => {},
    });
    token = store.mint({
      isOwner: true,
      actions: ACTIONS,
      replyTarget: "#room",
      senderDid: "did:plc:owner",
    });
  });

  afterEach(async () => {
    await server.close();
    await rm(dir, { recursive: true, force: true });
  });

  async function run(action: string, args: unknown[]): Promise<{ ok: boolean; error?: string }> {
    return new Promise((resolve, reject) => {
      const sock = createConnection(sockPath, () => {
        sock.write(JSON.stringify({ token, action, args }) + "\n");
      });
      sock.setEncoding("utf8");
      let buf = "";
      sock.on("data", (chunk: string) => {
        buf += chunk;
        const nl = buf.indexOf("\n");
        if (nl < 0) return;
        sock.end();
        resolve(JSON.parse(buf.slice(0, nl)));
      });
      sock.on("error", reject);
    });
  }

  it("sends a message through the signed send path, never as a raw line", async () => {
    expect(await run("privmsg-channel", ["#room", "shipped it"])).toEqual({ ok: true });
    expect(await run("privmsg-user", ["bob", "on my way"])).toEqual({ ok: true });
    expect(rec.calls.say).toEqual([
      ["#room", "shipped it"],
      ["bob", "on my way"],
    ]);
    expect(rec.calls.raw, "a hand-built PRIVMSG would go out unsigned").toEqual([]);
  });

  it("sends a notice the same way", async () => {
    expect(await run("notice-channel", ["#room", "back in five"])).toEqual({ ok: true });
    expect(await run("notice-user", ["bob", "heads up"])).toEqual({ ok: true });
    expect(rec.calls.notice).toEqual([
      ["#room", "back in five"],
      ["bob", "heads up"],
    ]);
    expect(rec.calls.raw).toEqual([]);
  });

  // JOIN, PART and NICK are control verbs: they assert nothing under the
  // agent's name, so there is no document for a signature to be about.
  it("keeps the control verbs as raw lines", async () => {
    expect(await run("join", ["#ops"])).toEqual({ ok: true });
    expect(await run("part", ["#ops", "done"])).toEqual({ ok: true });
    expect(await run("nick", ["agent2"])).toEqual({ ok: true });
    expect(rec.calls.raw).toEqual(["JOIN #ops", "PART #ops :done", "NICK agent2"]);
    expect(rec.calls.say).toEqual([]);
    expect(rec.calls.notice).toEqual([]);
  });

  it("still refuses malformed arguments before anything reaches the wire", async () => {
    const res = await run("privmsg-channel", ["not-a-channel", "hi"]);
    expect(res.ok).toBe(false);
    expect(rec.calls.say).toEqual([]);
    expect(rec.calls.raw).toEqual([]);
  });
});
