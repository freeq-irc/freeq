/**
 * Pins: the pi session lifecycle (start, the per-project lock, shutdown),
 * presence and provenance driven by pi's own events, the hello announced on
 * join, the SDK's logger, and that the renderers are registered and render.
 *
 * Written against freeq-pi as it is, before its runtime moved into
 * freeq-harness-kit; they must keep passing, unedited, after the move.
 */
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { log } from "@freeq/sdk";
import { OWNER, actEvent, baseConfig, startPi } from "./fake-pi.js";

const BOSS = "did:plc:boss";
const SELF = "did:key:zSelf";
const NICK = "pi-test1234-proj";
const LOCK = "freeq-connection-proj.lock";

/** A theme that returns text unstyled, so a render reads as plain lines. */
const plain = { fg: (_c: string, t: string) => t, bold: (t: string) => t };

afterEach(() => {
  vi.useRealTimers();
});

describe("session lifecycle", () => {
  it("is silent when freeq is not set up", async () => {
    const h = await startPi();
    expect(h.notices).toEqual([]);
    expect(h.bot.created).toEqual([]);
    const off = await startPi({ config: baseConfig({ enabled: false }) });
    expect(off.notices).toEqual([]);
    expect(off.bot.created).toEqual([]);
  });

  it("stays dormant in a project it does not know", async () => {
    const h = await startPi({ config: baseConfig({ projects: undefined }), project: "scratch" });
    expect(h.notices).toEqual([]);
    expect(h.bot.created).toEqual([]);
    expect(await h.tool({ action: "peers" })).toBe("freeq is not configured — cannot reach peers right now.");
  });

  it("connects in a known project with the pi identity and nick, and holds the lock", async () => {
    const h = await startPi({ config: baseConfig() });
    const o = h.bot.createOpts!;
    expect({ name: o.name, nick: o.nick, ownerDid: o.ownerDid, url: o.url, channels: o.channels, initialStatus: o.initialStatus }).toMatchInlineSnapshot(`
      {
        "channels": [
          "#work",
        ],
        "initialStatus": "project=proj model=test-model",
        "name": "pi-test1234-proj",
        "nick": "pi-test1234-proj",
        "ownerDid": "did:plc:owner",
        "url": "ws://test.invalid/irc",
      }
    `);
    expect(h.norm(o.root as string)).toBe("<home>/.freeq/bots");
    expect(existsSync(join(h.agentDir, LOCK))).toBe(true);
  });

  it("stays passive when another live process holds the project's lock", async () => {
    const pre = await startPi({ config: baseConfig(), start: false });
    writeFileSync(join(pre.agentDir, LOCK), JSON.stringify({ pid: process.ppid, at: 0, label: "/elsewhere/proj" }));
    await pre.fire("session_start");
    expect(pre.bot.created).toEqual([]);
    expect(pre.noticeTexts()).toMatchInlineSnapshot(`
      [
        "warning: freeq: another pi session in this project holds the connection (/elsewhere/proj). This window stays passive — one agent identity, one presence. Close that session, or run /freeq takeover here.",
      ]
    `);
    pre.notices.length = 0;
    await pre.command("status");
    expect(pre.lastNotice()!.text.split("\n")[2]).toMatchInlineSnapshot(`"state:    passive — another pi session holds this installation's connection"`);
  });

  it("on shutdown: says why held work stopped, stops the bot, releases the lock", async () => {
    const h = await startPi({ config: baseConfig({ trust: { [BOSS]: "handoff" } }) });
    await h.act(actEvent({ verb: "offer", taskId: "01JHELD0000000000000000000", did: BOSS, from: "boss", fields: { "act-to": SELF, "act-title": "held" } }));
    await h.act(actEvent({ verb: "accept", taskId: "01JHELD0000000000000000000", did: SELF, from: NICK }));
    h.bot.sent.length = 0;
    await h.shutdown();
    expect(h.bot.of("act").map((a) => a.payload)).toMatchInlineSnapshot(`
      [
        {
          "+freeq.at/act": "handoff",
          "+freeq.at/act-id": "01JHELD0000000000000000000",
          "+freeq.at/act-note": "the pi session working on this is shutting down after 0s — not finished",
          "+freeq.at/act-verb": "progress",
          "+freeq.at/from": "did:key:zSelf",
        },
      ]
    `);
    expect(h.bot.stopped).toEqual(["pi session ended"]);
    expect(existsSync(join(h.agentDir, LOCK))).toBe(false);
    expect(existsSync(join(h.agentDir, "freeq-handoffs.json"))).toBe(true);
  });

  it("redraws the footer's channel count when a join is confirmed", async () => {
    const h = await startPi({ config: baseConfig(), hasUI: true });
    expect(h.statuses.get("freeq")).toContain("0 ch");
    h.bot.emit("channelJoined", "#work");
    expect(h.statuses.get("freeq")).toContain("1 ch");
  });

  it("announces a pi hello into a channel once joined", async () => {
    const h = await startPi({ config: baseConfig() });
    h.bot.emit("channelJoined", "#work");
    const hello = h.bot.of("tagmsg").at(-1)!;
    expect(hello.target).toBe("#work");
    const p = hello.payload as Record<string, string>;
    expect(p["+freeq.at/event"]).toBe("pi_hello");
    expect(JSON.parse(decodeURIComponent(p["+freeq.at/payload"]!))).toMatchInlineSnapshot(`
      {
        "agent": "pi",
        "did": "did:key:zSelf",
        "meta": {
          "model": "test-model",
          "project": "proj",
        },
        "v": 1,
      }
    `);
  });

  it("routes the SDK's errors to a notice and drops its quieter output", async () => {
    const h = await startPi({ config: baseConfig() });
    log.error("socket", "reset");
    log.warn("ignored");
    log.debug("ignored");
    expect(h.noticeTexts()).toMatchInlineSnapshot(`
      [
        "error: freeq sdk: socket reset",
      ]
    `);
  });
});

describe("presence and provenance from pi's events", () => {
  it("names the step from a typed prompt, adds the tool, and goes back to active when settled", async () => {
    // Presence pushes are throttled by wall clock; a frozen clock keeps this exact.
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-09-30T12:00:00Z") });
    const h = await startPi({ config: baseConfig() });
    h.bot.states.length = 0;
    await h.fire("agent_start");
    await h.fire("message_start", { message: { role: "user", content: [{ type: "text", text: "look at why reconnect drops channels" }] } });
    await h.fire("tool_call", { toolName: "bash", input: { command: "npm test" } });
    await h.fire("agent_settled");
    expect(h.bot.states).toMatchInlineSnapshot(`
      [
        {
          "state": "executing",
          "status": "project=proj model=test-model doing=working",
          "task": undefined,
        },
        {
          "state": "executing",
          "status": "project=proj model=test-model doing=look+at+why+reconnect+drops+channels+·+0s",
          "task": undefined,
        },
        {
          "state": "active",
          "status": "project=proj model=test-model",
          "task": undefined,
        },
        {
          "state": "active",
          "status": "project=proj model=test-model",
          "task": undefined,
        },
      ]
    `);
  });

  it("does not take a step name from framed freeq input", async () => {
    const h = await startPi({ config: baseConfig() });
    h.bot.states.length = 0;
    await h.fire("message_start", { message: { role: "user", content: "[freeq — message from x] do a thing" } });
    expect(h.bot.states).toEqual([]);
  });

  it("mirrors a turn's changes as a signed provenance event and, at evidence, a line", async () => {
    const h = await startPi({ config: baseConfig({ provenance: "evidence" }) });
    await h.fire("tool_call", { toolName: "edit", input: { path: "/home/me/proj/src/parser.ts" } });
    await h.fire("tool_call", { toolName: "bash", input: { command: "cargo build" } });
    await h.fire("tool_call", { toolName: "read", input: { path: "/home/me/proj/README.md" } });
    h.bot.sent.length = 0;
    await h.fire("agent_settled");
    expect(h.bot.sent).toMatchInlineSnapshot(`
      [
        {
          "kind": "tagmsg",
          "payload": {
            "+freeq.at/event": "pi_provenance",
            "+freeq.at/payload": "%7B%22v%22%3A1%2C%22kind%22%3A%22turn%22%2C%22text%22%3A%22edited%20parser.ts%3B%20ran%3A%20cargo%20build%22%2C%22files%22%3A%5B%22parser.ts%22%5D%7D",
          },
          "target": "#work",
        },
        {
          "kind": "message",
          "payload": "⚙ edited parser.ts; ran: cargo build  [parser.ts]",
          "target": "#work",
        },
        {
          "kind": "tagmsg",
          "payload": {
            "+freeq.at/event": "pi_hello",
            "+freeq.at/payload": "%7B%22v%22%3A1%2C%22meta%22%3A%7B%22project%22%3A%22proj%22%2C%22model%22%3A%22test-model%22%7D%2C%22did%22%3A%22did%3Akey%3AzSelf%22%2C%22agent%22%3A%22pi%22%7D",
          },
          "target": "#work",
        },
      ]
    `);
  });

  it("mirrors tags only at decisions, and nothing when silent", async () => {
    const h = await startPi({ config: baseConfig({ provenance: "decisions" }) });
    await h.fire("tool_call", { toolName: "write", input: { path: "notes.md" } });
    h.bot.sent.length = 0;
    await h.fire("agent_settled");
    // The first settle also re-announces the model (see below).
    const events = (sent: typeof h.bot.sent) => sent.map((x) => `${x.kind} ${(x.payload as Record<string, string>)?.["+freeq.at/event"] ?? ""}`);
    expect(events(h.bot.sent)).toEqual(["tagmsg pi_provenance", "tagmsg pi_hello"]);
    const s = await startPi({ config: baseConfig({ provenance: "silent" }) });
    await s.fire("tool_call", { toolName: "write", input: { path: "notes.md" } });
    s.bot.sent.length = 0;
    await s.fire("agent_settled");
    expect(events(s.bot.sent)).toEqual(["tagmsg pi_hello"]);
  });

  it("narrates tool calls live at firehose", async () => {
    const h = await startPi({ config: baseConfig({ provenance: "firehose" }) });
    h.bot.sent.length = 0;
    await h.fire("tool_call", { toolName: "bash", input: { command: "git status\ngit diff" } });
    expect(h.bot.messages()).toMatchInlineSnapshot(`
      [
        "#work ⚙ bash: git status",
      ]
    `);
  });

  it("journals a turn's text while carrying a task", async () => {
    const h = await startPi({ config: baseConfig({ trust: { [BOSS]: "handoff" } }) });
    await h.act(actEvent({ verb: "offer", taskId: "01JJOURNAL0000000000000000", did: BOSS, from: "boss", fields: { "act-to": SELF, "act-title": "journaled" } }));
    await h.turn("Ported the lexer.\n\nNext: the parser.");
    expect(h.entries.filter((e) => e.customType === "freeq-task-note").map((e) => ({ ...(e.data as object), at: 0 }))).toMatchInlineSnapshot(`
      [
        {
          "at": 0,
          "kind": "start",
          "taskId": "01JJOURNAL0000000000000000",
          "text": "took on: journaled",
        },
        {
          "at": 0,
          "kind": "turn",
          "taskId": "01JJOURNAL0000000000000000",
          "text": "Ported the lexer.",
        },
      ]
    `);
  });

  it("re-announces when the model changes", async () => {
    const h = await startPi({ config: baseConfig() });
    await h.fire("agent_settled");
    h.bot.sent.length = 0;
    h.setModel("other-model");
    await h.fire("agent_settled");
    const hello = h.bot.of("tagmsg").find((t) => (t.payload as Record<string, string>)["+freeq.at/event"] === "pi_hello")!;
    expect(JSON.parse(decodeURIComponent((hello.payload as Record<string, string>)["+freeq.at/payload"]!)).meta.model).toBe("other-model");
  });
});

describe("rendering (registration and a sample only)", () => {
  it("renders a delivered message as a card", async () => {
    const h = await startPi({ start: false });
    const r = h.messageRenderers.get("freeq-inbound");
    const details = { kind: "chat", channel: "#work", from: "nap", did: OWNER, tier: "control", text: "hello there", reason: "r", expectsReply: true };
    const out = r({ content: "x", details }, { expanded: true, outputPad: 1 }, plain);
    expect(out.render(100).map((l: string) => l.trimEnd())).toMatchInlineSnapshot(`
      [
        " ⚡ #work · nap · control",
        " hello there",
        " r · the next reply goes back over freeq",
      ]
    `);
  });

  it("renders room lines and the overflow line", async () => {
    const h = await startPi({ start: false });
    const r = h.entryRenderers.get("freeq-room");
    const line = r({ data: { type: "line", direction: "in", channel: "#work", from: "peer", text: "hi", note: "withheld · tier observe" } }, { expanded: false }, plain);
    const more = r({ data: { type: "more", count: 3 } }, { expanded: false }, plain);
    expect([...line.render(100), ...more.render(100)].map((l: string) => l.trimEnd())).toMatchInlineSnapshot(`
      [
        " ⇐ #work <peer> hi  (withheld · tier observe)",
        "   … 3 more room messages",
      ]
    `);
  });

  it("renders a tool call and its result in one line each", async () => {
    const h = await startPi({ start: false });
    const t = h.tools.get("freeq");
    const call = t.renderCall({ action: "ask", to: "pi-chad", message: "which branch?" }, plain);
    const res = t.renderResult({ content: [{ type: "text", text: "No answer from pi-chad: timeout\nmore" }] }, { isPartial: false }, plain);
    expect([...call.render(100), ...res.render(100)].map((l: string) => l.trimEnd())).toMatchInlineSnapshot(`
      [
        "freeq ? ask → pi-chad  "which branch?"",
        "No answer from pi-chad: timeout  (+1 lines)",
      ]
    `);
  });
});
