import { describe, expect, it } from "vitest";

import { COMMIT_COMMAND, FREEQ_TASK_PREFIX, PR_COMMAND } from "../src/bridge.js";
import { questionText, readAnswer } from "../src/relay.js";
import { OWNER, PEER, baseConfig, startChannel } from "./helpers.js";

const QUESTIONS = [
  {
    question: "Which date library?",
    header: "Library",
    multiSelect: false,
    options: [{ label: "date-fns" }, { label: "dayjs", description: "smaller" }],
  },
];

describe("freeq-cc: the mod's freeq_ui tool", () => {
  it("answers a snapshot with the connection, the feed and a version that moves", async () => {
    const h = await startChannel({ config: baseConfig({ trust: { [PEER]: "message" } }) });
    const first = JSON.parse(await h.ui({ action: "snapshot" }));
    expect(first.connection).toMatchObject({ ownerDid: OWNER, enabled: true });
    expect(first.feed).toEqual([]);

    // Nothing changed: a few bytes.
    expect(JSON.parse(await h.ui({ action: "snapshot", since: first.version }))).toEqual({
      version: first.version,
      unchanged: true,
    });

    await h.dm("pal", PEER, "hello there");
    const next = JSON.parse(await h.ui({ action: "snapshot", since: first.version }));
    expect(next.version).toBeGreaterThan(first.version);
    expect(next.feed.at(-1)).toMatchObject({ direction: "in", from: "pal", text: expect.stringContaining("hello there") });
    expect(next.unread).toBeGreaterThan(0);

    await h.ui({ action: "mark_read" });
    expect(JSON.parse(await h.ui({ action: "snapshot" })).unread).toBe(0);
    await h.close();
  });

  it("does not count the mod's own calls as the session's work", async () => {
    const h = await startChannel({ config: baseConfig() });
    const out = await h.hook({ hook_event_name: "PreToolUse", tool_name: "mcp__plugin_freeq_freeq__freeq_ui", action: "snapshot" });
    expect(out.hookSpecificOutput).toEqual({ hookEventName: "PreToolUse", permissionDecision: "allow" });
    expect(h.channel.runtime.step).toBeUndefined();
    await h.close();
  });

  it("runs a subcommand for /fq and returns what it said, with no model turn", async () => {
    const h = await startChannel({ config: baseConfig() });
    const out = JSON.parse(await h.ui({ action: "command", line: "help" }));
    expect(out.text).toContain("status");
    const bad = JSON.parse(await h.ui({ action: "command", line: "nope" }));
    expect(bad.text).toContain('no subcommand "nope"');
    await h.close();
  });

  it("does not relay a question the person is at the terminal for", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.hook({ hook_event_name: "UserPromptSubmit", prompt: "pick a library" });
    expect(JSON.parse(await h.ui({ action: "relay_question", questions: QUESTIONS }))).toEqual({ relayed: false });
    await h.close();
  });

  it("relays a question when asked to always, and hands back the owner's answer", async () => {
    const h = await startChannel({ config: baseConfig(), settings: { relayQuestions: "always" } });
    const { relayed, id } = JSON.parse(await h.ui({ action: "relay_question", questions: QUESTIONS }));
    expect(relayed).toBe(true);
    expect(h.bot.messages().at(-1)).toContain(`Reply "q${id} <answer>"`);
    expect(JSON.parse(await h.ui({ action: "snapshot" })).questions).toHaveLength(1);

    const waiting = h.ui({ action: "await_question", id, wait_ms: 2000 });
    await h.dm("nap", OWNER, `q${id} 2`);
    const out = JSON.parse(await waiting);
    expect(out).toMatchObject({ state: "answered", answers: { "Which date library?": "dayjs" } });
    expect(out.note).toContain(OWNER);
    expect(JSON.parse(await h.ui({ action: "snapshot" })).questions).toEqual([]);
    await h.close();
  });

  it("stops waiting on the owner when the person answers at the terminal", async () => {
    const h = await startChannel({ config: baseConfig(), settings: { relayQuestions: "always" } });
    const { id } = JSON.parse(await h.ui({ action: "relay_question", questions: QUESTIONS }));
    const waiting = h.ui({ action: "await_question", id, wait_ms: 5000 });
    expect(JSON.parse(await h.ui({ action: "cancel_question", id }))).toEqual({ cancelled: true });
    expect(JSON.parse(await waiting)).toEqual({ state: "cancelled" });
    await h.close();
  });

  it("ignores a question reply from anyone but the owner", async () => {
    const h = await startChannel({ config: baseConfig({ trust: { [PEER]: "control" } }), settings: { relayQuestions: "always" } });
    const { id } = JSON.parse(await h.ui({ action: "relay_question", questions: QUESTIONS }));
    await h.dm("pal", PEER, `q${id} 1`);
    expect(JSON.parse(await h.ui({ action: "await_question", id, wait_ms: 50 }))).toEqual({ state: "pending" });
    await h.close();
  });
});

describe("freeq-cc: relay text", () => {
  it("reads a number, a label, or the owner's own words", () => {
    expect(readAnswer(QUESTIONS[0]!, "1")).toBe("date-fns");
    expect(readAnswer(QUESTIONS[0]!, "DAYJS")).toBe("dayjs");
    expect(readAnswer(QUESTIONS[0]!, "luxon, please")).toBe("luxon, please");
    expect(readAnswer({ question: "Which?", multiSelect: true, options: [{ label: "a" }, { label: "b" }] }, "1, 2")).toBe("a, b");
  });

  it("numbers the options in the DM", () => {
    expect(questionText("abcde", QUESTIONS)).toBe(
      'Claude needs an answer from you:\nWhich date library?\n   1) date-fns\n   2) dayjs — smaller\nReply "qabcde <answer>" — a number picks an option, or write your own.',
    );
  });
});

describe("freeq-cc: what the session bridge recognises", () => {
  it("knows a commit and a pull request when it sees one", () => {
    expect(COMMIT_COMMAND.test('git commit -m "x"')).toBe(true);
    expect(COMMIT_COMMAND.test("git add . && git commit -m x")).toBe(true);
    expect(COMMIT_COMMAND.test("git -C sub commit --amend")).toBe(true);
    expect(COMMIT_COMMAND.test("git log --grep commit")).toBe(false);
    expect(PR_COMMAND.test("gh pr create --fill")).toBe(true);
    expect(PR_COMMAND.test("gh pr view")).toBe(false);
  });

  it("posts a team task only when its subject asks for freeq", () => {
    expect(FREEQ_TASK_PREFIX.test("freeq: port the parser")).toBe(true);
    expect(FREEQ_TASK_PREFIX.test("port the parser")).toBe(false);
  });

  it("announces a team task in the team channel, and posts a freeq: one as open work", async () => {
    const h = await startChannel({ config: baseConfig(), settings: { teamChannel: "#work" } });
    await h.hook({ hook_event_name: "TaskCreated", task_id: "1", task_subject: "write tests", teammate_name: "tester" });
    expect(h.bot.messages()).toContain("#work [team] new task: write tests (for tester)");
    await h.hook({ hook_event_name: "TaskCreated", task_id: "2", task_subject: "freeq: port the parser", task_description: "the C one" });
    const posted = h.bot.sent.filter((s) => s.kind === "act");
    expect(posted.length).toBeGreaterThan(0);
    await h.close();
  });
});
