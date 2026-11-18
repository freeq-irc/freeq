import { expect, test } from "claude-code/testing";

const SNAP = {
  version: 3,
  connection: { state: "online", nick: "cc-proj", did: "did:key:zSelf", ownerDid: "did:plc:owner", enabled: true, muted: false },
  channels: ["#work"],
  peers: [{ nick: "pi-philipp", did: "did:plc:p", state: "active", doing: "fixing the parser", tier: "request", isAgent: true }],
  tasks: [{ id: "01TASKAAAA", title: "port the lexer", state: "offered", channel: "#work", from: "pi-philipp", side: "in", queued: true }],
  feed: [{ at: 0, direction: "in", channel: "#work", from: "pi-philipp", text: "lexer is yours if you want it", delivered: true }],
  unread: 1,
  approvals: [],
  questions: [],
  audit: [],
};

const PANE = {
  plugin: "freeq",
  component: "Pane",
  requestId: "freeq",
  props: {
    title: "freeq",
    isFocused: false,
    bodyColumns: 80,
    placement: "dock",
    scroll: { offset: 0, bodyRows: 20 },
    view: {},
  },
} as const;

const answer = (value: unknown) => ({ value: { content: [{ type: "text", text: JSON.stringify(value) }], isError: false } });

/** The engine beneath, with the channel server's freeq_ui answering. */
function engine(on: any, ui: (args: Record<string, unknown>) => unknown, calls: Array<Record<string, unknown>> = []): void {
  on("command.register", (_: unknown, e: { name: string }) => ({ value: { command: e.name } }));
  on("ui.open", () => ({ value: { isPlaced: true } }));
  on("ui.status", () => ({ value: undefined }));
  on("ui.toast", () => ({ value: undefined }));
  on("clock.every", () => ({ value: {} }));
  on("session.start", (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }));
  on("mcp.call", (_: unknown, e: { server: string; tool: string; args?: Record<string, unknown> }) => {
    calls.push({ server: e.server, tool: e.tool, ...(e.args ?? {}) });
    return answer(ui(e.args ?? {}));
  });
}

test("the pane shows the feed, then peers and work by tab", async ($, on) => {
  engine(on, (a) => (a.action === "snapshot" ? SNAP : { ok: true }));
  await $.session.start({ cwd: "/", surface: "terminal", isInteractive: true });
  // Let the first poll land.
  const wait = (globalThis as unknown as { setTimeout: (f: () => void, ms: number) => unknown }).setTimeout;
  await new Promise<void>((r) => void wait(r, 20));

  const ui = await $.ui.mount({ ...PANE, surface: "terminal" });
  expect((await ui.find({ type: "Text", text: /lexer is yours/ }))?.text).toContain("pi-philipp");

  await ui.press({ key: "tab-peers" });
  expect((await ui.find({ type: "Text", text: /pi-philipp/ }))?.text).toContain("fixing the parser");

  await ui.press({ key: "tab-work" });
  expect((await ui.find({ type: "Text", text: /port the lexer/ }))?.text).toContain("offered");
  await ui.unmount();
});

test("/fq runs a subcommand on the server with no model turn", async ($, on) => {
  const calls: Array<Record<string, unknown>> = [];
  engine(on, (a) => (a.action === "command" ? { text: `ran ${String(a.line)}` } : SNAP), calls);
  await $.session.start({ cwd: "/", surface: "terminal", isInteractive: true });

  const out = await $.command.run({ command: "fq", args: "status" } as never);
  expect(out.text).toBe("ran status");
  expect(out.isTextDisplayOnly).toBe(true);
  expect(calls.some((c) => c.tool === "freeq_ui" && c.action === "command" && c.line === "status")).toBe(true);
});

test("an AskUserQuestion the server relays is answered by the owner, without the dialog", async ($, on) => {
  let dialog = false;
  engine(on, (a) => {
    if (a.action === "relay_question") return { relayed: true, id: "abcde" };
    if (a.action === "await_question") return { state: "answered", answers: { "Which?": "dayjs" }, note: "Answered over freeq by the owner." };
    return SNAP;
  });
  on("tool.call", () => {
    dialog = true;
    return { result: { questions: [], answers: {} } };
  });
  const questions = [{ question: "Which?", header: "Lib", multiSelect: false, options: [{ label: "date-fns" }, { label: "dayjs" }] }];
  const ran = await $.tool.call({ tool: "AskUserQuestion", questions } as never);
  expect(dialog).toBe(false);
  expect((ran as { result: { answers: Record<string, string> } }).result.answers).toEqual({ "Which?": "dayjs" });
});

test("a question the server does not relay goes to the dialog as usual", async ($, on) => {
  let dialog = false;
  engine(on, (a) => (a.action === "relay_question" ? { relayed: false } : SNAP));
  on("tool.call", () => {
    dialog = true;
    return { result: { questions: [], answers: {} } };
  });
  await $.tool.call({ tool: "AskUserQuestion", questions: [{ question: "Which?", header: "Lib", multiSelect: false, options: [] }] } as never);
  expect(dialog).toBe(true);
});
