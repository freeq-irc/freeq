/**
 * The `/freeq` subcommands. The plugin ships one command file per
 * subcommand (`commands/<name>.md`, written by `commandFile`), so Claude
 * Code lists each as `/freeq:<name>`. What the person types reaches
 * freeq-cc's UserPromptSubmit hook first; `parseTyped` reads it there and
 * the runtime (`AgentRuntime.runCommand`) does the work, so the model never
 * runs a subcommand. The command file only tells Claude to show the answer.
 */

export interface CommandArg {
  name: string;
  description: string;
  required?: boolean;
}

export interface Command {
  name: string;
  description: string;
  args: CommandArg[];
}

/** `yes`, for a client that cannot show a confirmation (no MCP elicitation). */
const CONFIRM: CommandArg = {
  name: "confirm",
  description: "yes, to confirm without being asked (for a client that cannot ask)",
};

export const COMMANDS: Command[] = [
  { name: "status", description: "freeq: connection, identity, channels, trust summary", args: [] },
  {
    name: "doctor",
    description: "freeq: check identity, ownership, owner, config, server, connection, channels and this channel's setup",
    args: [],
  },
  {
    name: "login",
    description: "freeq: set the owner DID (your own), and the server if given, and connect",
    args: [
      { name: "did", description: "your DID, did:plc:…", required: true },
      { name: "server", description: "the freeq server, wss://…/irc, if not the configured one" },
    ],
  },
  {
    name: "authorize",
    description: "freeq: add this installation as one of your agents; 'verify' asks the server for its verdict",
    args: [{ name: "step", description: "verify, or --sign-cert (deprecated)" }],
  },
  {
    name: "join",
    description: "freeq: join a channel (for this project)",
    args: [{ name: "channel", description: "#channel", required: true }],
  },
  {
    name: "leave",
    description: "freeq: leave a channel (for this project)",
    args: [{ name: "channel", description: "#channel", required: true }],
  },
  { name: "peers", description: "freeq: reachable agents, what they are working on, their tier", args: [] },
  {
    name: "mode",
    description: "freeq: how this agent listens in a channel",
    args: [
      { name: "channel", description: "#channel", required: true },
      { name: "mode", description: "silent | addressed | participant", required: true },
    ],
  },
  {
    name: "trust",
    description: "freeq: set a DID's trust tier",
    args: [
      { name: "did", description: "did:plc:… or did:key:…", required: true },
      { name: "tier", description: "observe | message | request | handoff | control", required: true },
      CONFIRM,
    ],
  },
  { name: "mute", description: "freeq: stay connected but answer and deliver nothing", args: [] },
  { name: "unmute", description: "freeq: undo mute", args: [] },
  { name: "on", description: "freeq: enable and connect", args: [] },
  { name: "off", description: "freeq: disconnect and disable", args: [] },
  { name: "handoffs", description: "freeq: handoffs offered to you and by you", args: [] },
  { name: "tasks", description: "freeq: what is assigned, queued, offered, or open nearby", args: [] },
  {
    name: "resume",
    description: "freeq: re-enter assigned work (all of it, capped, if no id)",
    args: [{ name: "id", description: "task id or its short prefix" }],
  },
  {
    name: "accept",
    description: "freeq: take a queued or offered task now",
    args: [{ name: "id", description: "task id or its short prefix", required: true }],
  },
  {
    name: "decline",
    description: "freeq: turn an offered task down, with a reason",
    args: [
      { name: "id", description: "task id or its short prefix", required: true },
      { name: "reason", description: "why" },
    ],
  },
  {
    name: "drop",
    description: "freeq: fail work in flight honestly instead of leaving it hanging",
    args: [
      { name: "id", description: "task id or its short prefix", required: true },
      { name: "reason", description: "why" },
    ],
  },
  {
    name: "progress",
    description: "freeq: report progress on a task by hand",
    args: [
      { name: "id", description: "task id or its short prefix", required: true },
      { name: "note", description: "what has been done", required: true },
    ],
  },
  {
    name: "withheld",
    description: "freeq: messages addressed to you that were not delivered; 'drop' discards them",
    args: [{ name: "action", description: "drop" }],
  },
  {
    name: "policy",
    description: "freeq: accept a channel's join policy",
    args: [
      { name: "channel", description: "#channel", required: true },
      { name: "verb", description: "accept" },
    ],
  },
  {
    name: "takeover",
    description: "freeq: take this project's connection from another session",
    args: [CONFIRM],
  },
  {
    name: "verbosity",
    description: "freeq: how much of this session's work is mirrored to freeq",
    args: [{ name: "level", description: "quiet | normal | more | off" }],
  },
  {
    name: "provenance",
    description: "freeq: the provenance tier",
    args: [{ name: "level", description: "silent | decisions | evidence | firehose" }],
  },
  { name: "help", description: "freeq: the subcommands", args: [] },
];

/** Subcommands whose trailing `yes` confirms without being asked. */
export const CONFIRMABLE = new Set(COMMANDS.filter((c) => c.args.includes(CONFIRM)).map((c) => c.name));

/** A typed `/freeq:<sub> …` line, as the runtime takes it. */
export interface Typed {
  name: string;
  /** The subcommand and its words, without a confirming `yes`. */
  line: string;
  /** The person typed `yes` to confirm. */
  yes: boolean;
}

/**
 * Read a prompt as the person typed it. Only a prompt that starts with
 * `/freeq:<a known subcommand>` is one; every word after it is passed on,
 * so a note or a reason keeps all of its words.
 */
export function parseTyped(prompt: string): Typed | undefined {
  const m = /^\s*\/freeq:([a-z]+)(?:\s+([\s\S]*))?$/.exec(prompt);
  if (!m) return undefined;
  const name = m[1]!;
  if (!COMMANDS.some((c) => c.name === name)) return undefined;
  const words = (m[2] ?? "").trim().split(/\s+/).filter(Boolean);
  let yes = false;
  if (CONFIRMABLE.has(name) && words.at(-1)?.toLowerCase() === "yes") {
    words.pop();
    yes = true;
  }
  return { name, line: [name, ...words].join(" "), yes };
}

/**
 * The plugin's command file for a subcommand. Its text goes to Claude only
 * after the hook has run the subcommand and attached the answer, so it asks
 * Claude to show that answer and nothing more. `disable-model-invocation`
 * keeps the model from running it on its own. `npm run commands` writes
 * every file; a test checks they match.
 */
export function commandFile(c: Command): string {
  const hint = c.args.map((a) => (a.required ? `<${a.name}>` : `[${a.name}]`)).join(" ");
  return [
    "---",
    `description: ${JSON.stringify(c.description)}`,
    ...(hint ? [`argument-hint: ${JSON.stringify(hint)}`] : []),
    "disable-model-invocation: true",
    "---",
    "freeq has already run this command and attached its answer. Show me that answer exactly as it is, and nothing else. Do not run any tool. If no answer from freeq is attached, say that freeq-cc is not running in this session.",
    "",
  ].join("\n");
}
