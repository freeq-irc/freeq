// Owner commands: text from freeq → Fabro API calls → reply lines.
//
// Parsing and execution are pure over an injected FabroApi-shaped object so
// they can be tested without a server. The caller (cli.ts) is responsible for
// only feeding in messages whose sender DID is the bot's owner.
import { isActive, shortId, type Answer, type FabroApi, type Question, type RunInfo } from "./fabro-api.js";

export type Command =
  | { kind: "help" }
  | { kind: "status" }
  | { kind: "run"; workflow: string; goal?: string }
  | { kind: "approve" | "deny"; run?: string }
  | { kind: "answer"; run: string; text: string }
  | { kind: "cancel"; run: string }
  | { kind: "unknown"; text: string };

export const HELP = [
  "fabro commands (owner only):",
  "  status — active runs, and anything waiting on you",
  "  run <workflow> — start test-coverage / bug-hunt / dep-audit from main",
  "  run <workflow> <goal…> — start any workflow with a goal (e.g. run feature harden uploads)",
  "  approve [id] | deny [id] — answer a waiting gate (id optional if only one is waiting)",
  "  answer <id> <option or text> — for multiple-choice / freeform gates",
  "  cancel <id>",
];

/** If `text` addresses the bot in a channel (`fabro …`, `fabro: …`,
 *  `@fabro …`), return the rest; otherwise null. */
export function addressed(text: string, nick: string): string | null {
  const esc = nick.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp(`^\\s*@?${esc}[:,]?(?:\\s+(.*))?$`, "is").exec(text);
  if (!m) return null;
  return (m[1] ?? "").trim();
}

export function parseCommand(input: string): Command {
  const text = input.trim();
  const [verbRaw = "", ...rest] = text.split(/\s+/);
  const verb = verbRaw.toLowerCase();
  const arg = rest.join(" ").trim();
  switch (verb) {
    case "":
    case "help":
    case "?":
      return { kind: "help" };
    case "status":
    case "ps":
      return { kind: "status" };
    case "run":
    case "start": {
      if (!rest[0]) return { kind: "unknown", text };
      const goal = rest.slice(1).join(" ").trim();
      return { kind: "run", workflow: rest[0].toLowerCase(), goal: goal || undefined };
    }
    case "approve":
    case "yes":
      return { kind: "approve", run: rest[0] };
    case "deny":
    case "no":
    case "reject":
      return { kind: "deny", run: rest[0] };
    case "answer":
      if (rest.length < 2) return { kind: "unknown", text };
      return { kind: "answer", run: rest[0], text: rest.slice(1).join(" ") };
    case "cancel":
    case "stop":
      if (!arg) return { kind: "unknown", text };
      return { kind: "cancel", run: rest[0] };
    default:
      return { kind: "unknown", text };
  }
}

export interface CommandDeps {
  api: Pick<FabroApi, "listRuns" | "questions" | "answer" | "cancel" | "triggerAutomation" | "automationIds">;
  /** Start a workflow with an explicit goal (CLI path); returns the run id. */
  launchWithGoal: (workflow: string, goal: string) => Promise<string>;
  /** Workflows that exist in the repo's .fabro/workflows/. */
  workflows: () => Promise<string[]>;
}

type Match = { run: RunInfo } | { error: string };

function matchRun(runs: RunInfo[], handle: string): Match {
  const h = handle.toLowerCase();
  const hits = runs.filter((r) => r.id.toLowerCase() === h || r.id.toLowerCase().endsWith(h));
  if (hits.length === 1) return { run: hits[0] };
  if (hits.length === 0) return { error: `no recent run matches "${handle}"` };
  return { error: `"${handle}" matches ${hits.length} runs — use more of the id` };
}

interface Pending {
  run: RunInfo;
  question: Question;
}

async function pendingQuestions(deps: CommandDeps, runs: RunInfo[]): Promise<Pending[]> {
  const out: Pending[] = [];
  for (const run of runs.filter((r) => isActive(r.status))) {
    for (const question of await deps.api.questions(run.id)) out.push({ run, question });
  }
  return out;
}

export function describeQuestion(q: Question): string {
  const opts =
    q.question_type === "multiple_choice" || q.question_type === "multi_select"
      ? ` Options: ${q.options.map((o) => `${o.key} (${o.label})`).join(", ")}.`
      : "";
  return `"${q.text.replace(/\s+/g, " ").trim().slice(0, 300)}"${opts}`;
}

function answerFor(q: Question, text: string): Answer {
  if (q.question_type === "yes_no" || q.question_type === "confirmation") {
    if (/^(y|yes|approve|ok|go)$/i.test(text)) return { kind: "yes" };
    if (/^(n|no|deny|reject|stop)$/i.test(text)) return { kind: "no" };
  }
  const opt = q.options.find(
    (o) => o.key.toLowerCase() === text.toLowerCase() || o.label.toLowerCase() === text.toLowerCase(),
  );
  if (opt) return { kind: "selected", option_key: opt.key };
  if (q.allow_freeform || q.question_type === "freeform") return { kind: "text", text };
  throw new Error(`"${text}" isn't one of: ${q.options.map((o) => o.key).join(", ") || "yes, no"}`);
}

async function pickPending(deps: CommandDeps, handle: string | undefined): Promise<Pending | string> {
  const runs = await deps.api.listRuns();
  let scope = runs;
  if (handle) {
    const m = matchRun(runs, handle);
    if ("error" in m) return m.error;
    scope = [m.run];
  }
  const pending = await pendingQuestions(deps, scope);
  if (pending.length === 1) return pending[0];
  if (pending.length === 0) return handle ? `run ${shortId(scope[0].id)} isn't waiting on anything` : "nothing is waiting on you";
  return `${pending.length} gates are waiting — say which: ${pending.map((p) => shortId(p.run.id)).join(", ")}`;
}

export async function execute(cmd: Command, deps: CommandDeps): Promise<string[]> {
  switch (cmd.kind) {
    case "help":
      return HELP;

    case "unknown":
      return [`didn't understand "${cmd.text.slice(0, 80)}" — try: fabro help`];

    case "status": {
      const runs = await deps.api.listRuns();
      const active = runs.filter((r) => isActive(r.status));
      if (active.length === 0) return ["no active runs"];
      const pending = await pendingQuestions(deps, active);
      return active.map((r) => {
        const q = pending.find((p) => p.run.id === r.id);
        return `${shortId(r.id)} ${r.workflow} ${r.status}${q ? ` — waiting: ${describeQuestion(q.question)}` : ""}`;
      });
    }

    case "run": {
      const known = await deps.workflows();
      if (!known.includes(cmd.workflow)) {
        return [`unknown workflow "${cmd.workflow}" — have: ${known.join(", ")}`];
      }
      if (cmd.goal) {
        const id = await deps.launchWithGoal(cmd.workflow, cmd.goal);
        return [`started ${cmd.workflow} [${shortId(id)}] with your goal`];
      }
      const automations = await deps.api.automationIds();
      if (!automations.includes(cmd.workflow)) {
        return [`${cmd.workflow} needs a goal: fabro run ${cmd.workflow} <what to build>`];
      }
      const id = await deps.api.triggerAutomation(cmd.workflow);
      return [`started ${cmd.workflow} [${shortId(id)}] from main`];
    }

    case "approve":
    case "deny": {
      const p = await pickPending(deps, cmd.run);
      if (typeof p === "string") return [p];
      const q = p.question;
      if (q.question_type !== "yes_no" && q.question_type !== "confirmation") {
        return [`[${shortId(p.run.id)}] asks ${describeQuestion(q)} — reply: fabro answer ${shortId(p.run.id)} <choice>`];
      }
      await deps.api.answer(p.run.id, q.id, { kind: cmd.kind === "approve" ? "yes" : "no" });
      return [`${cmd.kind === "approve" ? "approved" : "denied"} ${p.run.workflow} [${shortId(p.run.id)}]`];
    }

    case "answer": {
      const p = await pickPending(deps, cmd.run);
      if (typeof p === "string") return [p];
      await deps.api.answer(p.run.id, p.question.id, answerFor(p.question, cmd.text));
      return [`answered ${p.run.workflow} [${shortId(p.run.id)}]`];
    }

    case "cancel": {
      const m = matchRun(await deps.api.listRuns(), cmd.run);
      if ("error" in m) return [m.error];
      await deps.api.cancel(m.run.id);
      return [`cancelled ${m.run.workflow} [${shortId(m.run.id)}]`];
    }
  }
}
