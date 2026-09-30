// Fabro hook context → one IRC line.
//
// Fabro POSTs the event context as JSON (docs.fabro.sh/agents/hooks, "Hook
// context"). Null fields are omitted, and fields vary by event, so every
// field here is optional and unknown events format to null (not posted).

export interface HookContext {
  event?: string;
  run_id?: string;
  workflow_name?: string;
  node_id?: string;
  node_label?: string;
  failure_reason?: string;
}

export interface FormatOptions {
  /** For an approval gate: the pending question, already described. */
  question?: string;
  /** Public base URL of the Fabro web UI, e.g. https://fabro-freeq.boxd.sh.
   *  When set, messages link to the run. */
  webUrl?: string;
  /** PR opened by the run, when known (run_complete only). */
  prUrl?: string;
}

const MAX_REASON = 240;

export function runLink(runId: string | undefined, webUrl?: string): string {
  if (!runId) return "";
  if (webUrl) return `${webUrl.replace(/\/+$/, "")}/runs/${runId}`;
  return `fabro inspect ${runId}`;
}

/** `[x7k2qa]` — the handle owner commands accept (last 6 of the ULID). */
function tag(runId: string | undefined): string {
  return runId ? ` [${runId.slice(-6).toLowerCase()}]` : "";
}

function oneLine(s: string, max: number): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

export function formatHook(ctx: HookContext, opts: FormatOptions = {}): string | null {
  const wf = `${ctx.workflow_name ?? "workflow"}${tag(ctx.run_id)}`;
  const link = runLink(ctx.run_id, opts.webUrl);
  const tail = link ? ` — ${link}` : "";

  switch (ctx.event) {
    case "run_start":
      return `fabro: ${wf} started${tail}`;
    case "run_complete":
      return opts.prUrl
        ? `fabro: ${wf} finished green — PR ${opts.prUrl}`
        : `fabro: ${wf} finished (no PR)${tail}`;
    case "run_failed": {
      const why = ctx.failure_reason ? `: ${oneLine(ctx.failure_reason, MAX_REASON)}` : "";
      return `fabro: ${wf} FAILED${why}${tail}`;
    }
    case "stage_start": {
      // Only human-gate stages are routed here (hook matcher "^approve").
      const gate = ctx.node_label ?? ctx.node_id ?? "a gate";
      const short = ctx.run_id ? ` ${ctx.run_id.slice(-6).toLowerCase()}` : "";
      const ask = opts.question ? ` ${opts.question}` : "";
      return `fabro: ${wf} is waiting for you at "${gate}".${ask} Reply: fabro approve${short} / fabro deny${short}${tail}`;
    }
    default:
      return null;
  }
}
