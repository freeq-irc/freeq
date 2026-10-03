// Fabro hook context → what to say, and to whom.
//
// Fabro POSTs the event context as JSON (docs.fabro.sh/agents/hooks, "Hook
// context"). Null fields are omitted, and fields vary by event, so every
// field here is optional and unknown events format to nothing.
//
// Two audiences. `channel` lines go to #freeq-dev, which anyone who accepts
// its rules can read — so they say only that something happened. Anything
// that can carry substance (a failure reason, a gate's question, which may
// summarize a plan) goes in `owner` and is sent to the owner by DM.

export interface HookContext {
  event?: string;
  run_id?: string;
  workflow_name?: string;
  node_id?: string;
  node_label?: string;
  failure_reason?: string;
}

export interface FormatOptions {
  /** Base URL of the Fabro web UI, e.g. http://127.0.0.1:32277. When set,
   *  owner messages link to the run. */
  webUrl?: string;
  /** PR opened by the run, when known (run_complete only). */
  prUrl?: string;
  /** For an approval gate: the pending question, already described. */
  question?: string;
}

export interface Notice {
  /** For the channel. */
  channel?: string;
  /** For the owner only (DM). */
  owner?: string;
}

const MAX_REASON = 400;

export function runLink(runId: string | undefined, webUrl?: string): string {
  if (!runId) return "";
  if (webUrl) return `${webUrl.replace(/\/+$/, "")}/runs/${runId}`;
  return `fabro inspect ${runId}`;
}

/** The handle owner commands accept: the lowercased ULID tail. */
function short(runId: string | undefined): string {
  return runId ? runId.slice(-6).toLowerCase() : "";
}

function oneLine(s: string, max: number): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

export function formatHook(ctx: HookContext, opts: FormatOptions = {}): Notice {
  const id = short(ctx.run_id);
  const wf = `${ctx.workflow_name ?? "workflow"}${id ? ` [${id}]` : ""}`;
  const link = runLink(ctx.run_id, opts.webUrl);
  const tail = link ? ` — ${link}` : "";

  switch (ctx.event) {
    case "run_start":
      return { channel: `fabro: ${wf} started` };
    case "run_complete":
      return {
        channel: opts.prUrl ? `fabro: ${wf} finished green — PR ${opts.prUrl}` : `fabro: ${wf} finished (no PR)`,
      };
    case "run_failed": {
      const why = ctx.failure_reason ? `: ${oneLine(ctx.failure_reason, MAX_REASON)}` : "";
      return {
        channel: `fabro: ${wf} FAILED`,
        owner: `fabro: ${wf} FAILED${why}${tail}`,
      };
    }
    case "stage_start": {
      // Only human-gate stages are routed here (hook matcher "^approve").
      const gate = ctx.node_label ?? ctx.node_id ?? "a gate";
      const ask = opts.question ? ` ${opts.question}` : "";
      return {
        channel: `fabro: ${wf} is waiting for the owner's approval`,
        owner: `fabro: ${wf} is waiting for you at "${gate}".${ask} Reply here: approve ${id} / deny ${id}${tail}`,
      };
    }
    default:
      return {};
  }
}
