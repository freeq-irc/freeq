/**
 * Voice: the pure parts of driving the freeq AV bridge from pi.
 *
 * The bridge (`freeq-claude-mcp`) is an MCP server that joins a call, runs
 * STT, speaks via TTS and projects a visual tile. The extension owns the
 * process and the listen loop; this module owns the two things worth testing
 * without a process: how a `freeq_av` tool call maps onto a bridge tool, and
 * how a transcript batch becomes inbound events.
 */

export type AvAction =
  | "say"
  | "post"
  | "show"
  | "show_file"
  | "show_diff"
  | "participants"
  | "recall"
  | "status";

export interface AvParams {
  action: AvAction;
  text?: string;
  priority?: "addressed" | "volunteer";
  title?: string;
  bullets?: string[];
  path?: string;
  lines?: string;
  label?: string;
}

/**
 * Map a `freeq_av` call onto the bridge's tool and arguments.
 *
 * `scrub` is applied to anything that will be spoken or posted: a secret
 * said out loud is still a leaked secret, and a path read aloud to a room is
 * still a path in durable history (the call is mirrored to the channel).
 */
export function toBridgeCall(
  p: AvParams,
  scrub: (text: string) => string,
): { tool: string; args: Record<string, unknown> } {
  switch (p.action) {
    case "say":
      return {
        tool: "freeq_say",
        args: { text: scrub(p.text ?? ""), priority: p.priority ?? "addressed" },
      };
    case "post":
      return { tool: "freeq_post", args: { text: scrub(p.text ?? "") } };
    case "show":
      return {
        tool: "freeq_show",
        args: {
          kind: "card",
          title: p.title ? scrub(p.title) : undefined,
          bullets: p.bullets?.map(scrub),
        },
      };
    case "show_file":
      return { tool: "freeq_show_file", args: { path: p.path, lines: p.lines } };
    case "show_diff":
      return { tool: "freeq_show_diff", args: { path: p.path, lines: p.lines } };
    case "participants":
      return { tool: "freeq_participants", args: {} };
    case "recall":
      return { tool: "freeq_recall", args: { query: p.text ?? "" } };
    case "status":
      return { tool: "freeq_set_status", args: { label: p.label ?? "listening" } };
  }
}

/** One line the bridge heard. */
export interface Transcript {
  speaker: string;
  text: string;
  addressed?: boolean;
  question?: string;
  timestamp_ms?: number;
}

/**
 * Which heard lines reach the model, and as what.
 *
 * Only addressed lines: the rest is the room talking to each other, which is
 * context the model can pull with `recall` but should not be woken for. The
 * speaker is a nick from the AV roster; there is no server-resolved DID on a
 * voice line, so the caller assigns the guest tier - a voice cannot be more
 * trusted than a typed message from the same unknown person.
 */
export function addressedUtterances(
  batch: { transcripts?: Transcript[] } | undefined,
): Array<{ from: string; text: string }> {
  const out: Array<{ from: string; text: string }> = [];
  for (const t of batch?.transcripts ?? []) {
    if (!t.addressed) continue;
    const text = (t.question ?? t.text ?? "").trim();
    if (!text) continue;
    out.push({ from: t.speaker, text: `(spoken in the call) ${text}` });
  }
  return out;
}

/** Parse the bridge's `freeq_listen` result text, tolerating garbage. */
export function parseListenResult(text: string): { transcripts?: Transcript[] } {
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? (v as { transcripts?: Transcript[] }) : {};
  } catch {
    return {};
  }
}
