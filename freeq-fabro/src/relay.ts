// Loopback HTTP endpoint Fabro's `type = "http"` hooks POST to.
//
// Always answers 204 quickly: Fabro HTTP hooks fail open, but a slow reply
// would still hold a blocking hook for up to its timeout. The PR lookup on
// run_complete (which polls GitHub) happens after the response.
import { createServer, type Server } from "node:http";
import { formatHook, type HookContext } from "./format.js";

export interface RelayOptions {
  /** Deliver one line to the channel. */
  post: (line: string) => void;
  /** Resolve the run's PR URL, if any (run_complete only). */
  findPr?: (runId: string) => Promise<string | undefined>;
  /** Describe the question an approval gate is asking (stage_start only). */
  describeGate?: (runId: string) => Promise<string | undefined>;
  webUrl?: string;
  log?: (msg: string) => void;
}

const MAX_BODY = 64 * 1024;

export async function handleHook(ctx: HookContext, opts: RelayOptions): Promise<void> {
  const prUrl =
    ctx.event === "run_complete" && ctx.run_id && opts.findPr
      ? await opts.findPr(ctx.run_id)
      : undefined;
  const question =
    ctx.event === "stage_start" && ctx.run_id && opts.describeGate
      ? await opts.describeGate(ctx.run_id).catch(() => undefined)
      : undefined;
  const line = formatHook(ctx, { webUrl: opts.webUrl, prUrl, question });
  if (line) opts.post(line);
}

export function createRelay(opts: RelayOptions): Server {
  const log = opts.log ?? (() => {});
  return createServer((req, res) => {
    if (req.method !== "POST" || req.url !== "/hook") {
      res.writeHead(404).end();
      return;
    }
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      body += chunk;
      if (body.length > MAX_BODY) req.destroy();
    });
    req.on("end", () => {
      res.writeHead(204).end();
      let ctx: HookContext;
      try {
        ctx = JSON.parse(body) as HookContext;
      } catch {
        log(`ignoring non-JSON hook body (${body.length} bytes)`);
        return;
      }
      log(`hook ${ctx.event ?? "?"} run=${ctx.run_id ?? "?"}`);
      handleHook(ctx, opts).catch((err) => log(`hook handling failed: ${String(err)}`));
    });
  });
}
