// Minimal client for the Fabro server's REST API (the parts the bot drives).
//
// The server listens on the executor VM's loopback only; the bot runs next to
// it and authenticates with the server's dev token. Endpoint shapes follow the
// server's own /api/v1/openapi.json (Fabro 0.254).

export type Fetch = typeof fetch;

export interface QuestionOption {
  key: string;
  label: string;
}

export interface Question {
  id: string;
  text: string;
  stage: string;
  question_type: "yes_no" | "multiple_choice" | "multi_select" | "freeform" | "confirmation";
  options: QuestionOption[];
  allow_freeform: boolean;
}

export interface RunInfo {
  id: string;
  workflow: string;
  status: string;
  prUrl?: string;
}

export type Answer =
  | { kind: "yes" }
  | { kind: "no" }
  | { kind: "selected"; option_key: string }
  | { kind: "text"; text: string };

/** Statuses a run can still make progress from (or is waiting in). */
const ACTIVE = new Set(["submitted", "pending", "runnable", "starting", "running", "blocked", "paused"]);

export function isActive(status: string): boolean {
  return ACTIVE.has(status);
}

/** Short, human-typeable run handle: the random tail of the ULID. */
export function shortId(runId: string): string {
  return runId.slice(-6).toLowerCase();
}

export class FabroApi {
  constructor(
    private readonly baseUrl: string,
    private readonly token: () => Promise<string>,
    private readonly doFetch: Fetch = fetch,
  ) {}

  private async call(method: string, path: string, body?: unknown): Promise<unknown> {
    const res = await this.doFetch(`${this.baseUrl.replace(/\/+$/, "")}/api/v1${path}`, {
      method,
      headers: {
        authorization: `Bearer ${await this.token()}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      let msg = text;
      try {
        const j = JSON.parse(text) as { message?: string; error?: string };
        msg = j.message ?? j.error ?? text;
      } catch {
        // non-JSON error body — use as is
      }
      throw new Error(`Fabro ${method} ${path} → ${res.status}: ${msg.slice(0, 200)}`);
    }
    return text ? JSON.parse(text) : undefined;
  }

  async listRuns(limit = 50): Promise<RunInfo[]> {
    const out = (await this.call("GET", `/runs?page%5Blimit%5D=${limit}`)) as {
      data: Array<{
        id: string;
        workflow?: { slug?: string | null; graph_name?: string | null };
        lifecycle?: { status?: { kind?: string } };
        pull_request?: { html_url?: string; url?: string } | null;
      }>;
    };
    return out.data.map((r) => ({
      id: r.id,
      workflow: r.workflow?.slug ?? r.workflow?.graph_name ?? "workflow",
      status: r.lifecycle?.status?.kind ?? "unknown",
      prUrl: r.pull_request?.html_url ?? r.pull_request?.url ?? undefined,
    }));
  }

  async questions(runId: string): Promise<Question[]> {
    const out = (await this.call("GET", `/runs/${runId}/questions`)) as { data: Question[] };
    return out.data;
  }

  async answer(runId: string, questionId: string, answer: Answer): Promise<void> {
    await this.call("POST", `/runs/${runId}/questions/${encodeURIComponent(questionId)}/answer`, answer);
  }

  async cancel(runId: string): Promise<void> {
    await this.call("POST", `/runs/${runId}/cancel`);
  }

  /** Fire an automation's API trigger; returns the new run's id. */
  async triggerAutomation(id: string): Promise<string> {
    const out = (await this.call("POST", `/automations/${encodeURIComponent(id)}/runs`)) as {
      id?: string;
      run_id?: string;
      data?: { id?: string };
    };
    const runId = out?.id ?? out?.run_id ?? out?.data?.id;
    if (!runId) throw new Error("Fabro started the automation but returned no run id");
    return runId;
  }

  async automationIds(): Promise<string[]> {
    const out = (await this.call("GET", "/automations")) as { data: Array<{ id: string }> };
    return out.data.map((a) => a.id);
  }
}
