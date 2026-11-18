/**
 * What freeq-cc mirrors from Claude Code's own machinery to freeq:
 *
 *   - agent-team tasks: with a team channel configured, each task the team
 *     creates is announced there, and a task whose subject starts with
 *     `freeq:` is posted as open freeq work that anyone's agent can claim.
 *     A posted task the team finishes itself first is withdrawn.
 *   - provenance: a commit the session makes, or a pull request it opens, is
 *     posted to the project's channels as a signed line, so who (which
 *     agent, acting for which owner) made the change is on the record.
 *
 * Both go through the runtime's own connection, so every line is signed
 * with the agent's session key like any other message it sends.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { channelsForProject } from "@freeq/harness-kit/config";
import type { AgentRuntime } from "@freeq/harness-kit/runtime";

const exec = promisify(execFile);

/** A team task subject that asks to be posted to freeq as open work. */
export const FREEQ_TASK_PREFIX = /^\s*freeq:\s*/i;

/** A shell command that makes a commit. */
export const COMMIT_COMMAND = /(^|[;&|]\s*|\s)git\s+(?:-C\s+\S+\s+)?commit\b/;

/** A shell command that opens a pull request. */
export const PR_COMMAND = /(^|[;&|]\s*|\s)gh\s+pr\s+create\b/;

const PR_URL = /https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/pull\/\d+/;

export interface BridgeOptions {
  runtime: AgentRuntime;
  /** Where team tasks are mirrored; none mirrors nothing. */
  teamChannel?: string;
  /** Post commits and pull requests to the project's channels. */
  provenance: boolean;
  cwd(): string;
  log(line: string): void;
  /** Told of each line the bridge sent, for the pane's feed. */
  sent?(channel: string, text: string): void;
}

export class SessionBridge {
  readonly #o: BridgeOptions;
  /** Team task id → the freeq task it was posted as. */
  readonly #posted = new Map<string, string>();
  #lastCommit: string | undefined;

  constructor(opts: BridgeOptions) {
    this.#o = opts;
  }

  /** The channels a provenance line goes to: this project's. */
  #projectChannels(): string[] {
    const rt = this.#o.runtime;
    const cfg = rt.config;
    if (!cfg || !rt.conn) return [];
    const joined = new Set(rt.conn.joinedChannels().map((c) => c.toLowerCase()));
    return channelsForProject(cfg, rt.currentProject).filter((c) => joined.has(c.toLowerCase()));
  }

  #say(channel: string, text: string): boolean {
    const conn = this.#o.runtime.conn;
    const ok = !!conn && conn.state === "online" && conn.send(channel, text);
    if (ok) this.#o.sent?.(channel, text);
    return ok;
  }

  // ── agent teams ─────────────────────────────────────────────────────────

  async onTaskCreated(input: Record<string, unknown>): Promise<void> {
    const channel = this.#o.teamChannel;
    const id = str(input.task_id);
    const subject = str(input.task_subject);
    if (!channel || !id || !subject) return;
    if (FREEQ_TASK_PREFIX.test(subject)) {
      const title = subject.replace(FREEQ_TASK_PREFIX, "");
      const out = await this.#o.runtime.runTool({
        action: "post",
        channel,
        title,
        brief: str(input.task_description),
      });
      const posted = /Posted an open task: (\S+)/.exec(out)?.[1];
      if (posted) this.#posted.set(id, posted);
      else this.#o.log(`freeq-cc: could not post team task ${id}: ${out.split("\n")[0]}`);
      return;
    }
    const who = str(input.teammate_name);
    this.#say(channel, `[team] new task: ${subject}${who ? ` (for ${who})` : ""}`);
  }

  async onTaskCompleted(input: Record<string, unknown>): Promise<void> {
    const channel = this.#o.teamChannel;
    const id = str(input.task_id);
    const subject = str(input.task_subject);
    if (!channel || !id) return;
    const posted = this.#posted.get(id);
    if (posted) {
      this.#posted.delete(id);
      // Still open on freeq means nobody else took it: withdraw it. One a
      // peer claimed is theirs to complete, and its completion comes back
      // through the runtime like any other.
      const rec = this.#o.runtime.handoffs?.get(posted);
      if (rec && rec.state === "open") {
        await this.#o.runtime.runTool({ action: "cancel", taskId: posted, message: "done by the team that posted it" });
      }
      return;
    }
    if (subject) this.#say(channel, `[team] done: ${subject}`);
  }

  // ── provenance ──────────────────────────────────────────────────────────

  async onPostToolUse(input: Record<string, unknown>): Promise<void> {
    if (!this.#o.provenance) return;
    if (str(input.tool_name) !== "Bash") return;
    const command = str(input.command) ?? "";
    if (COMMIT_COMMAND.test(command)) await this.#commit();
    else if (PR_COMMAND.test(command)) this.#pullRequest(str(input.response) ?? "");
  }

  async #commit(): Promise<void> {
    const channels = this.#projectChannels();
    if (!channels.length) return;
    let line: string;
    try {
      const { stdout } = await exec("git", ["log", "-1", "--format=%H%x09%ct%x09%s"], {
        cwd: this.#o.cwd(),
        timeout: 3000,
      });
      line = stdout.trim();
    } catch {
      return;
    }
    const [sha, ct, ...rest] = line.split("\t");
    if (!sha || sha === this.#lastCommit) return;
    // A commit made just now, not an old HEAD after a failed `git commit`.
    if (Math.abs(Date.now() / 1000 - Number(ct)) > 120) return;
    this.#lastCommit = sha;
    // Read the branch now: the one in the presence meta was read at connect,
    // and a session may switch branches (or make a repository's first commit).
    let branch: string | undefined;
    try {
      const { stdout } = await exec("git", ["symbolic-ref", "--short", "-q", "HEAD"], { cwd: this.#o.cwd(), timeout: 3000 });
      branch = stdout.trim() || undefined;
    } catch {
      branch = this.#o.runtime.conn?.meta.branch;
    }
    const text = `committed ${sha.slice(0, 10)}${branch ? ` on ${branch}` : ""}: ${rest.join("\t")}`;
    for (const c of channels) this.#say(c, text);
  }

  #pullRequest(response: string): void {
    const url = PR_URL.exec(response)?.[0];
    if (!url) return;
    for (const c of this.#projectChannels()) this.#say(c, `opened a pull request: ${url}`);
  }
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}
