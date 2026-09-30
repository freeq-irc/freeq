// Starting goal-driven runs from freeq.
//
// Automations cover "run X from main", but a run with an ad-hoc goal (the
// feature workflow) goes through the Fabro CLI in the executor's checkout —
// the CLI packages the workflow files for the server. The checkout is
// fast-forwarded first so the workflow matches main. Arguments are passed
// as an argv array (never through a shell), so the goal text is inert.
import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export type Exec = (file: string, args: string[], cwd: string) => Promise<string>;

export const execCli: Exec = async (file, args, cwd) =>
  (await execFileP(file, args, { cwd, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 })).stdout;

export interface LaunchOptions {
  /** The executor's freeq checkout, e.g. /home/boxd/freeq. */
  repoDir: string;
  /** Path to the fabro binary. */
  fabroBin: string;
  exec?: Exec;
}

const ULID = /\b[0-9A-HJKMNP-TV-Z]{26}\b/;

export async function launchWithGoal(workflow: string, goal: string, opts: LaunchOptions): Promise<string> {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(workflow)) throw new Error(`bad workflow name "${workflow}"`);
  const exec = opts.exec ?? execCli;
  await exec("git", ["pull", "--ff-only", "--quiet"], opts.repoDir);
  const out = await exec(
    opts.fabroBin,
    ["run", `.fabro/workflows/${workflow}/workflow.toml`, "--goal", goal, "--detach"],
    opts.repoDir,
  );
  const id = ULID.exec(out)?.[0];
  if (!id) throw new Error(`fabro run printed no run id: ${out.trim().slice(0, 200)}`);
  return id;
}

export async function listWorkflows(repoDir: string): Promise<string[]> {
  const entries = await readdir(join(repoDir, ".fabro", "workflows"), { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name).sort();
}
