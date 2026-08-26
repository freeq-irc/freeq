/**
 * Playwright global setup: the run builds and starts everything it needs.
 *
 * Ports are claimed, not shared — anything already listening on 16799, 8080
 * or 5173 stops the run before a single byte is built, because a run that
 * cannot own its world would otherwise silently test someone else's.
 * Everything after that is per-run: a freshly made temporary directory, a
 * server built from this checkout, and a vite started against that server.
 * Teardown gives it all back.
 */
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  APP_DIR,
  IRC_PORT,
  REPO_ROOT,
  VITE_PORT,
  WEB_PORT,
  portIsFree,
  portOwner,
  writeState,
  type RigState,
} from './shared';

/** The AV feature is not optional: without it /av/* answers 503 and the AV specs fail for that alone. */
const CARGO = path.join(os.homedir(), '.cargo', 'bin', 'cargo');
const CARGO_ARGS = ['build', '--release', '--bin', 'freeq-server', '--features', 'av-native'];

const HEALTH_URL = `http://127.0.0.1:${WEB_PORT}/api/v1/health`;
const VITE_URL = `http://127.0.0.1:${VITE_PORT}/`;

async function claimPorts(): Promise<void> {
  for (const port of [IRC_PORT, WEB_PORT, VITE_PORT]) {
    if (await portIsFree(port)) continue;
    throw new Error(
      `[e2e rig] port ${port} is already in use by ${portOwner(port)}. ` +
        `An e2e run starts its own server and vite and never adopts a running one. ` +
        `Stop that process and run again.`,
    );
  }
}

function shortHead(): string {
  return execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  }).trim();
}

function buildServer(): void {
  console.log(`[e2e rig] building: ${CARGO} ${CARGO_ARGS.join(' ')}`);
  execFileSync(CARGO, CARGO_ARGS, { cwd: REPO_ROOT, stdio: 'inherit' });
}

function start(command: string, args: string[], cwd: string, logPath: string, env: NodeJS.ProcessEnv): number {
  const log = fs.openSync(logPath, 'a');
  const child = spawn(command, args, { cwd, env, detached: true, stdio: ['ignore', log, log] });
  child.unref();
  fs.closeSync(log);
  if (!child.pid) throw new Error(`[e2e rig] failed to start ${command}`);
  return child.pid;
}

async function waitFor(what: string, logPath: string, check: () => Promise<string | null>): Promise<void> {
  const deadline = Date.now() + 60_000;
  let last = 'no response yet';
  while (Date.now() < deadline) {
    try {
      const problem = await check();
      if (problem === null) return;
      last = problem;
    } catch (e) {
      last = String(e);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  const tail = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').split('\n').slice(-30).join('\n') : '';
  throw new Error(`[e2e rig] ${what} never came up: ${last}\n--- last log lines ---\n${tail}`);
}

export default async function globalSetup(): Promise<void> {
  await claimPorts();

  const head = shortHead();
  buildServer();

  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeq-e2e-'));
  const state: RigState = { runDir };
  writeState(state);
  console.log(`[e2e rig] run directory ${runDir}`);

  const serverLog = path.join(runDir, 'server.log');
  state.serverPid = start(
    path.join(REPO_ROOT, 'target', 'release', 'freeq-server'),
    [
      '--listen-addr', `127.0.0.1:${IRC_PORT}`,
      '--web-addr', `127.0.0.1:${WEB_PORT}`,
      '--server-name', 'e2e',
      '--iroh',
      '--data-dir', path.join(runDir, 'srv'),
      '--db-path', path.join(runDir, 'server.db'),
    ],
    REPO_ROOT,
    serverLog,
    process.env,
  );
  writeState(state);
  installLastResortCleanup(state);

  await waitFor('freeq-server', serverLog, async () => {
    const res = await fetch(HEALTH_URL);
    if (!res.ok) return `health returned ${res.status}`;
    const health = (await res.json()) as { av?: boolean; git_commit?: string };
    if (health.av !== true) {
      return `health reports av=${health.av}; the binary was built without --features av-native`;
    }
    if (health.git_commit !== head) {
      return `health reports git_commit=${health.git_commit}, checkout HEAD is ${head}`;
    }
    return null;
  });
  console.log(`[e2e rig] freeq-server up on ${IRC_PORT}/${WEB_PORT} at ${head}, av=true`);

  const viteLog = path.join(runDir, 'vite.log');
  state.vitePid = start(
    path.join(APP_DIR, 'node_modules', '.bin', 'vite'),
    ['--port', String(VITE_PORT), '--strictPort', '--host', '127.0.0.1'],
    APP_DIR,
    viteLog,
    // Pinned, not inherited: a FREEQ_WEB left over in the shell would aim the
    // proxy at a deployment and the suite would quietly test that instead.
    { ...process.env, FREEQ_WEB: `http://127.0.0.1:${WEB_PORT}` },
  );
  writeState(state);

  await waitFor('vite', viteLog, async () => {
    const res = await fetch(VITE_URL);
    return res.ok ? null : `vite returned ${res.status}`;
  });
  console.log(`[e2e rig] vite up on ${VITE_PORT}`);
}

/** Teardown handles the normal paths; this catches a runner that dies outright. */
function installLastResortCleanup(state: RigState): void {
  process.once('exit', () => {
    for (const pid of [state.serverPid, state.vitePid]) {
      if (pid) {
        try {
          process.kill(-pid, 'SIGKILL');
        } catch {
          // already gone
        }
      }
    }
    fs.rmSync(state.runDir, { recursive: true, force: true });
  });
}
