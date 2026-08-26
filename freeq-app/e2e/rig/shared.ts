/**
 * Pieces both e2e rig hooks need: the ports a run claims, where it records
 * what it started, and the port/process probes.
 *
 * A run owns its world. It claims fixed ports, a freshly made temporary
 * directory, and the processes it started itself — and gives all of it back
 * in teardown.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** freeq-server's IRC listener; specs read FREEQ_IRC_PORT with this default. */
export const IRC_PORT = 16799;
/** freeq-server's HTTP/WebSocket listener; vite's proxy target by default. */
export const WEB_PORT = 8080;
/** The vite dev server the browser talks to. */
export const VITE_PORT = 5173;

export const APP_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const REPO_ROOT = path.resolve(APP_DIR, '..');

/** What one run started, handed from global setup to global teardown. */
export interface RigState {
  runDir: string;
  serverPid?: number;
  vitePid?: number;
}

/** Both hooks run in the runner process, so its pid names the state file. */
export const STATE_FILE = path.join(os.tmpdir(), `freeq-e2e-rig-${process.pid}.json`);

export function writeState(state: RigState): void {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state));
}

export function readState(): RigState | null {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) as RigState;
  } catch {
    return null;
  }
}

export function clearState(): void {
  try {
    fs.unlinkSync(STATE_FILE);
  } catch {
    // already gone
  }
}

/** Resolves false when anything is already listening on 127.0.0.1:port. */
export function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.once('listening', () => probe.close(() => resolve(true)));
    probe.listen(port, '127.0.0.1');
  });
}

/** Who holds the port, for the refusal message. Best effort — `ss` may be absent. */
export function portOwner(port: number): string {
  try {
    const out = execFileSync('ss', ['-ltnpH', `sport = :${port}`], { encoding: 'utf8' }).trim();
    const owner = out.match(/users:\(\((.*)\)\)$/m);
    return owner ? owner[1] : out || 'unidentified process';
  } catch {
    return 'unidentified process (ss unavailable)';
  }
}

/** SIGTERM the whole group, then SIGKILL whatever is still up. */
export async function killGroup(pid: number, label: string): Promise<void> {
  const signal = (sig: NodeJS.Signals) => {
    try {
      process.kill(-pid, sig);
      return true;
    } catch {
      return false;
    }
  };
  if (!signal('SIGTERM')) return;
  for (let i = 0; i < 100; i++) {
    await new Promise((r) => setTimeout(r, 100));
    try {
      process.kill(-pid, 0);
    } catch {
      return;
    }
  }
  console.warn(`[e2e rig] ${label} (pid ${pid}) ignored SIGTERM, killing`);
  signal('SIGKILL');
}
