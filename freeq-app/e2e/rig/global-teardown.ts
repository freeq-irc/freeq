/**
 * Playwright global teardown: give back everything the run took.
 *
 * Runs even when global setup failed part way, so it works from whatever the
 * setup managed to record — a run directory with no server, a server with no
 * vite, or nothing at all.
 */
import fs from 'node:fs';
import { clearState, killGroup, readState } from './shared';

export default async function globalTeardown(): Promise<void> {
  const state = readState();
  if (!state) return;

  if (state.vitePid) await killGroup(state.vitePid, 'vite');
  if (state.serverPid) await killGroup(state.serverPid, 'freeq-server');

  fs.rmSync(state.runDir, { recursive: true, force: true });
  clearState();
  console.log(`[e2e rig] stopped, ${state.runDir} removed`);
}
