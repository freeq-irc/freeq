#!/usr/bin/env node
/**
 * Write the plugin's command files, `commands/<name>.md`, one per `/freeq`
 * subcommand, from `dist/commands.js` (so `npm run build` comes first;
 * `npm run commands` does both). Removes a file whose subcommand is gone.
 * `test/commands.test.ts` checks the files match.
 */
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { COMMANDS, commandFile } from "../dist/commands.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "commands");
mkdirSync(dir, { recursive: true });
const keep = new Set(COMMANDS.map((c) => `${c.name}.md`));
for (const f of readdirSync(dir)) if (!keep.has(f)) rmSync(join(dir, f));
for (const c of COMMANDS) writeFileSync(join(dir, `${c.name}.md`), commandFile(c));
console.log(`freeq-cc: wrote ${COMMANDS.length} command files to commands/`);
