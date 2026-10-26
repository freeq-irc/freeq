#!/usr/bin/env node
/**
 * Build the sibling packages this one links to.
 *
 * `@freeq/sdk` and `@freeq/bot-kit` are consumed as `file:` dependencies, so
 * npm symlinks them without building — the consumer ends up linked to a
 * package with no `dist/`, and every import fails at runtime with a message
 * that says nothing about the real cause.
 *
 * Putting a `prepare` script in those packages instead does NOT work: npm
 * runs `prepare` for a file: dependency without installing its devDeps, so
 * `tsc` is missing and the whole install aborts.
 *
 * So the consumer builds them, which is the one place that reliably has a
 * working toolchain. Idempotent: skips anything already built.
 */
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const deps = ["freeq-sdk-js", "freeq-bot-kit-js"];

for (const name of deps) {
  const dir = resolve(here, "..", "..", name);
  if (!existsSync(dir)) {
    console.error(`[build-deps] ${name} not found at ${dir} — skipping.`);
    continue;
  }
  if (existsSync(join(dir, "dist", "index.js"))) continue; // already built

  console.error(`[build-deps] building ${name}…`);
  try {
    if (!existsSync(join(dir, "node_modules"))) {
      execFileSync("npm", ["install", "--silent"], { cwd: dir, stdio: "inherit" });
    }
    execFileSync("npm", ["run", "build", "--silent"], { cwd: dir, stdio: "inherit" });
  } catch (err) {
    console.error(
      `[build-deps] could not build ${name}: ${err.message}\n` +
        `  Build it by hand:  cd ${dir} && npm install && npm run build`,
    );
    process.exit(1);
  }
}
