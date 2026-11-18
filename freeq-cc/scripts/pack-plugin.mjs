#!/usr/bin/env node
/**
 * Build a self-contained copy of the plugin in `dist-plugin/`: the manifest,
 * hooks, mod, skills, agents, workflows and command files, with the two MCP
 * servers bundled into single files that need no node_modules. That folder
 * is what a marketplace installs (`.claude-plugin/marketplace.json` at the
 * repository root names it as the npm package `@freeq/cc`): publish it with
 * `cd dist-plugin && npm publish --access public`.
 *
 * A clone does not need this: `--plugin-dir` (or the local marketplace in
 * this folder) runs the plugin in place, against its own node_modules.
 */
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist-plugin");
rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "dist"), { recursive: true });

await build({
  entryPoints: { server: join(root, "src/server.ts"), av: join(root, "src/av.ts") },
  outdir: join(out, "dist"),
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  outExtension: { ".js": ".js" },
  // Some dependencies still `require` Node built-ins.
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  logLevel: "warning",
});

for (const part of [".claude-plugin/plugin.json", "hooks", "skills", "agents", "workflows", "commands", "types", "scripts/install-av.sh", "README.md"]) {
  cpSync(join(root, part), join(out, part), {
    recursive: true,
    filter: (src) => !/\.test\.tsx?$/.test(src),
  });
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
writeFileSync(
  join(out, "package.json"),
  `${JSON.stringify(
    {
      name: pkg.name,
      version: JSON.parse(readFileSync(join(root, ".claude-plugin/plugin.json"), "utf8")).version,
      description: pkg.description,
      type: "module",
      license: pkg.license,
      homepage: pkg.homepage,
      repository: pkg.repository,
      keywords: pkg.keywords,
      engines: pkg.engines,
    },
    null,
    2,
  )}\n`,
);
console.log(`freeq-cc: packed the plugin into ${out}`);
