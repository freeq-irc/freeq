import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The server's suites are *.spec.ts; the mod's (hooks/*.test.tsx) run
    // under `claude plugin test`, which takes every *.test.ts(x) it finds.
    include: ["test/**/*.spec.ts", "src/**/*.spec.ts"],
    // The kit's floor for HOME and fetch, before any module reads either.
    setupFiles: ["./test/setup.ts"],
  },
});
