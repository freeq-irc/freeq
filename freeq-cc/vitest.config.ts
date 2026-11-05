import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The kit's floor for HOME and fetch, before any module reads either.
    setupFiles: ["./test/setup.ts"],
  },
});
