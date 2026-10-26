import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The floor for HOME and fetch, before any module reads either: the kit
    // looks for identities under ~/.freeq at import, and asks the server what
    // is assigned on every connect.
    setupFiles: ["./src/test-setup.ts"],
  },
});
