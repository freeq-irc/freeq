import { describe, expect, it } from "vitest";
import { startPi } from "./fake-pi.js";

/** The editor's own provider, which the extension wraps. */
const base = {
  getSuggestions: async () => null,
  applyCompletion: () => ({ lines: [], cursorLine: 0, cursorCol: 0 }),
};

async function suggest(line: string) {
  const h = await startPi({ hasUI: true });
  expect(h.autocomplete).toHaveLength(1);
  const provider = h.autocomplete[0]!(base);
  return provider.getSuggestions([line], 0, line.length, { signal: new AbortController().signal });
}

describe("/freeq autocomplete", () => {
  it("offers handoffs for /freeq hand", async () => {
    const r = await suggest("/freeq hand");
    expect(r.prefix).toBe("hand");
    expect(r.items.map((i: { value: string }) => i.value)).toEqual(["handoffs"]);
  });
});
