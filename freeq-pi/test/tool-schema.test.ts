/**
 * pi registers the freeq tool with its own typebox schema; the kit carries
 * the same schema as plain JSON for other harnesses. They must not drift.
 */
import { describe, expect, it } from "vitest";
import { FREEQ_TOOL_DESCRIPTION, FREEQ_TOOL_NAME, FREEQ_TOOL_PARAMETERS } from "@freeq/harness-kit/tool";
import { startPi } from "./fake-pi.js";

describe("the freeq tool's schema", () => {
  it("is the kit's schema, name and description", async () => {
    const h = await startPi({ start: false });
    const t = h.tools.get(FREEQ_TOOL_NAME);
    expect(t.description).toBe(FREEQ_TOOL_DESCRIPTION);
    expect(JSON.parse(JSON.stringify(t.parameters))).toEqual(FREEQ_TOOL_PARAMETERS);
  });
});
