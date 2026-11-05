import { afterEach, describe, expect, it, vi } from "vitest";
import { routeConsoleToStderr } from "./stdout.js";

const saved = { log: console.log, info: console.info, debug: console.debug };

afterEach(() => {
  Object.assign(console, saved);
  vi.restoreAllMocks();
});

describe("routeConsoleToStderr", () => {
  it("sends console.log, info and debug to stderr and nothing to stdout", () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    routeConsoleToStderr();
    console.log("a");
    console.info("b");
    // The SDK logs dropped lines with console.debug.
    console.debug("c", 1);
    expect(out).not.toHaveBeenCalled();
    expect(err.mock.calls.map((c) => String(c[0]))).toEqual(["a\n", "b\n", "c 1\n"]);
  });
});
