import { describe, it, expect } from "vitest";
import { parseVerbositySteer as p } from "./steer.js";

describe("verbosity steering from the room", () => {
  it("understands the ways people actually say it", () => {
    expect(p("be more verbose")).toBe("firehose");
    expect(p("can you be a bit chattier in here")).toBe("firehose");
    expect(p("narrate what you're doing")).toBe("firehose");
    expect(p("quieter please")).toBe("decisions");
    expect(p("tone it down")).toBe("decisions");
    expect(p("less verbose")).toBe("decisions");
    expect(p("go silent in this channel")).toBe("silent");
    expect(p("stop posting your work here")).toBe("silent");
    expect(p("back to normal verbosity")).toBe("evidence");
  });

  it("does not mistake a question for a settings change", () => {
    // The false positive that would make people stop trusting the knob.
    expect(p("tell me more about the parser")).toBeUndefined();
    expect(p("is there less latency on zerosum?")).toBeUndefined();
    expect(p("more tests are failing now")).toBeUndefined();
    expect(p("the room got quiet after the restart")).toBeUndefined(); // about the room, no instruction
    expect(p("what does verbose mode do?")).toBeUndefined();
    expect(p("")).toBeUndefined();
  });
});
