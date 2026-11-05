import { describe, it, expect } from "vitest";
import {
  nextUpdate,
  progressLine,
  KEEPALIVE_INTERVALS,
  type ProgressState,
} from "./progress.js";

const INTERVAL = 60_000;
const step = (phrase: string, tool?: string, since = 0) => ({ phrase, since, tool });

describe("progress updates", () => {
  it("says nothing when no turn is running", () => {
    expect(nextUpdate({}, undefined, 1_000, { intervalMs: INTERVAL })).toBeUndefined();
  });

  it("speaks the first time it has anything to say", () => {
    const out = nextUpdate({}, step("answering chad in #freeq-dev"), 60_000, {
      intervalMs: INTERVAL,
    });
    expect(out?.text).toContain("answering chad in #freeq-dev");
    expect(out?.state.lastAt).toBe(60_000);
  });

  it("stays quiet when only the clock moved", () => {
    // The regression this module exists to avoid: a line a minute that says
    // the same thing is worse than silence, because it trains the room to
    // stop reading.
    const first = nextUpdate({}, step("running the test suite", "bash: npm test"), 60_000, {
      intervalMs: INTERVAL,
    })!;
    const second = nextUpdate(
      first.state,
      step("running the test suite", "bash: npm test"),
      120_000,
      { intervalMs: INTERVAL },
    );
    expect(second).toBeUndefined();
  });

  it("speaks again as soon as the work moves on", () => {
    const first = nextUpdate({}, step("running the test suite", "bash: npm test"), 60_000, {
      intervalMs: INTERVAL,
    })!;
    const second = nextUpdate(first.state, step("running the test suite", "edit: client.ts"), 90_000, {
      intervalMs: INTERVAL,
    });
    expect(second?.text).toContain("edit: client.ts");
  });

  it("repeats itself once the silence would be the story", () => {
    // Past the keepalive window, "still on the same thing" IS the news: it is
    // what a watcher checks for, and what a stuck agent looks like.
    const first = nextUpdate({}, step("running the test suite", "bash: npm test"), 0, {
      intervalMs: INTERVAL,
    })!;
    const quiet = nextUpdate(first.state, step("running the test suite", "bash: npm test"), INTERVAL, {
      intervalMs: INTERVAL,
    });
    expect(quiet).toBeUndefined();

    const later = nextUpdate(
      first.state,
      step("running the test suite", "bash: npm test"),
      INTERVAL * KEEPALIVE_INTERVALS,
      { intervalMs: INTERVAL },
    );
    expect(later?.text).toContain("running the test suite");
  });

  it("carries elapsed time, which is the point of the line", () => {
    const text = progressLine(step("waiting on the build", "bash: cargo build", 0), 8 * 60_000);
    expect(text).toMatch(/^⋯ /);
    expect(text).toContain("waiting on the build");
    expect(text).toContain("8m");
  });

  it("keeps the whole thing to one line", () => {
    const text = progressLine(
      step("a phrase that goes on and on and on well past any sane budget", "bash: x", 0),
      60_000,
    );
    expect(text).not.toContain("\n");
    expect(text.length).toBeLessThanOrEqual(130);
  });

  it("state round-trips, so a caller only has to hand it back", () => {
    let state: ProgressState = {};
    for (const [phrase, at] of [
      ["reading the server", 60_000],
      ["writing the fix", 120_000],
      ["running the tests", 180_000],
    ] as const) {
      const out = nextUpdate(state, step(phrase), at, { intervalMs: INTERVAL });
      expect(out, phrase).toBeDefined();
      state = out!.state;
    }
    expect(state.lastAt).toBe(180_000);
  });
});
