import { describe, it, expect } from "vitest";
import { addressedUtterances, parseListenResult, toBridgeCall } from "./av.js";

const noScrub = (t: string) => t;

describe("freeq_av → bridge tool", () => {
  it("maps every action onto a real bridge tool", () => {
    const actions = ["say", "post", "show", "show_file", "show_diff", "participants", "recall", "status"] as const;
    const tools = actions.map((action) => toBridgeCall({ action, text: "x", path: "p", label: "idle" }, noScrub).tool);
    expect(tools).toEqual([
      "freeq_say",
      "freeq_post",
      "freeq_show",
      "freeq_show_file",
      "freeq_show_diff",
      "freeq_participants",
      "freeq_recall",
      "freeq_set_status",
    ]);
  });

  it("scrubs what will be spoken or posted, but not file paths the bridge reads itself", () => {
    const scrub = (t: string) => t.replace(/sk_[a-z0-9]+/g, "[redacted]");
    expect(toBridgeCall({ action: "say", text: "the key is sk_abc123" }, scrub).args.text).toBe(
      "the key is [redacted]",
    );
    expect(toBridgeCall({ action: "post", text: "sk_abc123" }, scrub).args.text).toBe("[redacted]");
    expect(
      toBridgeCall({ action: "show", title: "sk_abc123", bullets: ["sk_def456", "fine"] }, scrub).args,
    ).toEqual({ kind: "card", title: "[redacted]", bullets: ["[redacted]", "fine"] });
    // show_file reads a local path and renders it on the tile; the path is
    // an argument to the bridge, not text leaving the machine.
    expect(toBridgeCall({ action: "show_file", path: "src/sk_abc123.ts" }, scrub).args.path).toBe(
      "src/sk_abc123.ts",
    );
  });

  it("defaults: say is addressed, status is listening", () => {
    expect(toBridgeCall({ action: "say", text: "hi" }, noScrub).args.priority).toBe("addressed");
    expect(toBridgeCall({ action: "status" }, noScrub).args.label).toBe("listening");
  });
});

describe("what the model hears", () => {
  it("delivers only addressed lines, marked as spoken, preferring the bare question", () => {
    const heard = addressedUtterances({
      transcripts: [
        { speaker: "chad", text: "hey bot, what broke?", addressed: true, question: "what broke?" },
        { speaker: "zapnap", text: "I think it's the parser", addressed: false },
        { speaker: "chad", text: "bot are you there", addressed: true },
        { speaker: "chad", text: "   ", addressed: true },
      ],
    });
    expect(heard).toEqual([
      { from: "chad", text: "(spoken in the call) what broke?" },
      { from: "chad", text: "(spoken in the call) bot are you there" },
    ]);
  });

  it("tolerates a bridge that returns nothing, or garbage", () => {
    expect(addressedUtterances(undefined)).toEqual([]);
    expect(addressedUtterances(parseListenResult("not json"))).toEqual([]);
    expect(addressedUtterances(parseListenResult("null"))).toEqual([]);
    expect(addressedUtterances(parseListenResult('{"transcripts":[]}'))).toEqual([]);
  });
});
