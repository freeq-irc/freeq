import { describe, expect, it } from "vitest";
import { formatHook, runLink } from "./format.js";

const base = { run_id: "01KV730C7B", workflow_name: "bug-hunt" };

describe("formatHook", () => {
  it("announces run start in the channel only", () => {
    expect(formatHook({ ...base, event: "run_start" }, { webUrl: "https://f.example/" }))
      .toEqual({ channel: "fabro: bug-hunt [730c7b] started" });
  });

  it("links the PR on completion when one was found", () => {
    expect(formatHook({ ...base, event: "run_complete" }, { prUrl: "https://github.com/x/y/pull/9" }))
      .toEqual({ channel: "fabro: bug-hunt [730c7b] finished green — PR https://github.com/x/y/pull/9" });
  });

  it("says so when a completed run opened no PR", () => {
    expect(formatHook({ ...base, event: "run_complete" }))
      .toEqual({ channel: "fabro: bug-hunt [730c7b] finished (no PR)" });
  });

  it("keeps the failure reason out of the channel and sends it to the owner", () => {
    const n = formatHook({ ...base, event: "run_failed", failure_reason: "secret path /home/x\nboom" },
      { webUrl: "http://127.0.0.1:32277" });
    expect(n.channel).toBe("fabro: bug-hunt [730c7b] FAILED");
    expect(n.owner).toBe("fabro: bug-hunt [730c7b] FAILED: secret path /home/x boom — http://127.0.0.1:32277/runs/01KV730C7B");
  });

  it("truncates long failure reasons to one line", () => {
    const n = formatHook({ ...base, event: "run_failed", failure_reason: "boom\n".repeat(200) });
    expect(n.owner).not.toContain("\n");
    expect(n.owner).toMatch(/^fabro: bug-hunt \[730c7b\] FAILED: boom boom .*… — fabro inspect 01KV730C7B$/);
  });

  it("keeps the gate's question private and tells the owner how to answer", () => {
    const n = formatHook(
      { ...base, workflow_name: "feature", event: "stage_start", node_id: "approve", node_label: "Approve plan?" },
      { question: '"Ship this plan: rotate the signing keys?"' },
    );
    expect(n.channel).toBe("fabro: feature [730c7b] is waiting for the owner's approval");
    expect(n.channel).not.toContain("signing keys");
    expect(n.owner).toBe(
      'fabro: feature [730c7b] is waiting for you at "Approve plan?". "Ship this plan: rotate the signing keys?" ' +
        "Reply here: approve 730c7b / deny 730c7b — fabro inspect 01KV730C7B",
    );
  });

  it("ignores events it has no message for", () => {
    expect(formatHook({ ...base, event: "checkpoint_saved" })).toEqual({});
    expect(formatHook({})).toEqual({});
  });
});

describe("runLink", () => {
  it("is empty without a run id", () => {
    expect(runLink(undefined, "https://f.example")).toBe("");
  });
});
