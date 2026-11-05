import { describe, expect, it } from "vitest";
import { launchWithGoal } from "./launch.js";

describe("launchWithGoal", () => {
  it("fast-forwards, then runs the workflow with the goal as a single argv entry", async () => {
    const calls: Array<[string, string[], string]> = [];
    const id = await launchWithGoal("feature", "harden uploads; rm -rf / $(whoami)", {
      repoDir: "/r", fabroBin: "/bin/fabro",
      exec: async (file, args, cwd) => {
        calls.push([file, args, cwd]);
        return file === "git" ? "" : "01M3QHMC0RTP0PJDFHZ7NDB1QW\n";
      },
    });
    expect(id).toBe("01M3QHMC0RTP0PJDFHZ7NDB1QW");
    expect(calls[0]).toEqual(["git", ["pull", "--ff-only", "--quiet"], "/r"]);
    expect(calls[1]).toEqual(["/bin/fabro",
      ["run", ".fabro/workflows/feature/workflow.toml", "--goal", "harden uploads; rm -rf / $(whoami)", "--detach"], "/r"]);
  });

  it("rejects workflow names that could escape the workflows dir", async () => {
    await expect(launchWithGoal("../x", "g", { repoDir: "/r", fabroBin: "f", exec: async () => "" }))
      .rejects.toThrow(/bad workflow name/);
  });

  it("fails loudly when the CLI prints no run id", async () => {
    await expect(launchWithGoal("feature", "g", { repoDir: "/r", fabroBin: "f", exec: async () => "error: nope" }))
      .rejects.toThrow(/printed no run id/);
  });
});
