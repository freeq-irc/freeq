import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateDidKey } from "@freeq/sdk";
import { SignInRefusedError } from "./bot.js";
import {
  createDaemonCLI,
  readPidIfAlive,
  serverApiOrigin,
  type DaemonPaths,
} from "./daemon-cli.js";

async function tmp(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "bot-kit-cli-test-"));
}

function pathsIn(dir: string): DaemonPaths {
  return {
    dir,
    daemonPid: join(dir, "daemon.pid"),
    daemonLog: join(dir, "daemon.log"),
    agentKey: join(dir, "agent.key"),
    delegation: join(dir, "delegation.json"),
  };
}

describe("readPidIfAlive", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await tmp();
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns null when pid file is missing", async () => {
    expect(await readPidIfAlive(join(dir, "missing.pid"))).toBeNull();
  });

  it("returns null when pid file is malformed", async () => {
    const path = join(dir, "malformed.pid");
    await writeFile(path, "not-a-number\n");
    expect(await readPidIfAlive(path)).toBeNull();
  });

  it("returns null for a pid that doesn't exist", async () => {
    const path = join(dir, "dead.pid");
    // pid 999999 is overwhelmingly likely to be free
    await writeFile(path, "999999\n");
    expect(await readPidIfAlive(path)).toBeNull();
  });

  it("returns the pid for a live process", async () => {
    const path = join(dir, "live.pid");
    await writeFile(path, `${process.pid}\n`);
    expect(await readPidIfAlive(path)).toBe(process.pid);
  });

  it("tolerates surrounding whitespace", async () => {
    const path = join(dir, "ws.pid");
    await writeFile(path, `  ${process.pid}  \n\n`);
    expect(await readPidIfAlive(path)).toBe(process.pid);
  });
});

describe("createDaemonCLI", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await tmp();
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("registers the v1 commands (launch, stop, status, doctor, tail)", () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
    });
    const names = cli.commands.map((c) => c.name()).sort();
    expect(names).toEqual(["doctor", "launch", "status", "stop", "tail"]);
  });

  it("exposes launchOptions as extra `launch` flags", () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
      launchOptions: [
        { flags: "--server <url>", description: "Server URL override" },
      ],
    });
    const launch = cli.commands.find((c) => c.name() === "launch")!;
    const flags = launch.options.map((o) => o.flags);
    expect(flags).toContain("--server <url>");
    expect(flags).toContain("--detach");
  });

  it("allows caller to add custom subcommands", () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
    });
    cli.command("grant <did>").description("Custom").action(() => {});
    const names = cli.commands.map((c) => c.name());
    expect(names).toContain("grant");
  });
});

describe("createDaemonCLI: doctor", () => {
  let dir: string;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    dir = await tmp();
    // commander's .parseAsync calls process.exit(1) when actions throw
    // and our doctor action exits(1) on failure; stub it so the test
    // doesn't kill the runner.
    exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((() => undefined) as never);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });
  afterEach(async () => {
    exitSpy.mockRestore();
    logSpy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  function output(): string {
    return logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  }

  it("flags missing identity and missing delegation as problems", async () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
    });
    await cli.parseAsync(["node", "testbot", "doctor"]);
    const out = output();
    expect(out).toContain("✗ agent identity");
    expect(out).toContain("✗ delegation");
    expect(out).toContain("problem(s)");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("reports identity ok when agent.key is present + valid", async () => {
    const paths = pathsIn(dir);
    const k = await generateDidKey();
    const seed = await k.exportSeed();
    await mkdir(paths.dir, { recursive: true });
    await writeFile(paths.agentKey, seed);

    const cli = createDaemonCLI({
      name: "testbot",
      paths,
      runDaemon: async () => ({ stop: async () => {} }),
    });
    await cli.parseAsync(["node", "testbot", "doctor"]);
    const out = output();
    expect(out).toContain("✓ agent identity");
    expect(out).toContain(k.did);
    // delegation is still missing, so still exits 1
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("includes caller doctor checks after built-ins, in order", async () => {
    const calls: string[] = [];
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
      doctorChecks: [
        {
          name: "custom-a",
          run: async () => {
            calls.push("a");
            return { ok: true, detail: "fine" };
          },
        },
        {
          name: "custom-b",
          run: async () => {
            calls.push("b");
            return { ok: "warn", reason: "soft warning" };
          },
        },
      ],
    });
    await cli.parseAsync(["node", "testbot", "doctor"]);
    expect(calls).toEqual(["a", "b"]);
    const out = output();
    expect(out).toContain("✓ custom-a: fine");
    expect(out).toContain("⚠ custom-b: soft warning");
  });

  it("treats a caller check that throws as a failure (doesn't crash doctor)", async () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
      doctorChecks: [
        {
          name: "throws",
          run: async () => {
            throw new Error("boom");
          },
        },
      ],
    });
    await cli.parseAsync(["node", "testbot", "doctor"]);
    const out = output();
    expect(out).toContain("✗ throws: boom");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("skips the server actor check when actorStatusUrl is omitted", async () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
    });
    await cli.parseAsync(["node", "testbot", "doctor"]);
    const out = output();
    expect(out).not.toContain("server actor record");
  });

  it("runs the server actor check when actorStatusUrl is provided + identity exists", async () => {
    const paths = pathsIn(dir);
    const k = await generateDidKey();
    const seed = await k.exportSeed();
    await mkdir(paths.dir, { recursive: true });
    await writeFile(paths.agentKey, seed);

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          online: true,
          nick: "testbot",
          // The actors route returns the stored declaration as it is.
          provenance: {
            type: "FreeqBotDelegation/v1",
            _verified: false,
            _verification_reason: "Unsigned certificate: unverified until the owner adds this bot",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    try {
      const cli = createDaemonCLI({
        name: "testbot",
        paths,
        runDaemon: async () => ({ stop: async () => {} }),
        actorStatusUrl: (did) => `https://example.test/actors/${did}`,
      });
      await cli.parseAsync(["node", "testbot", "doctor"]);
      const out = output();
      expect(out).toContain("server actor record");
      expect(out).toContain("online");
      // A warning, not a pass, with the reason after a colon.
      expect(out).toContain(
        "⚠ server actor record: online, provenance unverified: Unsigned certificate: unverified until the owner adds this bot",
      );
      expect(out).not.toContain("(v1.0)");
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("reports a verified declaration from the actors route's _verified field", async () => {
    const paths = pathsIn(dir);
    const k = await generateDidKey();
    await mkdir(paths.dir, { recursive: true });
    await writeFile(paths.agentKey, await k.exportSeed());

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          online: true,
          provenance: {
            type: "FreeqBotDelegation/v1",
            _verified: true,
            _verification_reason: "Owner's agent record at://x names this bot",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    try {
      const cli = createDaemonCLI({
        name: "testbot",
        paths,
        runDaemon: async () => ({ stop: async () => {} }),
        actorStatusUrl: (did) => `https://example.test/actors/${did}`,
      });
      await cli.parseAsync(["node", "testbot", "doctor"]);
      expect(output()).toContain("✓ server actor record: online, provenance verified");
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

describe("createDaemonCLI: status", () => {
  let dir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    dir = await tmp();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });
  afterEach(async () => {
    logSpy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  it("prints the actors route's _verified and _verification_reason", async () => {
    const paths = pathsIn(dir);
    const k = await generateDidKey();
    await mkdir(paths.dir, { recursive: true });
    await writeFile(paths.agentKey, await k.exportSeed());
    // A live pid, so status queries the server.
    await writeFile(paths.daemonPid, `${process.pid}\n`);

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          online: true,
          nick: "testbot",
          provenance: {
            type: "FreeqBotDelegation/v1",
            _verified: false,
            _verification_reason: "Owner's agent record at://x no longer names this bot",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    try {
      const cli = createDaemonCLI({
        name: "testbot",
        paths,
        runDaemon: async () => ({ stop: async () => {} }),
        actorStatusUrl: (did) => `https://example.test/actors/${did}`,
      });
      await cli.parseAsync(["node", "testbot", "status"]);
      expect(logSpy.mock.calls.map((c) => c.join(" ")).join("\n")).toContain(
        "provenance:     unverified: Owner's agent record at://x no longer names this bot",
      );
      expect(logSpy.mock.calls.map((c) => c.join(" ")).join("\n")).not.toContain("(v1.0)");
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

describe("serverApiOrigin", () => {
  it("maps the bot's WebSocket URL to its server's HTTP origin", () => {
    expect(serverApiOrigin("wss://irc.example.test/irc")).toBe("https://irc.example.test");
    expect(serverApiOrigin("ws://localhost:8080/irc")).toBe("http://localhost:8080");
  });
});

describe("createDaemonCLI: actorStatusUrl", () => {
  let dir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    dir = await tmp();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });
  afterEach(async () => {
    logSpy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  it("may be async, for a server address read from the bot's config", async () => {
    const paths = pathsIn(dir);
    const k = await generateDidKey();
    await mkdir(paths.dir, { recursive: true });
    await writeFile(paths.agentKey, await k.exportSeed());
    await writeFile(paths.daemonPid, `${process.pid}\n`);

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ online: true }), { status: 200 }));
    try {
      const cli = createDaemonCLI({
        name: "testbot",
        paths,
        runDaemon: async () => ({ stop: async () => {} }),
        actorStatusUrl: async (did) => `https://own.example.test/api/v1/actors/${did}`,
      });
      await cli.parseAsync(["node", "testbot", "status"]);
      expect(fetchSpy).toHaveBeenCalledWith(`https://own.example.test/api/v1/actors/${k.did}`);
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

describe("createDaemonCLI: launch, and how it ends", () => {
  let dir: string;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let onceSpy: ReturnType<typeof vi.spyOn>;
  let signals: Map<string, () => void>;

  beforeEach(async () => {
    dir = await tmp();
    exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    // The scaffold's signal handlers, kept to be called by hand.
    signals = new Map();
    onceSpy = vi.spyOn(process, "once").mockImplementation(((event: string, fn: () => void) => {
      signals.set(event, fn);
      return process;
    }) as never);
  });
  afterEach(async () => {
    exitSpy.mockRestore();
    logSpy.mockRestore();
    onceSpy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  const output = () => logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  const until = async (cond: () => boolean) => {
    for (let i = 0; i < 400 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
  };
  const pidGone = async (path: string) => {
    const { stat } = await import("node:fs/promises");
    await expect(stat(path)).rejects.toThrow();
  };

  it("exits 0 and removes its pid file when the daemon stops by itself", async () => {
    const paths = pathsIn(dir);
    let settle: ((why: string) => void) | undefined;
    const stops: string[] = [];
    const cli = createDaemonCLI({
      name: "testbot",
      paths,
      runDaemon: async () => ({
        stop: async (reason: string) => void stops.push(reason),
        stopped: new Promise<string>((resolve) => (settle = resolve)),
      }),
    });
    void cli.parseAsync(["node", "testbot", "launch"]);
    await until(() => settle !== undefined && signals.has("SIGTERM"));
    expect(await readPidIfAlive(paths.daemonPid)).toBe(process.pid);
    settle!("the server's words");
    await until(() => exitSpy.mock.calls.length > 0);
    expect(exitSpy.mock.calls).toEqual([[0]]);
    expect(output()).toContain("[refused] shutting down... the server's words");
    expect(stops).toEqual(["the server's words"]);
    await pidGone(paths.daemonPid);
  });

  it("exits 0 and removes its pid file when the server refuses the daemon's sign-in at start", async () => {
    const paths = pathsIn(dir);
    const cli = createDaemonCLI({
      name: "testbot",
      paths,
      runDaemon: async () => {
        throw new SignInRefusedError("the server's words");
      },
    });
    // process.exit is stubbed, so the action runs on past it and rejects;
    // a real exit ends there.
    await cli.parseAsync(["node", "testbot", "launch"]).catch(() => {});
    expect(exitSpy.mock.calls[0]).toEqual([0]);
    expect(output()).toContain("[refused] shutting down... the server's words");
    await pidGone(paths.daemonPid);
  });

  it("removes its pid file and rethrows when the daemon fails to start for another reason", async () => {
    const paths = pathsIn(dir);
    const cli = createDaemonCLI({
      name: "testbot",
      paths,
      runDaemon: async () => {
        throw new Error("boom");
      },
    });
    await expect(cli.parseAsync(["node", "testbot", "launch"])).rejects.toThrow("boom");
    expect(exitSpy).not.toHaveBeenCalled();
    await pidGone(paths.daemonPid);
  });

  it("exits 0 and removes its pid file on SIGTERM, a deferred start included", async () => {
    // A bot whose start() was deferred has started: its handle stops it.
    const paths = pathsIn(dir);
    const stops: string[] = [];
    const cli = createDaemonCLI({
      name: "testbot",
      paths,
      runDaemon: async () => ({ stop: async (reason: string) => void stops.push(reason), stopped: new Promise<string>(() => {}) }),
    });
    void cli.parseAsync(["node", "testbot", "launch"]);
    await until(() => signals.has("SIGTERM"));
    signals.get("SIGTERM")!();
    await until(() => exitSpy.mock.calls.length > 0);
    expect(exitSpy.mock.calls).toEqual([[0]]);
    expect(stops).toEqual(["signal SIGTERM"]);
    await pidGone(paths.daemonPid);
  });
});

describe("createDaemonCLI: stop", () => {
  let dir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    dir = await tmp();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });
  afterEach(async () => {
    logSpy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  it("reports 'no daemon' when no pid file exists", async () => {
    const cli = createDaemonCLI({
      name: "testbot",
      paths: pathsIn(dir),
      runDaemon: async () => ({ stop: async () => {} }),
    });
    await cli.parseAsync(["node", "testbot", "stop"]);
    expect(logSpy.mock.calls.flat().join(" ")).toContain("No daemon is running");
  });

  it("cleans up a stale pid file (process gone)", async () => {
    const paths = pathsIn(dir);
    await mkdir(paths.dir, { recursive: true });
    // Write a pid we know is dead
    await writeFile(paths.daemonPid, "999999\n");
    const cli = createDaemonCLI({
      name: "testbot",
      paths,
      runDaemon: async () => ({ stop: async () => {} }),
    });
    await cli.parseAsync(["node", "testbot", "stop"]);
    expect(await readPidIfAlive(paths.daemonPid)).toBeNull();
    // Stale-file cleanup means the file should be gone too.
    const { stat } = await import("node:fs/promises");
    await expect(stat(paths.daemonPid)).rejects.toThrow();
  });
});
