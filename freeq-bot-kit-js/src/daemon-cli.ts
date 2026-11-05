// createDaemonCLI — Commander-based scaffold for the boring parts of a
// long-running freeq bot daemon (launch/stop/status/doctor/tail). The
// caller supplies a `runDaemon` callback that contains domain logic;
// the scaffold owns the pid file, the --detach fork, the signal
// wiring, and the standard built-in doctor checks.
//
// The scaffold is opinionated about *patterns*, not *behavior*:
// - Two-callback launch model so prompts/persistence can happen in
//   foreground before forking, and the detached child re-runs the
//   same `preflight` idempotently after the fork.
// - Pid file is the source of truth for `stop`/`status`. Stale pid
//   detection is bot-kit's responsibility; bots don't reimplement it.
// - doctor runs built-ins (identity, delegation, server reachability,
//   provenance) first, then caller's checks. Order matters; bots
//   layering on top can assume the built-ins ran.
//
// What the scaffold does NOT do:
// - Prompt for user input (bots own that, in `preflight`).
// - Persist a config.json (bots own theirs).
// - Touch did:key rotation (sensitive enough that v1 leaves it to bots).
// - Reach into the SDK or FreeqBot (this layer is purely lifecycle).

import { Command } from "commander";
import { spawn, execSync } from "node:child_process";
import { mkdir, open, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { loadDelegation } from "./delegation.js";
import { loadOrCreateIdentity } from "./identity.js";

/** Discriminated result returned by a doctor check. */
export type DoctorResult =
  | { ok: true; detail?: string }
  | { ok: false; reason: string }
  | { ok: "warn"; reason: string };

/** One doctor check. `name` is shown in the output; `run` is awaited. */
export interface DoctorCheck {
  name: string;
  run: () => Promise<DoctorResult>;
}

export interface DaemonPaths {
  /** Directory for state (~/.mybot/). Created with mode 0700 if missing. */
  dir: string;
  /** Pid file path (~/.mybot/daemon.pid). */
  daemonPid: string;
  /** Daemon log path (~/.mybot/daemon.log) — used by --detach + tail. */
  daemonLog: string;
  /** Agent seed file path — used by the built-in identity doctor check. */
  agentKey: string;
  /** Delegation cert path — used by the built-in delegation check. */
  delegation: string;
}

export interface DaemonHandle {
  /** Called by the scaffold on SIGINT/SIGTERM. Should shut down cleanly. */
  stop(reason: string): Promise<void>;
}

/** What the launch action passes to runDaemon after preflight finishes. */
// deno-lint-ignore no-explicit-any
export type DaemonOpts = Record<string, any>;

export interface CreateDaemonCLIOptions<O extends DaemonOpts = DaemonOpts> {
  /** Bot name. Used in messages + as the default program name. */
  name: string;

  /** Paths the scaffold reads/writes on the bot's behalf. */
  paths: DaemonPaths;

  /** Daemon entry point. Runs only in the daemon process (foreground or
   *  detached child). Returns a handle so the scaffold can ask it to
   *  shut down on SIGINT/SIGTERM. */
  runDaemon: (opts: O) => Promise<DaemonHandle>;

  /** Optional pre-launch hook. Runs in BOTH the foreground (before fork)
   *  and the detached child (after fork). Must be idempotent: a re-run
   *  should see the persisted state from the first run and skip prompts.
   *  Returns the options object passed to runDaemon.
   *
   *  If omitted, runDaemon receives the parsed Commander options
   *  directly. */
  preflight?: (parsed: Record<string, unknown>) => Promise<O>;

  /** Extra `launch` command flags. Caller reads them from runDaemon's
   *  opts (or from preflight's `parsed` arg). */
  launchOptions?: Array<{ flags: string; description: string }>;

  /** Bot-specific doctor checks, appended after built-ins. */
  doctorChecks?: DoctorCheck[];

  /** Extra lines appended to `status` output. Useful for telemetry. */
  statusExtras?: () => Promise<string[]>;

  /** Optional REST URL to query for live actor state. Receives the
   *  bot's resolved did:key. If omitted, `status` + `doctor` skip the
   *  provenance check. Point it at the server the bot connects to, e.g.
   *  `${serverApiOrigin(url)}/api/v1/actors/${encodeURIComponent(did)}`;
   *  it may be async, to read that server from the bot's config. */
  actorStatusUrl?: (did: string) => string | Promise<string>;
}

/** The HTTP origin of the server at WebSocket URL `serverUrl`:
 *  `wss://host/irc` → `https://host`, `ws://host:port/irc` →
 *  `http://host:port`. */
export function serverApiOrigin(serverUrl: string): string {
  const u = new URL(serverUrl);
  return `${u.protocol === "wss:" ? "https:" : "http:"}//${u.host}`;
}

/** Construct the Commander program. The returned `Command` is the root
 *  — bot-specific subcommands can be added via `.command(...)`. Call
 *  `.parseAsync(process.argv)` to run.
 *
 *  v1 commands: launch, stop, status, doctor, tail. */
export function createDaemonCLI<O extends DaemonOpts = DaemonOpts>(
  opts: CreateDaemonCLIOptions<O>,
): Command {
  const program = new Command();
  program.name(opts.name).version("0.2.0");

  registerLaunch(program, opts);
  registerStop(program, opts);
  registerStatus(program, opts);
  registerDoctor(program, opts);
  registerTail(program, opts);

  return program;
}

// ── launch ─────────────────────────────────────────────────────────────

function registerLaunch<O extends DaemonOpts>(
  program: Command,
  opts: CreateDaemonCLIOptions<O>,
): void {
  const cmd = program
    .command("launch")
    .description(
      `Launch the ${opts.name} daemon. Use --detach to fork into the background.`,
    )
    .option(
      "--detach",
      `Fork into the background (logs to ${opts.paths.daemonLog}). Prompts complete in the foreground first.`,
    );

  for (const flag of opts.launchOptions ?? []) {
    cmd.option(flag.flags, flag.description);
  }

  cmd.action(async (parsed: Record<string, unknown>) => {
    // Preflight: prompts + config persistence happen here in foreground
    // FIRST. The detached child re-runs this idempotently.
    const daemonOpts = opts.preflight
      ? await opts.preflight(parsed)
      : (parsed as unknown as O);

    if (parsed.detach) {
      // Fork a fresh `<name> launch` subprocess (without --detach).
      // Parent exits after printing the child pid; child writes its
      // own pid file inside the spawned action.
      await mkdir(opts.paths.dir, { recursive: true, mode: 0o700 });
      const logFh = await open(opts.paths.daemonLog, "a", 0o600);
      const args = process.argv.slice(2).filter((a) => a !== "--detach");
      const child = spawn(process.argv0, [process.argv[1], ...args], {
        detached: true,
        stdio: ["ignore", logFh.fd, logFh.fd],
        env: { ...process.env, [`${envPrefix(opts.name)}DETACHED`]: "1" },
      });
      child.unref();
      await logFh.close();
      console.log(
        `${opts.name} launched (pid ${child.pid}); logs → ${opts.paths.daemonLog}`,
      );
      console.log(`  ${opts.name} status   — show live state`);
      console.log(`  ${opts.name} stop     — clean shutdown`);
      return;
    }

    // Foreground: write pid, run daemon, cleanup on exit.
    await mkdir(opts.paths.dir, { recursive: true, mode: 0o700 });
    await writeFile(opts.paths.daemonPid, String(process.pid) + "\n", {
      mode: 0o600,
    });

    const handle = await opts.runDaemon(daemonOpts);

    // Signal handlers: scaffold owns these so the bot doesn't have to.
    let stopping = false;
    const shutdown = async (sig: string): Promise<void> => {
      if (stopping) return;
      stopping = true;
      console.log(`\n[${sig}] shutting down...`);
      try {
        await handle.stop(`signal ${sig}`);
      } catch (err) {
        console.error(`[${sig}] stop failed: ${(err as Error).message}`);
      }
      try {
        await unlink(opts.paths.daemonPid);
      } catch {
        // already gone
      }
      process.exit(0);
    };
    process.once("SIGINT", () => void shutdown("SIGINT"));
    process.once("SIGTERM", () => void shutdown("SIGTERM"));

    // Block forever — shutdown is driven by signals.
    await new Promise<void>(() => {});
  });
}

// ── stop ───────────────────────────────────────────────────────────────

function registerStop<O extends DaemonOpts>(
  program: Command,
  opts: CreateDaemonCLIOptions<O>,
): void {
  program
    .command("stop")
    .description("Stop the running daemon (clean SIGTERM).")
    .action(async () => {
      const pid = await readPidIfAlive(opts.paths.daemonPid);
      if (pid === null) {
        console.log("No daemon is running.");
        // If pid file exists but the pid is dead, clean it up.
        try {
          await unlink(opts.paths.daemonPid);
        } catch {
          // already gone
        }
        return;
      }
      try {
        process.kill(pid, "SIGTERM");
        console.log(`Sent SIGTERM to pid ${pid}.`);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ESRCH") {
          console.log(`Pid ${pid} is gone; cleaning up stale pid file.`);
          await unlink(opts.paths.daemonPid).catch(() => {});
        } else {
          throw err;
        }
      }
    });
}

// ── status ─────────────────────────────────────────────────────────────

/** The `provenance` field of `GET /api/v1/actors/{did}`: the declaration
 *  the bot sent, as stored, with the server's verdict in the underscore
 *  fields it adds. */
interface StoredProvenance {
  _verified?: boolean;
  _verification_reason?: string;
}

function registerStatus<O extends DaemonOpts>(
  program: Command,
  opts: CreateDaemonCLIOptions<O>,
): void {
  program
    .command("status")
    .description(`Show ${opts.name} daemon status.`)
    .action(async () => {
      const pid = await readPidIfAlive(opts.paths.daemonPid);
      const did = await safeReadAgentDid(opts.paths.agentKey);
      const cert = await loadDelegation({ certPath: opts.paths.delegation }).catch(
        () => null,
      );

      console.log(`─── ${opts.name} status ───`);
      console.log(`pid file:       ${opts.paths.daemonPid}`);
      console.log(
        `daemon:         ${pid !== null ? `running (pid ${pid})` : "not running"}`,
      );
      console.log(`agent DID:      ${did ?? "(no agent.key)"}`);
      console.log(
        `delegation:     ${cert ? (cert.signature ? "signed" : "unsigned") : "(none)"}`,
      );

      if (opts.statusExtras) {
        const extras = await opts.statusExtras();
        for (const line of extras) console.log(line);
      }

      if (pid !== null && did && opts.actorStatusUrl) {
        try {
          const resp = await fetch(await opts.actorStatusUrl(did));
          if (resp.ok) {
            const json = (await resp.json()) as Record<string, unknown>;
            console.log(`actor.online:   ${json.online}`);
            console.log(`actor.nick:     ${json.nick ?? "(none)"}`);
            const provenance = json.provenance as StoredProvenance | undefined;
            if (provenance) {
              // The reason after a colon: it may hold parentheses of its own.
              console.log(
                `provenance:     ${provenance._verified === true ? "verified" : "unverified"}: ${provenance._verification_reason ?? "—"}`,
              );
            }
          } else {
            console.log(`actor api:      ${resp.status} ${resp.statusText}`);
          }
        } catch (e) {
          console.log(`actor api:      error: ${(e as Error).message}`);
        }
      }
    });
}

// ── doctor ─────────────────────────────────────────────────────────────

function registerDoctor<O extends DaemonOpts>(
  program: Command,
  opts: CreateDaemonCLIOptions<O>,
): void {
  program
    .command("doctor")
    .description(
      "Sanity-check identity, delegation, server reachability, and bot-specific checks.",
    )
    .action(async () => {
      console.log(`─── ${opts.name} doctor ───`);
      let problems = 0;
      let warnings = 0;
      const print = (name: string, r: DoctorResult): void => {
        if (r.ok === true) {
          console.log(`  ✓ ${name}${r.detail ? `: ${r.detail}` : ""}`);
        } else if (r.ok === "warn") {
          console.log(`  ⚠ ${name}: ${r.reason}`);
          warnings++;
        } else {
          console.log(`  ✗ ${name}: ${r.reason}`);
          problems++;
        }
      };

      const builtIns: DoctorCheck[] = [
        {
          name: "agent identity",
          run: async () => {
            const did = await safeReadAgentDid(opts.paths.agentKey);
            return did
              ? { ok: true, detail: did }
              : {
                  ok: false,
                  reason: `no agent.key at ${opts.paths.agentKey} — run '${opts.name} launch' to generate`,
                };
          },
        },
        {
          name: "delegation",
          run: async () => {
            const cert = await loadDelegation({
              certPath: opts.paths.delegation,
            }).catch((e) => ({ __err: (e as Error).message }) as const);
            if (cert && "__err" in cert) {
              return { ok: false, reason: `delegation malformed: ${cert.__err}` };
            }
            if (!cert) {
              return {
                ok: false,
                reason: `no delegation.json at ${opts.paths.delegation}`,
              };
            }
            const did = await safeReadAgentDid(opts.paths.agentKey);
            if (did && cert.bot_did !== did) {
              return {
                ok: false,
                reason: `delegation.bot_did ≠ agent.did (${cert.bot_did} vs ${did})`,
              };
            }
            return {
              ok: true,
              detail: `${cert.signature ? "signed" : "unsigned"} (bot=${cert.bot_did}, creator=${cert.creator_did})`,
            };
          },
        },
      ];

      if (opts.actorStatusUrl) {
        builtIns.push({
          name: "server actor record",
          run: async () => {
            const did = await safeReadAgentDid(opts.paths.agentKey);
            if (!did) return { ok: "warn", reason: "no identity to query" };
            try {
              const resp = await fetch(await opts.actorStatusUrl!(did));
              if (!resp.ok) {
                return { ok: false, reason: `${resp.status} ${resp.statusText}` };
              }
              const json = (await resp.json()) as Record<string, unknown>;
              const online = json.online === true ? "online" : "offline";
              const provenance = json.provenance as StoredProvenance | undefined;
              // Unverified is a warning, not a pass: the owner link is not
              // set up. The reason goes after a colon, since it may hold
              // parentheses of its own.
              if (provenance?._verified === true) {
                return { ok: true, detail: `${online}, provenance verified` };
              }
              return {
                ok: "warn",
                reason: `${online}, provenance unverified: ${provenance?._verification_reason ?? "—"}`,
              };
            } catch (e) {
              return {
                ok: false,
                reason: `actor api unreachable: ${(e as Error).message}`,
              };
            }
          },
        });
      }

      for (const c of builtIns) {
        try {
          print(c.name, await c.run());
        } catch (e) {
          print(c.name, { ok: false, reason: (e as Error).message });
        }
      }
      for (const c of opts.doctorChecks ?? []) {
        try {
          print(c.name, await c.run());
        } catch (e) {
          print(c.name, { ok: false, reason: (e as Error).message });
        }
      }

      console.log("");
      if (problems > 0) {
        console.log(
          `${problems} problem(s)${warnings > 0 ? `, ${warnings} warning(s)` : ""}.`,
        );
        process.exit(1);
      } else if (warnings > 0) {
        console.log(`All required checks passed (${warnings} warning(s)).`);
      } else {
        console.log("All checks passed.");
      }
    });
}

// ── tail ───────────────────────────────────────────────────────────────

function registerTail<O extends DaemonOpts>(
  program: Command,
  opts: CreateDaemonCLIOptions<O>,
): void {
  program
    .command("tail")
    .description(`Stream the daemon log (${opts.paths.daemonLog}).`)
    .option("-n, --lines <n>", "show the last N lines first", "40")
    .action(async (cmdOpts: { lines?: string }) => {
      const lines = cmdOpts.lines ?? "40";
      const proc = spawn("tail", ["-F", "-n", lines, opts.paths.daemonLog], {
        stdio: ["ignore", "inherit", "inherit"],
      });
      proc.on("error", (err) => {
        console.error(`tail failed: ${err.message}`);
        process.exit(1);
      });
      process.once("SIGINT", () => proc.kill("SIGTERM"));
    });
}

// ── helpers ────────────────────────────────────────────────────────────

/** Read pid file. Returns null if missing, malformed, or pointing at a
 *  process that no longer exists. */
export async function readPidIfAlive(pidPath: string): Promise<number | null> {
  let raw: string;
  try {
    raw = await readFile(pidPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const pid = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(pid) || pid <= 0) return null;
  try {
    // Signal 0: no-op, just checks process existence.
    process.kill(pid, 0);
    return pid;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return null;
    // EPERM: process exists but we lack permission to signal — treat as
    // alive (better than a false negative).
    return pid;
  }
}

/** Read agent.key and derive the DID, without re-creating if missing. */
async function safeReadAgentDid(seedPath: string): Promise<string | null> {
  try {
    await stat(seedPath);
  } catch {
    return null;
  }
  const id = await loadOrCreateIdentity({ seedPath }).catch(() => null);
  return id?.did ?? null;
}

/** Turn "my-bot" → "MY_BOT_", "swarm-coordinator" → "SWARM_COORDINATOR_". */
function envPrefix(name: string): string {
  return name.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase() + "_";
}
