// Long-lived freeqcc daemon: load identity + owner + delegation,
// connect to freeq, listen for DMs, dispatch owner DMs to claude.
//
// Phase 5 wires connect + announce + heartbeat. The DM gate + claude
// dispatch (phase 6) hangs off the returned client.
import { loadOrCreateIdentity, loadOrMintDelegation } from "@freeq/bot-kit";
import { loadOrPromptOwner } from "./owner.js";
import { connect, type Connected } from "./connect.js";
import { createTurnGate, type TurnGateState } from "@freeq/bot-kit";
import { readFile } from "node:fs/promises";
import writeFileAtomic from "write-file-atomic";
import { dispatchToClaudeStreaming } from "./dispatch.js";
import { logRefused } from "./audit.js";
import { actionsFor, createAccessMap, type AllowlistEntry } from "./allowlist.js";
import { paths, ensureDir } from "./paths.js";
import { writeFile } from "node:fs/promises";
import { TokenStore, startControlServer, type ControlServerHandle } from "./control.js";

interface DispatchTelemetry {
  dispatchCount: number;
  totalCostUsd: number;
  lastDispatchCostUsd: number;
  lastDispatchAt: string;
}

async function persistDispatchTelemetry(t: DispatchTelemetry): Promise<void> {
  try {
    await ensureDir();
    await writeFile(
      paths.dir + "/telemetry.json",
      JSON.stringify(t, null, 2) + "\n",
      { mode: 0o600 },
    );
  } catch {
    // best-effort
  }
}

export interface DaemonOptions {
  /** IRC nick. If omitted, derives from owner handle: `<owner>-agent` (truncated). */
  nick?: string;
  serverUrl?: string;
}

/** Default nick: `<owner-handle>-agent`, truncated to fit IRC nick limits. */
function deriveDefaultNick(handle: string): string {
  const base = handle.replace(/[^a-zA-Z0-9.-]/g, "").toLowerCase();
  const proposed = `${base}-agent`;
  // Most IRC servers cap nicks at 32; freeq is permissive but keep it sane.
  return proposed.length > 30 ? proposed.slice(0, 30) : proposed;
}

export async function runDaemon(opts: DaemonOptions = {}): Promise<Connected> {
  const agent = await loadOrCreateIdentity({ seedPath: paths.agentKey });
  const owner = await loadOrPromptOwner();
  const delegation = await loadOrMintDelegation({
    certPath: paths.delegation,
    agentDid: agent.did,
    ownerDid: owner.did,
  });
  const nick = opts.nick ?? deriveDefaultNick(owner.handle);

  console.log("─── freeqcc daemon ───");
  console.log(`agent DID:      ${agent.did}${agent.isFresh ? " (fresh)" : ""}`);
  console.log(`owner:          @${owner.handle} (${owner.did})`);
  console.log(`delegation:     ${delegation.signature ? "signed" : "unsigned (v1.0)"}`);
  console.log(`server:         ${opts.serverUrl ?? "wss://irc.freeq.at/irc"}`);
  console.log(`nick:           ${nick}`);
  console.log("──────────────────────");

  const conn = await connect({
    identity: agent,
    ownerDid: owner.did,
    delegation,
    nick,
    serverUrl: opts.serverUrl,
  });

  console.log(`✓ connected as ${conn.nick}`);
  console.log(`  DM @${conn.nick} from @${owner.handle} to talk to your local Claude Code.`);

  // ── Control socket (per-dispatch capability tokens) ──
  // Tokens are minted in handleDm, plumbed to the claude subprocess via env,
  // and used by `freeqcc send` to drive owner-authorized IRC actions
  // (JOIN/PART/PRIVMSG/NOTICE/NICK). Allowlisted non-owner DIDs get tokens
  // too, but with isOwner=false; today every action is owner-only and is
  // refused for non-owner tokens.
  const tokenStore = new TokenStore();
  const controlServer: ControlServerHandle = await startControlServer({
    store: tokenStore,
    sink: {
      raw: (line) => conn.client.raw(line),
      say: (target, text) => conn.client.sendMessage(target, text),
      notice: (target, text) => conn.client.sendNotice(target, text),
      get nick() { return conn.client.nick; },
    },
  });

  // ── Bot's own channel ──
  // The freeq web client creates / uses #<bot-nick> as the conversation
  // surface for bots, so messages a user thinks they're DMing actually
  // land there. Auto-join so we receive them. Channel messages from the
  // owner are routed through the same gate as DMs.
  const botChannel = `#${conn.nick}`;
  conn.client.raw(`JOIN ${botChannel}`);
  console.log(`  Auto-joined ${botChannel} (alternate conversation surface).`);

  // ── Raw wire debug (FREEQCC_DEBUG_RAW=1) ──
  if (process.env.FREEQCC_DEBUG_RAW === "1") {
    conn.client.on("raw", (line: string) => {
      // Dump every incoming line. Noisy but invaluable when DMs go missing.
      console.log(`[raw] ${line}`);
    });
  }

  // ── Owner-DID gate + claude dispatch (phase 6) ──
  //
  // We track sender DIDs via the SDK's `memberDid` event (fires on WHOIS).
  // For an unknown sender we fire WHOIS, queue the message for up to 3s,
  // and dispatch (or refuse) once the DID resolves.
  // Rate-limit + cycle-detection gate (bot-kit-owned semantics). State
  // is persisted to ~/.freeqcc/gate.json via write-file-atomic so a
  // crash mid-write never leaves a half-truncated state file.
  const gatePath = paths.dir + "/gate.json";
  const gate = await createTurnGate({
    load: async () => {
      try {
        return JSON.parse(await readFile(gatePath, "utf8")) as TurnGateState;
      } catch {
        return {
          lastRefusalAt: [],
          lastDispatchAt: 0,
          dispatchTimestamps: [],
          perPeerDispatches: [],
          cycleBackoffUntil: [],
        };
      }
    },
    save: async (state) =>
      writeFileAtomic(gatePath, JSON.stringify(state, null, 2) + "\n", {
        mode: 0o600,
      }),
  });
  // Hot-reloadable access map (replaces the old fs.watch / mtime-poll loop).
  // createAccessMap wraps bot-kit's createDidMap with freeqcc's JSON format
  // and atomic-write semantics; the daemon just reacts to changes here.
  const accessMap = await createAccessMap(paths.allowlist);
  const printAllowlist = (entries: AllowlistEntry[]): void => {
    if (entries.length === 0) return;
    console.log(`allowlist:      ${entries.length} extra DID(s) allowed beyond owner`);
    for (const e of entries) {
      const acts = e.actions && e.actions.length > 0 ? e.actions.join(",") : "chat-only";
      console.log(`  - ${e.did}${e.label ? ` (${e.label})` : ""} [${acts}]`);
    }
  };
  printAllowlist(accessMap.list());
  accessMap.onChange((entries) => {
    console.log(`[allowlist] reloaded — ${entries.length} entries`);
    printAllowlist(entries);
  });
  const persistGate = (): void => {
    void gate.persist().catch((err) => {
      console.warn(`[gate] persist failed: ${(err as Error).message}`);
    });
  };
  let totalCostUsd = 0;
  let dispatchCount = 0;

  // Pre-warm the cache for the owner so the first owner DM doesn't pay
  // a WHOIS round-trip. bot.resolveSenderDid's resolver will absorb the
  // memberDid response automatically.
  conn.client.raw(`WHOIS ${owner.handle}`);

  const handleDm = async (
    fromNick: string,
    text: string,
    msgTags: Record<string, string>,
    replyTarget: string,
  ): Promise<void> => {
    // Resolver: account-tag → in-bot cache (auto-populated by memberDid;
    // invalidated on userRenamed/userQuit + 5-min TTL) → WHOIS with 3s
    // race. Replaces the hand-rolled WHOIS dance + nickToDid map that
    // used to live here.
    const senderDid = await conn.resolveSenderDid({
      from: fromNick,
      tags: msgTags,
    });

    // Re-read allowlist each dispatch so live-reload edits take effect.
    const allowlist = accessMap.list();
    const allowedDids = allowlist.map((e) => e.did);

    // freeqcc's policy: owner is always allowed; allowlisted DIDs are
    // allowed; everyone else is refused. The gate doesn't know about
    // owner / allowlist — caller passes refusalReason when rejecting.
    // Owner is also exempt from cycle detection (humans, not bots).
    const isAllowed =
      senderDid !== null &&
      (senderDid === owner.did || allowedDids.includes(senderDid));
    const refusalReason = isAllowed
      ? undefined
      : senderDid
        ? "non-owner sender"
        : "could not verify your identity";
    const decision = gate.evaluate({
      senderDid,
      senderNick: fromNick,
      refusalReason,
      skipCycleDetection: senderDid === owner.did,
    });

    if (decision.kind === "silent") {
      return;
    }
    if (decision.kind === "refuse") {
      const allowlistMode = allowedDids.length > 0;
      const refusalText = senderDid
        ? `I'm @${owner.handle}'s agent. I only respond to ${allowlistMode ? "owner + allowlisted DIDs" : "them"}.`
        : `I'm @${owner.handle}'s agent and I couldn't verify your identity. I only respond to authenticated users on @${owner.handle}'s allowlist.`;
      conn.client.sendMessage(replyTarget, refusalText);
      await logRefused({
        ts: new Date().toISOString(),
        fromNick,
        fromDid: senderDid,
        text: text.slice(0, 200),
        reason: decision.reason,
      });
      console.log(`[refused] ${fromNick} (${senderDid ?? "no-did"}): ${decision.reason}`);
      persistGate();
      return;
    }

    // Dispatch — set executing presence, stream claude into the chat as it
    // produces tokens, then mark final.
    conn.client.raw("PRESENCE :state=executing;status=responding to owner");
    const isOwnerDispatch = senderDid === owner.did;
    console.log(`[dispatch] ${fromNick} → ${replyTarget}${isOwnerDispatch ? " (owner)" : " (allowlisted)"}: ${text.slice(0, 80)}`);
    dispatchCount++;
    persistGate();

    // Mint a per-dispatch capability token. claude -p subprocess gets it via
    // env; if claude calls `freeqcc send`, the daemon validates the token
    // and checks per-action whether it's in the granted set.
    const grantedActions = actionsFor(senderDid ?? "", owner.did, allowlist);
    const dispatchToken = tokenStore.mint({
      isOwner: isOwnerDispatch,
      actions: grantedActions,
      senderDid,
      replyTarget,
    });

    // Streaming bookkeeping. The first PRIVMSG carries +freeq.at/streaming=1
    // and the SDK auto-includes msgid in tags. Server overwrites msgid with
    // its own; we recover the assigned msgid via echo-message (SDK emits a
    // self message event with msg.id once the server has acked).
    let streamMsgId: string | null = null;
    let streamSent = false;
    let pendingFlush: NodeJS.Timeout | null = null;
    let lastFlushedText = "";
    let latestText = "";
    const FLUSH_INTERVAL_MS = 500;

    // Listen for our own echo to capture the server-assigned msgid.
    const onEcho = (
      _channel: string,
      msg: { id?: string; isSelf?: boolean; tags?: Record<string, string> },
    ): void => {
      if (!msg.isSelf || streamMsgId) return;
      if (msg.tags?.["+freeq.at/streaming"] !== "1") return;
      if (msg.id) streamMsgId = msg.id;
    };
    conn.client.on("message", onEcho);

    const sendStreamingPrivmsg = (chunkText: string): void => {
      // Initial: tag streaming=1, no edit ref. SDK assigns msgid via echo.
      const safe = chunkText.replace(/[\r\n]/g, " ").slice(0, 1500) || "…";
      conn.client.sendTagged(replyTarget, safe, { "+freeq.at/streaming": "1" });
      streamSent = true;
      lastFlushedText = chunkText;
    };

    const sendStreamingEdit = (chunkText: string, isFinal: boolean): void => {
      if (!streamMsgId) return; // can't edit without msgid yet
      const safe = chunkText.replace(/[\r\n]/g, " ").slice(0, 1500) || "…";
      const tags: Record<string, string> = { "+draft/edit": streamMsgId };
      if (!isFinal) tags["+freeq.at/streaming"] = "1";
      conn.client.sendTagged(replyTarget, safe, tags);
      lastFlushedText = chunkText;
    };

    const flush = (isFinal: boolean): void => {
      if (latestText === lastFlushedText && !isFinal) return;
      if (!streamSent) {
        sendStreamingPrivmsg(latestText);
      } else {
        sendStreamingEdit(latestText, isFinal);
      }
    };

    const scheduleFlush = (): void => {
      if (pendingFlush) return;
      pendingFlush = setTimeout(() => {
        pendingFlush = null;
        flush(false);
      }, FLUSH_INTERVAL_MS);
    };

    try {
      await dispatchToClaudeStreaming(
        text,
        {
        onChunk: (accumulated) => {
          latestText = accumulated;
          if (!streamSent) {
            // First chunk: send immediately so msgid lookup starts.
            sendStreamingPrivmsg(accumulated);
          } else {
            scheduleFlush();
          }
        },
        onComplete: async (final, _sessionId, durationMs, costUsd) => {
          if (typeof costUsd === "number" && Number.isFinite(costUsd)) {
            totalCostUsd += costUsd;
            // Record per-conversation cost so /freeqcc status can show it.
            void persistDispatchTelemetry({
              dispatchCount,
              totalCostUsd,
              lastDispatchCostUsd: costUsd,
              lastDispatchAt: new Date().toISOString(),
            });
          }
          if (pendingFlush) {
            clearTimeout(pendingFlush);
            pendingFlush = null;
          }
          latestText = final || latestText || "(claude returned empty)";
          if (!streamSent) {
            // Never streamed (model returned only the result event).
            // Fire one PRIVMSG with the final text, no streaming tag.
            const safe = latestText.replace(/[\r\n]/g, " ").slice(0, 1500);
            conn.client.sendMessage(replyTarget, safe);
          } else {
            // We sent a streaming PRIVMSG but the echo with the server-
            // assigned msgid may not have arrived yet. Wait up to 2s; if
            // no msgid, fall back to a fresh PRIVMSG (the streaming-tagged
            // first chunk will look incomplete to clients, but at least
            // the user gets the final reply).
            const deadline = Date.now() + 2000;
            while (!streamMsgId && Date.now() < deadline) {
              await new Promise((r) => setTimeout(r, 50));
            }
            if (streamMsgId) {
              flush(true); // final edit clears the streaming tag
            } else {
              const safe = latestText.replace(/[\r\n]/g, " ").slice(0, 1500);
              conn.client.sendMessage(replyTarget, safe);
              console.warn(
                `[stream] msgid never arrived via echo — sent fallback PRIVMSG`,
              );
            }
          }
          console.log(
            `[reply] ${durationMs}ms: ${latestText.slice(0, 80)}`,
          );
          tokenStore.expire(dispatchToken);
        },
        onError: (err) => {
          if (pendingFlush) {
            clearTimeout(pendingFlush);
            pendingFlush = null;
          }
          const message = (err as Error).message;
          if (streamSent && streamMsgId) {
            conn.client.sendTagged(
              replyTarget,
              `(claude error: ${message.slice(0, 200)})`,
              { "+draft/edit": streamMsgId },
            );
          } else {
            conn.client.sendMessage(
              replyTarget,
              `(error invoking claude: ${message.slice(0, 200)})`,
            );
          }
          console.error(`[dispatch error]`, err);
          tokenStore.expire(dispatchToken);
        },
      },
        {
          controlSock: paths.controlSock,
          token: dispatchToken,
          isOwner: isOwnerDispatch,
          grantedActions,
          replyTarget,
          senderDid,
          ownerDid: owner.did,
        },
      );
    } finally {
      conn.client.off("message", onEcho);
      conn.client.raw("PRESENCE :state=online");
      // Belt-and-suspenders: expire even if the SDK crashed before callbacks.
      tokenStore.expire(dispatchToken);
    }
  };

  conn.client.on(
    "message",
    (
      channel: string,
      msg: {
        from: string;
        text: string;
        isSelf?: boolean;
        tags?: Record<string, string>;
      },
    ) => {
      if (msg.isSelf) return;
      const isChannel = channel.startsWith("#") || channel.startsWith("&");

      if (!isChannel) {
        // Direct DM — sender nick is the conversation partner.
        void handleDm(msg.from, msg.text, msg.tags ?? {}, msg.from).catch((e) => {
          console.error("[handleDm error]", e);
        });
        return;
      }

      // Channel message. The bot's own channel (#<bot-nick>) is treated as
      // a DM surface — every message goes through the gate as if it were a
      // DM. This mirrors how freeq web clients deliver "DMs to a bot".
      if (channel.toLowerCase() === botChannel.toLowerCase()) {
        void handleDm(msg.from, msg.text, msg.tags ?? {}, channel).catch((e) => {
          console.error("[handleDm error]", e);
        });
        return;
      }

      // Other channels: only respond when explicitly addressed. bot-kit's
      // checkMention owns the matcher + per-channel cooldown. Default
      // matcher accepts `@<nick>` or `<nick>:`/`<nick>,` anywhere (with
      // word boundary); bare `<nick>` references are ignored.
      const m = conn.checkMention(channel, msg.text);
      if (m.kind === "ignore") return;
      if (m.kind === "cooldown") {
        console.log(
          `[mention cooldown] ${channel}: silent (${Math.round(m.remainingMs / 1000)}s remaining)`,
        );
        return;
      }
      void handleDm(msg.from, m.stripped || msg.text, msg.tags ?? {}, channel).catch((e) => {
        console.error("[handleDm error]", e);
      });
    },
  );

  // Compose the shutdown sequence: control socket → connection. pid-file
  // cleanup + SIGINT/SIGTERM wiring are owned by the createDaemonCLI
  // scaffold in cli.ts.
  return {
    ...conn,
    stop: async (reason: string) => {
      try {
        await controlServer.close();
      } catch {
        // best-effort — socket may already be gone
      }
      await conn.stop(reason);
    },
  };
}
