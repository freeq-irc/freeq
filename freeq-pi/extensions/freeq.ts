/**
 * @freeq/pi — multiplayer pi over freeq.
 *
 * This file is the pi adapter: it maps pi's extension API onto the freeq
 * runtime in @freeq/harness-kit (`AgentRuntime`), and draws freeq in pi's
 * TUI (the inbound card, room lines, footer, title, offer card, mark, peers
 * widget and autocomplete).
 *
 * Hard rules enforced here and in the runtime (build spec §4):
 *   - zero pi core changes; documented extension surfaces only
 *   - remote input never invokes local tools directly: it becomes a framed,
 *     tier-gated user message, and the local agent decides what to do
 *   - content reaches the model in exactly ONE place (the runtime's
 *     `deliver`, which calls `harness.deliver` below), gated by
 *     `decideInbound` — no other code path may inject remote input
 *   - no filesystem paths in advertised presence
 *   - connection failure degrades to offline, never breaks the session
 *   - one installation identity; sessions are metadata
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { Container, Text } from "@earendil-works/pi-tui";

import { tierFor, type FreeqConfig, type Tier } from "@freeq/harness-kit/config";
import { McpStdioClient } from "../src/mcp-stdio.js";
import { addressedUtterances, parseListenResult, toBridgeCall, type AvParams } from "../src/av.js";
import { setLogger } from "@freeq/sdk";
import {
  footerLine,
  inboundCardParts,
  offerCardLines,
  roomLineParts,
  type RoomLineInput,
} from "@freeq/harness-kit/ui";
import { markForTerminal, supportsTruecolor, WORDMARK } from "../src/logo.js";
import { peerColor } from "@freeq/harness-kit/ui";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { JOURNAL_ENTRY, notesFor } from "@freeq/harness-kit/journal";
import { homedir } from "node:os";
import { join as joinPath } from "node:path";
import { AgentRuntime } from "@freeq/harness-kit/runtime";
import { FREEQ_TOOL_DESCRIPTION } from "@freeq/harness-kit/tool";
import type { Harness } from "@freeq/harness-kit/harness";

export default function (pi: ExtensionAPI): void {
  /**
   * The context of the pi event being handled. The harness reads the
   * session's cwd, model, idleness and UI from it; every handler below
   * records its own before calling into the runtime.
   */
  let lastCtx: ExtensionContext | undefined;
  const track = (ctx: ExtensionContext | undefined): void => {
    if (ctx) lastCtx = ctx;
  };

  /** pi as a freeq harness. */
  const harness: Harness = {
    name: "pi",
    commandHint: (sub) => `/freeq ${sub}`,
    get agentDir() {
      return getAgentDir();
    },
    configDirName: CONFIG_DIR_NAME,
    projectTrusted: () => lastCtx?.isProjectTrusted() ?? false,
    cwd: () => lastCtx?.cwd ?? process.cwd(),
    modelId: () => lastCtx?.model?.id,
    deliver: (msg) => {
      // A custom message, not sendUserMessage: the model receives the framed
      // content, but the transcript renders it as a coloured freeq card
      // (renderer below) instead of pretending the operator typed it.
      //
      // deliverAs is REQUIRED while streaming; omitting it throws. When idle,
      // pi sends immediately and triggers a turn. `followUp` waits for the
      // agent to have NO more tool calls - i.e. until the whole task is done,
      // every build and test run included. Someone talking to a working agent
      // got silence for ten minutes and then four answers at once. `steer`
      // delivers after the current tool call, before the next model call: the
      // agent finishes what it is doing, reads the message, and can answer
      // before continuing. The runtime asks for it (`interrupt`) only for
      // addressed input from `request` tier and up.
      pi.sendMessage(
        {
          customType: "freeq-inbound",
          content: msg.content,
          display: true,
          details: msg.card satisfies FreeqInboundDetails,
        },
        { deliverAs: msg.interrupt ? "steer" : "followUp", triggerTurn: true },
      );
    },
    notify: (text, level) => lastCtx?.ui.notify(text, level),
    confirm: async (title, body) => (lastCtx ? lastCtx.ui.confirm(title, body) : false),
    isIdle: () => lastCtx?.isIdle() ?? false,
    journal: {
      // `appendEntry` persists in the pi session log without entering model
      // context, so the journal costs nothing until the task is resumed.
      append: (note) => pi.appendEntry(JOURNAL_ENTRY, note),
      read: (taskId) => notesFor(lastCtx?.sessionManager.getEntries() ?? [], taskId),
    },
    roomLine: (input) => {
      if (input.direction === "out") receipt(input);
      else surface(input);
    },
    stateChanged: () => refreshUi(),
    connected: () => {
      if (!lastCtx) return;
      refreshUi(lastCtx);
      showMarkOnce(lastCtx);
    },
    roster: (title, lines, dids) => {
      const ctx = lastCtx;
      if (!ctx) return;
      // A widget rather than a toast: the roster is something you read and
      // compare, and each row is coloured by its peer's DID so the same
      // correspondent is recognisable at a glance across sessions.
      ctx.ui.setWidget("freeq-peers", (_tui, theme) => {
        const box = new Container();
        box.addChild(new Text(theme.fg("toolTitle", theme.bold(title)), 1, 0));
        lines.forEach((line, i) => {
          box.addChild(new Text(theme.fg(peerColor(dids[i]), line), 1, 0));
        });
        box.addChild(new Text(theme.fg("dim", "  (clears on your next turn)"), 1, 0));
        return box;
      });
      peersVisible = true;
      setTimeout(() => clearPeers(ctx), 30_000).unref?.();
    },
    doctorLines: async () => [
      rt.passive
        ? {
            name: "this window",
            status: "warn",
            detail: "passive — another pi session holds the connection (/freeq takeover)",
          }
        : rt.conn
          ? { name: "this window", status: "ok", detail: "holds the connection" }
          : { name: "this window", status: "warn", detail: "holds no connection" },
    ],
    stepBegan: (phrase) => {
      // In a call, the tile is the room's window into this agent: the phrase
      // belongs there too, not only in presence strings.
      if (av && avChannel) {
        try {
          const call = toBridgeCall(
            { action: "show", title: "⚙ working", bullets: [phrase] },
            (t) => rt.conn?.scrubForWire(t, avChannel!) ?? t,
          );
          void av.call(call.tool, call.args, 15_000).catch(() => {});
        } catch {
          /* the tile is decoration; never let it break a turn */
        }
      }
    },
  };

  const rt = new AgentRuntime(harness);

  // ── inline rendering ──────────────────────────────────────────────────
  //
  // freeq traffic is first-class transcript content, not toasts: a message
  // that reaches the model is a coloured card (who, where, at what
  // authority), and room chatter is a live entry line coloured by speaker.
  // The MODEL still receives the security frame as message content — the
  // card is presentation only, so the tier gate and framing are untouched.

  /** details payload carried on every injected freeq message. */
  interface FreeqInboundDetails {
    kind: "chat" | "ask";
    channel: string;
    from: string;
    did: string | null;
    tier: Tier;
    text: string;
    reason: string;
    expectsReply: boolean;
  }

  pi.registerMessageRenderer("freeq-inbound", (message, { expanded, outputPad }, theme) => {
    const d = message.details as FreeqInboundDetails | undefined;
    if (!d) {
      const raw = typeof message.content === "string" ? message.content : "";
      return new Text(raw, outputPad, 0);
    }
    const p = inboundCardParts({
      kind: d.kind,
      channel: d.channel,
      from: d.from,
      tier: d.tier,
      text: d.text,
    });
    const box = new Container();
    box.addChild(
      new Text(
        theme.fg("accent", `${p.icon} ${p.venue}`) +
          theme.fg("dim", " · ") +
          theme.fg(peerColor(d.did ?? undefined), p.from) +
          theme.fg("dim", ` · ${p.badge}`),
        outputPad,
        0,
      ),
    );
    for (const line of p.body.split("\n")) box.addChild(new Text(line, outputPad, 0));
    if (expanded) {
      box.addChild(
        new Text(
          theme.fg("dim", `${d.reason}${d.expectsReply ? " · the next reply goes back over freeq" : ""}`),
          outputPad,
          0,
        ),
      );
    }
    return box;
  });

  /**
   * Room entries: `{ type: "line", … }` per message, or a coalesced
   * `{ type: "more", count }` when a burst overflowed. Never sent to the
   * model — this is the transcript's view of the room, not its content.
   */
  type FreeqRoomData =
    | ({ type: "line" } & RoomLineInput)
    | { type: "more"; count: number };

  pi.registerEntryRenderer("freeq-room", (entry, { expanded }, theme) => {
    const d = entry.data as FreeqRoomData | undefined;
    if (!d) return undefined;
    if (d.type === "more") {
      return new Text(
        theme.fg("dim", `  … ${d.count} more room message${d.count === 1 ? "" : "s"}`),
        1,
        0,
      );
    }
    const p = roomLineParts(d, expanded ? 1000 : 160);
    const line =
      theme.fg("dim", `${p.arrow} `) +
      theme.fg("accent", p.venue) +
      " " +
      theme.fg(peerColor(d.did), `<${p.from}>`) +
      " " +
      p.text +
      (p.note ? theme.fg("dim", `  (${p.note})`) : "");
    return new Text(line, 1, 0);
  });


  /** Show something we posted to freeq in the transcript, as a receipt. */
  function receipt(input: RoomLineInput): void {
    try {
      pi.appendEntry("freeq-room", { type: "line", ...input } satisfies FreeqRoomData);
    } catch {
      /* best-effort */
    }
  }

  /**
   * OBSERVE-tier traffic is surfaced, not injected — and now it is surfaced
   * LIVE: each room message becomes one coloured entry line in the
   * transcript the moment it arrives, rather than a toast batch every four
   * seconds that scrolled away and was gone.
   *
   * The guard against a busy room is burst coalescing, not batching: more
   * than BURST_MAX lines inside BURST_WINDOW collapses the overflow into a
   * single "… and N more" entry once the burst settles, so a flood cannot
   * bury the transcript (or bloat the session file — entries persist).
   */
  const BURST_WINDOW_MS = 3_000;
  const BURST_MAX = 8;
  let burstCount = 0;
  let burstOverflow = 0;
  let burstTimer: NodeJS.Timeout | undefined;
  function surface(input: RoomLineInput): void {
    try {
      if (burstCount < BURST_MAX) {
        burstCount++;
        pi.appendEntry("freeq-room", { type: "line", ...input } satisfies FreeqRoomData);
      } else {
        burstOverflow++;
      }
    } catch {
      /* best-effort */
    }
    if (burstTimer) {
      clearTimeout(burstTimer);
    }
    burstTimer = setTimeout(() => {
      burstTimer = undefined;
      burstCount = 0;
      if (burstOverflow > 0) {
        const n = burstOverflow;
        burstOverflow = 0;
        try {
          pi.appendEntry("freeq-room", { type: "more", count: n } satisfies FreeqRoomData);
        } catch {
          /* best-effort */
        }
      }
    }, BURST_WINDOW_MS);
    burstTimer.unref?.();
  }

  /**
   * Paint everything persistent from current state: footer status, terminal
   * title, and the offer card above the editor. Called from every event that
   * changes any of it, and cheap enough to call generously - it renders from
   * memory and pi coalesces redraws.
   *
   * Before this the extension used exactly two UI primitives, notify and
   * confirm. Every fact scrolled past as a toast and was gone; you could not
   * glance at the terminal and see that you were online, who was around, or
   * that work was waiting for you.
   */
  /**
   * The freeq mark, once per session, on the first successful connect. Not
   * on reconnect - a mark that repaints every time the socket blips is noise.
   * Rendered as a widget above the editor and cleared on the next turn, so it
   * is a greeting, not furniture.
   */
  let markShown = false;
  function showMarkOnce(ctx: ExtensionContext): void {
    if (markShown || !ctx.hasUI) return;
    markShown = true;
    const lines = supportsTruecolor() ? markForTerminal() : [];
    if (lines.length === 0) {
      ctx.ui.notify(`${WORDMARK} · connected as ${rt.conn?.nick ?? "?"}`, "info");
      return;
    }
    const caption = `  ${rt.conn?.nick ?? "?"} · ${rt.config?.channels.join(" ") ?? ""}`;
    // A component factory, not a string[]: pi truncates an array widget at
    // MAX_WIDGET_LINES (10) and says so, which is how the mark first shipped
    // with its ears cut off. The factory path has no such cap.
    ctx.ui.setWidget("freeq-mark", (_tui, theme) => {
      const box = new Container();
      for (const line of lines) box.addChild(new Text(line, 1, 0));
      box.addChild(new Text(theme.fg("muted", caption), 1, 0));
      return box;
    });
    markVisible = true;
    // A greeting should not outlive the hello: cleared on the next model
    // turn (handler below), or after 20s, whichever first.
    setTimeout(() => clearMark(ctx), 20_000).unref?.();
  }
  let markVisible = false;
  function clearMark(ctx: ExtensionContext): void {
    if (!markVisible) return;
    markVisible = false;
    ctx.ui.setWidget("freeq-mark", undefined);
  }
  /** `/freeq status` shows the mark too, for twelve seconds. */
  function showStatusMark(ctx: ExtensionContext): void {
    if (ctx.hasUI && supportsTruecolor()) {
      const lines = markForTerminal();
      if (lines.length) {
        ctx.ui.setWidget("freeq-mark", (_tui, _theme) => {
          const box = new Container();
          for (const line of lines) box.addChild(new Text(line, 1, 0));
          return box;
        });
        markVisible = true;
        setTimeout(() => clearMark(ctx), 12_000).unref?.();
      }
    }
  }
  let peersVisible = false;
  function clearPeers(ctx: ExtensionContext): void {
    if (!peersVisible) return;
    peersVisible = false;
    ctx.ui.setWidget("freeq-peers", undefined);
  }
  pi.on("turn_start", async (_e, ctx) => {
    track(ctx);
    clearMark(ctx);
    clearPeers(ctx);
    rt.onTurnStart();
  });

  let uiCtx: ExtensionContext | undefined;
  function refreshUi(ctx?: ExtensionContext): void {
    const c = ctx ?? uiCtx;
    if (!c?.hasUI) return;
    uiCtx = c;
    const online = rt.conn?.state === "online";
    const waiting = rt.offers?.all() ?? [];
    const store = rt.handoffs;

    c.ui.setStatus(
      "freeq",
      footerLine({
        online,
        passive: rt.passive,
        nick: rt.conn?.nick,
        // Confirmed joins, not configured ones: the footer's job is to say
        // where we ARE. A refused channel shows as a shortfall, not a count.
        channels: rt.conn?.joinedChannels().length ?? 0,
        channelsRefused: rt.conn?.refusedChannels().length ?? 0,
        withheld: rt.withheld.size,
        dormant: rt.dormant,
        peers: rt.conn?.peers().length ?? 0,
        offersWaiting: waiting.length,
        working: rt.currentLabel(),
        inCall: avChannel,
      }, rt.names),
    );

    // Title: which agent this window is, so a row of terminals reads.
    if (online && rt.conn?.nick) c.ui.setTitle(`pi · ${rt.conn.nick}`);

    // Offer card: the oldest waiting offer, until acted on. Rendered as a
    // component factory rather than a string[] so it picks up theme colours
    // — a plain monochrome box read as scaffolding, not as a thing to act on.
    const first = waiting[0];
    const rec = first && store ? store.get(first.taskId) : undefined;
    if (rec && rt.config) {
      const width = Math.min(100, Math.max(56, (process.stdout.columns ?? 80) - 4));
      const cardLines = offerCardLines(
        {
          taskId: rec.id,
          title: rec.title,
          from: rec.lastActor ?? rec.offerer.slice(0, 16),
          tier: tierFor(rt.config, rec.offerer),
          queuedAt: first.queuedAt,
          deadline: rec.deadline,
          brief: rec.note,
        },
        width,
        rt.names,
      );
      c.ui.setWidget("freeq-offer", (_tui, theme) => {
        const box = new Container();
        cardLines.forEach((line, i) => {
          let t: Text;
          if (i === 0 || i === cardLines.length - 1) {
            // The frame: an offer demands a decision, so it is warning-toned.
            t = new Text(theme.fg("warning", line), 1, 0);
          } else if (i === 1) {
            t = new Text(theme.fg("toolTitle", theme.bold(line)), 1, 0);
          } else if (line.includes("/freeq accept")) {
            t = new Text(theme.fg("accent", line), 1, 0);
          } else {
            t = new Text(theme.fg("muted", line), 1, 0);
          }
          box.addChild(t);
        });
        return box;
      });
    } else {
      c.ui.setWidget("freeq-offer", undefined);
    }
  }

  // ── lifecycle ───────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    track(ctx);
    uiCtx = ctx;
    // The SDK used to write diagnostics straight to the console, which in a
    // full-screen TUI means straight over whatever the renderer had drawn —
    // a flapping connection painted one "dropped message" line per heartbeat
    // across the layout and left it corrupted until a repaint. pi owns this
    // screen, so the SDK's diagnostics come here instead: errors surface as
    // notices, everything quieter is dropped rather than drawn.
    setLogger({
      error: (m, ...a) => rt.notify(`freeq sdk: ${m} ${a.join(" ")}`.trim(), "error"),
      warn: () => {},
      debug: () => {},
    });
    await rt.start();
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    track(ctx);
    await hangup("session shutdown");
    await rt.stop();
  });

  // Report "working" for the whole run, and go quiet again when it settles.
  pi.on("agent_start", async (_event, ctx) => {
    track(ctx);
    rt.onRunStart();
  });

  // A typed prompt becomes the step phrase. Injected freeq input is role
  // 'custom' and skips this (deliver already named that step); the runtime's
  // '[freeq —' guard covers anything framed as a plain user message.
  pi.on("message_start", async (event, ctx) => {
    track(ctx);
    const m = (event as { message?: { role?: string; content?: unknown } }).message;
    if (m?.role !== "user") return;
    const text = Array.isArray(m.content)
      ? m.content
          .filter((c): c is { type: "text"; text: string } =>
            !!c && typeof c === "object" && (c as { type?: string }).type === "text",
          )
          .map((c) => c.text)
          .join("\n")
      : typeof m.content === "string"
        ? m.content
        : "";
    rt.onUserPrompt(text);
  });

  // Name the current tool so a watcher sees movement, and note anything that
  // counts as a consequence for the log.
  pi.on("tool_call", async (event, ctx) => {
    track(ctx);
    const e = event as { toolName?: string; input?: Record<string, unknown> };
    rt.onToolCall(e.toolName, e.input);
  });

  // Capture assistant text so an inbound ask can be answered with it.
  pi.on("turn_end", async (event, ctx) => {
    track(ctx);
    const content = (event as { message?: { content?: unknown } }).message?.content;
    if (!Array.isArray(content)) return;
    const text = content
      .filter((c): c is { type: "text"; text: string } =>
        !!c && typeof c === "object" && (c as { type?: string }).type === "text",
      )
      .map((c) => c.text)
      .join("\n")
      .trim();
    const hasToolCalls = content.some(
      (c) => !!c && typeof c === "object" && (c as { type?: string }).type === "toolCall",
    );
    rt.onTurnEnd(text, hasToolCalls);
  });

  pi.on("agent_settled", async (_event, ctx) => {
    track(ctx);
    await rt.onSettled();
  });

  // ── the tool ────────────────────────────────────────────────────────────

  // ── Voice: join a freeq AV call ────────────────────────────────────────
  //
  // The AV bridge (freeq-claude-mcp) is an MCP server: it joins a call, runs
  // STT, speaks via TTS, projects a visual tile. Until now only Claude Code
  // could drive it, because only Claude Code speaks MCP. pi drives it here
  // through the small stdio client in src/mcp-stdio.ts.
  //
  // What comes IN from the call goes through the same tier-gated `deliver`
  // as a channel message: a voice line addressed to the agent is an inbound
  // event from a server-resolved participant, not a privileged instruction.
  // What goes OUT is under the model's control via the `freeq_av` tool.

  let av: McpStdioClient | undefined;
  let avChannel: string | undefined;
  let avListening = false;

  /** Where the bridge binary is. Built by `cargo build --release -p freeq-claude-mcp`. */
  function avBinary(): string | undefined {
    const candidates = [
      process.env.FREEQ_AV_BRIDGE,
      joinPath(homedir(), "src", "freeq", "target", "release", "freeq-claude-mcp"),
    ].filter((c): c is string => !!c);
    return candidates.find((c) => existsSync(c));
  }

  /**
   * STT/TTS keys. Read from the environment first; failing that, from Claude
   * Code's settings, which is where the AV skill has always kept them. They
   * are handed to the bridge process and never logged or written.
   */
  async function avEnv(): Promise<NodeJS.ProcessEnv> {
    const env: NodeJS.ProcessEnv = {};
    const want = ["GROQ_API_KEY", "ELEVENLABS_API_KEY", "FREEQ_ELEVEN_VOICE_ID", "FREEQ_ELEVEN_MODEL"];
    for (const k of want) if (process.env[k]) env[k] = process.env[k];
    if (!env.GROQ_API_KEY || !env.ELEVENLABS_API_KEY) {
      try {
        const raw = await readFile(joinPath(homedir(), ".claude", "settings.json"), "utf8");
        const settings = JSON.parse(raw) as { env?: Record<string, string> };
        for (const k of want) if (!env[k] && settings.env?.[k]) env[k] = settings.env[k];
      } catch {
        /* no Claude settings; the bridge will say what it is missing */
      }
    }
    return env;
  }

  async function hangup(reason: string): Promise<void> {
    avListening = false;
    const client = av;
    av = undefined;
    const ch = avChannel;
    avChannel = undefined;
    if (!client) return;
    try {
      if (client.alive) await client.call("freeq_disconnect", {}, 5_000);
    } catch {
      /* leaving is best-effort */
    }
    await client.close();
    if (ch) rt.pushStatus("active", undefined, undefined, true);
    void reason;
  }

  /**
   * Long-poll the bridge for transcripts and feed addressed ones to the
   * model. Runs until hangup. Unaddressed lines are what the room is saying
   * to each other - context, not a request - so they are not delivered; the
   * model can ask for recent context with freeq_av(freeq_recall) if it needs
   * it.
   */
  async function listenLoop(ctx: ExtensionContext, cfg: FreeqConfig): Promise<void> {
    while (avListening && av?.alive) {
      let result;
      try {
        // The bridge long-polls; give it generous room before we call it hung.
        result = await av.call("freeq_listen", {}, 70_000);
      } catch (err) {
        if (!avListening) return;
        rt.notify(`freeq call: listen failed - ${(err as Error).message}`, "warning");
        await new Promise((r) => setTimeout(r, 2_000));
        continue;
      }
      for (const u of addressedUtterances(parseListenResult(McpStdioClient.text(result)))) {
        if (!avChannel) break;
        rt.deliver({
          kind: "chat",
          channel: avChannel,
          from: u.from,
          did: null,
          text: u.text,
          addressed: true,
          mode: cfg.muted ? "silent" : "addressed",
          tier: tierFor(cfg, null),
        });
      }
    }
  }

  pi.registerTool({
    name: "freeq_av",
    label: "freeq call",
    description:
      "Act in the freeq voice call this session has joined with /freeq call. " +
      "'say' speaks a line (TTS) and posts it to the channel; 'post' drops text " +
      "in the channel without speaking (links, code, decisions); 'show' puts a " +
      "card on your video tile; 'show_file' renders a file slice; 'show_diff' a " +
      "diff; 'participants' lists who is on the call; 'recall' searches recent " +
      "transcript; 'status' sets your visual state (listening/thinking/presenting/idle). " +
      "Use 'say' for what you would say out loud and 'post' for what people will " +
      "want to scroll back to. Never speak secrets or absolute paths.",
    parameters: Type.Object({
      action: Type.Union([
        Type.Literal("say"),
        Type.Literal("post"),
        Type.Literal("show"),
        Type.Literal("show_file"),
        Type.Literal("show_diff"),
        Type.Literal("participants"),
        Type.Literal("recall"),
        Type.Literal("status"),
      ]),
      text: Type.Optional(Type.String({ description: "For say/post: the words. For recall: the query." })),
      priority: Type.Optional(
        Type.Union([Type.Literal("addressed"), Type.Literal("volunteer")], {
          description: "For say: 'addressed' always speaks; 'volunteer' respects the room's cooldown.",
        }),
      ),
      title: Type.Optional(Type.String()),
      bullets: Type.Optional(Type.Array(Type.String())),
      path: Type.Optional(Type.String({ description: "For show_file/show_diff: file path in the working tree." })),
      lines: Type.Optional(Type.String({ description: "For show_file/show_diff: a line range like 40-80." })),
      label: Type.Optional(Type.String({ description: "For status: listening | thinking | presenting | idle" })),
    }),
    async execute(_id, params) {
      const out = (text: string, isError = false) => ({
        content: [{ type: "text" as const, text }],
        details: {},
        isError,
      });
      if (!av?.alive || !avChannel) {
        return out("Not in a call. Ask the user to run /freeq call #channel.", true);
      }
      const channel = avChannel;
      const { tool, args } = toBridgeCall(params as AvParams, (t) =>
        rt.conn ? rt.conn.scrubForWire(t, channel) : t,
      );
      const r = await av.call(tool, args, 30_000);
      return out(McpStdioClient.text(r) || "(ok)", !!r.isError);
    },
  });

  pi.registerTool({
    name: "freeq",
    label: "freeq",
    description: FREEQ_TOOL_DESCRIPTION,
    parameters: Type.Object({
      action: Type.Union(
        [
          Type.Literal("peers"),
          Type.Literal("ask"),
          Type.Literal("send"),
          Type.Literal("say"),
          Type.Literal("handoff"),
          Type.Literal("handoffs"),
          Type.Literal("complete"),
          Type.Literal("cancel"),
          Type.Literal("post"),
          Type.Literal("claim"),
          Type.Literal("accept"),
          Type.Literal("decline"),
          Type.Literal("decision"),
          Type.Literal("status"),
        ],
        { description: "What to do" },
      ),
      to: Type.Optional(
        Type.String({ description: "Peer nick for ask/send; peer DID or nick for handoff" }),
      ),
      channel: Type.Optional(Type.String({ description: "Channel like #dev, for say/handoff" })),
      message: Type.Optional(
        Type.String({
          description: "Message, question, completion note, or reason for 'cancel'",
        }),
      ),
      timeoutSec: Type.Optional(
        Type.Number({ description: "Seconds to wait for an ask reply (default 120)" }),
      ),
      title: Type.Optional(Type.String({ description: "Short title of the work, for handoff" })),
      brief: Type.Optional(
        Type.String({ description: "Full context the other agent needs, for handoff" }),
      ),
      taskId: Type.Optional(
        Type.String({ description: "Task id, for complete/cancel/claim" }),
      ),
      rationale: Type.Optional(
        Type.String({ description: "Why, for 'decision' — the part worth keeping" }),
      ),
      alternatives: Type.Optional(
        Type.String({ description: "What was rejected, for 'decision'" }),
      ),
      evidence: Type.Optional(
        Type.String({ description: "Commit, task id, file or URL backing a 'decision'" }),
      ),
      caps: Type.Optional(
        Type.String({
          description:
            "Capabilities a claimer should have, for 'post' — space-separated hints " +
            "like 'pi/lang:rust pi/repo:github.com/o/r'. Advisory only.",
        }),
      ),
    }),
    // What a call looks like in the transcript. The default is the raw JSON
    // arguments, which reads as plumbing; this reads as what it is - a message
    // to a named peer, or a piece of work offered to one.
    renderCall(args, theme) {
      const a = args as Record<string, unknown>;
      const who = (a.to as string | undefined) ?? (a.channel as string | undefined) ?? "";
      const verb = String(a.action ?? "");
      const icon: Record<string, string> = {
        ask: "?", send: "→", say: "#", handoff: "⇢", post: "⇢", claim: "✓", complete: "✔",
        cancel: "✗", peers: "⬡", handoffs: "≡", decision: "§", status: "⚙",
      };
      let line = theme.fg("toolTitle", theme.bold("freeq ")) + theme.fg("accent", `${icon[verb] ?? "·"} ${verb}`);
      // Colour the peer by their DID when we know it, so the same
      // correspondent looks the same across sessions and machines.
      const whoDid = rt.conn?.peers().find((p) => p.nick.toLowerCase() === who.toLowerCase())?.did;
      if (who) line += theme.fg("dim", " → ") + theme.fg(peerColor(whoDid), who);
      const text = (a.message as string | undefined) ?? (a.title as string | undefined);
      if (text) {
        const one = text.replace(/\s+/g, " ").trim();
        line += theme.fg("dim", `  "${one.length > 72 ? `${one.slice(0, 71)}…` : one}"`);
      }
      return new Text(line, 0, 0);
    },
    renderResult(result, { isPartial }, theme) {
      if (isPartial) return new Text(theme.fg("warning", "…waiting on the wire"), 0, 0);
      const text = result.content
        .filter((c): c is { type: "text"; text: string } => c.type === "text")
        .map((c) => c.text)
        .join("\n")
        .trim();
      const first = text.split("\n")[0] ?? "";
      const more = text.includes("\n") ? theme.fg("dim", `  (+${text.split("\n").length - 1} lines)`) : "";
      const tone = /^(No answer|Cannot|not |Error|failed)/i.test(first) ? "warning" : "success";
      return new Text(theme.fg(tone, first.length > 100 ? `${first.slice(0, 99)}…` : first) + more, 0, 0);
    },
    async execute(_id, params, _signal, _onUpdate, ctx) {
      track(ctx);
      const text = await rt.runTool(params);
      return { content: [{ type: "text" as const, text }], details: {} };
    },
  });

  // ── /freeq ──────────────────────────────────────────────────────────────

  // ── Autocomplete ───────────────────────────────────────────────────────
  //
  // Task ids are ULIDs and peer nicks are things like chad-bot-mdsnd. Nobody
  // types those. After `/freeq <sub> `, complete the argument from live
  // state: subcommands, then peers or task ids as the subcommand demands.
  const SUBCOMMANDS = [
    "status", "doctor", "peers", "join", "leave", "mode", "trust", "mute", "unmute", "on", "off",
    "handoffs", "tasks", "resume", "accept", "decline", "drop", "progress", "login", "authorize",
    "takeover", "verbosity", "provenance", "call", "hangup", "policy", "withheld",
  ];
  const TASK_SUBS = new Set(["accept", "decline", "drop", "progress", "resume"]);
  const PEER_SUBS = new Set(["trust"]);
  pi.on("session_start", async (_e, ctx) => {
    if (!ctx.hasUI) return;
    ctx.ui.addAutocompleteProvider((current) => ({
      triggerCharacters: [],
      async getSuggestions(lines, line, col, options) {
        const before = (lines[line] ?? "").slice(0, col);
        const m = before.match(/^\/freeq(?:\s+(\S*))?(?:\s+(\S*))?$/);
        if (!m) return current.getSuggestions(lines, line, col, options);
        const [, sub = "", arg] = m;
        // Completing the subcommand.
        if (arg === undefined) {
          const items = SUBCOMMANDS.filter((c) => c.startsWith(sub)).map((c) => ({ value: c, label: c }));
          return { prefix: sub, items };
        }
        // Completing the argument.
        if (TASK_SUBS.has(sub)) {
          const recs = rt.handoffs?.all() ?? [];
          const items = recs
            .filter((r) => r.id.toLowerCase().startsWith(arg.toLowerCase()))
            .slice(0, 12)
            .map((r) => ({ value: r.id.slice(0, 10), label: r.id.slice(0, 10), description: `${r.state} · ${r.title}` }));
          return { prefix: arg, items };
        }
        if (PEER_SUBS.has(sub)) {
          const items = (rt.conn?.peers() ?? [])
            .filter((p) => p.did)
            .filter((p) => p.nick.toLowerCase().startsWith(arg.toLowerCase()) || (p.did ?? "").startsWith(arg))
            .map((p) => ({ value: p.did!, label: p.nick, description: p.did }));
          return { prefix: arg, items };
        }
        if (sub === "join" || sub === "leave" || sub === "mode" || sub === "call") {
          const chans = (rt.config?.channels ?? []).filter((c) => c.startsWith(arg || "#"));
          return { prefix: arg, items: chans.map((c) => ({ value: c, label: c })) };
        }
        return current.getSuggestions(lines, line, col, options);
      },
      applyCompletion(lines, line, col, item, prefix) {
        return current.applyCompletion(lines, line, col, item, prefix);
      },
      shouldTriggerFileCompletion(lines, line, col) {
        const before = (lines[line] ?? "").slice(0, col);
        if (/^\/freeq\b/.test(before)) return false;
        return current.shouldTriggerFileCompletion?.(lines, line, col) ?? true;
      },
    }));
    refreshUi(ctx);
  });

  pi.registerCommand("freeq", {
    description: "freeq multiplayer: login, authorize, status, join, leave, peers, mode, trust, call, hangup",
    handler: async (args, ctx) => {
      track(ctx);
      const [sub = "status"] = args.trim().split(/\s+/).filter(Boolean);
      if (sub === "status") showStatusMark(ctx);
      await rt.runCommand(args);
    },
  });
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

