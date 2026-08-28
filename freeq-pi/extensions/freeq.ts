/**
 * @freeq/pi — multiplayer pi over freeq.
 *
 * M1 scope: identity, connection, presence, `/freeq` commands.
 * M2 adds the `freeq` tool and the tiered inbound pipeline; inbound messages
 * are currently surfaced in the TUI only and NEVER injected into the model.
 *
 * Hard rules enforced here (build spec §4):
 *   - zero pi core changes; extension surfaces only
 *   - no filesystem paths in advertised presence
 *   - connection failure degrades to offline, never breaks the session
 *   - one installation identity; sessions are metadata
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";

import {
  loadConfig,
  saveConfig,
  modeFor,
  tierFor,
  MODES,
  type FreeqConfig,
  type Mode,
} from "../src/config.js";
import { deriveInstallSlug, defaultNick, isDid } from "../src/identity.js";
import { collectSessionMeta, describeMeta } from "../src/presence.js";
import { FreeqConnection } from "../src/connection.js";

export default function (pi: ExtensionAPI): void {
  let config: FreeqConfig | undefined;
  let sources: string[] = [];
  let conn: FreeqConnection | undefined;
  let agentDir = getAgentDir();

  const notify = (ctx: ExtensionContext | undefined, text: string, level: "info" | "warning" | "error") => {
    try {
      ctx?.ui.notify(text, level);
    } catch {
      /* notification is best-effort */
    }
  };

  async function ensureConfig(ctx: ExtensionContext): Promise<FreeqConfig> {
    if (config) return config;
    agentDir = getAgentDir();
    const loaded = await loadConfig({
      agentDir,
      cwd: ctx.cwd,
      configDirName: CONFIG_DIR_NAME,
      projectTrusted: ctx.isProjectTrusted(),
    });
    config = loaded.config;
    sources = loaded.sources;
    if (!config.install) config.install = deriveInstallSlug();
    return config;
  }

  async function connect(ctx: ExtensionContext): Promise<string> {
    const cfg = await ensureConfig(ctx);
    if (!cfg.enabled) return "freeq is disabled (`/freeq on` to enable)";
    if (!isDid(cfg.ownerDid)) return "freeq: not logged in — run `/freeq login <did:plc:…>`";
    if (conn && conn.state !== "offline") return `freeq: already ${conn.state}`;

    const meta = await collectSessionMeta({
      cwd: ctx.cwd,
      model: ctx.model?.id,
      // session id is ephemeral metadata, never an identity
      sessionId: undefined,
    });

    conn = new FreeqConnection({
      ownerDid: cfg.ownerDid,
      server: cfg.server,
      slug: cfg.install ?? deriveInstallSlug(),
      nick: cfg.nick,
      channels: cfg.channels,
      meta,
      onNotice: (text, level) => notify(ctx, text, level),
      onMessage: (channel, msg) => {
        // M1: surface only. The tiered pipeline (M2) is the ONLY path that
        // may ever reach the model — nothing here calls sendUserMessage.
        const tier = tierFor(cfg, null);
        void tier;
        notify(ctx, `freeq [${channel}] <${msg.from}> ${msg.text.slice(0, 120)}`, "info");
      },
    });

    await conn.start();
    return `freeq: ${conn.describe()}`;
  }

  // ── lifecycle ───────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    const cfg = await ensureConfig(ctx);
    if (!cfg.enabled || !isDid(cfg.ownerDid)) return; // silent when not set up
    const msg = await connect(ctx);
    if (conn?.state !== "online") notify(ctx, msg, "warning");
  });

  pi.on("session_shutdown", async () => {
    await conn?.stop("pi session ended");
    conn = undefined;
  });

  // Keep advertised model current without re-advertising on every turn.
  let lastModel: string | undefined;
  pi.on("agent_settled", async (_event, ctx) => {
    if (!conn || conn.state !== "online") return;
    const model = ctx.model?.id;
    if (model === lastModel) return;
    lastModel = model;
    conn.updateMeta({ ...conn.meta, model });
  });

  // ── /freeq ──────────────────────────────────────────────────────────────

  pi.registerCommand("freeq", {
    description: "freeq multiplayer: login, status, join, leave, peers, mode, trust",
    handler: async (args, ctx) => {
      const [sub = "status", ...rest] = args.trim().split(/\s+/).filter(Boolean);
      const cfg = await ensureConfig(ctx);

      switch (sub) {
        case "login": {
          const did = rest[0];
          if (!isDid(did)) {
            ctx.ui.notify("usage: /freeq login did:plc:… (your own DID — the agent is bound to it)", "warning");
            return;
          }
          cfg.ownerDid = did;
          cfg.install ??= deriveInstallSlug();
          cfg.nick ??= defaultNick(cfg.install);
          await saveConfig(agentDir, cfg);
          ctx.ui.notify(`freeq: owner set to ${did}; connecting…`, "info");
          ctx.ui.notify(await connect(ctx), conn?.state === "online" ? "info" : "warning");
          return;
        }

        case "status": {
          const lines = [
            `owner:   ${cfg.ownerDid ?? "(not logged in — /freeq login <did>)"}`,
            `server:  ${cfg.server}`,
            `state:   ${conn ? conn.describe() : "offline (not connected)"}`,
            `channels: ${cfg.channels.length ? cfg.channels.join(", ") : "(none)"}`,
            `config:  ${sources.length ? sources.join(", ") : "(defaults only)"}`,
          ];
          ctx.ui.notify(lines.join("\n"), "info");
          return;
        }

        case "on":
        case "off": {
          cfg.enabled = sub === "on";
          await saveConfig(agentDir, cfg);
          if (!cfg.enabled) {
            await conn?.stop("disabled");
            conn = undefined;
            ctx.ui.notify("freeq: disabled", "info");
          } else {
            ctx.ui.notify(await connect(ctx), "info");
          }
          return;
        }

        case "join": {
          const channel = rest[0];
          if (!channel?.startsWith("#")) {
            ctx.ui.notify("usage: /freeq join #channel", "warning");
            return;
          }
          if (!cfg.channels.some((c) => c.toLowerCase() === channel.toLowerCase())) {
            cfg.channels.push(channel);
            await saveConfig(agentDir, cfg);
          }
          const ok = conn?.join(channel);
          ctx.ui.notify(
            ok ? `freeq: joined ${channel} (mode: ${modeFor(cfg, channel)})`
               : `freeq: saved ${channel}; will join when connected`,
            ok ? "info" : "warning",
          );
          return;
        }

        case "leave": {
          const channel = rest[0];
          if (!channel?.startsWith("#")) {
            ctx.ui.notify("usage: /freeq leave #channel", "warning");
            return;
          }
          cfg.channels = cfg.channels.filter((c) => c.toLowerCase() !== channel.toLowerCase());
          await saveConfig(agentDir, cfg);
          conn?.leave(channel);
          ctx.ui.notify(`freeq: left ${channel}`, "info");
          return;
        }

        case "peers": {
          const peers = conn?.peers() ?? [];
          if (!peers.length) {
            ctx.ui.notify(
              conn?.state === "online"
                ? "freeq: no peers seen yet (they announce on presence updates)"
                : "freeq: offline — no peers",
              "info",
            );
            return;
          }
          const lines = peers.map((p) => {
            const age = Math.round((Date.now() - p.seen) / 1000);
            return `${p.nick}  ${p.state}  ${describeMeta(p.meta)}  [${p.did ?? "no did"}] ${age}s ago`;
          });
          ctx.ui.notify(`freeq peers (${peers.length}):\n${lines.join("\n")}`, "info");
          return;
        }

        case "mode": {
          const [channel, mode] = rest;
          if (!channel?.startsWith("#") || !mode || !(MODES as readonly string[]).includes(mode)) {
            ctx.ui.notify(`usage: /freeq mode #channel <${MODES.join("|")}>`, "warning");
            return;
          }
          cfg.modes[channel.toLowerCase()] = mode as Mode;
          await saveConfig(agentDir, cfg);
          ctx.ui.notify(`freeq: ${channel} → ${mode}`, "info");
          return;
        }

        case "trust": {
          const [did, tier] = rest;
          if (!isDid(did) || !tier) {
            ctx.ui.notify("usage: /freeq trust did:plc:… <observe|message|request|handoff|control>", "warning");
            return;
          }
          if (!(tier in { observe: 0, message: 0, request: 0, handoff: 0, control: 0 })) {
            ctx.ui.notify(`freeq: unknown tier '${tier}'`, "warning");
            return;
          }
          cfg.trust[did] = tier as never;
          await saveConfig(agentDir, cfg);
          ctx.ui.notify(`freeq: ${did} → ${tier}`, "info");
          return;
        }

        default:
          ctx.ui.notify(
            "freeq: /freeq [status|login <did>|join #c|leave #c|peers|mode #c <m>|trust <did> <tier>|on|off]",
            "info",
          );
      }
    },
  });
}
