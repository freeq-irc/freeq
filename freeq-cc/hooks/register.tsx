/**
 * freeq-cc's mod: freeq drawn inside Claude Code.
 *
 *   - a pane (`/fq`): the room feed, peers and their trust tiers, the work
 *     offered and held (accept / decline in place), and the approval audit
 *   - a band above the prompt: what waits on someone (an offer for you, an
 *     approval or a question your owner was also asked on freeq)
 *   - a status line: connection, nick, unread, offers
 *   - `/fq <subcommand>`: every `/freeq:` subcommand, run at once with no model
 *     turn and no tokens, even while Claude is working
 *   - the freeq tool's rows say who a message went to
 *   - an AskUserQuestion in a response a freeq message started is held and
 *     asked of the owner over freeq too; their signed answer, or yours at the
 *     terminal, settles it
 *
 * The mod holds no connection: everything goes through the plugin's own MCP
 * server (`plugin:freeq:freeq`, its `freeq_ui` tool, `src/channel.ts`).
 * Where mods are off, the `/freeq:` command files still work.
 */

import { atom, read, update } from "claude-code";
import type { EngineInterface, Register, Timer } from "claude-code";

import type { Held, Snap, View } from "../types";

const SERVER = "plugin:freeq:freeq";
const UI_TOOL = "freeq_ui";
const FREEQ_TOOL = "mcp__plugin_freeq_freeq__freeq";
const PANE = "freeq";
const POLL_MS = 2000;
const VIEWS: readonly View[] = ["feed", "peers", "work", "audit"];

const snap = atom({ plugin: "freeq", key: "snap" } as const, null, { shape: "snap-1" });
const view = atom({ plugin: "freeq", key: "view" } as const, "feed" as View);
const held = atom({ plugin: "freeq", key: "held" } as const, null as Held | null);

type $ = EngineInterface;

/** One `freeq_ui` call; its JSON answer, or undefined when the server is not there. */
async function ui($: $, action: string, args: Record<string, unknown> = {}): Promise<any> {
  const r = await $.mcp.call(SERVER, UI_TOOL, { action, ...args });
  const block = r.content.find((c: { type: string }) => c.type === "text") as { text?: string } | undefined;
  if (r.isError || !block?.text) return undefined;
  try {
    return JSON.parse(block.text);
  } catch {
    return undefined;
  }
}

const short = (did?: string): string => (did ? (did.length > 22 ? `${did.slice(0, 14)}…${did.slice(-4)}` : did) : "");
const clock = (ms: number): string => {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
};
const offersFor = (s: Snap) => s.tasks.filter((t) => t.side === "in" && (t.queued || t.state === "offered" || t.state === "open"));

/** The line under the prompt. */
/** Where a feed line was said: the channel, or "dm <peer>" for a direct message (whose target is a DID). */
export function placeOf(s: Snap, l: Snap["feed"][number]): string {
  if (/^[#&]/.test(l.channel)) return l.channel;
  const peer = s.peers.find((p) => p.did === l.channel || p.nick === l.channel);
  const name = l.direction === "in" ? "" : peer?.nick ?? (l.channel.startsWith("did:") ? `${l.channel.slice(0, 14)}…` : l.channel);
  return name ? `dm ${name}` : "dm";
}

export function statusLine(s: Snap | null): string | undefined {
  if (!s) return undefined;
  const c = s.connection;
  // The engine already names the plugin in front of this text.
  if (!c.enabled) return "○ off";
  const online = c.state === "online";
  const bits = [`${online ? "●" : "○"} ${online ? (c.nick ?? "online") : c.state}${c.muted ? " (muted)" : ""}`];
  if (!online && c.lastError) bits.push(c.lastError.slice(0, 40));
  if (s.unread) bits.push(`${s.unread} unread`);
  const heldBack = (s.withheld ?? []).reduce((n, w) => n + w.count, 0);
  if (heldBack) bits.push(`${heldBack} held back`);
  const offers = offersFor(s).length;
  if (offers) bits.push(`${offers} offer${offers > 1 ? "s" : ""}`);
  if (s.approvals.length || s.questions.length) bits.push("waiting on owner");
  return bits.join(" · ");
}

// The module's own variables start over at a reload; `$.state` keeps the snapshot.
let last: Snap | null = null;
let poll: Timer | undefined;

/** Read a fresh snapshot; redraw and retell the status only when it moved. */
async function refresh($: $): Promise<void> {
  try {
    await refreshNow($);
  } catch {
    // The server is not up yet or went away, or the session is ending: the
    // next poll tries again.
  }
}

async function refreshNow($: $): Promise<void> {
  const s = await ui($, "snapshot", last ? { since: last.version } : {});
  if (!s || s.unchanged) return;
  const prev = last;
  last = s as Snap;
  await update($, snap, () => last);
  $.ui.status(statusLine(last));
  // A new offer for this agent is worth a toast; the rest waits in the pane.
  const before = new Set(prev ? offersFor(prev).map((t) => t.id) : []);
  for (const t of offersFor(last)) {
    if (prev && !before.has(t.id)) $.ui.toast(`freeq: ${t.from ?? "someone"} offers "${t.title}" — /fq work`);
  }
}

async function openPane($: $, tab?: View): Promise<string> {
  if (tab) await update($, view, () => tab);
  const opened = await $.ui.open({ id: PANE, title: "freeq" });
  void ui($, "mark_read").catch(() => undefined);
  return opened.isPlaced ? "" : `freeq pane waits for room (${"reason" in opened ? String(opened.reason) : "no seat"}).`;
}

/** Run a subcommand line on the server and refresh. */
async function run($: $, line: string): Promise<void> {
  await ui($, "command", { line });
  await refresh($);
}

export const register: Register = (on) => {
  on("session.start", async ($, e, next) => {
    await $.command.register({
      name: "fq",
      description: "freeq: open the pane, or run a subcommand now (/fq status, /fq peers, /fq accept <id>…)",
      argumentHint: "[feed|peers|work|audit|<subcommand> …]",
      immediate: true,
    });
    poll?.cancel();
    poll = $.clock.every(POLL_MS, () => void refresh($));
    void refresh($);
    return next(e);
  });

  on("session.end", async ($, e, next) => {
    poll?.cancel();
    poll = undefined;
    return next(e);
  });

  // ── /fq ─────────────────────────────────────────────────────────────────

  on("command.run", { command: "fq" }, async ($, e) => {
    const args = e.args.trim();
    const [first = "", ...rest] = args.split(/\s+/);
    if (!args || (VIEWS as readonly string[]).includes(first)) {
      const note = await openPane($, (first || undefined) as View | undefined);
      return { text: note || "freeq pane opened.", isTextDisplayOnly: true };
    }
    if (first === "route") {
      // Hand a task you hold to another of your local sessions to do.
      const [id, ...to] = rest;
      if (!id || !to.length) return { text: "usage: /fq route <task-id> <session>", isTextDisplayOnly: true };
      const task = last?.tasks.find((t) => t.id === id || t.id.startsWith(id));
      if (!task) return { text: `no task ${id} here — /fq work lists them`, isTextDisplayOnly: true };
      const target = to.join(" ");
      await $.session.send({
        to: target,
        text:
          `Work routed from freeq (task ${task.id.slice(0, 10)}, from ${task.from ?? "a peer"}): ${task.title}\n` +
          `Do it in this session, then reply to me with a short summary; I will complete it on freeq.`,
      });
      return { text: `routed "${task.title}" to ${target}. Complete it here when they report back.`, isTextDisplayOnly: true };
    }
    let out: any;
    try {
      out = await ui($, "command", { line: args });
    } catch (err) {
      return { text: `freeq-cc is not running in this session (${(err as Error).message}).`, isTextDisplayOnly: true };
    }
    void refresh($);
    // The engine names the plugin in front of the text; the server does too.
    return { text: String(out?.text ?? "(no output)").replace(/^freeq:?\s+/, ""), isTextDisplayOnly: true };
  });

  // ── the pane ────────────────────────────────────────────────────────────

  on("ui.render", { component: "Pane", requestId: PANE }, async ($, e) => {
    const { Box, Text, Button } = $.ui.resolve(e);
    const s = await read($, snap);
    const tab = await read($, view);
    const rows = Math.max(4, (e.viewport?.rows ?? 24) - 5);
    if (!s) {
      return (
        <Box flexDirection="column">
          <Text dimColor>freeq-cc is starting, or is not running in this session.</Text>
          <Text dimColor>Start Claude Code with the freeq plugin; /freeq:doctor says what is missing.</Text>
        </Box>
      );
    }
    const c = s.connection;
    const tabs = (
      <Box flexDirection="row" gap={1}>
        {VIEWS.map((v) => (
          <Button key={`tab-${v}`} label={v === tab ? `[${v}]` : v} plain onPress={() => update($, view, () => v)} />
        ))}
      </Box>
    );
    const head = (
      <Text>
        <Text color={c.state === "online" ? "green" : "yellow"}>{c.state === "online" ? "●" : "○"}</Text>{" "}
        <Text bold>{c.nick ?? "freeq"}</Text>
        <Text dimColor>
          {" "}
          {short(c.did)}
          {c.ownerDid ? ` · for ${short(c.ownerDid)}` : " · self-owned"}
          {s.channels.length ? ` · ${s.channels.join(" ")}` : ""}
        </Text>
      </Text>
    );

    let body;
    if (tab === "peers") {
      body = s.peers.length ? (
        s.peers.slice(0, rows).map((p) => (
          <Text key={`peer-${p.nick}`} wrap="truncate-end">
            <Text color={p.state === "active" ? "green" : undefined}>{p.isAgent ? "◆" : "●"}</Text> <Text bold>{p.nick}</Text>
            <Text dimColor>
              {" "}
              {p.tier}
              {p.doing ? ` · ${p.doing}` : p.project ? ` · ${p.project}` : ""}
            </Text>
          </Text>
        ))
      ) : (
        <Text dimColor>No peers seen yet.</Text>
      );
    } else if (tab === "work") {
      body = s.tasks.length ? (
        s.tasks.slice(0, rows).map((t) => {
          const offered = t.side === "in" && (t.queued || t.state === "offered" || t.state === "open");
          return (
            <Box key={`task-${t.id}`} flexDirection="row" gap={1}>
              <Text wrap="truncate-end">
                <Text dimColor>{t.side === "in" ? "←" : "→"} {t.id.slice(0, 8)}</Text> {t.title}
                <Text dimColor>
                  {" "}
                  · {t.state}
                  {t.from && t.side === "in" ? ` · from ${t.from}` : ""}
                </Text>
              </Text>
              {offered && (
                <Button key={`accept-${t.id}`} label="Accept" onPress={() => void run($, `accept ${t.id}`)} />
              )}
              {offered && (
                <Button
                  key={`decline-${t.id}`}
                  label="Decline"
                  onPress={() => void run($, `decline ${t.id} not now`)}
                />
              )}
            </Box>
          );
        })
      ) : (
        <Text dimColor>No work offered or held. Agents hand work here with the freeq tool's handoff.</Text>
      );
    } else if (tab === "audit") {
      body = s.audit.length ? (
        s.audit
          .slice(-rows)
          .reverse()
          .map((r) => (
            <Text key={`audit-${r.at}-${r.request}`} wrap="truncate-end">
              <Text color={r.applied ? "green" : "red"}>{r.applied ? "✓" : "✗"}</Text> {r.kind === "permission" ? `${r.answer} ${r.subject}` : `"${r.answer}"`}
              <Text dimColor>
                {" "}
                · {r.verdict}
                {r.kid ? ` ${r.kid.slice(0, 8)}` : ""} · {r.at.slice(11, 16)}
                {r.reason ? ` · ${r.reason}` : ""}
              </Text>
            </Text>
          ))
      ) : (
        <Text dimColor>No answers from your owner over freeq yet. Each one is kept in ~/.freeq/cc/approvals.jsonl.</Text>
      );
    } else {
      body = s.feed.length ? (
        s.feed.slice(-rows).map((l, i) => (
          <Text key={`feed-${l.at}-${i}`} wrap="truncate-end" dimColor={l.direction === "in" && !l.delivered}>
            <Text dimColor>{clock(l.at)}</Text> {l.direction === "in" ? "←" : "→"} <Text dimColor>{placeOf(s, l)}</Text>{" "}
            <Text bold>{l.direction === "in" ? l.from : "you"}</Text> {l.text.replace(/\s+/g, " ")}
            {l.note ? <Text dimColor> · {l.note}</Text> : null}
          </Text>
        ))
      ) : (
        <Text dimColor>Nothing yet. Messages, mentions and what this agent sends appear here.</Text>
      );
    }

    return (
      <Box flexDirection="column">
        {head}
        {tabs}
        <Box flexDirection="column" marginTop={1}>
          {body}
        </Box>
      </Box>
    );
  });

  // ── the band ────────────────────────────────────────────────────────────

  on("ui.render", { component: "AbovePrompt" }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e);
    const s = await read($, snap);
    const q = await read($, held);
    if (!s && !q) return next(e);
    const { Box, Text, Button } = $.ui.resolve(e);
    const rows = [];
    if (q) {
      rows.push(
        <Box key="held" flexDirection="row" gap={1}>
          <Text wrap="truncate-end">
            <Text color="cyan">⇄</Text> Asked your owner on freeq: <Text dimColor>{q.question}</Text>
          </Text>
          <Button key="answer-here" label="Answer here" onPress={() => void ui($, "cancel_question", { id: q.id })} />
        </Box>,
      );
    }
    for (const a of s?.approvals ?? []) {
      rows.push(
        <Text key={`approval-${a.requestId}`} wrap="truncate-end">
          <Text color="cyan">⇄</Text> Approval for {a.tool} also sent to your owner on freeq <Text dimColor>({a.requestId})</Text>
        </Text>,
      );
    }
    const w = s?.withheld?.[0];
    if (w) {
      rows.push(
        <Box key={`withheld-${w.key}`} flexDirection="row" gap={1}>
          <Text wrap="truncate-end">
            <Text color="yellow">freeq</Text> held back {w.count} message{w.count > 1 ? "s" : ""} from <Text bold>{w.from}</Text>{" "}
            <Text dimColor>(not trusted yet)</Text>
          </Text>
          {w.did ? <Button key={`trust-${w.key}`} label="Trust" onPress={() => void run($, `trust ${w.did} message`)} /> : null}
          <Button key={`drop-${w.key}`} label="Drop" onPress={() => void run($, "withheld drop")} />
        </Box>,
      );
    }
    const offer = s ? offersFor(s)[0] : undefined;
    if (offer) {
      rows.push(
        <Box key={`offer-${offer.id}`} flexDirection="row" gap={1}>
          <Text wrap="truncate-end">
            <Text color="yellow">freeq</Text> {offer.from ?? "someone"} offers <Text bold>{offer.title}</Text>
          </Text>
          <Button key={`band-accept-${offer.id}`} label="Accept" onPress={() => void run($, `accept ${offer.id}`)} />
          <Button key={`band-open-${offer.id}`} label="Details" onPress={() => void openPane($, "work")} />
        </Box>,
      );
    }
    if (!rows.length) return next(e);
    return <Box flexDirection="column">{rows}</Box>;
  });

  // ── the freeq tool's rows ───────────────────────────────────────────────

  on("ui.render", { component: "ToolUse" }, async ($, e, next) => {
    if (e.props.tool !== FREEQ_TOOL) return next(e);
    const input = (e.props.input ?? {}) as { action?: string; to?: string; channel?: string };
    const where = input.to ? `@${input.to}` : input.channel;
    if (!where || !["send", "say", "ask", "handoff", "post"].includes(input.action ?? "")) return next(e);
    const s = await read($, snap);
    const { Box, Text } = $.ui.resolve(e);
    const row = await next(e);
    return (
      <Box flexDirection="column">
        {row}
        <Text dimColor>
          {"  "}
          {input.action === "ask" ? "asked" : input.action === "handoff" || input.action === "post" ? "offered to" : "to"} {where}
          {s?.connection.nick ? ` · signed as ${s.connection.nick}` : ""}
        </Text>
      </Box>
    );
  });

  // ── a question, held for the owner ──────────────────────────────────────

  on("tool.call", { tool: "AskUserQuestion" }, async ($, e, next) => {
    let asked: any;
    try {
      asked = await ui($, "relay_question", { questions: e.questions });
    } catch {
      return next(e);
    }
    if (!asked?.relayed || typeof asked.id !== "string") return next(e);
    const id: string = asked.id;
    await update($, held, () => ({ id, question: e.questions.map((q) => q.question).join(" · ") }));
    try {
      while (!next.signal.aborted) {
        // Each wait is the server's (up to 25 s) and stops this hook's clock.
        const out = await ui($, "await_question", { id, wait_ms: 20_000 });
        if (out?.state === "answered") {
          return {
            result: { questions: e.questions, answers: out.answers ?? {} },
            context: [String(out.note ?? "Answered by the owner over freeq.")],
          };
        }
        if (!out || out.state === "cancelled") break;
      }
    } finally {
      await update($, held, () => null);
    }
    if (next.signal.aborted) void ui($, "cancel_question", { id }).catch(() => undefined);
    // Answered here instead: the dialog as usual.
    return next(e);
  });
};
