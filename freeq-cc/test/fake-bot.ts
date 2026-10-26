/**
 * A bot-kit bot as far as the kit's connection uses one (the same shape as
 * the kit's own test fake, `freeq-harness-kit/src/runtime.test.ts`).
 * Everything put on the wire lands in `sent`, in order.
 */
import type { BotLike } from "@freeq/harness-kit/connection";

export class FakeBot implements BotLike {
  handlers = new Map<string, Array<(...a: never[]) => void>>();
  sent: Array<{ kind: string; target: string; payload: unknown }> = [];
  nickValue: string | null = "cc-test1234-proj";
  provenance = null;
  identity = { did: "did:key:zSelf" };
  mention: ((text: string, nick: string) => string | null) | undefined;
  client = ((self: FakeBot) => ({
    get nick() {
      return self.nickValue;
    },
    join: (channel: string) => self.sent.push({ kind: "join", target: channel, payload: null }),
    raw: (line: string) => self.sent.push({ kind: "raw", target: "", payload: line }),
    sendMessage: (target: string, text: string) => self.sent.push({ kind: "message", target, payload: text }),
    sendTagmsg: (target: string, tags: Record<string, string>) =>
      self.sent.push({ kind: "tagmsg", target, payload: tags }),
    sendAct: async (target: string, tags: Record<string, string>) => {
      self.sent.push({ kind: "act", target, payload: tags });
      return "01JTASK0000000000000000000";
    },
    signing: { getPublicKey: () => "pk" },
  }))(this);
  on(event: string, handler: (...a: never[]) => void): unknown {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
    return this;
  }
  async start(): Promise<unknown> {
    return this;
  }
  async stop(): Promise<unknown> {
    return this;
  }
  setState(): void {}
  checkMention(_channel: string, text: string): { kind: string; stripped?: string } {
    const s = this.mention?.(text, this.nickValue ?? "") ?? null;
    return s === null ? { kind: "ignore" } : { kind: "respond", stripped: s };
  }
  async resolveSenderDid(msg: { tags?: Record<string, string> }): Promise<string | null> {
    return msg.tags?.account ?? null;
  }
  emit(event: string, ...args: unknown[]): void {
    for (const h of this.handlers.get(event) ?? []) (h as (...a: unknown[]) => void)(...args);
  }
  /** PRIVMSGs as `target text`. */
  messages(): string[] {
    return this.sent.filter((s) => s.kind === "message").map((s) => `${s.target} ${String(s.payload)}`);
  }
  /** Replies to inbound asks, decoded. */
  askReplies(): Array<{ to: string; req: string; a?: string; err?: string }> {
    return this.sent
      .filter((s) => s.kind === "tagmsg" && (s.payload as Record<string, string>)["+freeq.at/event"] === "pi_ask_reply")
      .map((s) => ({
        to: s.target,
        ...JSON.parse(decodeURIComponent((s.payload as Record<string, string>)["+freeq.at/payload"]!)),
      }));
  }
}
