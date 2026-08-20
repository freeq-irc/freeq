// The moves a bot can make on a task.
//
// One function per verb the RFC gives a sender. `expire` and `auto-accept` are
// not here: only the server may make those moves, and it makes them from the
// sweep. Neither is `confirm`: a receipt is the action's home writing about an
// event it filed.
//
// Every one does the same paired send — the signed task TAGMSG that *is* the
// event, and the plain-text line that renders it for the people in the room,
// linked back by `+freeq.at/ref`. Two documents, each signing its own id.
//
// Vocabulary, as the rest of the system uses it: the *author* of a message is
// whoever wrote it; the *actor* of an event is whoever performed it. These
// helpers always send as the bot itself, so for them the two are the same
// identity — the `from` tag names the actor, and the server refuses a task
// message whose actor is not its sender.

import type { FreeqClient } from "@freeq/sdk";
import { REVIVAL_TAG } from "./act-transitions.js";

/** What every task step needs: where it happens, and who is doing it. */
export interface ActContext {
  client: FreeqClient;
  /** The channel, or the recipient's DID for a task in a direct conversation. */
  target: string;
  /** The acting identity — this bot's DID. */
  did: string;
}

/** What an offer declares. Everything but a title is optional. */
export interface OfferOptions {
  title: string;
  /** The kind of task. `handoff` unless something says otherwise — a bounty
   *  is opened by the same verb, and takes bids instead of a recipient. */
  kind?: string;
  /** Name a recipient to make the offer directed; leave it out and anyone
   *  may claim it. */
  to?: string;
  /** A self-declared hint. Stored, filterable, never a gate. */
  caps?: string;
  /** Unix seconds. Bounds how long the offer stands — not how long the work
   *  may take. */
  deadline?: number;
  /** A link to the task's materials, and a hash of them. */
  ctx?: string;
  ctxHash?: string;
  /** The finished action this one revives — a failed handoff re-offered, a
   *  forfeited bounty re-listed. Legal only here, on the opener. */
  replaces?: string;
  /** The line people see. Defaults to something plain. */
  humanText?: string;
}

/** What a follow-up may carry. */
export interface StepOptions {
  /** A sentence for the record, covered by the signature like every act tag. */
  note?: string;
  /** The kind of task this step is on. `handoff` unless something says
   *  otherwise — a step names the kind it belongs to, the way its opener did. */
  kind?: string;
  /** The line people see. */
  humanText?: string;
}

/** What a task is when nobody says otherwise. */
const KIND = "handoff";

function stepTags(verb: string, did: string, taskId: string, note?: string, kind?: string) {
  const tags: Record<string, string> = {
    "+freeq.at/act": kind ?? KIND,
    "+freeq.at/act-verb": verb,
    "+freeq.at/from": did,
    "+freeq.at/act-id": taskId,
  };
  if (note) tags["+freeq.at/act-note"] = note;
  return tags;
}

/**
 * Open a task. Returns its id — the offer's own event id *is* the task's id,
 * which is why an offer carries no `act-id` of its own.
 */
export async function offer(ctx: ActContext, opts: OfferOptions): Promise<string> {
  const tags: Record<string, string> = {
    "+freeq.at/act": opts.kind ?? KIND,
    "+freeq.at/act-verb": "offer",
    "+freeq.at/from": ctx.did,
    "+freeq.at/act-title": opts.title,
  };
  if (opts.to) tags["+freeq.at/act-to"] = opts.to;
  if (opts.caps) tags["+freeq.at/act-caps"] = opts.caps;
  if (opts.deadline !== undefined) {
    tags["+freeq.at/act-deadline"] = String(opts.deadline);
  }
  if (opts.ctx) tags["+freeq.at/act-ctx"] = opts.ctx;
  if (opts.ctxHash) tags["+freeq.at/act-ctx-h"] = opts.ctxHash;
  // Tagged only when there is something to revive: an absent relation and an
  // empty one are different claims, and the signature covers whichever is here.
  if (opts.replaces) tags[`+freeq.at/${REVIVAL_TAG}`] = opts.replaces;
  return ctx.client.sendAct(ctx.target, tags, {
    humanText: opts.humanText ?? `offered: ${opts.title}`,
  });
}

/** Take a task that was offered to you. */
export async function accept(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("accept", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? "accepted the task",
    taskId,
  });
}

/** Turn down a task that was offered to you. */
export async function decline(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("decline", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? "declined the task",
    taskId,
  });
}

/** Take an open task nobody was named for. First valid claim wins. */
export async function claim(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("claim", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? "claimed the task",
    taskId,
  });
}

/** Report progress on work you hold. Leaves the task assigned. */
export async function progress(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("progress", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? (opts.note ? `progress: ${opts.note}` : "made progress"),
    taskId,
  });
}

/** Finish work you hold. Terminal. */
export async function complete(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("complete", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? "completed the task",
    taskId,
  });
}

/**
 * Give up work you hold. Terminal, and also the walk-away verb: the record
 * cannot yet tell "tried and failed" from "handing it back untouched".
 */
export async function fail(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("fail", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? "failed the task",
    taskId,
  });
}

/** The only kind that has bids to take and a winner to name. */
const BOUNTY = "bounty";

/**
 * Put your name in for an open bounty. Additive: a bid leaves the bounty
 * exactly where it found it, and every bid stays on file.
 *
 * A bid says nothing about price. `note` is freeform and signed like any act
 * tag; pricing is the agents' to agree, not the substrate's to define.
 */
export async function bid(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  const tags = stepTags("bid", ctx.did, taskId, opts.note, BOUNTY);
  return ctx.client.sendAct(ctx.target, tags, {
    humanText: opts.humanText ?? (opts.note ? `bid: ${opts.note}` : "bid on the bounty"),
    taskId,
  });
}

/**
 * Take one of the bids on a bounty you posted, and assign the work to whoever
 * wrote it.
 *
 * `bidEventId` is the bid's own event id, not the bidder's DID: a bounty's
 * terms live in the bid, and bids are the one place several candidates sit
 * side by side, so taking one means naming the exact event. The server checks
 * only that the named event is a bid on this action — which of them is worth
 * taking stays the poster's signed choice.
 */
export async function award(
  ctx: ActContext,
  taskId: string,
  bidEventId: string,
  opts: StepOptions = {},
): Promise<string> {
  const tags = stepTags("award", ctx.did, taskId, opts.note, BOUNTY);
  tags["+freeq.at/act-accepts"] = bidEventId;
  return ctx.client.sendAct(ctx.target, tags, {
    humanText: opts.humanText ?? 'awarded the bounty',
    taskId,
  });
}

/**
 * Hand in the work on a bounty you hold. The bounty waits for the poster from
 * here: nothing about a submission says the work is done, only that it is in.
 */
export async function submit(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("submit", ctx.did, taskId, opts.note, BOUNTY), {
    humanText: opts.humanText ?? "submitted the work",
    taskId,
  });
}

/**
 * Send submitted work back for another pass. The bounty is assigned again and
 * the worker still holds it — asking for changes is the poster answering, so
 * it also stops the review clock and starts a fresh one on the next
 * submission.
 */
export async function revise(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("revise", ctx.did, taskId, opts.note, BOUNTY), {
    humanText: opts.humanText ?? "asked for changes",
    taskId,
  });
}

/**
 * Accept submitted work on a bounty you posted. Terminal, and the poster's
 * word rather than the worker's — which is the whole difference between this
 * kind and a handoff.
 *
 * A payment reference rides along as an ordinary act tag if there is one. The
 * server stores and relays it and never reads it: what settled, and whether it
 * settled, live above this.
 */
export async function acceptWork(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(
    ctx.target,
    stepTags("accept-work", ctx.did, taskId, opts.note, BOUNTY),
    {
      humanText: opts.humanText ?? "accepted the work",
      taskId,
    },
  );
}

/**
 * Give up a bounty you hold, before or after handing the work in. Terminal:
 * re-listing it is a new bounty naming this one in `replaces`, because the
 * machine only runs forward.
 */
export async function forfeit(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("forfeit", ctx.did, taskId, opts.note, BOUNTY), {
    humanText: opts.humanText ?? "forfeited the bounty",
    taskId,
  });
}

/**
 * Withdraw a task you posted. The poster's unilateral act, legal from every
 * live state including mid-work — the worker gets the event, not a say.
 */
export async function cancel(
  ctx: ActContext,
  taskId: string,
  opts: StepOptions = {},
): Promise<string> {
  return ctx.client.sendAct(ctx.target, stepTags("cancel", ctx.did, taskId, opts.note, opts.kind), {
    humanText: opts.humanText ?? "cancelled the task",
    taskId,
  });
}
