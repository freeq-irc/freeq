// The moves a bot can make on a task.
//
// One function per verb the RFC gives a sender. `expire` is not here: only
// the server may make that move, and it makes it from the sweep, and neither
// is `confirm`: a receipt is the action's home writing about an event it
// filed.
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
 * Pick the winner of a bounty you posted, and assign the work to them.
 *
 * The poster names a winner rather than becoming one, which is why `act-to`
 * is on the award and why the view reads the assignee from it. Nothing checks
 * that the winner bid: the server never picks, and that cuts both ways — this
 * signed choice is the record.
 */
export async function award(
  ctx: ActContext,
  taskId: string,
  winnerDid: string,
  opts: StepOptions = {},
): Promise<string> {
  const tags = stepTags("award", ctx.did, taskId, opts.note, BOUNTY);
  tags["+freeq.at/act-to"] = winnerDid;
  return ctx.client.sendAct(ctx.target, tags, {
    humanText: opts.humanText ?? `awarded the bounty to ${winnerDid}`,
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
