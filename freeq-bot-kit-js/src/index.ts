/**
 * @freeq/bot-kit — on-disk persistence + announce-sequence orchestration for
 * freeq bots, on top of {@link https://www.npmjs.com/package/@freeq/sdk @freeq/sdk}.
 *
 * Usage:
 *   const bot = await FreeqBot.create({ name, ownerDid, nick, url });
 *   bot.on('message', (ch, msg) => bot.client.sendMessage(ch, `echo: ${msg.text}`));
 *   await bot.start();
 *
 *   process.once('SIGINT',  () => bot.stop('SIGINT').then(()  => process.exit(0)));
 *   process.once('SIGTERM', () => bot.stop('SIGTERM').then(() => process.exit(0)));
 */

export { FreeqBot } from "./bot.js";
export type {
  ActorClass,
  FreeqBotCreateOptions,
  FreeqBotStartOptions,
  FreeqBotStopOptions,
  MentionResult,
  MentionMatcher,
} from "./bot.js";

// Default mention matcher — exported so bot authors can compose with it
// (e.g. wrap it with extra logic) rather than reimplementing.
export { matchMention } from "./mention.js";

// Re-export the SDK surface that bot consumers commonly need, so they can
// depend on @freeq/bot-kit alone. (Bots that need anything not re-exported
// here can still depend on @freeq/sdk directly.)
export { FreeqClient, fetchProfile } from "@freeq/sdk";
export type { FreeqEvents, NickCollisionPolicy, TransportState } from "@freeq/sdk";

// Low-level helpers — for callers that want to read identity/cert state
// (e.g. a CLI's `status` command) without constructing a FreeqBot.
export { loadOrCreateIdentity } from "./identity.js";
export type {
  AgentIdentity,
  LoadOrCreateIdentityOptions,
} from "./identity.js";
export {
  loadDelegation,
  loadOrMintDelegation,
  buildDelegation,
  signDelegation,
  canonicalizeForSigning,
} from "./delegation.js";
export type {
  DelegationCert,
  LoadDelegationOptions,
  LoadOrMintDelegationOptions,
  BuildDelegationOptions,
} from "./delegation.js";

// freeq.at/act signing — the act RFC's canonical (sign-what's-present over
// act-* tags, plus the caller-supplied venue and event id), kid derivation,
// and sign/verify. Byte-compatible with freeq_sdk::act; contract fixtures in
// spec/act-signing-vectors.json.
export {
  actCanonical,
  deriveKid,
  signActTags,
  verifyActTags,
  publicKeyFromMultibase,
  ACT_SIG_TAG,
} from "./act.js";
export type { ActVerifyResult } from "./act.js";

// The moves a bot can make on a task — one function per verb, each doing the
// paired send (the signed task event, plus the line people read). A handoff's
// first, then the ones only a bounty has. `expire` and `auto-accept` are
// absent on purpose: only the server makes those moves.
export {
  offer,
  accept,
  decline,
  claim,
  progress,
  complete,
  fail,
  cancel,
  bid,
  award,
  submit,
  revise,
  acceptWork,
  forfeit,
} from "./act-verbs.js";
export type { ActContext, OfferOptions, StepOptions } from "./act-verbs.js";

// The task lifecycle rules — which move is legal, from which state, by whom.
// The rules are data (spec/act-transitions.json, copied into src/); this is
// the checker that reads them, mirroring freeq_sdk::act_transitions so a bot
// can pre-check a move and reach the same verdict the server will.
export {
  DEADLINE_TOLERANCE_MS,
  checkOpen,
  checkTransition,
  eventTimeMs,
  initialState,
  isTerminal,
  openingVerb,
  refusalDescription,
} from "./act-transitions.js";
export type {
  CheckResult,
  EventSender,
  RefusalReason,
  Task,
  TaskEvent,
} from "./act-transitions.js";

// Daemon CLI scaffold — Commander-based launch/stop/status/doctor/tail
// for long-running freeq bot daemons. Caller provides runDaemon + paths;
// bot-kit handles pid files, --detach forking, signal wiring, and the
// built-in identity/delegation/server doctor checks.
export { createDaemonCLI, readPidIfAlive } from "./daemon-cli.js";
export type {
  CreateDaemonCLIOptions,
  DaemonPaths,
  DaemonHandle,
  DaemonOpts,
  DoctorCheck,
  DoctorResult,
} from "./daemon-cli.js";

// Hot-reloadable, DID-keyed map. Backs allowlists, banlists, roles,
// tiers, friends — same primitive, different wiring. See README.
export { createDidMap } from "./did-map.js";
export type {
  DidMapSource,
  DidMapSave,
  DidMapBaseOptions,
  DidMapMutableOptions,
  DidMapReadOnly,
  DidMapMutable,
} from "./did-map.js";

// Sender-DID resolver — also surfaced as bot.resolveSenderDid() on
// FreeqBot. Standalone export is for bots that don't use the wrapper.
export { createDidResolver } from "./did-resolver.js";
export type {
  DidResolver,
  DidResolverClient,
  DidResolverOptions,
  ResolveOpts,
} from "./did-resolver.js";

// Rate-limit + cycle-detection gate. Caller-owned persistence via
// optional load/save callbacks (same pattern as createDidMap).
export { createTurnGate } from "./turn-gate.js";
export type {
  CreateTurnGateOptions,
  CyclePolicy,
  EvaluateArgs as TurnGateEvaluateArgs,
  GateDecision,
  TurnGate,
  TurnGateState,
} from "./turn-gate.js";
