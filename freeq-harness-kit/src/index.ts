/**
 * @freeq/harness-kit — freeq for agent harnesses.
 *
 * The freeq-level behaviour an agent harness shares: configuration and
 * trust tiers, the inbound gate and framing, asks, discovery, handoffs and
 * their verification, provenance, presence, the task journal and resume.
 * Every module is also importable on its own, as `@freeq/harness-kit/<name>`.
 */

export * from "./ask.js";
export * from "./config.js";
export * from "./connection.js";
export * from "./discovery.js";
export * from "./doctor.js";
export * from "./handoff.js";
export * from "./harness.js";
export * from "./identity.js";
export * from "./inbound.js";
export * from "./journal.js";
export * from "./lock.js";
export * from "./names.js";
export * from "./owner-key.js";
export * from "./presence.js";
export * from "./progress.js";
export * from "./provenance.js";
export * from "./runtime.js";
export * from "./scrub.js";
export * from "./status.js";
export * from "./steer.js";
export * from "./tool.js";
export * from "./ui.js";
export * from "./verify.js";
export * from "./withheld.js";

// Two names are exported by two modules each. The root keeps the task-list
// forms; the other is at its own subpath (`@freeq/harness-kit/ui`).
export { formatAge } from "./handoff.js";
export type { ProvenanceTier } from "./provenance.js";
