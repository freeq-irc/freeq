/**
 * @freeq/sdk — TypeScript SDK for building freeq IRC clients.
 *
 * @example
 * ```typescript
 * import { FreeqClient } from '@freeq/sdk';
 *
 * const client = new FreeqClient({
 *   url: 'wss://irc.freeq.at/irc',
 *   nick: 'mybot',
 * });
 *
 * client.on('message', (channel, msg) => {
 *   console.log(`[${channel}] ${msg.from}: ${msg.text}`);
 * });
 *
 * client.on('ready', () => {
 *   client.join('#mychannel');
 *   client.sendMessage('#mychannel', 'Hello from the SDK!');
 * });
 *
 * client.connect();
 * ```
 */

// Main client
export { FreeqClient } from './client.js';

// Event types
export type { FreeqEvents } from './events.js';

// IRC protocol utilities
export { parse, format, prefixNick } from './parser.js';

// Transport
export { Transport } from './transport.js';

// Types
export type {
  IRCMessage,
  Message,
  Member,
  Channel,
  PinnedMessage,
  WhoisInfo,
  ChannelListEntry,
  AvSession,
  AvParticipant,
  TransportState,
  SaslCredentials,
  FreeqClientOptions,
  Batch,
  // Agent-native types
  PresenceState,
  GovernanceSignal,
  GovernancePayload,
  PresencePayload,
  CoordinationEventPayload,
  SpendPayload,
  BudgetSnapshot,
  AgentSpawnedPayload,
  AgentDespawnedPayload,
  HistoryOptions,
  EmitEventOptions,
  HeartbeatHandle,
  NickCollisionPolicy,
  ReconnectConfig,
} from './types.js';

// Profiles
export { fetchProfile, prefetchProfiles, getCachedProfile } from './profiles.js';
export type { ATProfile } from './profiles.js';

// did:key SASL — generate a fresh authenticatable identity with no
// PDS, no OAuth, no external service. See `examples/full-validation-bot/`
// for the canonical usage pattern.
export { generateDidKey, importDidKey } from './did-key.js';
export type { DidKey } from './did-key.js';

// VC-bootstrapped E2E group channels (EG1/EGK1) — passphrase-free, server-blind
// channel encryption with per-epoch revocation. Interop-compatible with the
// Rust `freeq-sdk::e2ee_group`. See docs/VC-BOOTSTRAPPED-CHANNEL-E2EE.md.
export {
  createGroup, rotate, encryptGroup, decryptGroup,
  sealFor, openSealed, sealedToWire, sealedFromWire,
  sealBatch, openBest, isGroupEncrypted, parseEpoch,
} from './e2ee_group.js';
export type { GroupState, SealedGroupKey, X25519Secret } from './e2ee_group.js';

// What a client can honestly say about who someone is — one rule, shared
// byte-for-byte with the Rust SDK via spec/identity-claims.json.
export {
  claimForMessage,
  claimForPerson,
  stampingEpochUnix,
} from './identity-claim.js';
export type {
  IdentityClaim,
  IdentityClaimState,
  MessageClaimInput,
  PersonClaimInput,
  PersonLookup,
} from './identity-claim.js';
