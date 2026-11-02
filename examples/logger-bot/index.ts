/**
 * freeq-logger-bot — reference bot built on @freeq/sdk.
 *
 * Discovers the freeq agent assistance interface via /.well-known/agent.json
 * (informational; the bot doesn't depend on it), then connects to the IRC
 * server and writes every event it sees to stdout + a JSON-Lines log file.
 *
 * Designed to be the smallest useful example — drop in your own DID/key
 * + auto-join channels and you have a working logger / observer bot.
 *
 * Usage:
 *   FREEQ_SERVER=wss://irc.freeq.at/irc \
 *   FREEQ_NICK=alice-logger \
 *   FREEQ_CHANNELS=#freeq,#freeq-dev \
 *   FREEQ_LOGFILE=./events.jsonl \
 *   npm start
 *
 * Defaults: connects to wss://irc.freeq.at/irc as a guest, joins #freeq.
 */

import { FreeqClient, type FreeqEvents } from '@freeq/sdk';
import * as fs from 'node:fs';

// ─── Config ─────────────────────────────────────────────────────────────

const SERVER_WS =
  process.env.FREEQ_SERVER ?? 'wss://irc.freeq.at/irc';
const SERVER_HTTP = SERVER_WS
  .replace(/^ws:/, 'http:')
  .replace(/^wss:/, 'https:')
  .replace(/\/irc$/, '');
const NICK =
  process.env.FREEQ_NICK ??
  `logbot-${Math.random().toString(36).slice(2, 6)}`;
const CHANNELS = (process.env.FREEQ_CHANNELS ?? '#freeq')
  .split(',')
  .map((c) => c.trim())
  .filter(Boolean);
const LOGFILE = process.env.FREEQ_LOGFILE ?? './events.jsonl';
const QUIT_AFTER_MS = process.env.FREEQ_QUIT_AFTER_MS
  ? parseInt(process.env.FREEQ_QUIT_AFTER_MS, 10)
  : 0;

// ─── Logger sink ────────────────────────────────────────────────────────

const sink = fs.createWriteStream(LOGFILE, { flags: 'a' });
process.on('exit', () => sink.end());

function logEvent(kind: string, payload: unknown) {
  const entry = {
    ts: new Date().toISOString(),
    bot: NICK,
    kind,
    payload: jsonSafe(payload),
  };
  const line = JSON.stringify(entry);
  sink.write(line + '\n');
  console.log(line);
}

/**
 * Make values JSON-serialisable. The SDK exposes Map / Set / Date in
 * some payloads (member lists, reaction sets, message timestamps) —
 * convert them to plain values so JSON.stringify doesn't drop them.
 */
function jsonSafe(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Map) return Object.fromEntries(
    [...value.entries()].map(([k, v]) => [String(k), jsonSafe(v)]),
  );
  if (value instanceof Set) return [...value].map(jsonSafe);
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = jsonSafe(v);
    }
    return out;
  }
  return value;
}

// ─── Discovery (informational) ──────────────────────────────────────────

async function probeDiscovery() {
  try {
    const resp = await fetch(`${SERVER_HTTP}/.well-known/agent.json`);
    if (!resp.ok) {
      logEvent('discovery_failed', { status: resp.status });
      return;
    }
    const meta = await resp.json();
    logEvent('discovery', meta);
  } catch (e: unknown) {
    logEvent('discovery_error', { error: (e as Error).message });
  }
}

// ─── Wire every event ───────────────────────────────────────────────────

/**
 * The complete list of events the SDK emits. Kept in sync with
 * `freeq-sdk-js/src/events.ts` — adding a new event there is one line
 * here. Each event's payload is wrapped into an args[] array so the
 * sink format is uniform regardless of how many positional args the
 * SDK passes.
 */
const ALL_EVENTS: (keyof FreeqEvents)[] = [
  // Connection lifecycle
  'connectionStateChanged',
  'registered',
  'nickChanged',
  'authenticated',
  'authError',
  'authErrorRetry',
  'signingKeyRefused',
  // Channel events
  'channelJoined',
  'channelLeft',
  'memberJoined',
  'memberLeft',
  'membersList',
  'membersCleared',
  'memberDid',
  'topicChanged',
  'modeChanged',
  // User events
  'userQuit',
  'userRenamed',
  'userAway',
  'userKicked',
  'invited',
  'whois',
  // Message events
  'message',
  'messageEdited',
  'messageDeleted',
  'reactionAdded',
  'reactionRemoved',
  'typing',
  'systemMessage',
  // History + DMs
  'historyBatch',
  'dmTarget',
  // Channel listing
  'channelListEntry',
  'channelListEnd',
  // Pins
  'pins',
  'pinAdded',
  'pinRemoved',
  // AV sessions
  'avSessionUpdate',
  'avSessionRemoved',
  'avTicket',
  // Other / edge
  'joinGateRequired',
  'motdStart',
  'motd',
  'ready',
  'error',
];

function attachAll(client: FreeqClient) {
  for (const ev of ALL_EVENTS) {
    // Variadic forwarder — each event has a different signature; we
    // preserve all positional args by capturing them into an array.
    (client.on as unknown as (
      e: string,
      h: (...args: unknown[]) => void,
    ) => void)(ev, (...args: unknown[]) => logEvent(ev, args));
  }

  // The catch-all `raw` event ensures we never miss something the
  // typed events don't surface. It fires on every IRC line received,
  // BEFORE the typed event for that line. Logging both is intentional —
  // makes it easy to correlate "this raw line produced these typed
  // events" when you're debugging the SDK or the server.
  client.on('raw', (line: string, parsed: unknown) =>
    logEvent('raw', { line, parsed: jsonSafe(parsed) }),
  );
}

// ─── Main ───────────────────────────────────────────────────────────────

async function main() {
  await probeDiscovery();

  const client = new FreeqClient({
    url: SERVER_WS,
    nick: NICK,
    channels: CHANNELS,
  });

  attachAll(client);

  // Once we're past CAP/registration, the SDK auto-joins the channels
  // we passed in the ctor; the channelJoined event will fire and the
  // logger will start capturing channel traffic from there.
  client.once('ready', () => {
    logEvent('bot_ready', {
      server: SERVER_WS,
      nick: client.nick,
      channels: CHANNELS,
      logfile: LOGFILE,
    });
  });

  client.connect();

  // Optional auto-quit so a long smoke run doesn't hold the process
  // open forever; useful in CI.
  if (QUIT_AFTER_MS > 0) {
    setTimeout(() => {
      logEvent('bot_shutdown', { reason: 'quit_after_ms reached', ms: QUIT_AFTER_MS });
      client.disconnect();
      sink.end(() => process.exit(0));
    }, QUIT_AFTER_MS);
  }

  // Graceful Ctrl-C
  process.on('SIGINT', () => {
    logEvent('bot_shutdown', { reason: 'SIGINT' });
    client.disconnect();
    sink.end(() => process.exit(0));
  });
}

main().catch((e: Error) => {
  logEvent('fatal', { error: e.message, stack: e.stack });
  process.exit(1);
});
