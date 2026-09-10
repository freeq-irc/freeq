/** IRC message parser and formatter. */

import type { IRCMessage } from './types.js';
import { log } from "./log.js";

/** Extract nick from a prefix like "nick!user@host". */
export function prefixNick(prefix: string): string {
  const i = prefix.indexOf('!');
  return i > 0 ? prefix.slice(0, i) : prefix;
}

/** Parse a raw IRC line into a structured message. */
export function parse(raw: string): IRCMessage {
  let line = raw.replace(/\r?\n$/, '');
  const tags: Record<string, string> = {};

  // Parse tags (@key=value;key2=value2)
  if (line.startsWith('@')) {
    const sp = line.indexOf(' ');
    const tagStr = line.substring(1, sp);
    line = line.slice(sp + 1).trimStart();
    for (const t of tagStr.split(';')) {
      const eq = t.indexOf('=');
      if (eq >= 0) {
        tags[t.slice(0, eq)] = t
          .slice(eq + 1)
          .replace(/\\s/g, ' ')
          .replace(/\\:/g, ';')
          .replace(/\\\\/g, '\\')
          .replace(/\\r/g, '\r')
          .replace(/\\n/g, '\n');
      } else {
        tags[t] = '';
      }
    }
  }

  // Parse prefix (:server or :nick!user@host)
  let prefix = '';
  if (line.startsWith(':')) {
    const sp = line.indexOf(' ');
    prefix = line.slice(1, sp);
    line = line.slice(sp + 1);
  }

  // Parse command and params
  const params: string[] = [];
  while (line.length) {
    if (line.startsWith(':')) {
      params.push(line.slice(1));
      break;
    }
    const sp = line.indexOf(' ');
    if (sp < 0) {
      params.push(line);
      break;
    }
    params.push(line.slice(0, sp));
    line = line.slice(sp + 1);
  }

  const command = (params.shift() || '').toUpperCase();
  return { tags, prefix, command, params };
}

/** Serialize tags to IRC tag string (without @). */
function serializeTags(tags: Record<string, string>): string {
  return Object.entries(tags)
    .map(([k, v]) => {
      const escaped = v
        .replace(/\\/g, '\\\\')
        .replace(/;/g, '\\:')
        .replace(/ /g, '\\s')
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n');
      return escaped ? `${k}=${escaped}` : k;
    })
    .join(';');
}

/**
 * Empirical safe ceiling for a single IRC line going into freeq-server.
 * The server's MAX_LINE_LEN is 8192; we warn earlier to leave headroom
 * for tags the server may add on receive (msgid, account, sig, etc.).
 * Crossing this threshold doesn't *guarantee* the message will be
 * truncated — but it's far enough into the danger zone that callers
 * should know about it before something silently disappears on the
 * wire (which happened live 2026-05-21 with a rebuttal-prompt body
 * that JSON-stringified to 8.6KB and was truncated at ~8KB by the
 * server, making the panelist's JSON.parse fail with a confusing
 * "Unterminated string" error).
 */
export const LINE_SIZE_WARN_THRESHOLD = 7000;

/**
 * IRCv3 message-tags spec: client tags max 4094 bytes (the `@...`
 * portion, excluding the leading `@` and trailing space). Going over
 * is a spec violation; the freeq-server may silently drop the line.
 */
export const TAG_SIZE_WARN_THRESHOLD = 4094;

/** Format a raw IRC line from parts. */
export function format(
  command: string,
  params: string[],
  tags?: Record<string, string>,
): string {
  let line = '';
  let serializedTagsLen = 0;
  if (tags && Object.keys(tags).length > 0) {
    const serialized = serializeTags(tags);
    serializedTagsLen = serialized.length;
    line += `@${serialized} `;
  }
  line += command;
  for (let i = 0; i < params.length; i++) {
    // The trailing param needs a leading `:` if it contains a space, starts
    // with `:`, OR is empty. Without the colon an empty last param serializes
    // to `CMD target ` (no trailing) and the peer can't recover a `body=""` —
    // which silently drops blank lines inside a draft/multiline BATCH and
    // breaks byte-exact round-trip (e.g. commit-reveal hashes).
    if (
      i === params.length - 1 &&
      (params[i] === '' || params[i].includes(' ') || params[i].startsWith(':'))
    ) {
      line += ` :${params[i]}`;
    } else {
      line += ` ${params[i]}`;
    }
  }
  if (
    serializedTagsLen > TAG_SIZE_WARN_THRESHOLD ||
    line.length > LINE_SIZE_WARN_THRESHOLD
  ) {
    const target = params[0] ?? '<no-target>';
    // eslint-disable-next-line no-console
    log.warn(
      `[freeq-sdk] oversize ${command} to ${target}: line=${line.length}B (warn>${LINE_SIZE_WARN_THRESHOLD}), tags=${serializedTagsLen}B (warn>${TAG_SIZE_WARN_THRESHOLD}). Server may truncate or drop silently.`,
    );
  }
  return line;
}
