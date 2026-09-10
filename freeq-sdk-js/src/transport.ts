/** WebSocket IRC transport with auto-reconnect and heartbeat. */

import type { TransportState } from './types.js';
import { log } from "./log.js";

export interface TransportOptions {
  url: string;
  onLine: (line: string) => void;
  onStateChange: (state: TransportState) => void;
}

export class Transport {
  private ws: WebSocket | null = null;
  private opts: TransportOptions;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private intentionalClose = false;
  private lastDataReceived = 0;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  // Tightened from 45s/90s: a half-dead socket (TCP still "open" but the
  // server stopped responding) used to drop outbound traffic for up to 90s
  // before the watchdog forced a reconnect — long enough that the bot
  // silently vanished from channels. Ping every 20s, declare dead after 45s
  // (two missed pings) so presence recovers within ~45s.
  private static PING_INTERVAL = 20_000;
  private static DEAD_TIMEOUT = 45_000;

  constructor(opts: TransportOptions) {
    this.opts = opts;
  }

  connect() {
    this.intentionalClose = false;
    this.opts.onStateChange('connecting');

    try {
      this.ws = new WebSocket(this.opts.url);
    } catch {
      this.opts.onStateChange('disconnected');
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.lastDataReceived = Date.now();
      this.opts.onStateChange('connected');
      this.startHeartbeat();
    };

    this.ws.onmessage = (e: MessageEvent) => {
      this.lastDataReceived = Date.now();
      const data = typeof e.data === 'string' ? e.data : '';
      for (const line of data.split('\n')) {
        const trimmed = line.replace(/\r$/, '');
        if (trimmed) this.opts.onLine(trimmed);
      }
    };

    this.ws.onclose = () => {
      this.stopHeartbeat();
      this.opts.onStateChange('disconnected');
      if (!this.intentionalClose) {
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = () => {
      // onclose will fire after this
    };
  }

  send(line: string) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      if (this.ws.bufferedAmount > 65536) {
        log.warn('[transport] High bufferedAmount, forcing reconnect');
        this.ws.close();
        return;
      }
      this.ws.send(line);
    } else {
      // Expected while the transport is reconnecting, and it used to be one
      // line per heartbeat written straight into the host's terminal. Debug,
      // not warn: a caller that needs to know a send was lost has
      // onStateChange for that.
      log.debug('[transport] dropped while disconnected:', line);
    }
  }

  /** Wait for the WebSocket send buffer to drain. Resolves when
   *  `bufferedAmount` reaches 0 (or the WS is no longer open), or after
   *  `maxMs`. Useful before disconnecting to ensure outbound messages
   *  (PRESENCE=offline, QUIT, etc.) actually reach the server. */
  async flush(maxMs = 2000): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const start = Date.now();
    while (Date.now() - start < maxMs) {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      if (this.ws.bufferedAmount === 0) return;
      await new Promise((r) => setTimeout(r, 20));
    }
  }

  disconnect() {
    this.intentionalClose = true;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      // Note: callers that care about delivery (e.g. bot-kit's stop()) should
      // call `flush()` first. We still emit a defensive QUIT here for callers
      // that haven't sent one, but it may be lost if the buffer is non-empty.
      try { this.send('QUIT :Leaving'); } catch { /* ignore */ }
      this.ws.close();
      this.ws = null;
    }
    this.opts.onStateChange('disconnected');
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      const elapsed = Date.now() - this.lastDataReceived;
      if (elapsed > Transport.DEAD_TIMEOUT) {
        log.warn(
          `[transport] no data for ${Transport.DEAD_TIMEOUT / 1000}s, forcing reconnect`,
        );
        this.stopHeartbeat();
        if (this.ws) {
          this.ws.close();
          this.ws = null;
        }
      } else if (elapsed > Transport.PING_INTERVAL) {
        this.send('PING :heartbeat');
      }
    }, 10_000);
  }

  private stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer || this.intentionalClose) return;
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts - 1), 30000);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}
