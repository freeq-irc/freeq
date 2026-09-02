/**
 * Adversarial tests for the step-up popup helper.
 *
 * Verifies the cases that are most likely to bite users:
 * - Popup blocker returns null → must not full-redirect (would lose chat).
 * - User closes popup early → must resolve, not hang.
 * - Timeout fires → must resolve, not leak handlers.
 * - Stray `freeq-oauth` postMessage from a different flow → must NOT
 *   resolve as success.
 * - Wrong-purpose postMessage → must NOT resolve.
 * - 403-detector parses the structured body and only the structured one.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { detectStepUpRequired, requestStepUp } from './oauth-step-up';

// ── DOM stubs ────────────────────────────────────────────────────────────

interface FakePopup {
  closed: boolean;
  close: () => void;
}

let openCalls: string[] = [];
let nextPopup: FakePopup | null;
const broadcastListeners: Array<(e: MessageEvent) => void> = [];
const messageListeners: Array<(e: MessageEvent) => void> = [];
const broadcastInstances: Array<{ name: string; closed: boolean }> = [];

class FakeBroadcastChannel {
  name: string;
  closed = false;
  constructor(name: string) {
    this.name = name;
    broadcastInstances.push(this);
  }
  set onmessage(fn: (e: MessageEvent) => void) {
    broadcastListeners.push(fn);
  }
  close() {
    this.closed = true;
  }
}

beforeEach(() => {
  openCalls = [];
  nextPopup = { closed: false, close: () => { /* no-op */ } };
  broadcastListeners.length = 0;
  messageListeners.length = 0;
  broadcastInstances.length = 0;

  vi.useFakeTimers();

  // @ts-expect-error stub
  globalThis.window = globalThis.window || {};
  // @ts-expect-error
  globalThis.window.open = (url: string) => {
    openCalls.push(url);
    return nextPopup;
  };
  // @ts-expect-error
  globalThis.window.location = { href: '' };
  // @ts-expect-error
  globalThis.window.addEventListener = (
    ev: string,
    fn: (e: MessageEvent) => void,
  ) => {
    if (ev === 'message') messageListeners.push(fn);
  };
  // @ts-expect-error
  globalThis.window.removeEventListener = (
    ev: string,
    fn: (e: MessageEvent) => void,
  ) => {
    if (ev === 'message') {
      const i = messageListeners.indexOf(fn);
      if (i >= 0) messageListeners.splice(i, 1);
    }
  };
  // @ts-expect-error
  globalThis.BroadcastChannel = FakeBroadcastChannel;
});

afterEach(() => {
  vi.useRealTimers();
});

// ── helpers ──────────────────────────────────────────────────────────────

function fireBroadcast(data: unknown) {
  for (const fn of broadcastListeners) {
    fn({ data } as MessageEvent);
  }
}

// ── Tests: requestStepUp ─────────────────────────────────────────────────

describe('requestStepUp', () => {
  it('opens a popup with the right URL shape', async () => {
    const promise = requestStepUp('blob_upload', 'did:plc:abc');
    expect(openCalls.length).toBe(1);
    expect(openCalls[0]).toContain('/auth/step-up?purpose=blob_upload');
    expect(openCalls[0]).toContain('did=did%3Aplc%3Aabc');

    fireBroadcast({ type: 'freeq-oauth-step-up', purpose: 'blob_upload' });
    await expect(promise).resolves.toEqual({ ok: true });
  });

  it('does NOT full-redirect when popup is blocked', async () => {
    nextPopup = null;
    const before = (globalThis.window as any).location.href;
    const outcome = await requestStepUp('blob_upload', 'did:plc:abc');
    expect(outcome).toEqual({ ok: false, reason: 'popup_blocked' });
    // Crucial: the helper must not unilaterally redirect the main
    // window — that would lose the user's chat session.
    expect((globalThis.window as any).location.href).toBe(before);
  });

  it('resolves with reason=closed when the popup is closed early', async () => {
    nextPopup = { closed: false, close: () => {} };
    const promise = requestStepUp('blob_upload', 'did:plc:abc');
    nextPopup.closed = true;
    // The closed-watcher polls every 500ms.
    await vi.advanceTimersByTimeAsync(600);
    await expect(promise).resolves.toEqual({ ok: false, reason: 'closed' });
  });

  it('resolves with reason=timeout after the configured TTL', async () => {
    const promise = requestStepUp('blob_upload', 'did:plc:abc', { timeoutMs: 1000 });
    await vi.advanceTimersByTimeAsync(1100);
    await expect(promise).resolves.toEqual({ ok: false, reason: 'timeout' });
  });

  it('ignores unrelated BroadcastChannel messages', async () => {
    const promise = requestStepUp('blob_upload', 'did:plc:abc', { timeoutMs: 1000 });
    // A *different* OAuth flow (primary login) fires its own message —
    // the step-up helper must NOT treat that as success.
    fireBroadcast({ type: 'freeq-oauth', result: { did: 'x' } });
    fireBroadcast({ type: 'freeq-oauth-step-up', purpose: 'bluesky_post' });
    fireBroadcast(null);
    fireBroadcast({ type: 'unrelated' });
    // Still pending. Run timers to confirm it eventually resolves only
    // via the timeout, not via any of those stray messages.
    await vi.advanceTimersByTimeAsync(1100);
    await expect(promise).resolves.toEqual({ ok: false, reason: 'timeout' });
  });

  it('matches purpose strictly', async () => {
    const promise = requestStepUp('bluesky_post', 'did:plc:abc');
    // A blob_upload completion must NOT satisfy a bluesky_post wait,
    // even though they share the type prefix.
    fireBroadcast({ type: 'freeq-oauth-step-up', purpose: 'blob_upload' });
    await vi.advanceTimersByTimeAsync(0);
    // Now fire the right one.
    fireBroadcast({ type: 'freeq-oauth-step-up', purpose: 'bluesky_post' });
    await expect(promise).resolves.toEqual({ ok: true });
  });

  it('cleans up the BroadcastChannel after resolve', async () => {
    const promise = requestStepUp('blob_upload', 'did:plc:abc');
    fireBroadcast({ type: 'freeq-oauth-step-up', purpose: 'blob_upload' });
    await promise;
    // The most recently created BroadcastChannel should be closed.
    const last = broadcastInstances[broadcastInstances.length - 1];
    expect(last.closed).toBe(true);
  });

  it('cleans up the message listener after resolve', async () => {
    const before = messageListeners.length;
    const promise = requestStepUp('blob_upload', 'did:plc:abc');
    expect(messageListeners.length).toBe(before + 1);
    fireBroadcast({ type: 'freeq-oauth-step-up', purpose: 'blob_upload' });
    await promise;
    expect(messageListeners.length).toBe(before);
  });
});

// ── Tests: detectStepUpRequired ──────────────────────────────────────────

describe('detectStepUpRequired', () => {
  function jsonResp(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }

  it('returns the purpose for a structured 403', async () => {
    const r = jsonResp(403, { error: 'step_up_required', purpose: 'blob_upload' });
    expect(await detectStepUpRequired(r)).toBe('blob_upload');
  });

  it('returns null for a non-403 status', async () => {
    const r = jsonResp(401, { error: 'step_up_required', purpose: 'blob_upload' });
    expect(await detectStepUpRequired(r)).toBeNull();
  });

  it('returns null for a 403 without the structured body', async () => {
    const r = jsonResp(403, { error: 'forbidden' });
    expect(await detectStepUpRequired(r)).toBeNull();
  });

  it('returns null for a 403 with non-JSON body', async () => {
    const r = new Response('plain text forbidden', {
      status: 403,
      headers: { 'content-type': 'text/plain' },
    });
    expect(await detectStepUpRequired(r)).toBeNull();
  });

  it('returns null for unknown purpose values (defends against future server drift)', async () => {
    const r = jsonResp(403, {
      error: 'step_up_required',
      purpose: 'become_admin',
    });
    expect(await detectStepUpRequired(r)).toBeNull();
  });

  it('recognizes the media_space purpose', async () => {
    const r = jsonResp(403, {
      error: 'step_up_required',
      purpose: 'media_space',
    });
    expect(await detectStepUpRequired(r)).toBe('media_space');
  });

  it('does not consume the original response body', async () => {
    const r = jsonResp(403, { error: 'step_up_required', purpose: 'blob_upload' });
    await detectStepUpRequired(r);
    // Caller should still be able to read the body for logging / display.
    const body = await r.json();
    expect(body.error).toBe('step_up_required');
  });
});
