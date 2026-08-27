/**
 * Helper for the freeq-server's `/auth/step-up` flow.
 *
 * The default OAuth login asks Bluesky for `atproto` only — proof of
 * identity, no PDS write access. When the user triggers a feature that
 * needs more (image upload, Bluesky cross-post), the server's API
 * returns 403 with a structured `step_up_required` body. This helper
 * pops the step-up flow in a popup window, waits for the BroadcastChannel
 * "ok" signal from the callback page, and resolves so the caller can
 * retry the original action.
 */
export type StepUpPurpose = 'blob_upload' | 'bluesky_post' | 'media_space';

/**
 * Returns the base URL of the freeq HTTP server. The web app is normally
 * served from the same origin (production), but in dev (vite) the server
 * lives on a different port — `__FREEQ_TARGET__` is wired by vite config.
 */
function serverOrigin(): string {
  // Same-origin in production; vite proxy in dev (so '' works for both).
  return '';
}

/** Outcome returned by [`requestStepUp`]. Lets the caller distinguish
 *  "user said no" / "popup blocked" / "took too long" / "succeeded"
 *  without parsing a boolean. */
export type StepUpOutcome =
  | { ok: true }
  | { ok: false; reason: 'popup_blocked' | 'closed' | 'timeout' };

/**
 * Drive a step-up OAuth flow.
 *
 * Resolves with `{ok:true}` when the popup confirms the new permission
 * was granted, otherwise an `{ok:false, reason:…}` describing why so the
 * caller can surface the right user-facing message. Never throws.
 */
export async function requestStepUp(
  purpose: StepUpPurpose,
  did: string,
  opts: { timeoutMs?: number } = {},
): Promise<StepUpOutcome> {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const url =
    `${serverOrigin()}/auth/step-up?purpose=${encodeURIComponent(purpose)}` +
    `&did=${encodeURIComponent(did)}`;

  const popup = window.open(url, 'freeq-step-up', 'width=520,height=720');
  if (!popup) {
    // Popups blocked. Falling back to a full-page redirect would lose
    // the user's chat state (the BroadcastChannel signal can't reach a
    // tab that no longer exists). Refuse instead — the caller surfaces
    // a "please allow popups" message.
    return { ok: false, reason: 'popup_blocked' };
  }

  // Two notification channels in case the browser blocks one:
  //   1. BroadcastChannel('freeq-oauth-step-up') — works cross-tab.
  //   2. window.postMessage from the popup directly.
  // Either signal resolves the promise.
  return await new Promise<StepUpOutcome>((resolve) => {
    let done = false;
    const finish = (outcome: StepUpOutcome) => {
      if (done) return;
      done = true;
      try { bc.close(); } catch { /* ignore */ }
      window.removeEventListener('message', onMsg);
      clearInterval(closedTimer);
      clearTimeout(timeoutTimer);
      try { popup.close(); } catch { /* ignore */ }
      resolve(outcome);
    };

    const bc = new BroadcastChannel('freeq-oauth-step-up');
    bc.onmessage = (ev: MessageEvent) => {
      if (ev.data?.type === 'freeq-oauth-step-up' && ev.data?.purpose === purpose) {
        finish({ ok: true });
      }
    };

    const onMsg = (ev: MessageEvent) => {
      if (ev.data?.type === 'freeq-oauth-step-up' && ev.data?.purpose === purpose) {
        finish({ ok: true });
      }
    };
    window.addEventListener('message', onMsg);

    // If the user closes the popup without completing, give up.
    const closedTimer = setInterval(() => {
      if (popup.closed) finish({ ok: false, reason: 'closed' });
    }, 500);

    // Hard ceiling so a forgotten popup never wedges the caller.
    const timeoutTimer = setTimeout(() => finish({ ok: false, reason: 'timeout' }), timeoutMs);
  });
}

/**
 * If the response is the server's structured `step_up_required` 403,
 * returns the purpose; otherwise null. Lets call sites decide whether
 * to drive the step-up flow without re-parsing the body themselves.
 *
 * The response is consumed (one-shot read) — pass a clone if you need
 * the body again.
 */
export async function detectStepUpRequired(
  resp: Response,
): Promise<StepUpPurpose | null> {
  if (resp.status !== 403) return null;
  try {
    const body = await resp.clone().json();
    if (body?.error === 'step_up_required' && body?.purpose) {
      const p = body.purpose as string;
      if (p === 'blob_upload' || p === 'bluesky_post' || p === 'media_space') return p;
    }
  } catch {
    // Not JSON, or wrong shape. Treat as a regular 403.
  }
  return null;
}
