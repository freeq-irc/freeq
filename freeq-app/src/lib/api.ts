/**
 * REST helper: attach the session bearer to API calls.
 *
 * Channel-scoped read endpoints (`/pins`, `/audit`, `/events`, `/sessions`,
 * `/topic`, `/history`, `/export`, and the governance endpoints) all enforce the
 * same access rule as history: a mode-restricted channel (+i / +k / encrypted)
 * is refused unless the bearer resolves to a member, op or founder. A bare
 * `fetch()` therefore works for public channels and silently 403s for private
 * ones — which is exactly the sort of thing that looks fine in dev and breaks
 * for the people who care most about privacy.
 *
 * The bearer arrives asynchronously (API-BEARER notice, shortly after
 * `registered`), so callers must tolerate its absence: guests never get one, and
 * public endpoints don't need it.
 */
import { getClient } from '../irc/client';

/** Merge `Authorization: Bearer …` into `extra` when a session bearer exists. */
export function authHeaders(extra?: HeadersInit): HeadersInit {
  const bearer = getClient()?.apiBearer;
  if (!bearer) return extra ?? {};
  const h = new Headers(extra ?? {});
  h.set('Authorization', `Bearer ${bearer}`);
  return h;
}

/** `fetch` with the session bearer attached when available. */
export function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(path, { ...init, headers: authHeaders(init.headers) });
}

/** Is there a session bearer right now? */
export function hasBearer(): boolean {
  return !!getClient()?.apiBearer;
}

/**
 * Is a bearer plausibly still on its way?
 *
 * True only when a client exists but has no bearer yet — the window between
 * `registered` and the API-BEARER notice. A guest connection also lands here
 * briefly and then simply times out, which costs one wait and nothing else.
 * With no client at all there is nothing to wait for.
 */
export function bearerPending(): boolean {
  const c = getClient();
  return !!c && !c.apiBearer;
}

/**
 * Resolve once a session bearer exists, or give up after `timeoutMs`.
 *
 * The API-BEARER notice arrives shortly after `registered`, so anything that
 * fires on mount can race it. Callers that would otherwise report "you are
 * not allowed" should wait here first and retry, rather than tell an
 * authenticated member they are a stranger.
 */
export async function waitForBearer(timeoutMs = 4000): Promise<string | null> {
  const step = 200;
  for (let waited = 0; waited < timeoutMs; waited += step) {
    const b = getClient()?.apiBearer;
    if (b) return b;
    await new Promise((r) => setTimeout(r, step));
  }
  return getClient()?.apiBearer ?? null;
}
