// Service worker — app shell cache + offline support
// CACHE_VERSION is replaced at build time by the build script.
// Each deploy produces a unique sw.js → browser re-installs → activate clears old cache.
const CACHE_NAME = 'freeq-__BUILD_HASH__';

self.addEventListener('install', (event) => {
  // Pre-cache the app shell (index.html)
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(['/']))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  // Clean old caches
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never cache: non-GET, WebSocket, API, OAuth
  if (event.request.method !== 'GET') return;
  if (url.pathname.startsWith('/irc') || url.pathname.startsWith('/api') || url.pathname.startsWith('/auth')) {
    return;
  }
  // Other origins (account providers, DID documents) go straight to the network.
  if (url.origin !== self.location.origin) return;

  // Hashed assets (/assets/*) — cache-first (immutable, filename changes on content change)
  if (url.pathname.startsWith('/assets/')) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((resp) => {
          if (resp.ok) {
            const clone = resp.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return resp;
        });
      })
    );
    return;
  }

  // HTML/navigation — network-first, fall back to cached shell
  if (event.request.mode === 'navigate' || event.request.destination === 'document') {
    event.respondWith(
      fetch(event.request)
        .then((resp) => {
          // Update cache with fresh HTML
          const clone = resp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('/', clone));
          return resp;
        })
        .catch(() => caches.match('/'))
    );
    return;
  }

  // Static files (favicon, icons, manifest) — stale-while-revalidate
  event.respondWith(
    caches.match(event.request).then((cached) => {
      const fetchPromise = fetch(event.request).then((resp) => {
        if (resp.ok) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return resp;
      }).catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
