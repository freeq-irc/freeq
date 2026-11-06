import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { ErrorBoundary } from './components/ErrorBoundary'
import { consumeRoomLink } from './lib/room-link'

// A room share link (`/r/<name>#<token>` or `/?room=<name>#<token>`) is
// parked for the connect flow and scrubbed from the URL before anything
// renders, so the token never sits in the address bar or in history.
consumeRoomLink();

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>,
  );
}

// Register service worker for PWA
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}
