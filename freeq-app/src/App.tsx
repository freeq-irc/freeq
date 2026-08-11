import { useState, useCallback, useEffect, useRef } from 'react';
import { useStore } from './store';
import { useKeyboard } from './hooks/useKeyboard';
import { setUnreadCount } from './lib/notifications';
import { ConnectScreen } from './components/ConnectScreen';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { MessageList, TypingIndicatorBar } from './components/MessageList';
import { ComposeBox } from './components/ComposeBox';
import { MemberList } from './components/MemberList';
import { QuickSwitcher } from './components/QuickSwitcher';
import { SettingsPanel } from './components/SettingsPanel';
import { ReconnectBanner } from './components/ReconnectBanner';
import { GuestUpgradeBanner } from './components/GuestUpgradeBanner';
import { ImageLightbox } from './components/ImageLightbox';
import { SearchModal } from './components/SearchModal';
import { ChannelListModal } from './components/ChannelListModal';
import { ThreadView } from './components/ThreadView';
import { JoinGateModal } from './components/JoinGateModal';
import { ChannelSettingsPanel } from './components/ChannelSettingsPanel';
import { KeyboardShortcuts } from './components/KeyboardShortcuts';
import { ToastContainer } from './components/Toast';
import { startUpdateCheck } from './lib/update-check';
import { FileDropOverlay } from './components/FileDropOverlay';
import { InstallPrompt } from './components/InstallPrompt';
import { OnboardingTour } from './components/OnboardingTour';
import { BookmarksPanel } from './components/BookmarksPanel';
import { MotdBanner } from './components/MotdBanner';
import { CallPanel } from './components/CallPanel';

const SIDEBAR_OPEN_KEY = 'freeq-sidebar-open';
const MEMBERS_OPEN_KEY = 'freeq-members-open';

function getStoredBoolean(key: string, fallback: boolean) {
  if (typeof window === 'undefined') return fallback;
  try {
    const value = window.localStorage.getItem(key);
    return value === null ? fallback : value === 'true';
  } catch {
    return fallback;
  }
}

function setStoredBoolean(key: string, value: boolean) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(key, String(value));
  } catch {
    // Storage can be unavailable in private browsing or locked-down embeds.
  }
}

function isDesktopViewport() {
  return typeof window === 'undefined' || window.innerWidth >= 768;
}

export default function App() {
  const registered = useStore((s) => s.registered);
  const wasRegistered = useStore((s) => s.wasRegistered);
  const setWasRegistered = useStore((s) => s.setWasRegistered);
  const theme = useStore((s) => s.theme);
  // Once we've been registered in this session, don't flash back to ConnectScreen
  // on brief state transitions (e.g. reconnect). The ReconnectBanner handles that.
  // `wasRegistered` lives in the store so explicit logout (`fullReset`) can clear
  // it and bounce back to ConnectScreen.
  useEffect(() => {
    if (registered && !wasRegistered) setWasRegistered(true);
  }, [registered, wasRegistered, setWasRegistered]);
  // Stale-tab detector: prompt to reload when a new build is deployed.
  useEffect(() => startUpdateCheck(), []);
  const showApp = registered || wasRegistered;
  const [quickSwitcher, setQuickSwitcher] = useState(false);
  const [settings, setSettings] = useState(false);
  const [shortcuts, setShortcuts] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(() => getStoredBoolean(SIDEBAR_OPEN_KEY, true));
  const [membersOpen, setMembersOpen] = useState(() => getStoredBoolean(MEMBERS_OPEN_KEY, isDesktopViewport()));
  const threadMsgId = useStore((s) => s.threadMsgId);
  const threadChannel = useStore((s) => s.threadChannel);
  const channels = useStore((s) => s.channels);
  const activeChannel = useStore((s) => s.activeChannel);
  const setActive = useStore((s) => s.setActiveChannel);
  const hasRightSidebar = activeChannel !== 'server';
  const isProfileSidebar = hasRightSidebar && !activeChannel.startsWith('#');
  const rightSidebarWidth = isProfileSidebar ? 'w-64' : 'w-52';
  const rightSidebarDesktopWidth = isProfileSidebar ? 'md:w-64' : 'md:w-52';

  useEffect(() => {
    setStoredBoolean(SIDEBAR_OPEN_KEY, sidebarOpen);
  }, [sidebarOpen]);

  useEffect(() => {
    setStoredBoolean(MEMBERS_OPEN_KEY, membersOpen);
  }, [membersOpen]);

  // Swipe gesture to open/close sidebar on mobile
  const touchStart = useRef<{ x: number; y: number } | null>(null);
  useEffect(() => {
    const onStart = (e: TouchEvent) => {
      touchStart.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    };
    const onEnd = (e: TouchEvent) => {
      if (!touchStart.current) return;
      const dx = e.changedTouches[0].clientX - touchStart.current.x;
      const dy = Math.abs(e.changedTouches[0].clientY - touchStart.current.y);
      // Horizontal swipe (>80px, mostly horizontal)
      if (Math.abs(dx) > 80 && dy < 60 && window.innerWidth < 768) {
        if (dx > 0 && touchStart.current.x < 40) setSidebarOpen(true);
        else if (dx < 0 && sidebarOpen) setSidebarOpen(false);
      }
      touchStart.current = null;
    };
    document.addEventListener('touchstart', onStart, { passive: true });
    document.addEventListener('touchend', onEnd, { passive: true });
    return () => { document.removeEventListener('touchstart', onStart); document.removeEventListener('touchend', onEnd); };
  }, [sidebarOpen]);

  // Apply theme to document
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // Mobile keyboard: resize layout when virtual keyboard appears
  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;
    const onResize = () => {
      // When keyboard is open, visualViewport.height < window.innerHeight
      const offset = window.innerHeight - vv.height;
      document.documentElement.style.setProperty('--vk-offset', `${offset}px`);
    };
    vv.addEventListener('resize', onResize);
    vv.addEventListener('scroll', onResize);
    return () => { vv.removeEventListener('resize', onResize); vv.removeEventListener('scroll', onResize); };
  }, []);

  // Request notification permission when registered
  useEffect(() => {
    // Notification permission is deferred to first mention (see notifications.ts)
  }, [registered]);

  // Handle invite link auto-join when already connected
  useEffect(() => {
    if (!registered) return;
    const hash = window.location.hash;
    if (hash.startsWith('#auto-join=')) {
      const ch = decodeURIComponent(hash.slice('#auto-join='.length));
      window.history.replaceState(null, '', window.location.pathname);
      // Join and switch to the channel
      import('./irc/client').then(({ joinChannel }) => {
        joinChannel(ch);
        setActive(ch);
      });
    }
  }, [registered, setActive]);

  // Close sidebar and member list on mobile when switching channels
  useEffect(() => {
    if (window.innerWidth < 768) {
      setSidebarOpen(false);
      setMembersOpen(false);
    }
  }, [activeChannel]);

  // Ensure modals close when we disconnect
  useEffect(() => {
    if (!registered) {
      setQuickSwitcher(false);
      setSettings(false);
      setShortcuts(false);
      useStore.getState().setSearchOpen(false);
      useStore.getState().setChannelListOpen(false);
      useStore.getState().setLightboxUrl(null);
      useStore.getState().closeThread();
    }
  }, [registered]);

  // Total unread for title badge
  const totalUnread = [...channels.values()].reduce((sum, ch) => sum + ch.unreadCount, 0);
  setUnreadCount(totalUnread);

  // Global keyboard shortcuts
  const switchToNth = useCallback((n: number) => {
    const favorites = useStore.getState().favorites;
    const allJoined = [...channels.values()].filter((ch) => ch.isJoined);
    const allChans = allJoined
      .filter((ch) => ch.name.startsWith('#') || ch.name.startsWith('&'))
      .sort((a, b) => a.name.localeCompare(b.name));
    const favList = allChans.filter((ch) => favorites.has(ch.name.toLowerCase()));
    const chanList = allChans.filter((ch) => !favorites.has(ch.name.toLowerCase()));
    const dmList = allJoined
      .filter((ch) => !ch.name.startsWith('#') && !ch.name.startsWith('&') && ch.name !== 'server')
      .sort((a, b) => a.name.localeCompare(b.name));
    const ordered = [...favList, ...chanList, ...dmList];
    if (ordered[n]) setActive(ordered[n].name);
  }, [channels, setActive]);

  const switchChannel = useCallback((dir: -1 | 1) => {
    const sorted = [...channels.values()]
      .filter((ch) => ch.isJoined)
      .sort((a, b) => a.name.localeCompare(b.name));
    const idx = sorted.findIndex((ch) => ch.name.toLowerCase() === activeChannel.toLowerCase());
    const next = sorted[idx + dir];
    if (next) setActive(next.name);
  }, [channels, activeChannel, setActive]);

  useKeyboard(registered ? {
    'mod+k': () => setQuickSwitcher(true),
    'mod+f': () => useStore.getState().setSearchOpen(true),
    'alt+ArrowUp': () => switchChannel(-1),
    'alt+ArrowDown': () => switchChannel(1),
    'mod+/': () => setShortcuts(true),
    'mod+b': () => useStore.getState().setBookmarksPanelOpen(true),
    'alt+1': () => switchToNth(0),
    'alt+2': () => switchToNth(1),
    'alt+3': () => switchToNth(2),
    'alt+4': () => switchToNth(3),
    'alt+5': () => switchToNth(4),
    'alt+6': () => switchToNth(5),
    'alt+7': () => switchToNth(6),
    'alt+8': () => switchToNth(7),
    'alt+9': () => switchToNth(8),
    'alt+0': () => switchToNth(9),
    'escape': () => {
      setQuickSwitcher(false);
      setSettings(false);
      setShortcuts(false);
      useStore.getState().setSearchOpen(false);
      useStore.getState().setChannelListOpen(false);
      useStore.getState().setLightboxUrl(null);
      useStore.getState().closeThread();
    },
  } : {}, [channels, switchToNth, registered]);

  if (!showApp) {
    return (
      <div className="h-dvh flex flex-col bg-bg">
        <ConnectScreen />
      </div>
    );
  }

  return (
    <div className="fixed inset-0 flex flex-col bg-bg overflow-hidden" style={{ bottom: 'var(--vk-offset, 0px)' }}>
      <ReconnectBanner />
      <GuestUpgradeBanner />
      <div className="flex flex-1 min-h-0">
        <div
          className={`app-sidebar-backdrop fixed inset-0 bg-black/40 z-20 md:hidden ${
            sidebarOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
          }`}
          onClick={() => setSidebarOpen(false)}
        />
        <div className={`app-sidebar-shell fixed inset-y-0 left-0 z-30 w-64 md:relative md:inset-auto md:h-full ${
          sidebarOpen ? 'translate-x-0 md:w-64' : '-translate-x-full md:w-0 md:translate-x-0 pointer-events-none'
        }`}>
          <Sidebar onOpenSettings={() => setSettings(true)} />
        </div>

        <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
          <MotdBanner />
          <TopBar
            onToggleSidebar={() => setSidebarOpen((open) => !open)}
            onToggleMembers={() => setMembersOpen((open) => !open)}
            sidebarOpen={sidebarOpen}
            membersOpen={membersOpen}
          />
          <CallPanel />
          <MessageList />
          <TypingIndicatorBar />
          <ComposeBox />
        </main>
        {/* Member/profile list — inline on desktop, overlay on mobile */}
        {hasRightSidebar && (
          <>
            <div
              className={`app-sidebar-backdrop fixed inset-0 bg-black/40 z-20 md:hidden ${
                membersOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
              }`}
              onClick={() => setMembersOpen(false)}
            />
            <div className={`app-sidebar-shell fixed right-0 top-0 bottom-0 z-30 ${rightSidebarWidth} md:relative md:inset-auto md:z-auto md:h-full ${
              membersOpen ? `translate-x-0 ${rightSidebarDesktopWidth}` : 'translate-x-full md:w-0 md:translate-x-0 pointer-events-none'
            }`}>
              <MemberList />
            </div>
          </>
        )}
        {threadMsgId && threadChannel && (
          <ThreadView
            rootMsgId={threadMsgId}
            channel={threadChannel}
            onClose={() => useStore.getState().closeThread()}
          />
        )}
      </div>
      <QuickSwitcher open={quickSwitcher} onClose={() => setQuickSwitcher(false)} />
      <SettingsPanel open={settings} onClose={() => setSettings(false)} />
      <ImageLightbox />
      <SearchModal />
      <ChannelListModal />
      <JoinGateModal />
      <ChannelSettingsPanel />
      <KeyboardShortcuts open={shortcuts} onClose={() => setShortcuts(false)} />
      <ToastContainer />
      <FileDropOverlay />
      <InstallPrompt />
      <OnboardingTour />
      <BookmarksPanel />
    </div>
  );
}
