import Foundation

/// Keyboard-driven buffer navigation (iPad hardware keyboard). Mirrors the
/// macOS client's ⌥↑/↓, ⌥⇧↑/↓, ⌘1–9 and ⌃⌘1–9 behaviors.
extension AppState {
    /// Favorite buffers (channels + DMs) in favorite order, present ones only.
    var favoriteBuffers: [ChannelState] {
        let all = channels + dmBuffers
        return favoritesOrder.compactMap { name in all.first { $0.name == name } }
    }

    /// Full sidebar-ordered buffer names, matching what's rendered on screen:
    /// favorites first (favorite order), then channels **alphabetically**, then
    /// DMs by recency. ⌘1–9 and ⌥↑/↓ step through this exact order, so the
    /// numbers line up with the visible list.
    private var sidebarBufferOrder: [String] {
        let sortedChannels = channels
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            .map(\.name)
        let sortedDms = dmBuffers
            .filter { !isBufferBlocked($0.name) }
            .sorted { $0.lastActivity > $1.lastActivity }
            .map(\.name)
        return BufferNavigation.sidebarOrder(
            channels: sortedChannels, favoriteOrder: favoritesOrder, dms: sortedDms)
    }

    /// Buffers with unread messages.
    private var unreadBufferNames: Set<String> {
        Set(unreadCounts.filter { $0.value > 0 }.map(\.key))
    }

    /// Navigate to a buffer by name — drives both the iPad split view (via
    /// `activeChannel`) and the iPhone navigation stacks (via the pending nav).
    func navigate(toBuffer name: String) {
        activeChannel = name
        requestDmHistoryOnOpenIfNeeded(name)
        if name.hasPrefix("#") || name.hasPrefix("&") {
            pendingChannelNav = name
        } else {
            pendingDMNick = name
        }
    }

    /// ⌥↑ / ⌥↓ — step to the adjacent buffer (⌥⇧↑/↓ when `unreadOnly`).
    func switchToAdjacentChannel(delta: Int, unreadOnly: Bool = false) {
        guard let target = BufferNavigation.step(
            order: sidebarBufferOrder, current: activeChannel, delta: delta,
            unreadOnly: unreadOnly, unread: unreadBufferNames
        ) else { return }
        navigate(toBuffer: target)
    }

    /// ⌘1…⌘9 — jump to buffer N (0-based) in sidebar order.
    func switchToChannelByIndex(_ index: Int) {
        guard let target = BufferNavigation.atIndex(index, order: sidebarBufferOrder) else { return }
        navigate(toBuffer: target)
    }

    /// ⌃⌘1…⌃⌘9 — jump to favorite N (0-based).
    func switchToFavorite(_ index: Int) {
        let favs = favoriteBuffers
        guard index >= 0, index < favs.count else { return }
        navigate(toBuffer: favs[index].name)
    }
}
