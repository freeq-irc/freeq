import Foundation

/// Whose PART is this?
///
/// A PART line carries a nick and nothing else. Every device signed in as the same
/// identity shares that nick, so "a PART whose nick equals mine" cannot distinguish
/// *this* client leaving a channel from the phone, the web client, or a game session
/// leaving one. The old code assumed it was always us, dropped the channel, and
/// wrote the removal into the persisted auto-join list — so closing a browser tab
/// could silently and permanently remove a channel from the Mac, one the user was
/// not even looking at.
///
/// The asymmetry with JOIN matters. Handling a foreign JOIN as our own is harmless
/// because joining is additive and idempotent. Handling a foreign PART as our own is
/// destructive *and* durable, so it needs a real answer rather than a safe default.
///
/// The answer is intent: we know which channels *we* asked to leave. A self-nick
/// PART for a channel we requested is ours. One we did not request belongs to
/// another device, and we keep the channel.
enum SelfPartResolve {
    /// What to do with an incoming PART.
    enum Decision: Equatable {
        /// We asked for this. Remove the channel and stop auto-joining it.
        case leaveChannel
        /// Another of our devices left. Keep the channel and the subscription.
        case ignoreOtherDevice
        /// Somebody else left a channel we are in. Update the roster only.
        case removeMember(nick: String)
    }

    /// How long a request we sent stays credible.
    ///
    /// Requests are matched by channel name, not by any id the server echoes back,
    /// so an unbounded record would make a much later foreign PART look like ours.
    /// A few seconds is far longer than a round trip and far shorter than the gap
    /// between a user leaving a channel here and another device leaving it there.
    static let requestValidity: TimeInterval = 10

    /// Decide what an incoming PART means.
    ///
    /// - Parameters:
    ///   - channel: channel named in the PART.
    ///   - partNick: nick in the PART line.
    ///   - myNick: this client's current nick.
    ///   - pendingRequests: channels we sent a PART for, with when we sent it.
    ///   - now: current time, injected for testability.
    static func decide(
        channel: String,
        partNick: String,
        myNick: String,
        pendingRequests: [String: Date],
        now: Date = Date()
    ) -> Decision {
        guard partNick.lowercased() == myNick.lowercased() else {
            return .removeMember(nick: partNick)
        }
        guard let requestedAt = pendingRequests[channel.lowercased()] else {
            return .ignoreOtherDevice
        }
        guard now.timeIntervalSince(requestedAt) <= requestValidity else {
            // We did ask once, but too long ago for this to be the reply.
            return .ignoreOtherDevice
        }
        return .leaveChannel
    }
}
