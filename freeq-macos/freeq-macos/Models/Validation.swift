import Foundation

/// Pure-Foundation input validation + safe URL/regex constructors.
///
/// Lives here (not buried in views) so it can be unit-tested without
/// the SwiftUI / AppKit / Keychain stack — the test target at
/// `freeq-macos/Tests/` mirrors this file and runs the same assertions
/// under `swift test`.
///
/// Every constructor returns `URL?` rather than a force-unwrapped URL:
/// freeq messages can carry arbitrary user-controlled handles, rkeys,
/// and identifiers, and `URL(string:)` rejects them when they contain
/// whitespace / control chars / certain unicode. A force-unwrap there
/// is a crash-on-bad-input, not a programmer error.
public enum Validation {
    // MARK: - URL builders

    /// `https://bsky.app/profile/<handle>` with percent-encoding applied
    /// to `handle`. Returns nil only when the encoded result still
    /// fails URL parsing — rare in practice but possible with empty input.
    public static func makeBlueSkyProfileURL(handle: String) -> URL? {
        let trimmed = handle.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let encoded = trimmed.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        ) else { return nil }
        return URL(string: "https://bsky.app/profile/\(encoded)")
    }

    /// `https://bsky.app/profile/<handle>/post/<rkey>` with percent-encoding.
    public static func makeBlueSkyPostURL(handle: String, rkey: String) -> URL? {
        let trimmedHandle = handle.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedRkey = rkey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHandle.isEmpty, !trimmedRkey.isEmpty else { return nil }
        guard let h = trimmedHandle.addingPercentEncoding(
                withAllowedCharacters: .urlPathAllowed
              ),
              let r = trimmedRkey.addingPercentEncoding(
                withAllowedCharacters: .urlPathAllowed
              )
        else { return nil }
        return URL(string: "https://bsky.app/profile/\(h)/post/\(r)")
    }

    /// `https://youtube.com/watch?v=<id>` with percent-encoding.
    public static func makeYouTubeWatchURL(videoId: String) -> URL? {
        let trimmed = videoId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let encoded = trimmed.addingPercentEncoding(
            withAllowedCharacters: .urlQueryAllowed
        ) else { return nil }
        return URL(string: "https://youtube.com/watch?v=\(encoded)")
    }

    /// Build the broker `/session` endpoint URL. Returns nil for
    /// empty / malformed base URLs — caller must surface to the user
    /// rather than force-unwrapping.
    public static func brokerSessionURL(brokerBase: String) -> URL? {
        let trimmed = brokerBase.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        // Strip trailing slashes so "host/" + "/session" → "host/session".
        let normalized = trimmed.hasSuffix("/")
            ? String(trimmed.dropLast())
            : trimmed
        return URL(string: "\(normalized)/session")
    }

    /// Build the broker `/auth/login` URL with handle + return_to query
    /// params. Uses `URLComponents` so query item values are encoded
    /// safely against injection — a handle containing `&` or `=` can't
    /// smuggle additional query parameters.
    public static func brokerLoginURL(
        brokerBase: String,
        handle: String,
        returnTo: String
    ) -> URL? {
        let trimmedBase = brokerBase.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedBase.isEmpty else { return nil }
        let normalized = trimmedBase.hasSuffix("/")
            ? String(trimmedBase.dropLast())
            : trimmedBase
        guard var comps = URLComponents(string: "\(normalized)/auth/login")
        else { return nil }
        // `mobile=1` tells the broker to complete via the `freeq://` app
        // scheme (host-agnostic) instead of rendering a popup web page —
        // matches iOS and Android. `ASWebAuthenticationSession` intercepts
        // that redirect by its `freeq` callback scheme.
        comps.queryItems = [
            URLQueryItem(name: "handle", value: handle),
            URLQueryItem(name: "mobile", value: "1"),
            // `intent=enroll` asks the account for permission to write this
            // device's key records, on top of the identity-only default.
            URLQueryItem(name: "intent", value: "enroll"),
            URLQueryItem(name: "return_to", value: returnTo),
        ]
        return comps.url
    }

    // MARK: - IRC nick validation

    public enum NickError: Error, Equatable {
        case empty
        case tooLong(maxLen: Int)
        case containsWhitespace
        case startsWithDigit
        case invalidCharacter(scalar: String)
    }

    /// RFC-2812-flavoured IRC nick validation. Conservative — rejects
    /// whitespace, control chars, and anything outside the conventional
    /// `[A-Za-z][A-Za-z0-9_\-\[\]\\{\}^|]*` set. Catches the typical
    /// user errors (typing a space, typing their full name with a
    /// period) at submit time so the user sees a useful message instead
    /// of a server "Invalid nick" round-trip later.
    public static func validateIrcNick(_ nick: String) -> Result<String, NickError> {
        // Strip surrounding whitespace before checking — we don't reject
        // a leading space, we just trim it.
        let trimmed = nick.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return .failure(.empty) }
        if trimmed.count > 30 { return .failure(.tooLong(maxLen: 30)) }
        if trimmed.contains(where: { $0.isWhitespace }) {
            return .failure(.containsWhitespace)
        }
        if let first = trimmed.first, first.isNumber {
            return .failure(.startsWithDigit)
        }
        let allowed: Set<Character> = Set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-[]\\{}^|"
        )
        for c in trimmed {
            if !allowed.contains(c) {
                return .failure(.invalidCharacter(scalar: String(c)))
            }
        }
        return .success(trimmed)
    }

    // MARK: - Safe NSDataDetector

    /// `NSDataDetector(types: link)` can theoretically return nil if the
    /// regex engine fails to compile (extremely rare on Foundation, but
    /// the API is `try?`). Centralised here so callers don't repeat the
    /// `guard let detector = …` boilerplate; tests pin the behaviour.
    public static func linkDetector() -> NSDataDetector? {
        try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
    }

    /// Wrapper that returns an empty array of matches if the detector
    /// failed to construct — so a malformed regex environment can never
    /// crash the message-rendering code path.
    public static func linkMatches(in text: String) -> [NSTextCheckingResult] {
        guard let detector = linkDetector() else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return detector.matches(in: text, options: [], range: range)
    }
}
