import Foundation

/// A parsed agent coordination event carried on a message
/// (`+freeq.at/event` + friends). Pure/Foundation-only so it lives in the
/// test-harness core; `AppState` maps the FFI `CoordinationEvent` into this
/// at the event boundary.
///
/// `Codable` because the local caches persist it: a cached row that lost its
/// event renders as plain text after a relaunch, and dedup on load keeps the
/// cached copy, so the replay that carries the tags is discarded.
struct CoordinationInfo: Equatable, Codable {
    var eventType: String
    var taskId: String?
    var phase: String?
    var evidenceType: String?
    var reference: String?
    var payload: String?
}

/// One key/value line on an event card.
struct PayloadRow: Equatable {
    let key: String
    let value: String
}

/// The rows an event card shows for its `+freeq.at/payload` tag.
///
/// The tag is JSON by convention and nothing enforces it, so the rule answers
/// for everything that can arrive rather than for the happy case: an object
/// spreads into its top-level keys, anything else that parses becomes one
/// `payload` row, and text that never was JSON becomes that same row carrying
/// what was sent. A tag that arrived is never dropped.
///
/// A value is shown as the document wrote it, never re-serialized: a string
/// decoded, everything else sliced out of the source text with the whitespace
/// between its tokens dropped. The parsed value would not do — `0.3` comes
/// back out of `JSONSerialization` as `0.29999999999999999`.
///
/// The same rule the web and Android clients apply, so one payload reads the
/// same on all four.
enum EventCardPayload {

    static func rows(_ rawTagValue: String?) -> [PayloadRow] {
        guard let raw = rawTagValue, !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return [] }
        // Percent-decoding, not form decoding: `+` stays a plus. Malformed
        // escaping keeps the bytes that arrived rather than throwing them away.
        let decoded = raw.removingPercentEncoding ?? raw
        let trimmed = decoded.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = trimmed.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        else { return [PayloadRow(key: "payload", value: decoded)] }

        if let object = parsed as? [String: Any] {
            return objectRows(object, text: trimmed)
        }
        if let string = parsed as? String {
            return [PayloadRow(key: "payload", value: string)]
        }
        return [PayloadRow(key: "payload", value: compact(trimmed))]
    }

    /// One row per top-level key, in the order the document wrote them, each
    /// value the source text the document gave it.
    ///
    /// Both come off the text rather than out of the parsed value:
    /// `JSONSerialization` hands back a dictionary, which has an order of its
    /// own and would put the rows in a different sequence from the other three
    /// clients, and a parsed number no longer knows how it was written.
    private static func objectRows(_ object: [String: Any], text: String) -> [PayloadRow] {
        if let scanned = scanObject(text) {
            // A key written twice is one row: the rows are keyed by their key.
            var seen = Set<String>()
            return scanned
                .filter { seen.insert($0.key).inserted }
                .map { PayloadRow(key: $0.key, value: showSource($0.raw)) }
        }
        return object.keys.sorted().map {
            PayloadRow(key: $0, value: showParsed(object[$0] as Any))
        }
    }

    /// One top-level key with the source text of its value.
    private struct Entry {
        let key: String
        let raw: String
    }

    /// The top-level entries of a JSON object, each with the source text of its
    /// value, in the order the document wrote them.
    ///
    /// Nil when the text is not one complete JSON object, which leaves the
    /// caller its own fallback.
    private static func scanObject(_ text: String) -> [Entry]? {
        let chars = Array(text)
        var i = 0
        func skip() { while i < chars.count && isSpace(chars[i]) { i += 1 } }
        func at() -> Character? { i < chars.count ? chars[i] : nil }
        func closes(_ entries: [Entry]) -> [Entry]? {
            i += 1
            skip()
            return i == chars.count ? entries : nil
        }

        skip()
        guard at() == "{" else { return nil }
        i += 1
        var entries: [Entry] = []
        skip()
        if at() == "}" { return closes(entries) }
        while true {
            skip()
            guard at() == "\"" else { return nil }
            guard let keyEnd = endOfString(chars, from: i),
                  let key = decodeString(String(chars[i...keyEnd]))
            else { return nil }
            i = keyEnd + 1
            skip()
            guard at() == ":" else { return nil }
            i += 1
            skip()
            guard let valueEnd = endOfValue(chars, from: i) else { return nil }
            entries.append(Entry(key: key, raw: String(chars[i..<valueEnd])))
            i = valueEnd
            skip()
            if at() == "," { i += 1; continue }
            if at() == "}" { return closes(entries) }
            return nil
        }
    }

    /// The index of the quote that closes the string opened at `start`.
    private static func endOfString(_ chars: [Character], from start: Int) -> Int? {
        var i = start + 1
        while i < chars.count {
            if chars[i] == "\\" { i += 2; continue }
            if chars[i] == "\"" { return i }
            i += 1
        }
        return nil
    }

    /// The index just past the value that starts at `start`.
    private static func endOfValue(_ chars: [Character], from start: Int) -> Int? {
        guard start < chars.count else { return nil }
        let c = chars[start]
        if c == "\"" {
            guard let end = endOfString(chars, from: start) else { return nil }
            return end + 1
        }
        if c == "{" || c == "[" {
            var depth = 0
            var i = start
            while i < chars.count {
                let ch = chars[i]
                if ch == "\"" {
                    guard let end = endOfString(chars, from: i) else { return nil }
                    i = end + 1
                    continue
                }
                if ch == "{" || ch == "[" {
                    depth += 1
                } else if ch == "}" || ch == "]" {
                    depth -= 1
                    if depth == 0 { return i + 1 }
                }
                i += 1
            }
            return nil
        }
        var i = start
        while i < chars.count, !isSpace(chars[i]),
              chars[i] != ",", chars[i] != "}", chars[i] != "]" {
            i += 1
        }
        return i == start ? nil : i
    }

    /// The same text with the whitespace between its tokens dropped.
    private static func compact(_ text: String) -> String {
        let chars = Array(text)
        var out = ""
        var i = 0
        while i < chars.count {
            if chars[i] == "\"" {
                guard let end = endOfString(chars, from: i) else {
                    return out + String(chars[i...])
                }
                out += String(chars[i...end])
                i = end + 1
                continue
            }
            if !isSpace(chars[i]) { out.append(chars[i]) }
            i += 1
        }
        return out
    }

    private static func isSpace(_ c: Character) -> Bool {
        c == " " || c == "\t" || c == "\n" || c == "\r"
    }

    /// The text of a JSON string token, decoded.
    private static func decodeString(_ token: String) -> String? {
        guard let data = "[\(token)]".data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [Any],
              array.count == 1
        else { return nil }
        return array.first as? String
    }

    /// A value as a row shows it: a string decoded, everything else as written.
    private static func showSource(_ raw: String) -> String {
        if raw.hasPrefix("\""), let string = decodeString(raw) { return string }
        return compact(raw)
    }

    /// A parsed value, for the fallback where the source text could not be read.
    private static func showParsed(_ value: Any) -> String {
        if value is NSNull { return "null" }
        if let s = value as? String { return s }
        if let data = try? JSONSerialization.data(
            withJSONObject: value,
            options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes]),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        return String(describing: value)
    }
}
