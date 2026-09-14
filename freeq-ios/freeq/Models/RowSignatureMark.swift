import Foundation

/// The signature mark a message row wears, decided from the row's verdict.
/// Pure/Foundation → unit-testable; the views only apply it. Mirrors the
/// macOS `RowSignatureMark`.
enum RowSignatureMark: Equatable {
    /// The sender's own device signed: a lock at `opacity`, full when the key
    /// is published in their account, 30% while only their server vouches.
    case lock(opacity: Double)
    /// The signature failed, or was made after its key was retired.
    case warning

    /// The lock's opacity while only the sender's server vouches for the key.
    static let vouchedOpacity = 0.3

    /// The mark for a verdict; nil with no verdict and for every state that
    /// shows nothing: server-signed, unsigned, unverifiable, still checking.
    static func of(_ verdict: VerdictInfo?) -> RowSignatureMark? {
        guard let verdict else { return nil }
        switch verdict.kind {
        case .device:
            return .lock(opacity: verdict.layer == .published ? 1 : vouchedOpacity)
        case .invalid, .retired:
            return .warning
        case .server, .unsigned, .unverifiable, .pending:
            return nil
        }
    }

    /// A row's mark once its check has answered; `mark` is nil for a verdict
    /// that shows nothing.
    struct Settled: Equatable {
        let mark: RowSignatureMark?
    }

    /// The settled mark for a verdict; nil with no verdict or while pending.
    static func settled(_ verdict: VerdictInfo?) -> Settled? {
        guard let verdict, verdict.kind != .pending else { return nil }
        return Settled(mark: of(verdict))
    }

    /// Whether a row that would group under its header starts its own header
    /// instead: only when both marks have settled and differ. Nil is pending,
    /// and a pending mark matches.
    static func startsHeader(header: Settled?, row: Settled?) -> Bool {
        guard let header, let row else { return false }
        return header != row
    }

    /// Which rows start a header, in one pass over the transcript. A row
    /// starts one when it breaks the sender's run, or when its settled mark
    /// differs from its header's, the nearest header above it in the run.
    static func headers(breaksRun: [Bool], marks: [Settled?]) -> [Bool] {
        var headers: [Bool] = []
        headers.reserveCapacity(breaksRun.count)
        var headerMark: Settled? = nil
        for (breaks, mark) in zip(breaksRun, marks) {
            let starts = breaks || startsHeader(header: headerMark, row: mark)
            if starts { headerMark = mark }
            headers.append(starts)
        }
        return headers
    }
}
