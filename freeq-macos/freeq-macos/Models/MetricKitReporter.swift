import Foundation
import MetricKit
import os

/// Subscribes to MetricKit crash + hang diagnostics so we find failures
/// before users report them (today the user IS the crash reporter). On the
/// next launch after a crash, MetricKit delivers a `MXCrashDiagnostic` with
/// the call stack and termination reason; hangs arrive as `MXHangDiagnostic`.
///
/// Reports go to the unified log (subsystem `at.freeq.macos`, category
/// `diagnostics`) AND to a rolling file in the app's container
/// (`Diagnostics/latest-diagnostics.txt`) so they're inspectable without
/// Console. No PII beyond stack frames leaves the device; nothing is uploaded.
final class MetricKitReporter: NSObject, MXMetricManagerSubscriber {
    static let shared = MetricKitReporter()

    private let log = Logger(subsystem: "at.freeq.macos", category: "diagnostics")

    func start() {
        // MetricKit exists on macOS only from 26; on older systems the
        // manager symbol isn't there and the call would crash.
        guard #available(macOS 26.0, *) else { return }
        MXMetricManager.shared.add(self)
    }

    // Performance metrics (launch time, hang time, memory) — logged at a
    // glance; the file is for the perf receipts §7.5 calls for.
    func didReceive(_ payloads: [MXMetricPayload]) {
        for payload in payloads {
            if let launch = payload.applicationLaunchMetrics {
                log.info("launch p50 \(launch.histogrammedTimeToFirstDraw.description, privacy: .public)")
            }
            appendToFile(header: "METRICS \(payload.timeStampBegin)–\(payload.timeStampEnd)",
                         body: String(data: payload.jsonRepresentation(), encoding: .utf8) ?? "")
        }
    }

    // The important part: crash + hang diagnostics with call stacks.
    func didReceive(_ payloads: [MXDiagnosticPayload]) {
        for payload in payloads {
            for crash in payload.crashDiagnostics ?? [] {
                let reason = crash.terminationReason ?? "unknown"
                let signal = crash.signal?.stringValue ?? "?"
                log.critical("CRASH termination=\(reason, privacy: .public) signal=\(signal, privacy: .public)")
                appendToFile(header: "CRASH \(reason) signal=\(signal)",
                             body: String(data: crash.jsonRepresentation(), encoding: .utf8) ?? "")
            }
            for hang in payload.hangDiagnostics ?? [] {
                let dur = hang.hangDuration.description
                log.error("HANG duration=\(dur, privacy: .public)")
                appendToFile(header: "HANG \(dur)",
                             body: String(data: hang.jsonRepresentation(), encoding: .utf8) ?? "")
            }
        }
    }

    private func appendToFile(header: String, body: String) {
        guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return }
        let base = dir.appendingPathComponent("at.freeq.macos/Diagnostics", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        let url = base.appendingPathComponent("latest-diagnostics.txt")
        let entry = "\n===== \(header) =====\n\(body)\n"
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(entry.data(using: .utf8) ?? Data())
            try? handle.close()
        } else {
            try? entry.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
