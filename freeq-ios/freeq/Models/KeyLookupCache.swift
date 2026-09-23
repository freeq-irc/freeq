import Foundation
import os.log

/// Where the SDK's key lookup keeps what it has learned between launches:
/// the signing keys it found, each account's proven records with their
/// listing time, and the proof CIDs that checked.
///
/// One file per device, shared by every session on it, guests included, and
/// kept through sign-out, as the web app keeps its snapshot.
/// Nothing here is secret — every record in it is public in its account's
/// repository, and every proof was checked before it was kept — so it sits
/// in Application Support beside the buffer cache rather than the Keychain,
/// which the device key needs and this does not, and needs no account to
/// name it.
final class FileKeyLookupStore: KeyLookupStore {

    private static let log = Logger(subsystem: "at.freeq.ios", category: "keylookup")
    private static let fileName = "key-lookup.json"

    private func url() -> URL? {
        Self.directory()?.appendingPathComponent(Self.fileName)
    }

    func load() throws -> String? {
        guard let url = url(), FileManager.default.fileExists(atPath: url.path) else { return nil }
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            Self.log.warning("reading the key lookup cache failed: \(error.localizedDescription)")
            return nil
        }
    }

    /// Write through a temporary file and replace, so a process killed
    /// mid-write leaves the previous snapshot intact rather than a half file.
    func save(snapshot: String) throws {
        guard let url = url() else { return }
        let temp = url.appendingPathExtension("tmp")
        do {
            try snapshot.write(to: temp, atomically: false, encoding: .utf8)
            if FileManager.default.fileExists(atPath: url.path) {
                _ = try FileManager.default.replaceItemAt(url, withItemAt: temp)
            } else {
                try FileManager.default.moveItem(at: temp, to: url)
            }
        } catch {
            try? FileManager.default.removeItem(at: temp)
            Self.log.warning("keeping the key lookup cache failed: \(error.localizedDescription)")
        }
    }

    private static func directory() -> URL? {
        let fm = FileManager.default
        guard let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        else { return nil }
        let dir = appSupport.appendingPathComponent("freeq", isDirectory: true)
        if !fm.fileExists(atPath: dir.path) {
            do { try fm.createDirectory(at: dir, withIntermediateDirectories: true) }
            catch { return nil }
        }
        return dir
    }
}
