import Foundation
import SQLite3

/// Local SQLite message store for persistence across app restarts.
actor MessageStore {
    static let shared = MessageStore()
    private var db: OpaquePointer?

    /// `path` overrides the shared caches location so a test can open a
    /// throwaway database instead of the user's own.
    init(path: String? = nil) {
        openDatabase(at: path)
        createTable()
    }

    private func openDatabase(at override: String?) {
        let dbPath: String
        if let override {
            dbPath = override
        } else {
            let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            let dir = caches.appendingPathComponent("at.freeq.macos", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            dbPath = dir.appendingPathComponent("messages.sqlite").path
        }

        if sqlite3_open(dbPath, &db) != SQLITE_OK {
            Log.irc.error("Failed to open message database")
        }
        // WAL mode for performance
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nil, nil, nil)
    }

    private func createTable() {
        let sql = """
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            channel TEXT NOT NULL,
            from_nick TEXT NOT NULL,
            text TEXT NOT NULL,
            timestamp REAL NOT NULL,
            is_action INTEGER DEFAULT 0,
            is_signed INTEGER DEFAULT 0,
            is_edited INTEGER DEFAULT 0,
            is_deleted INTEGER DEFAULT 0,
            reply_to TEXT,
            origin TEXT,
            act_ref TEXT,
            coordination TEXT,
            UNIQUE(id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel, timestamp);
        CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
        """
        sqlite3_exec(db, sql, nil, nil, nil)
        // Additive migration for DBs created before the origin column existed.
        // Without it, federated messages reload from cache with origin == nil and
        // render as local — re-showing the verified/signed badges we suppress.
        sqlite3_exec(db, "ALTER TABLE messages ADD COLUMN origin TEXT;", nil, nil, nil)
        // Same again for the task a companion line names. A cached line that
        // lost it can never draw its card, and dedup on load keeps the cached
        // copy, so the replay that carries the tag is discarded.
        sqlite3_exec(db, "ALTER TABLE messages ADD COLUMN act_ref TEXT;", nil, nil, nil)
        // And again for the coordination event a row carries. Same reason: a
        // cached delegation_notice or status_update line that lost it renders
        // as plain text, and dedup keeps the cached copy over the replay.
        sqlite3_exec(db, "ALTER TABLE messages ADD COLUMN coordination TEXT;", nil, nil, nil)
    }

    /// The coordination event as one JSON object, matching what Android's
    /// buffer cache stores — all six fields, so every card the style policy
    /// still draws can be redrawn from cache alone.
    private static func encodeCoordination(_ info: CoordinationInfo?) -> String {
        guard let info,
              let data = try? JSONEncoder().encode(info),
              let json = String(data: data, encoding: .utf8) else { return "" }
        return json
    }

    private static func decodeCoordination(_ raw: String?) -> CoordinationInfo? {
        guard let raw, !raw.isEmpty, let data = raw.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(CoordinationInfo.self, from: data)
    }

    /// Store a message.
    func store(_ msg: ChatMessage, channel: String) {
        let sql = """
        INSERT OR REPLACE INTO messages (id, channel, from_nick, text, timestamp, is_action, is_signed, is_edited, is_deleted, reply_to, origin, act_ref, coordination)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (msg.id as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (channel.lowercased() as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 3, (msg.from as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 4, (msg.text as NSString).utf8String, -1, nil)
        sqlite3_bind_double(stmt, 5, msg.timestamp.timeIntervalSince1970)
        sqlite3_bind_int(stmt, 6, msg.isAction ? 1 : 0)
        sqlite3_bind_int(stmt, 7, msg.isSigned ? 1 : 0)
        sqlite3_bind_int(stmt, 8, msg.isEdited ? 1 : 0)
        sqlite3_bind_int(stmt, 9, msg.isDeleted ? 1 : 0)
        sqlite3_bind_text(stmt, 10, ((msg.replyTo ?? "") as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 11, ((msg.origin ?? "") as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 12, ((msg.actRef ?? "") as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 13, (Self.encodeCoordination(msg.coordination) as NSString).utf8String, -1, nil)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE {
            Log.ui.error("MessageStore.save sqlite3_step rc=\(rc, privacy: .public) channel=\(channel, privacy: .public)")
        }
    }

    /// Load recent messages for a channel.
    func loadMessages(channel: String, limit: Int = 200) -> [ChatMessage] {
        let sql = """
        SELECT id, from_nick, text, timestamp, is_action, is_signed, is_edited, is_deleted, reply_to, origin, act_ref, coordination
        FROM messages
        WHERE channel = ? AND is_deleted = 0
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (channel.lowercased() as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 2, Int32(limit))

        var messages: [ChatMessage] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = String(cString: sqlite3_column_text(stmt, 0))
            let from = String(cString: sqlite3_column_text(stmt, 1))
            let text = String(cString: sqlite3_column_text(stmt, 2))
            let timestamp = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 3))
            let isAction = sqlite3_column_int(stmt, 4) != 0
            let isSigned = sqlite3_column_int(stmt, 5) != 0
            let isEdited = sqlite3_column_int(stmt, 6) != 0
            let replyTo = sqlite3_column_text(stmt, 8).map(String.init(cString:))
            let origin = sqlite3_column_text(stmt, 9).map(String.init(cString:))
            let actRef = sqlite3_column_text(stmt, 10).map(String.init(cString:))
            let coordination = sqlite3_column_text(stmt, 11).map(String.init(cString:))

            var msg = ChatMessage(
                id: id, from: from, text: text, isAction: isAction,
                timestamp: timestamp, replyTo: replyTo?.isEmpty == true ? nil : replyTo
            )
            msg.isSigned = isSigned
            msg.isEdited = isEdited
            msg.origin = (origin?.isEmpty == true) ? nil : origin
            msg.actRef = (actRef?.isEmpty == true) ? nil : actRef
            msg.coordination = Self.decodeCoordination(coordination)
            messages.append(msg)
        }
        // Flipped to ascending (timestamp, id). `timestamp` is REAL seconds,
        // so same-second rows need the id to come back in a fixed order;
        // ids are ULIDs, so that order is mint order.
        return messages.reversed()
    }

    /// Re-key a conversation's cached messages (nick-keyed DM folded into its
    /// DID-keyed thread). Without this, cached history stays under the old
    /// nick key and vanishes from the thread on the next launch.
    func renameChannel(from oldName: String, to newName: String) {
        let sql = "UPDATE OR IGNORE messages SET channel = ? WHERE channel = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (newName.lowercased() as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (oldName.lowercased() as NSString).utf8String, -1, nil)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE {
            Log.ui.error("MessageStore.renameChannel sqlite3_step rc=\(rc, privacy: .public)")
        }
    }

    /// Mark a message as deleted.
    func markDeleted(msgId: String) {
        let sql = "UPDATE messages SET is_deleted = 1 WHERE id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (msgId as NSString).utf8String, -1, nil)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE {
            Log.ui.error("MessageStore.markDeleted sqlite3_step rc=\(rc, privacy: .public)")
        }
    }

    /// Update edited message.
    func markEdited(msgId: String, newText: String) {
        let sql = "UPDATE messages SET text = ?, is_edited = 1 WHERE id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (newText as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (msgId as NSString).utf8String, -1, nil)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE {
            Log.ui.error("MessageStore.markEdited sqlite3_step rc=\(rc, privacy: .public)")
        }
    }

    /// Search messages.
    func search(query: String, channel: String? = nil, limit: Int = 50) -> [(channel: String, msg: ChatMessage)] {
        var sql = """
        SELECT id, channel, from_nick, text, timestamp, is_action, is_signed, origin
        FROM messages
        WHERE is_deleted = 0 AND (text LIKE ? OR from_nick LIKE ?)
        """
        if channel != nil { sql += " AND channel = ?" }
        sql += " ORDER BY timestamp DESC, id DESC LIMIT ?"

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        let pattern = "%\(query)%"
        sqlite3_bind_text(stmt, 1, (pattern as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (pattern as NSString).utf8String, -1, nil)
        var paramIdx: Int32 = 3
        if let ch = channel {
            sqlite3_bind_text(stmt, paramIdx, (ch.lowercased() as NSString).utf8String, -1, nil)
            paramIdx += 1
        }
        sqlite3_bind_int(stmt, paramIdx, Int32(limit))

        var results: [(String, ChatMessage)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = String(cString: sqlite3_column_text(stmt, 0))
            let ch = String(cString: sqlite3_column_text(stmt, 1))
            let from = String(cString: sqlite3_column_text(stmt, 2))
            let text = String(cString: sqlite3_column_text(stmt, 3))
            let timestamp = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
            let isAction = sqlite3_column_int(stmt, 5) != 0
            var msg = ChatMessage(id: id, from: from, text: text, isAction: isAction, timestamp: timestamp, replyTo: nil)
            msg.isSigned = sqlite3_column_int(stmt, 6) != 0
            let origin = sqlite3_column_text(stmt, 7).map(String.init(cString:))
            msg.origin = (origin?.isEmpty == true) ? nil : origin
            results.append((ch, msg))
        }
        return results
    }
}
