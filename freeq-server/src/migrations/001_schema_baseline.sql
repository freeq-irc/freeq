-- Migration 1: the schema baseline.
--
-- Moved verbatim from the CREATE statements Db::init() used to replay on
-- every boot. Everything is IF NOT EXISTS: on a database that predates the
-- ladder this converges over whatever already exists; on a fresh database
-- it builds the schema from nothing. Columns that were added to live
-- deployments over time are NOT folded into these definitions — they are
-- applied by the ALTER loop in 001_schema_baseline.rs, which older
-- databases still need.

CREATE TABLE IF NOT EXISTS channels (
    name        TEXT PRIMARY KEY,
    topic_text  TEXT,
    topic_set_by TEXT,
    topic_set_at INTEGER,
    topic_locked INTEGER NOT NULL DEFAULT 0,
    invite_only  INTEGER NOT NULL DEFAULT 0,
    no_ext_msg   INTEGER NOT NULL DEFAULT 0,
    moderated    INTEGER NOT NULL DEFAULT 0,
    key          TEXT,
    founder_did  TEXT,
    did_ops_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS bans (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    channel  TEXT NOT NULL,
    mask     TEXT NOT NULL,
    set_by   TEXT NOT NULL,
    set_at   INTEGER NOT NULL,
    UNIQUE(channel, mask)
);

CREATE TABLE IF NOT EXISTS invite_exceptions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    channel  TEXT NOT NULL,
    mask     TEXT NOT NULL,
    set_by   TEXT NOT NULL,
    set_at   INTEGER NOT NULL,
    UNIQUE(channel, mask)
);

CREATE TABLE IF NOT EXISTS messages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    channel   TEXT NOT NULL,
    sender    TEXT NOT NULL,
    text      TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    tags_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_messages_channel_ts
    ON messages(channel, timestamp DESC);

CREATE TABLE IF NOT EXISTS identities (
    did  TEXT PRIMARY KEY,
    nick TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS prekey_bundles (
    did         TEXT PRIMARY KEY,
    bundle_json TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Sealed group keys for VC-bootstrapped E2E channels (EG1/EGK1).
-- Each row is a group secret sealed to ONE member's X25519 key at
-- ONE epoch. The server stores/relays these opaque blobs but can
-- never open them (see freeq-sdk::e2ee_group). Multiple epochs are
-- retained so a member can decrypt channel history across rotations.
CREATE TABLE IF NOT EXISTS group_keys (
    channel     TEXT NOT NULL,
    member_did  TEXT NOT NULL,
    epoch       INTEGER NOT NULL,
    sealed_wire TEXT NOT NULL,      -- EGK1:... opaque sealed blob
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (channel, member_did, epoch)
);

-- Append-only history of client message-signing keys. Keyed by
-- (did, kid) so re-registering never overwrites — every key a DID
-- has used stays verifiable after a reconnect. kid is
-- base64url(sha256(pubkey)[..16]) (freeq_sdk::act::derive_kid_bytes).
-- get_signing_key(did) returns the latest; get_signing_key_by_kid
-- fetches a specific one. Legacy did-keyed rows are migrated by
-- migrate_signing_keys_to_kid_history (still in init(): it manages
-- its own transaction).
CREATE TABLE IF NOT EXISTS signing_keys (
    did            TEXT NOT NULL,
    kid            TEXT NOT NULL,
    pubkey         BLOB NOT NULL,         -- raw 32-byte ed25519 public key
    registered_at  INTEGER NOT NULL,
    PRIMARY KEY (did, kid)
);

CREATE TABLE IF NOT EXISTS user_channels (
    did     TEXT NOT NULL,
    channel TEXT NOT NULL,
    PRIMARY KEY (did, channel)
);

-- Cross-device read markers (IRCv3 draft/read-marker). One row per
-- (DID, target) — the last-read timestamp a user's clients have
-- converged on. The marker only ever moves forward (enforced by the
-- MARKREAD handler); `updated_at` records when the server last wrote
-- it. Guests (no DID) never land here — their markers are
-- session-local and never persisted.
CREATE TABLE IF NOT EXISTS read_markers (
    did        TEXT NOT NULL,
    target     TEXT NOT NULL,
    timestamp  TEXT NOT NULL,      -- ISO 8601, as in server-time
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (did, target)
);

-- Per-DID favorite channels, so a user's favorites roam across
-- their devices (synced via the REST /api/v1/favorites endpoint).
-- `ord` preserves the user's ordering (Favorites section + ⌃⌘1-9).
CREATE TABLE IF NOT EXISTS user_favorites (
    did        TEXT NOT NULL,
    channel    TEXT NOT NULL,
    ord        INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (did, channel)
);

-- Agent governance.
CREATE TABLE IF NOT EXISTS agent_capability_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    capability TEXT NOT NULL,
    scope TEXT,
    ttl_seconds INTEGER DEFAULT 0,
    requires_approval INTEGER DEFAULT 0,
    rate_limit INTEGER DEFAULT 0,
    granted_by TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    UNIQUE(channel, agent_did, capability, scope)
);

CREATE TABLE IF NOT EXISTS governance_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT,
    target_did TEXT NOT NULL,
    action TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    reason TEXT,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    capability TEXT NOT NULL,
    resource TEXT,
    requested_at INTEGER NOT NULL,
    granted_by TEXT,
    granted_at INTEGER,
    denied_by TEXT,
    denied_at INTEGER,
    deny_reason TEXT,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS agent_manifests (
    agent_did TEXT PRIMARY KEY,
    manifest_json TEXT NOT NULL,
    manifest_url TEXT,
    registered_by TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS spawned_agents (
    child_did TEXT PRIMARY KEY,
    parent_did TEXT NOT NULL,
    parent_session TEXT NOT NULL,
    nick TEXT NOT NULL,
    channel TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    ttl_seconds INTEGER,
    task_ref TEXT,
    spawned_at INTEGER NOT NULL,
    despawned_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_spawn_parent ON spawned_agents(parent_did);
CREATE INDEX IF NOT EXISTS idx_spawn_channel ON spawned_agents(channel);

CREATE TABLE IF NOT EXISTS agent_spend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    amount REAL NOT NULL,
    unit TEXT NOT NULL,
    description TEXT,
    task_ref TEXT,
    timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_spend_channel_agent ON agent_spend(channel, agent_did, timestamp);
CREATE INDEX IF NOT EXISTS idx_spend_period ON agent_spend(channel, agent_did, unit, timestamp);

CREATE TABLE IF NOT EXISTS channel_budgets (
    channel TEXT NOT NULL,
    agent_did TEXT,
    budget_json TEXT NOT NULL,
    set_by TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    PRIMARY KEY(channel, agent_did)
);

CREATE TABLE IF NOT EXISTS coordination_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    channel TEXT NOT NULL,
    ref_id TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    signature TEXT,
    timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_coord_channel ON coordination_events(channel, timestamp);
CREATE INDEX IF NOT EXISTS idx_coord_ref ON coordination_events(ref_id);
CREATE INDEX IF NOT EXISTS idx_coord_actor ON coordination_events(actor_did, timestamp);

CREATE TABLE IF NOT EXISTS pins (
    channel      TEXT NOT NULL,
    msgid        TEXT NOT NULL,
    pinned_by    TEXT NOT NULL,
    pinned_at    INTEGER NOT NULL,
    UNIQUE(channel, msgid)
);
CREATE INDEX IF NOT EXISTS idx_pins_channel ON pins(channel, pinned_at DESC);

-- Private media: metadata for blobs stored encrypted-at-rest on local
-- disk and served via signed capability URLs. The bytes live on disk
-- (see `media_store`), not in this table — only metadata is recorded.
CREATE TABLE IF NOT EXISTS media (
    id           TEXT PRIMARY KEY,
    uploader_did TEXT NOT NULL,
    scope        TEXT NOT NULL,   -- channel name or canonical_dm_key
    mime         TEXT NOT NULL,
    size         INTEGER NOT NULL,
    alt          TEXT,
    filename     TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    deleted_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_media_scope ON media(scope, created_at DESC);

CREATE TABLE IF NOT EXISTS reactions (
    target_msgid TEXT NOT NULL,
    channel      TEXT NOT NULL,
    reactor_nick TEXT NOT NULL,
    reactor_did  TEXT,
    emoji        TEXT NOT NULL,
    timestamp    INTEGER NOT NULL,
    UNIQUE(target_msgid, reactor_nick, emoji)
);
CREATE INDEX IF NOT EXISTS idx_reactions_msgid ON reactions(target_msgid);
CREATE INDEX IF NOT EXISTS idx_reactions_channel ON reactions(channel);

-- AV sessions.
CREATE TABLE IF NOT EXISTS av_sessions (
    id               TEXT PRIMARY KEY,
    channel          TEXT,
    created_by       TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    ended_at         INTEGER,
    ended_by         TEXT,
    title            TEXT,
    iroh_ticket      TEXT,
    backend          TEXT NOT NULL DEFAULT '"iroh-live"',
    recording        BOOLEAN NOT NULL DEFAULT FALSE,
    max_participants INTEGER
);
CREATE INDEX IF NOT EXISTS idx_av_sessions_channel ON av_sessions(channel, created_at DESC);

CREATE TABLE IF NOT EXISTS av_participants (
    session_id  TEXT NOT NULL REFERENCES av_sessions(id),
    did         TEXT NOT NULL,
    nick        TEXT NOT NULL,
    joined_at   INTEGER NOT NULL,
    left_at     INTEGER,
    role        TEXT NOT NULL DEFAULT '"speaker"',
    PRIMARY KEY (session_id, did)
);

CREATE TABLE IF NOT EXISTS av_artifacts (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES av_sessions(id),
    kind         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    created_by   TEXT,
    content_ref  TEXT NOT NULL,
    content_type TEXT NOT NULL,
    visibility   TEXT NOT NULL DEFAULT '"participants"',
    title        TEXT
);
CREATE INDEX IF NOT EXISTS idx_av_artifacts_session ON av_artifacts(session_id);
