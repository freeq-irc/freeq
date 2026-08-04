use clap::Parser;

/// freeq IRC server with AT Protocol SASL authentication.
#[derive(Parser, Debug, Clone)]
#[command(name = "freeq-server", version, about)]
pub struct ServerConfig {
    /// Plain TCP listener address. (`--bind` kept as an alias — older docs
    /// and docker-compose files used it.)
    #[arg(long, alias = "bind", default_value = "127.0.0.1:6667")]
    pub listen_addr: String,

    /// TLS listener address. Only active if --tls-cert and --tls-key are set.
    #[arg(long, default_value = "127.0.0.1:6697")]
    pub tls_listen_addr: String,

    /// Path to TLS certificate PEM file.
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// Path to TLS private key PEM file.
    #[arg(long)]
    pub tls_key: Option<String>,

    /// Server name used in IRC messages.
    #[arg(long, default_value = "freeq")]
    pub server_name: String,

    /// Challenge validity window in seconds.
    #[arg(long, default_value = "60")]
    pub challenge_timeout_secs: u64,

    /// Path to SQLite database file. If not set, uses in-memory storage (no persistence).
    #[arg(long)]
    pub db_path: Option<String>,

    /// Run the migration ladder to this schema version and exit instead of
    /// starting the server. Requires --db-path. Downgrades run each rung's
    /// down migration; a rung with no down (irreversible) stops with an
    /// error. Normal startup always migrates to latest — this exists for
    /// the other direction, e.g. before rolling back to an older binary.
    #[arg(long, value_name = "VERSION")]
    pub migrate_to: Option<usize>,

    /// HTTP/WebSocket listener address. Enables WebSocket IRC transport and REST API.
    /// If not set, no HTTP listener starts.
    #[arg(long)]
    pub web_addr: Option<String>,

    /// Enable iroh transport (QUIC-based, encrypted, NAT-traversing).
    /// The server's iroh endpoint address will be printed on startup.
    #[arg(long)]
    pub iroh: bool,

    /// UDP port for iroh transport. If not set, a random port is used.
    #[arg(long)]
    pub iroh_port: Option<u16>,

    /// S2S peer iroh endpoint IDs to connect to on startup.
    /// Comma-separated. Each entry is `<endpoint-id>` (resolved via discovery)
    /// or `<endpoint-id>@<host:port>` to dial a direct address, bypassing
    /// discovery (LAN/static deployments, and the federation test harness).
    #[arg(long, value_delimiter = ',')]
    pub s2s_peers: Vec<String>,

    /// Allowed S2S peer endpoint IDs. If set, only these peers can connect.
    /// If empty (default), any peer can connect (open federation).
    /// Comma-separated list of hex endpoint IDs.
    #[arg(long, value_delimiter = ',')]
    pub s2s_allowed_peers: Vec<String>,

    /// Where each S2S peer serves its own users' message-signing keys.
    /// Comma-separated `<endpoint-id>=<http(s)://base>` entries — the base URL
    /// of the peer's REST API, e.g. `44f1415c...=https://irc.example.com`.
    /// Without an entry a peer's signatures stay uncheckable here (never
    /// "invalid"), because there is nowhere to fetch the signer's key from.
    /// Deliberately configuration rather than something a peer announces: no
    /// peer gets to choose where this server sends requests.
    #[arg(long, value_delimiter = ',')]
    pub s2s_peer_api: Vec<String>,

    /// S2S peer trust levels. Format: "endpoint_id:level" where level is
    /// "full" (default), "relay" (messages only), or "readonly" (observe only).
    /// Peers not listed here default to "full" if in --s2s-allowed-peers.
    #[arg(long, value_delimiter = ',')]
    pub s2s_peer_trust: Vec<String>,

    /// Server DID for federated identity (Phase 5). Format: did:web:irc.example.com
    /// When set, this DID is included in Hello handshakes and can be used by peers
    /// for DID-based allowlisting instead of raw endpoint IDs.
    #[arg(long)]
    pub server_did: Option<String>,

    /// Data directory for server state files (iroh key, etc.).
    /// Defaults to the directory containing --db-path, or current directory.
    #[arg(long)]
    pub data_dir: Option<String>,

    /// TEST/DEV ONLY: resolve these DIDs from a static in-memory map instead of
    /// the network. Comma-separated `did=<publicKeyMultibase>` entries. When set,
    /// the server uses a static DID resolver (no HTTP/PLC lookups). Used by the
    /// federation test harness to authenticate test identities offline. Empty in
    /// production — leave unset to use the real network resolver.
    #[arg(long, value_delimiter = ',')]
    pub did_resolver_static: Vec<String>,

    /// Maximum messages to retain per channel in the database.
    /// When exceeded, oldest messages are pruned. 0 = unlimited.
    #[arg(long, default_value = "10000")]
    pub max_messages_per_channel: usize,

    /// Message of the Day text. If not set, no MOTD is sent.
    #[arg(long)]
    pub motd: Option<String>,

    /// Path to a file containing the Message of the Day. Overrides --motd.
    #[arg(long)]
    pub motd_file: Option<String>,

    /// Directory containing web client static files (index.html, etc.).
    /// If set, files are served at the root path (/) of the web listener.
    /// Typically points to the freeq-web/ directory.
    #[arg(long)]
    pub web_static_dir: Option<String>,

    /// Plugins to load. Format: "name" or "name:key=val,key2=val2".
    /// Can be specified multiple times.
    #[arg(long = "plugin")]
    pub plugins: Vec<String>,

    /// Directory containing plugin config files (*.toml).
    /// Each TOML file defines one plugin and its configuration.
    #[arg(long)]
    pub plugin_dir: Option<String>,

    /// Require DID provenance for channel authority operations (founder, ops, bans).
    /// When enabled, op grants/bans from peers without DID provenance are rejected.
    /// This closes the "legacy peer auth bypass" but breaks backward compatibility
    /// with peers that don't send DID metadata.
    #[arg(long)]
    pub require_did_for_ops: bool,

    /// GitHub OAuth App Client ID (for credential verification).
    /// Create one at https://github.com/settings/developers
    /// Can also be set via GITHUB_CLIENT_ID environment variable.
    #[arg(long, env = "GITHUB_CLIENT_ID")]
    pub github_client_id: Option<String>,

    /// GitHub OAuth App Client Secret.
    /// Can also be set via GITHUB_CLIENT_SECRET environment variable.
    #[arg(long, env = "GITHUB_CLIENT_SECRET")]
    pub github_client_secret: Option<String>,

    /// Shared secret for the auth broker (HMAC-SHA256 over request body).
    /// If set, enables /auth/broker/* endpoints.
    #[arg(long, env = "BROKER_SHARED_SECRET")]
    pub broker_shared_secret: Option<String>,

    /// Server operator password. If set, the OPER command is enabled.
    /// OPER grants global operator privileges (can kick/ban in any channel, etc.)
    /// Can also be set via OPER_PASSWORD environment variable.
    #[arg(long, env = "OPER_PASSWORD")]
    pub oper_password: Option<String>,

    /// DIDs that are automatically granted server operator status on connect.
    /// Comma-separated list.
    #[arg(long, value_delimiter = ',', env = "OPER_DIDS")]
    pub oper_dids: Vec<String>,

    /// Connect-time allowlist (opt-in; for a company running its OWN instance).
    /// If non-empty, ONLY these DIDs may authenticate. Empty = open (anyone with
    /// a valid AT identity), the default for a public instance.
    #[arg(long, value_delimiter = ',', env = "FREEQ_ALLOWED_DIDS")]
    pub allowed_dids: Vec<String>,

    /// Connect-time allowlist by handle domain (opt-in). If non-empty, only DIDs
    /// whose handle ends in one of these domains (e.g. `acme.com`) may
    /// authenticate. Empty = no domain restriction.
    #[arg(long, value_delimiter = ',', env = "FREEQ_ALLOWED_DID_DOMAINS")]
    pub allowed_did_domains: Vec<String>,

    /// Refuse guest (unauthenticated) connections entirely. Default: guests
    /// allowed. A company instance can set this to require AT identity.
    #[arg(long, env = "FREEQ_NO_GUEST", default_value_t = false)]
    pub no_guest: bool,

    /// Periodically re-verify connected users' DIDs and disconnect any whose DID
    /// document no longer contains a valid authentication key (offboarding /
    /// key removal). Value is the interval in minutes; 0 = disabled (default).
    /// SAFE by design: never disconnects on a resolution error (network/outage),
    /// only on a DID that resolves successfully but is de-keyed.
    #[arg(long, env = "FREEQ_REVERIFY_IDENTITY_MINS", default_value_t = 0)]
    pub reverify_identity_mins: u64,

    /// Delete stored messages older than this many days (compliance retention).
    /// 0 = disabled (default) — keep everything up to the per-channel count cap.
    #[arg(long, env = "FREEQ_MESSAGE_RETENTION_DAYS", default_value_t = 0)]
    pub message_retention_days: u64,

    // ── Agent Assistance Interface: LLM provider ───────────────────
    /// LLM provider for the `POST /agent/session` free-form router.
    /// `openai` = any OpenAI-compatible /chat/completions endpoint
    /// (covers OpenAI itself, Together, Fireworks, Groq, vLLM,
    /// llama.cpp server, Ollama with /v1, TGI, LMDeploy, etc).
    /// `none` (or unset) = endpoint returns LLM_NOT_CONFIGURED.
    #[arg(long, env = "FREEQ_LLM_PROVIDER")]
    pub llm_provider: Option<String>,

    /// Base URL for the OpenAI-compatible endpoint, e.g.
    /// `https://api.openai.com/v1` or `http://127.0.0.1:11434/v1`.
    #[arg(long, env = "FREEQ_LLM_BASE_URL")]
    pub llm_base_url: Option<String>,

    /// API key for the LLM provider (sent as `Authorization: Bearer`).
    /// Many local OSS servers ignore this field.
    #[arg(long, env = "FREEQ_LLM_API_KEY")]
    pub llm_api_key: Option<String>,

    /// Model name passed verbatim to the provider.
    #[arg(long, env = "FREEQ_LLM_MODEL")]
    pub llm_model: Option<String>,

    /// Hard ceiling on each LLM HTTP call, in seconds. Default 8.
    #[arg(long, env = "FREEQ_LLM_TIMEOUT_SECS", default_value = "8")]
    pub llm_timeout_secs: u64,

    /// Price per 1k tokens per model, for the metered model proxy.
    ///
    /// A loan of capacity has to be denominated in something, and the provider
    /// reports tokens while a budget is set in a unit like usd. This is the
    /// conversion, and it is configuration rather than a hardcoded table because
    /// provider pricing changes without asking us.
    #[arg(skip)]
    pub model_prices: std::collections::HashMap<String, crate::model_proxy::ModelPrice>,

    /// Price applied to a model with no entry in `model_prices`.
    ///
    /// Not zero. An unpriced model is the easiest way to get free capacity, so the
    /// default must be expensive enough to be safe rather than convenient.
    #[arg(skip)]
    pub model_price_default: crate::model_proxy::ModelPrice,

    /// Price a model for the metered proxy: `--model-price gpt-4o-mini=0.15,0.60`
    /// (input,output per 1k tokens). Repeatable.
    #[arg(long = "model-price", value_name = "MODEL=IN,OUT")]
    pub model_price_args: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:6667".to_string(),
            tls_listen_addr: "127.0.0.1:6697".to_string(),
            tls_cert: None,
            tls_key: None,
            server_name: "freeq".to_string(),
            challenge_timeout_secs: 60,
            db_path: None,
            migrate_to: None,
            web_addr: None,
            iroh: false,
            iroh_port: None,
            s2s_peers: vec![],
            s2s_allowed_peers: vec![],
            s2s_peer_api: vec![],
            s2s_peer_trust: vec![],
            server_did: None,
            data_dir: None,
            did_resolver_static: vec![],
            max_messages_per_channel: 10000,
            motd: None,
            motd_file: None,
            web_static_dir: None,
            plugins: vec![],
            plugin_dir: None,
            require_did_for_ops: false,
            github_client_id: None,
            github_client_secret: None,
            broker_shared_secret: None,
            oper_password: None,
            oper_dids: vec![],
            allowed_dids: vec![],
            allowed_did_domains: vec![],
            no_guest: false,
            reverify_identity_mins: 0,
            message_retention_days: 0,
            llm_provider: None,
            llm_base_url: None,
            llm_api_key: None,
            llm_model: None,
            llm_timeout_secs: 8,
            model_prices: std::collections::HashMap::new(),
            model_price_args: Vec::new(),
            model_price_default: crate::model_proxy::ModelPrice {
                input_per_1k: 5.0,
                output_per_1k: 15.0,
            },
        }
    }
}

impl ServerConfig {
    /// Returns true if TLS is configured.
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    /// Resolve the data directory for state files.
    /// Priority: --data-dir > parent of --db-path > platform state dir > CWD (with warning).
    pub fn data_dir(&self) -> std::path::PathBuf {
        if let Some(ref dir) = self.data_dir {
            std::path::PathBuf::from(dir)
        } else if let Some(ref db_path) = self.db_path {
            std::path::Path::new(db_path)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        } else if let Some(state_dir) = Self::platform_state_dir() {
            let dir = state_dir.join("freeq");
            if !dir.exists() {
                let _ = std::fs::create_dir_all(&dir);
            }
            dir
        } else {
            tracing::warn!(
                "No --data-dir set and no platform state directory found; \
                 falling back to current working directory. \
                 Secret keys will be written to CWD — use --data-dir in production."
            );
            std::path::PathBuf::from(".")
        }
    }

    /// Returns the platform-appropriate state directory, if available.
    /// Linux: $XDG_STATE_HOME or ~/.local/state
    /// macOS: ~/Library/Application Support
    fn platform_state_dir() -> Option<std::path::PathBuf> {
        #[cfg(target_os = "macos")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                return Some(std::path::PathBuf::from(home).join("Library/Application Support"));
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
                && !xdg.is_empty()
            {
                return Some(std::path::PathBuf::from(xdg));
            }
            if let Some(home) = std::env::var_os("HOME") {
                return Some(std::path::PathBuf::from(home).join(".local/state"));
            }
        }
        None
    }
}
