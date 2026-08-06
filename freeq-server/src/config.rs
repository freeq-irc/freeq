use clap::Parser;

/// freeq IRC server with AT Protocol SASL authentication.
#[derive(Parser, Debug, Clone)]
#[command(name = "freeq-server", version, about)]
pub struct ServerConfig {
    /// Read options from a TOML file. Every flag below is also a file key
    /// under its underscore name (`--listen-addr` → `listen_addr`), except
    /// `--config` itself and `--migrate-to` (a maintenance verb — a file
    /// that migrates-and-exits on every boot would be a footgun).
    /// Precedence: CLI flag > environment variable > file > built-in default.
    /// An unknown key in the file is a startup error, so typos fail loudly.
    #[arg(long, env = "FREEQ_CONFIG", value_name = "PATH")]
    pub config: Option<String>,

    /// Validate the configuration (including --config, if given) and exit —
    /// nothing starts. Deploy scripts run this before restarting the service
    /// so a bad edit is caught while the old server is still up.
    #[arg(long)]
    pub check_config: bool,

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

    /// Delete event-log rows older than this many days. 0 = disabled
    /// (default) — keep everything.
    ///
    /// Separate from message retention on purpose. The log is append-only and
    /// outlives the bodies it points at: a message pruned for space or for
    /// compliance leaves its event behind, which is what keeps "this id was
    /// used, by this actor, at this time" answerable afterwards. That also
    /// means the log grows without bound unless an operator says otherwise,
    /// so this is the knob that says otherwise — a deliberate, local decision
    /// about disk, not a default that quietly discards evidence.
    #[arg(long, env = "FREEQ_EVENT_RETENTION_DAYS", default_value_t = 0)]
    pub event_retention_days: u64,

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
            config: None,
            check_config: false,
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
            event_retention_days: 0,
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

/// A map-shaped setting: natively a TOML table, but the CLI flag spells it
/// as `key<sep>value` strings, and the file accepts that spelling too.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum MapOrPairs {
    Map(std::collections::BTreeMap<String, String>),
    Pairs(Vec<String>),
}

impl MapOrPairs {
    /// The CLI spelling, which is what the rest of the server parses.
    fn into_pairs(self, sep: char) -> Vec<String> {
        match self {
            MapOrPairs::Map(m) => m.into_iter().map(|(k, v)| format!("{k}{sep}{v}")).collect(),
            MapOrPairs::Pairs(v) => v,
        }
    }
}

/// Every settable flag as an optional TOML key, named after its struct field.
/// Excluded on purpose: `config` (a file naming a file) and `migrate_to` (a
/// maintenance verb that must not run on every boot). `deny_unknown_fields`
/// turns a typo'd key into a startup error instead of a silently-ignored line.
#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen_addr: Option<String>,
    tls_listen_addr: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    server_name: Option<String>,
    challenge_timeout_secs: Option<u64>,
    db_path: Option<String>,
    web_addr: Option<String>,
    iroh: Option<bool>,
    iroh_port: Option<u16>,
    s2s_peers: Option<Vec<String>>,
    s2s_allowed_peers: Option<Vec<String>>,
    s2s_peer_api: Option<MapOrPairs>,
    s2s_peer_trust: Option<MapOrPairs>,
    server_did: Option<String>,
    data_dir: Option<String>,
    did_resolver_static: Option<MapOrPairs>,
    max_messages_per_channel: Option<usize>,
    motd: Option<String>,
    motd_file: Option<String>,
    web_static_dir: Option<String>,
    plugins: Option<Vec<String>>,
    plugin_dir: Option<String>,
    require_did_for_ops: Option<bool>,
    github_client_id: Option<String>,
    github_client_secret: Option<String>,
    broker_shared_secret: Option<String>,
    oper_password: Option<String>,
    oper_dids: Option<Vec<String>>,
    allowed_dids: Option<Vec<String>>,
    allowed_did_domains: Option<Vec<String>>,
    no_guest: Option<bool>,
    reverify_identity_mins: Option<u64>,
    message_retention_days: Option<u64>,
    event_retention_days: Option<u64>,
    llm_provider: Option<String>,
    llm_base_url: Option<String>,
    llm_api_key: Option<String>,
    llm_model: Option<String>,
    llm_timeout_secs: Option<u64>,
    model_price_args: Option<Vec<String>>,
}

/// Whether the operator said this on the command line or in the environment —
/// the two sources that beat the file.
fn explicitly_set(matches: &clap::ArgMatches, id: &str) -> bool {
    matches!(
        matches.value_source(id),
        Some(clap::parser::ValueSource::CommandLine | clap::parser::ValueSource::EnvVariable)
    )
}

impl ServerConfig {
    /// Production entry point: parse the CLI, and if `--config` (or
    /// `FREEQ_CONFIG`) names a file, layer it underneath.
    pub fn load() -> Result<Self, String> {
        let matches = <Self as clap::CommandFactory>::command().get_matches();
        let mut cfg = <Self as clap::FromArgMatches>::from_arg_matches(&matches)
            .map_err(|e| e.to_string())?;
        if let Some(path) = cfg.config.clone() {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("--config {path}: {e}"))?;
            let file: FileConfig =
                toml::from_str(&text).map_err(|e| format!("--config {path}: {e}"))?;
            apply_file(&mut cfg, &matches, file);
        }
        Ok(cfg)
    }

    /// The same layering with the file's text passed in — the testable seam.
    pub fn from_args_and_file_str<I, T>(args: I, file_toml: Option<&str>) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = <Self as clap::CommandFactory>::command()
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;
        let mut cfg = <Self as clap::FromArgMatches>::from_arg_matches(&matches)
            .map_err(|e| e.to_string())?;
        if let Some(text) = file_toml {
            let file: FileConfig = toml::from_str(text).map_err(|e| e.to_string())?;
            apply_file(&mut cfg, &matches, file);
        }
        Ok(cfg)
    }
}

/// File values fill in wherever the CLI and environment were silent.
fn apply_file(cfg: &mut ServerConfig, matches: &clap::ArgMatches, file: FileConfig) {
    macro_rules! plain {
        ($($field:ident),* $(,)?) => {$(
            if let Some(v) = file.$field {
                if !explicitly_set(matches, stringify!($field)) {
                    cfg.$field = v;
                }
            }
        )*};
    }
    macro_rules! optional {
        ($($field:ident),* $(,)?) => {$(
            if let Some(v) = file.$field {
                if !explicitly_set(matches, stringify!($field)) {
                    cfg.$field = Some(v);
                }
            }
        )*};
    }
    // Map-shaped settings: a TOML table (or the CLI's pair spelling),
    // normalized to the pair form the server parses.
    if let Some(v) = file.s2s_peer_api
        && !explicitly_set(matches, "s2s_peer_api")
    {
        cfg.s2s_peer_api = v.into_pairs('=');
    }
    if let Some(v) = file.s2s_peer_trust
        && !explicitly_set(matches, "s2s_peer_trust")
    {
        cfg.s2s_peer_trust = v.into_pairs(':');
    }
    if let Some(v) = file.did_resolver_static
        && !explicitly_set(matches, "did_resolver_static")
    {
        cfg.did_resolver_static = v.into_pairs('=');
    }
    plain!(
        listen_addr,
        tls_listen_addr,
        server_name,
        challenge_timeout_secs,
        iroh,
        s2s_peers,
        s2s_allowed_peers,
        max_messages_per_channel,
        plugins,
        require_did_for_ops,
        oper_dids,
        allowed_dids,
        allowed_did_domains,
        no_guest,
        reverify_identity_mins,
        message_retention_days,
        event_retention_days,
        llm_timeout_secs,
        model_price_args,
    );
    optional!(
        tls_cert,
        tls_key,
        db_path,
        web_addr,
        iroh_port,
        server_did,
        data_dir,
        motd,
        motd_file,
        web_static_dir,
        plugin_dir,
        github_client_id,
        github_client_secret,
        broker_shared_secret,
        oper_password,
        llm_provider,
        llm_base_url,
        llm_api_key,
        llm_model,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str], file: Option<&str>) -> Result<ServerConfig, String> {
        let argv = std::iter::once("freeq-server").chain(args.iter().copied());
        ServerConfig::from_args_and_file_str(argv, file)
    }

    #[test]
    fn file_values_apply_when_the_cli_is_silent() {
        let c = cfg(
            &[],
            Some(
                r#"
                listen_addr = "0.0.0.0:6667"
                server_name = "toml-test"
                max_messages_per_channel = 42
                iroh = true
                s2s_peer_api = ["abcd=https://irc.example.com"]
                "#,
            ),
        )
        .unwrap();
        assert_eq!(c.listen_addr, "0.0.0.0:6667");
        assert_eq!(c.server_name, "toml-test");
        assert_eq!(c.max_messages_per_channel, 42);
        assert!(c.iroh);
        assert_eq!(c.s2s_peer_api, vec!["abcd=https://irc.example.com"]);
    }

    #[test]
    fn a_cli_flag_beats_the_file() {
        let c = cfg(
            &["--server-name", "from-cli"],
            Some(r#"server_name = "from-file""#),
        )
        .unwrap();
        assert_eq!(c.server_name, "from-cli");
    }

    #[test]
    fn defaults_hold_when_neither_speaks() {
        let c = cfg(&[], Some(r#"motd = "hi""#)).unwrap();
        assert_eq!(c.listen_addr, "127.0.0.1:6667");
        assert_eq!(c.server_name, "freeq");
        assert_eq!(c.motd.as_deref(), Some("hi"));
    }

    #[test]
    fn a_cli_list_replaces_the_file_list() {
        let c = cfg(
            &["--oper-dids", "did:plc:cli1,did:plc:cli2"],
            Some(r#"oper_dids = ["did:plc:file"]"#),
        )
        .unwrap();
        assert_eq!(c.oper_dids, vec!["did:plc:cli1", "did:plc:cli2"]);
    }

    #[test]
    fn an_unknown_key_is_a_loud_error_naming_the_key() {
        let err = cfg(&[], Some(r#"lisen_addr = "typo""#)).unwrap_err();
        assert!(err.contains("lisen_addr"), "error must name the bad key: {err}");
    }

    #[test]
    fn migrate_to_is_not_a_file_key() {
        // A file that migrates-and-exits on every boot would be a footgun;
        // the maintenance verb stays CLI-only.
        let err = cfg(&[], Some("migrate_to = 2")).unwrap_err();
        assert!(err.contains("migrate_to"), "{err}");
    }

    #[test]
    fn malformed_toml_is_a_clear_error() {
        let err = cfg(&[], Some("this is not toml ===")).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn no_file_means_plain_cli_parsing() {
        let c = cfg(&["--server-name", "bare"], None).unwrap();
        assert_eq!(c.server_name, "bare");
    }

    /// A map-shaped setting reads naturally as a TOML table, and the CLI's
    /// pair spelling stays valid — both normalize to the same thing.
    #[test]
    fn peer_maps_accept_tables_and_pair_strings() {
        let c = cfg(
            &[],
            Some(
                r#"
                [s2s_peer_api]
                "abcd" = "https://irc.example.com"

                [s2s_peer_trust]
                "abcd" = "relay"
                "#,
            ),
        )
        .unwrap();
        assert_eq!(c.s2s_peer_api, vec!["abcd=https://irc.example.com"]);
        assert_eq!(c.s2s_peer_trust, vec!["abcd:relay"]);

        let c = cfg(&[], Some(r#"s2s_peer_api = ["abcd=https://irc.example.com"]"#)).unwrap();
        assert_eq!(c.s2s_peer_api, vec!["abcd=https://irc.example.com"]);

        let c = cfg(
            &["--s2s-peer-api", "cli=https://cli.example.com"],
            Some(r#"s2s_peer_api = ["file=https://file.example.com"]"#),
        )
        .unwrap();
        assert_eq!(c.s2s_peer_api, vec!["cli=https://cli.example.com"]);
    }

    /// The shipped example must never drift from the real schema: uncomment
    /// every `# key = value` line (`##` lines are prose, per the file's own
    /// convention) and the result must parse under `deny_unknown_fields`.
    /// A renamed or removed flag whose example line goes stale fails here.
    #[test]
    fn the_shipped_example_file_matches_the_schema() {
        let example = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../server.toml.example"),
        )
        .expect("server.toml.example missing from the repo root");
        let uncommented: String = example
            .lines()
            .filter(|l| l.starts_with("# ") && l.contains('='))
            .map(|l| &l[2..])
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            uncommented.lines().count() >= 30,
            "the example should cover the flag surface; got {} settings",
            uncommented.lines().count()
        );
        let parsed: Result<super::FileConfig, _> = toml::from_str(&uncommented);
        parsed.expect("every setting in server.toml.example must be a valid config key");
    }
}
