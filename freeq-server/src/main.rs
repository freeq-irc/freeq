use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider before any TLS usage.
    // Iroh brings in ring, but rustls needs an explicit provider selection.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    // Use JSON logs in production (FREEQ_LOG_JSON=1), human-readable otherwise
    let json_logs = std::env::var("FREEQ_LOG_JSON").unwrap_or_default() == "1";
    let filter = EnvFilter::from_default_env().add_directive("freeq_server=info".parse()?);
    if json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let mut config = freeq_server::config::ServerConfig::parse();

    // A maintenance verb, not a server mode: run the ladder to the requested
    // version and exit. Startup only ever migrates up; this is how the tested
    // down migrations get run without hand-written SQL.
    if let Some(target) = config.migrate_to {
        let Some(ref db_path) = config.db_path else {
            anyhow::bail!("--migrate-to requires --db-path (in-memory storage has nothing to migrate)");
        };
        let (before, after) = freeq_server::migrations::migrate_to(db_path, target)
            .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
        tracing::info!(before, after, target, "migration ladder finished");
        return Ok(());
    }

    // Fold --model-price flags into the price table the metered proxy charges from.
    if !config.model_price_args.is_empty() {
        config.model_prices = freeq_server::model_proxy::parse_price_args(&config.model_price_args);
        tracing::info!(
            models = config.model_prices.len(),
            "Model prices configured for the metered proxy"
        );
    }

    tracing::info!("Starting IRC server on {}", config.listen_addr);
    if config.tls_enabled() {
        tracing::info!("TLS enabled on {}", config.tls_listen_addr);
    }
    if let Some(ref web_addr) = config.web_addr {
        tracing::info!("HTTP/WebSocket enabled on {web_addr}");
    }
    if config.iroh {
        tracing::info!("Iroh transport enabled");
    }

    // Resolve --motd-file into --motd
    if let Some(ref path) = config.motd_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                tracing::info!("Loaded MOTD from {path}");
                config.motd = Some(content);
            }
            Err(e) => tracing::warn!("Failed to read MOTD file {path}: {e}"),
        }
    }
    let server = freeq_server::server::Server::new(config);
    server.run().await
}
