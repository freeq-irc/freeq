use std::sync::Arc;

use freeq_auth_broker::{BrokerConfig, BrokerState, derive_encryption_key, init_db, router};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let public_url =
        std::env::var("BROKER_PUBLIC_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());
    let freeq_server_url =
        std::env::var("FREEQ_SERVER_URL").unwrap_or_else(|_| "https://irc.freeq.at".to_string());
    let shared_secret = std::env::var("BROKER_SHARED_SECRET").unwrap_or_else(|_| "".to_string());
    let db_path = std::env::var("BROKER_DB_PATH").unwrap_or_else(|_| "broker.db".to_string());

    // Ensure parent directory exists (for /app/data/broker.db etc.)
    if let Some(parent) = std::path::Path::new(&db_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }

    if shared_secret.is_empty() {
        tracing::error!(
            "BROKER_SHARED_SECRET not set — refusing to start. Set this env var to a strong random secret."
        );
        std::process::exit(1);
    }

    let encryption_key = derive_encryption_key(&shared_secret);
    tracing::info!("Session encryption key derived from BROKER_SHARED_SECRET");

    // On Miren, the persistent disk is mounted async — the container can boot
    // before the disk lease is bound. Retry the open with a bounded backoff
    // so we don't crash-loop while waiting for the mount, but we still surface
    // a real failure (bad path, missing perms) within ~60s.
    let db_open_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut delay = std::time::Duration::from_secs(1);
    let db = loop {
        match rusqlite::Connection::open(&db_path) {
            Ok(db) => break db,
            Err(e) if std::time::Instant::now() < db_open_deadline => {
                tracing::warn!(
                    db_path = %db_path,
                    delay_secs = delay.as_secs(),
                    error = %e,
                    "Broker DB not openable yet — retrying (waiting for disk mount?)"
                );
                std::fs::create_dir_all(
                    std::path::Path::new(&db_path)
                        .parent()
                        .unwrap_or(std::path::Path::new(".")),
                )
                .ok();
                std::thread::sleep(delay);
                delay = (delay * 2).min(std::time::Duration::from_secs(8));
            }
            Err(e) => panic!("Failed to open broker db after 60s of retries: {e}"),
        }
    };
    init_db(&db).expect("Failed to init db");

    let state = Arc::new(BrokerState {
        config: BrokerConfig {
            public_url,
            freeq_server_url,
            shared_secret,
            _db_path: db_path,
            encryption_key,
        },
        pending: Mutex::new(std::collections::HashMap::new()),
        db: Mutex::new(db),
        refresh_locks: Mutex::new(std::collections::HashMap::new()),
    });

    let app = router(state);

    let addr = std::env::var("BROKER_ADDR").unwrap_or_else(|_| {
        if let Ok(port) = std::env::var("PORT") {
            format!("0.0.0.0:{port}")
        } else {
            "0.0.0.0:8081".to_string()
        }
    });
    tracing::info!(%addr, "freeq auth broker listening");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
