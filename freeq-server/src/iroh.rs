//! Iroh transport for the IRC server.
//!
//! Accepts IRC connections over iroh's QUIC-based encrypted transport.
//! Each iroh connection opens a single bidirectional stream that carries
//! IRC lines, exactly like a TCP connection. The server treats it as
//! just another `AsyncRead + AsyncWrite` stream via `handle_generic()`.
//!
//! This gives us:
//! - Encrypted transport by default (no separate TLS setup)
//! - NAT hole-punching + relay fallback
//! - Public-key identity per endpoint
//! - Path toward P2P and mesh topologies

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::server::SharedState;

/// ALPN protocol identifier for IRC-over-iroh.
pub const ALPN: &[u8] = b"freeq/iroh/1";

/// Handle an accepted iroh connection.
///
/// Waits for the client to open a bidirectional stream, bridges it via
/// a DuplexStream (same pattern as WebSocket), and passes it to the
/// generic IRC connection handler.
///
/// The iroh `Connection` is held alive for the entire duration so QUIC
/// keep-alives work and we detect disconnects promptly. When the QUIC
/// connection drops, the recv bridge task gets EOF/error, shuts down
/// the bridge, and the IRC handler's read loop breaks — triggering full
/// session cleanup (QUIT broadcast, channel removal, etc.).
pub async fn handle_connection(conn: Connection, state: Arc<SharedState>) {
    let remote_id = conn.remote_id();
    tracing::info!(%remote_id, "Iroh connection accepted");

    let (send, recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::warn!(%remote_id, "Failed to accept bi stream: {e}");
            return;
        }
    };

    // Bridge QUIC streams to a DuplexStream that handle_generic() can use.
    let (irc_side, bridge_side) = tokio::io::duplex(16384);
    let (irc_read, irc_write) = tokio::io::split(irc_side);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // Task: QUIC recv → bridge_write → IRC handler reads
    let rx_remote = remote_id;
    let rx_handle = tokio::spawn(async move {
        let mut recv = recv;
        let mut buf = vec![0u8; 4096];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if bridge_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break, // Stream finished
                Err(e) => {
                    tracing::debug!(remote = %rx_remote, "QUIC recv error: {e}");
                    break;
                }
            }
        }
        tracing::debug!(remote = %rx_remote, "Iroh recv bridge ended, shutting down");
        let _ = bridge_write.shutdown().await;
    });

    // Task: IRC handler writes → bridge_read → QUIC send
    let tx_remote = remote_id;
    let tx_handle = tokio::spawn(async move {
        let mut send = send;
        let mut buf = vec![0u8; 4096];
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(remote = %tx_remote, "Bridge read error: {e}");
                    break;
                }
            }
        }
        let _ = send.finish();
        // Wait for the peer to acknowledge everything sent, so the
        // connection close below cannot discard unacknowledged lines.
        let _ = send.stopped().await;
    });

    // The IRC handler sees a normal AsyncRead + AsyncWrite stream.
    // This blocks until the client disconnects (EOF, error, or ping timeout).
    let stream = crate::web::WsBridge {
        reader: irc_read,
        writer: irc_write,
    };
    let iroh_id = remote_id.to_string();
    match crate::connection::handle_generic_with_meta(stream, state, Some(iroh_id)).await {
        Ok(()) => tracing::info!(%remote_id, "Iroh client disconnected (clean)"),
        Err(e) => tracing::warn!(%remote_id, "Iroh client disconnected with error: {e}"),
    }

    // Clean up bridge tasks — the IRC handler has already run session cleanup
    // (QUIT broadcast, channel removal, nick release, etc.).
    rx_handle.abort();
    // Let the send side deliver what the handler queued last (a FAIL and
    // ERROR before a server-side close); abort as before if it stalls.
    let mut tx_handle = tx_handle;
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut tx_handle)
        .await
        .is_err()
    {
        tx_handle.abort();
    }

    // Explicitly close the QUIC connection so the remote side gets
    // a CONNECTION_CLOSE frame instead of a silent timeout.
    conn.close(0u32.into(), b"session ended");
    tracing::debug!(%remote_id, "Iroh QUIC connection closed");
}

/// Load or generate a persistent secret key for stable endpoint identity.
fn load_or_create_secret_key(path: &std::path::Path) -> Result<iroh::SecretKey> {
    if path.exists() {
        crate::secrets::tighten_permissions(path);
        let hex = std::fs::read_to_string(path)?;
        let key: iroh::SecretKey = hex
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid iroh secret key in {}: {e}", path.display()))?;
        Ok(key)
    } else {
        // Generate a random 32-byte secret key
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let key = iroh::SecretKey::from_bytes(&bytes);
        // Serialize as hex bytes
        let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        crate::secrets::write_secret(path, hex.as_bytes())?;
        tracing::info!("Generated new iroh secret key at {}", path.display());
        Ok(key)
    }
}

/// Bind the iroh endpoint with our ALPNs registered at the TLS layer.
///
/// Does not spawn an accept loop — call [`spawn_router`] after any other
/// subsystems that need to register protocols on the same endpoint
/// (e.g. iroh-live for AV) have been initialized.
///
/// Returns the endpoint (for getting the address/node ID to share with clients).
pub async fn start(state: Arc<SharedState>, bind_port: Option<u16>) -> Result<iroh::Endpoint> {
    // Use a persistent secret key so the endpoint ID is stable across restarts.
    // Store in data_dir (respects --data-dir / --db-path parent).
    let key_path = state.config.data_dir().join("iroh-key.secret");
    let secret_key = load_or_create_secret_key(&key_path)?;

    let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec(), crate::s2s::S2S_ALPN.to_vec()]);

    if let Some(port) = bind_port {
        builder = builder.bind_addr(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            port,
        ))?;
    }

    let endpoint = builder.bind().await?;

    tracing::info!("Iroh endpoint ID: {}", endpoint.id());

    let _ = state;
    Ok(endpoint)
}

/// `ProtocolHandler` that bridges accepted iroh client connections into
/// `handle_connection`.
#[derive(Clone)]
pub struct IrohClientProtocol {
    pub state: Arc<SharedState>,
}

impl std::fmt::Debug for IrohClientProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohClientProtocol").finish()
    }
}

impl iroh::protocol::ProtocolHandler for IrohClientProtocol {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        handle_connection(conn, Arc::clone(&self.state)).await;
        Ok(())
    }
}

/// Build and spawn the iroh `Router` that owns the endpoint's accept loop.
///
/// The Router registers handlers for `freeq/iroh/1` (client) and
/// `freeq/s2s/1` (server-to-server). When `live` is provided, iroh-live's
/// gossip + MoQ protocols are also registered on the same Router so AV
/// works without iroh-live spawning its own router (which would otherwise
/// `set_alpns` over the freeq ALPNs and break inbound dials).
///
/// The returned `Router` must be kept alive for the lifetime of the
/// server — dropping it aborts the accept task.
pub fn spawn_router(
    endpoint: iroh::Endpoint,
    state: Arc<SharedState>,
    #[cfg(feature = "av-native")] live: Option<&iroh_live::Live>,
) -> iroh::protocol::Router {
    let builder = iroh::protocol::Router::builder(endpoint)
        .accept(
            ALPN,
            IrohClientProtocol {
                state: Arc::clone(&state),
            },
        )
        .accept(crate::s2s::S2S_ALPN, crate::s2s::S2sProtocol { state });

    #[cfg(feature = "av-native")]
    let builder = match live {
        Some(live) => live.register_protocols(builder),
        None => builder,
    };

    builder.spawn()
}
