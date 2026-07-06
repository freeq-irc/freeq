//! The client-provider seam.
//!
//! The engine never decides *how* an outbound HTTP client is built — that's
//! network policy the caller owns. Discovery walks a chain of
//! attacker-influenced URLs (PDS → auth server), so a multi-tenant caller
//! (the server, the broker) must SSRF-validate and DNS-pin a fresh client per
//! URL; a loopback caller (the CLI, talking to the user's own PDS) can reuse
//! one plain client. `freeq-oauth` stays agnostic: it asks the provider for a
//! client per URL and knows nothing about SSRF.

/// Supplies an HTTP client for a specific outbound URL.
#[allow(async_fn_in_trait)]
pub trait ClientProvider {
    /// Return a client suitable for requesting `url`. Implementations that
    /// enforce SSRF policy validate `url` here and return an error to refuse.
    async fn client_for(&self, url: &str) -> anyhow::Result<reqwest::Client>;
}

/// A [`ClientProvider`] that hands back the same client for every URL.
///
/// For callers with no SSRF exposure — the loopback CLI login, which only
/// ever talks to the user's own resolved PDS. Multi-tenant callers must NOT
/// use this; they need per-URL validation.
pub struct SharedClient(pub reqwest::Client);

impl ClientProvider for SharedClient {
    async fn client_for(&self, _url: &str) -> anyhow::Result<reqwest::Client> {
        Ok(self.0.clone())
    }
}
