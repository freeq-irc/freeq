//! SSRF protection utilities.
//!
//! Provides IP validation and DNS-pinning helpers to prevent Server-Side
//! Request Forgery when fetching user-controlled URLs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Returns `true` if the IP address belongs to a private, loopback,
/// link-local, or otherwise non-publicly-routable range.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: &Ipv4Addr) -> bool {
    v4.is_loopback()            // 127.0.0.0/8
        || v4.is_private()      // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()   // 169.254/16
        || v4.is_broadcast()    // 255.255.255.255
        || v4.is_unspecified()  // 0.0.0.0
        // CGNAT / Shared Address Space
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64.0.0/10
        // Documentation ranges
        || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2) // 192.0.2.0/24
        || (v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100) // 198.51.100.0/24
        || (v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113) // 203.0.113.0/24
}

fn is_private_v6(v6: &Ipv6Addr) -> bool {
    v6.is_loopback()        // ::1
        || v6.is_unspecified()  // ::
        // ULA fc00::/7
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        // Link-local fe80::/10
        || (v6.segments()[0] & 0xffc0) == 0xfe80
        // IPv4-mapped private addresses (::ffff:10.x.x.x, etc.)
        || {
            if let Some(v4) = v6.to_ipv4_mapped() {
                is_private_v4(&v4)
            } else {
                false
            }
        }
}

/// Returns `true` if the hostname looks like a private/local hostname.
pub fn is_private_hostname(host: &str) -> bool {
    // Strip trailing dot (DNS root) before checking
    let h = host.to_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    h == "localhost"
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".localhost")
        || h == "[::1]"
}

/// Resolve a hostname and verify that none of the resolved IPs are private.
///
/// Returns the list of resolved socket addresses on success, or an error
/// if any resolved IP is private or if DNS resolution fails.
pub async fn resolve_and_check(host: &str, port: u16) -> Result<Vec<SocketAddr>, SsrfError> {
    if is_private_hostname(host) {
        return Err(SsrfError::PrivateHost(host.to_string()));
    }

    // If the host is already an IP literal, check directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(SsrfError::PrivateIp(ip));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| SsrfError::DnsError(e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::DnsError("No addresses resolved".to_string()));
    }

    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            return Err(SsrfError::PrivateIp(addr.ip()));
        }
    }

    Ok(addrs)
}

/// Build a `reqwest::Client` that pins DNS resolution to pre-validated addresses.
///
/// This prevents TOCTOU / DNS-rebinding attacks by forcing reqwest to use
/// the IP addresses we already validated, rather than re-resolving.
pub fn pinned_client(
    host: &str,
    addrs: &[SocketAddr],
    timeout: std::time::Duration,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none()); // no redirects by default (caller can override)

    // Pin all resolved addresses so reqwest won't re-resolve via DNS
    for addr in addrs {
        builder = builder.resolve(host, *addr);
    }

    builder.build()
}

#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    #[error("Private/reserved hostname: {0}")]
    PrivateHost(String),
    #[error("Private/reserved IP: {0}")]
    PrivateIp(IpAddr),
    #[error("DNS resolution failed: {0}")]
    DnsError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap())); // CGNAT

        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(is_private_ip(&"::".parse().unwrap()));
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));

        assert!(!is_private_ip(&"2607:f8b0:4004:800::200e".parse().unwrap()));
    }

    #[test]
    fn test_private_hostname() {
        assert!(is_private_hostname("localhost"));
        assert!(is_private_hostname("foo.local"));
        assert!(is_private_hostname("bar.internal"));
        assert!(is_private_hostname("test.localhost"));
        assert!(!is_private_hostname("example.com"));
    }
}
