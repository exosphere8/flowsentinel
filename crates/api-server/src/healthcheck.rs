//! `api-server healthcheck`: a minimal HTTP probe of `GET /health`, so
//! container health checks need no extra tools in the image.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Largest response read.
const MAX_RESPONSE_BYTES: u64 = 4096;

/// Where to probe a server listening on `addr`: an unspecified address
/// (`0.0.0.0` or `::`) is reached through loopback.
pub fn target(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

/// Requests `GET /health` from `addr` and succeeds on a `200` status.
pub async fn probe(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let target = target(addr);
    let attempt = async {
        let mut stream = TcpStream::connect(target)
            .await
            .map_err(|e| format!("cannot connect to {target}: {e}"))?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| format!("cannot send the request: {e}"))?;
        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("cannot read the response: {e}"))?;
        let status = response
            .split(|&b| b == b'\r' || b == b'\n')
            .next()
            .map(String::from_utf8_lossy)
            .unwrap_or_default()
            .into_owned();
        if status.starts_with("HTTP/1.1 200 ") || status.starts_with("HTTP/1.0 200 ") {
            Ok(())
        } else {
            Err(format!("unexpected response: {status:?}"))
        }
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| format!("no response from {target} within {} s", timeout.as_secs()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspecified_addresses_are_probed_on_loopback() {
        assert_eq!(
            target("0.0.0.0:8080".parse().unwrap()).to_string(),
            "127.0.0.1:8080"
        );
        assert_eq!(
            target("[::]:9000".parse().unwrap()).to_string(),
            "[::1]:9000"
        );
        assert_eq!(
            target("192.0.2.5:80".parse().unwrap()).to_string(),
            "192.0.2.5:80"
        );
    }
}
