// crates/ql-broker/src/proxy.rs
//
//! The HTTP CONNECT proxy that fronts all of an agent's egress.
//!
//! In the deployed shape, the agent lives in a network namespace whose only
//! route is to this broker, with `HTTPS_PROXY=http://<broker>` set. Every
//! outbound TLS connection becomes a `CONNECT host:port` request to the broker,
//! which applies [`BrokerPolicy`] and either tunnels the bytes (allowed) or
//! refuses with `403` (denied). Because the broker performs the actual upstream
//! connection, the allow-list and private-range checks are enforced centrally,
//! and the agent never gets a raw route to the metadata endpoint.
//!
//! This is a deliberately small, synchronous (thread-per-connection)
//! implementation: no async runtime, tiny dependency surface, easy to audit.

use crate::policy::{BrokerPolicy, Decision};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Serve the broker on `listener` forever, applying `policy` to each request.
/// Each connection is handled on its own thread.
pub fn serve(listener: TcpListener, policy: Arc<BrokerPolicy>) -> io::Result<()> {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let policy = Arc::clone(&policy);
                thread::spawn(move || {
                    // A single misbehaving client must never take down the broker.
                    let _ = handle_connection(stream, &policy);
                });
            }
            Err(e) => eprintln!("ql-broker: accept error: {e}"),
        }
    }
    Ok(())
}

/// Handle one proxied connection: parse the request, apply policy, and either
/// tunnel or refuse.
pub fn handle_connection(client: TcpStream, policy: &BrokerPolicy) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(client.try_clone()?);

    // Request line, e.g. "CONNECT example.com:443 HTTP/1.1".
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(()); // client closed
    }
    // Drain the remaining request headers (up to the blank line), capturing the
    // QuantmLayer authorization header (the agent's signed delegation token) if
    // present.
    let mut auth: Option<String> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("x-ql-authorization") {
                auth = Some(value.trim().to_string());
            }
        }
    }

    let mut client = client; // own it for writing responses
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        // We only implement CONNECT (HTTPS tunneling), which is what package
        // managers and agents use. Plain-HTTP forwarding is intentionally out
        // of scope for this component.
        return write_status(
            &mut client,
            501,
            "Not Implemented",
            "only CONNECT is supported",
        );
    }

    let (host, port) = match split_host_port(parts[1]) {
        Some(hp) => hp,
        None => return write_status(&mut client, 400, "Bad Request", "malformed authority"),
    };

    // Authorize the connection: token-gated (a signed delegation token in the
    // X-QL-Authorization header) when enabled, otherwise the static allow-list.
    // A denied host never triggers a DNS lookup, and the decision is audited.
    let now = ql_audit::AuditLog::now_millis();
    if let Decision::Deny(reason) = policy.authorize_connect(&host, port, auth.as_deref(), now) {
        log_decision(&host, port, "DENY (authorization)");
        return write_status(&mut client, 403, "Forbidden", reason);
    }

    // Resolve, then apply the private-range check against every resolved IP.
    let resolved: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(_) => {
            log_decision(&host, port, "DENY (unresolved)");
            return write_status(&mut client, 502, "Bad Gateway", "could not resolve host");
        }
    };
    let ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();

    match policy.evaluate(&host, &ips) {
        Decision::Deny(reason) => {
            log_decision(&host, port, "DENY (policy)");
            write_status(&mut client, 403, "Forbidden", reason)
        }
        Decision::Allow => {
            // The policy has already vetted every resolved IP (when
            // block_private_ranges is on, evaluate() guaranteed none are
            // blocked; when off, the operator opted into them). Connect to the
            // first resolved address.
            let Some(target) = resolved.first() else {
                return write_status(&mut client, 502, "Bad Gateway", "no address");
            };
            match TcpStream::connect_timeout(target, Duration::from_secs(10)) {
                Ok(upstream) => {
                    log_decision(&host, port, "ALLOW");
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    tunnel(client, upstream)
                }
                Err(_) => write_status(&mut client, 502, "Bad Gateway", "upstream connect failed"),
            }
        }
    }
}

/// Pipe bytes in both directions until either side closes.
fn tunnel(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut client_rd = client.try_clone()?;
    let mut up_wr = upstream.try_clone()?;
    // client → upstream on a worker thread.
    let to_upstream = thread::spawn(move || {
        let _ = io::copy(&mut client_rd, &mut up_wr);
        let _ = up_wr.shutdown(std::net::Shutdown::Write);
    });
    // upstream → client on this thread.
    let mut up_rd = upstream;
    let mut client_wr = client;
    let _ = io::copy(&mut up_rd, &mut client_wr);
    let _ = client_wr.shutdown(std::net::Shutdown::Write);
    let _ = to_upstream.join();
    Ok(())
}

/// Split an "host:port" authority. The host may be an IPv6 literal in brackets.
fn split_host_port(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // [v6]:port
        let (h, p) = rest.split_once(']')?;
        let port = p.strip_prefix(':')?.parse().ok()?;
        Some((h.to_string(), port))
    } else {
        let (h, p) = authority.rsplit_once(':')?;
        Some((h.to_string(), p.parse().ok()?))
    }
}

/// Write a minimal HTTP response and close.
fn write_status(client: &mut TcpStream, code: u16, reason: &str, body: &str) -> io::Result<()> {
    let payload = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(payload.as_bytes())
}

/// Emit a one-line audit record. In production this would be structured and
/// shipped to the control plane; the broker is the natural egress audit point.
fn log_decision(host: &str, port: u16, decision: &str) {
    eprintln!("ql-broker: {decision} {host}:{port}");
}

/// Read up to `limit` bytes from a stream — small helper for tests/diagnostics.
#[allow(dead_code)]
pub(crate) fn read_some(stream: &mut TcpStream, limit: usize) -> io::Result<String> {
    let mut buf = vec![0u8; limit];
    let n = stream.read(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}
