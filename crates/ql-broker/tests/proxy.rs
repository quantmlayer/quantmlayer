// crates/ql-broker/tests/proxy.rs
//
//! Hermetic integration tests for the broker — no internet required.
//!
//! * The *tunnel* test proves the proxy mechanics: with an open policy it
//!   relays bytes between a client and a local upstream.
//! * The *refusal* test proves enforcement: with the default deny-by-default
//!   policy, a `CONNECT` to the cloud-metadata address is refused with `403`,
//!   without ever contacting it.

use ql_broker::{serve, BrokerPolicy};
use ql_profile::NetPolicy;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Start the broker on an ephemeral loopback port; return its address.
fn start_broker(policy: BrokerPolicy) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let policy = Arc::new(policy);
    thread::spawn(move || {
        let _ = serve(listener, policy);
    });
    addr
}

#[test]
fn tunnels_bytes_to_an_allowed_upstream() {
    // A trivial upstream that replies with a known banner.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_addr = upstream.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut s, _)) = upstream.accept() {
            let mut buf = [0u8; 16];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"UPSTREAM_OK");
        }
    });

    // Open policy (no deny, no private-range block) so we can tunnel to
    // loopback purely to exercise the proxy plumbing.
    let policy = BrokerPolicy::from_net_policy(&NetPolicy {
        default_deny: false,
        allow_domains: vec![],
        block_private_ranges: false,
    });
    let broker = start_broker(policy);

    let mut client = TcpStream::connect(&broker).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "CONNECT {up_addr} HTTP/1.1\r\nHost: {up_addr}\r\n\r\n"
    )
    .unwrap();

    // Expect the 200 Connection Established status line.
    let mut head = [0u8; 39];
    client.read_exact(&mut head).unwrap();
    let head = String::from_utf8_lossy(&head);
    assert!(head.contains("200"), "expected 200, got: {head:?}");

    // Now the tunnel is live: send through it and read the upstream banner.
    client.write_all(b"ping").unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert!(reply.contains("UPSTREAM_OK"), "got: {reply:?}");
}

#[test]
fn refuses_cloud_metadata() {
    // Default policy: deny-by-default + block private ranges.
    let policy = BrokerPolicy::from_net_policy(&NetPolicy::default());
    let broker = start_broker(policy);

    let mut client = TcpStream::connect(&broker).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // The classic SSRF target.
    write!(
        client,
        "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"
    )
    .unwrap();

    let mut resp = String::new();
    client.read_to_string(&mut resp).unwrap();
    assert!(
        resp.contains("403"),
        "metadata must be refused, got: {resp:?}"
    );
}

#[test]
fn refuses_host_not_on_allow_list() {
    // Allow only pypi.org; a different host must be refused before any lookup.
    let policy = BrokerPolicy::from_net_policy(&NetPolicy {
        default_deny: true,
        allow_domains: vec!["pypi.org".into()],
        block_private_ranges: true,
    });
    let broker = start_broker(policy);

    let mut client = TcpStream::connect(&broker).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n"
    )
    .unwrap();

    let mut resp = String::new();
    client.read_to_string(&mut resp).unwrap();
    assert!(
        resp.contains("403"),
        "off-list host must be refused, got: {resp:?}"
    );
}
