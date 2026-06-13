// crates/ql-bench/src/bin/ql-netprobe.rs
//
//! `ql-netprobe` — attempts to reach an internal network service.
//!
//! Stands in for a cloud-metadata SSRF: the harness hosts a fake "metadata"
//! service on the host's primary (private) IP, and this probe tries to connect
//! and read it. The address is non-loopback, so:
//!
//! * With no containment, the connection succeeds and the probe prints whatever
//!   the service returned (the secret marker) — the harness reads VULNERABLE.
//! * Inside QuantmLayer's network namespace there is no route to that address,
//!   so the connection fails, nothing is printed — the harness reads BLOCKED.
//!
//! Usage: `ql-netprobe <ip> <port>`

use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let ip = args.next().unwrap_or_default();
    let port = args.next().unwrap_or_default();
    let addr = format!("{ip}:{port}");

    // Resolve and connect with a short timeout so a blocked attempt fails fast.
    let Ok(mut sockaddrs) = addr.to_socket_addrs() else {
        return;
    };
    let Some(sockaddr) = sockaddrs.next() else {
        return;
    };

    match TcpStream::connect_timeout(&sockaddr, Duration::from_secs(2)) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = String::new();
            // Read whatever the stand-in service sends and echo it; if it
            // contains the marker, the harness counts the attack as successful.
            let _ = stream.read_to_string(&mut buf);
            print!("{buf}");
        }
        Err(_) => {
            // No route / refused / timed out: the target was unreachable.
        }
    }
}
