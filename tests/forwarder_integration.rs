use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value as Json;

// bind to an ephemeral IPv4 UDP socket and return the socket (client only)
fn bind_udp_v4_client() -> UdpSocket {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind client");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock
}

fn bind_udp_v6_client() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    sock.set_write_timeout(Some(Duration::from_millis(500)))?;
    Ok(sock)
}

// simple UDP echo server that runs on a background thread
fn spawn_udp_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (sock, addr) = {
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind");
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        sock.set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        (sock, addr)
    };
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    // echo back exactly what we received
                    let _ = sock.send_to(&buf[..n], src);
                }
                Err(_) => {
                    // timeouts are fine; keep listening for a short while
                }
            }
        }
    });
    (addr, handle)
}

fn spawn_udp_echo_server_v6() -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let (sock, addr) = {
        let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        sock.set_write_timeout(Some(Duration::from_millis(500)))?;
        let addr = sock.local_addr().unwrap();
        (sock, addr)
    };
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let _ = sock.send_to(&buf[..n], src);
                }
                Err(_) => {}
            }
        }
    });
    Ok((addr, handle))
}

fn find_forwarder_bin() -> String {
    // Try Cargo's env vars first (hyphens become underscores)
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_udp-forwarder") {
        return p;
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_udp_forwarder") {
        return p;
    }

    // Fallback: derive from the crate root and typical target locations
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let candidates = [
        format!("{}/target/debug/udp-forwarder", manifest_dir),
        format!("{}/target/debug/udp_forwarder", manifest_dir),
        format!("{}/target/release/udp-forwarder", manifest_dir),
        format!("{}/target/release/udp_forwarder", manifest_dir),
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return c.clone();
        }
    }
    panic!(
        "could not find forwarder binary; tried env(CARGO_BIN_EXE_udp[-_]forwarder) and {:?}",
        candidates
    );
}

fn wait_for_listen_addr(child: &mut std::process::Child, max_wait: Duration) -> SocketAddr {
    use std::net::ToSocketAddrs;
    let start = Instant::now();
    let mut buf = String::new();
    let stdout = child.stdout.as_mut().expect("child stdout missing");
    while start.elapsed() < max_wait {
        let mut chunk = [0u8; 4096];
        match stdout.read(&mut chunk) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if let Some(line) = buf.lines().find(|l| l.starts_with("Listening on ")) {
                    // expected: "Listening on <addr>, forwarding to upstream ..."
                    if let Some(rest) = line.strip_prefix("Listening on ") {
                        if let Some((addr_str, _)) = rest.split_once(',') {
                            // parse SocketAddr from the printed address
                            let mut it = addr_str
                                .to_string()
                                .to_socket_addrs()
                                .expect("parse printed addr");
                            if let Some(sa) = it.next() {
                                return sa;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    panic!(
        "did not see 'Listening on' line in forwarder stdout within {:?}; saw: {}",
        max_wait, buf
    );
}

fn wait_for_stats_json(child: &mut std::process::Child, max_wait: Duration) -> Json {
    let start = Instant::now();
    let stdout = child.stdout.as_mut().expect("child stdout missing");
    let mut buf = String::new();
    while start.elapsed() < max_wait {
        let mut chunk = [0u8; 4096];
        match stdout.read(&mut chunk) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                for line in buf.lines() {
                    if line.starts_with('{') && line.ends_with('}') {
                        if let Ok(json) = serde_json::from_str::<Json>(line) {
                            return json;
                        }
                    }
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    panic!(
        "did not see stats JSON within {:?}; saw buffer: {}",
        max_wait, buf
    );
}

fn json_addr(v: &Json) -> SocketAddr {
    let s = v.as_str().expect("expected string socket addr in JSON");
    s.parse::<SocketAddr>()
        .expect("invalid socket addr string in JSON")
}

#[test]
fn single_client_forwarding_ipv4() {
    // upstream echo server
    let (up_addr, _up_thread) = spawn_udp_echo_server();

    // client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client();
    let client_local = client_sock.local_addr().expect("client local addr");

    // spawn the forwarder binary
    let bin = find_forwarder_bin();

    // run with small timeout & auto-exit on idle
    let mut child = Command::new(bin)
        .arg("127.0.0.1:0")
        .arg(up_addr.to_string())
        .arg("--timeout-secs")
        .arg("2")
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn forwarder");

    let listen_addr = wait_for_listen_addr(&mut child, Duration::from_secs(3));

    // send one datagram to the forwarder; expect to receive same payload back (echo through upstream)
    let payload = b"hello-through-forwarder";
    client_sock
        .send_to(payload, listen_addr)
        .expect("send to forwarder");

    let mut buf = [0u8; 1024];
    let (n, _src) = client_sock
        .recv_from(&mut buf)
        .expect("recv from forwarder");
    assert_eq!(&buf[..n], payload, "echo payload mismatch");

    // Wait for a stats line and validate fields
    let stats = wait_for_stats_json(&mut child, Duration::from_secs(2));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert!(stats["c2u_pkts"].as_u64().unwrap_or(0) == 1);
    assert!(stats["u2c_pkts"].as_u64().unwrap_or(0) == 1);
    assert!(stats["client"].is_string());
    assert!(stats["upstream"].is_string());

    // Validate addresses exactly (listen is random port, but client local addr is known)
    let stats_client = json_addr(&stats["client"]);
    assert_eq!(stats_client, client_local, "stats client addr mismatch");
    let stats_upstream = json_addr(&stats["upstream"]);
    assert_eq!(stats_upstream, up_addr, "stats upstream addr mismatch");

    // Validate byte counters for one packet
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );

    // Latency fields should be numbers (≥ 0)
    assert!(stats["c2u_avg_us"].is_number());
    assert!(stats["u2c_avg_us"].is_number());
    assert!(stats["c2u_max_us"].is_number());
    assert!(stats["u2c_max_us"].is_number());

    // after ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }
    // if it didn't exit, kill for cleanliness
    let _ = child.kill();
    panic!("forwarder did not exit after idle timeout");
}

#[test]
fn single_client_forwarding_ipv6() {
    // if IPv6 loopback is unavailable on this host, skip gracefully
    let client_sock = match bind_udp_v6_client() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("IPv6 loopback not available; skipping IPv6 test");
            return;
        }
    };
    let client_local = client_sock.local_addr().expect("client local addr v6");
    let (up_addr, _up_thread) = match spawn_udp_echo_server_v6() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("IPv6 echo server could not bind; skipping");
            return;
        }
    };

    let bin = find_forwarder_bin();

    let mut child = Command::new(bin)
        .arg("[::1]:0")
        .arg(up_addr.to_string())
        .arg("--timeout-secs")
        .arg("2")
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn forwarder");

    let listen_addr = wait_for_listen_addr(&mut child, Duration::from_secs(3));

    let payload = b"hello-through-forwarder-v6";
    client_sock.send_to(payload, listen_addr).expect("send v6");
    let mut buf = [0u8; 1024];
    let (n, _src) = client_sock.recv_from(&mut buf).expect("recv v6");
    assert_eq!(&buf[..n], payload);

    // stats line
    let stats = wait_for_stats_json(&mut child, Duration::from_secs(2));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert!(stats["c2u_pkts"].as_u64().unwrap_or(0) == 1);
    assert!(stats["u2c_pkts"].as_u64().unwrap_or(0) == 1);
    assert!(stats["client"].is_string());
    assert!(stats["upstream"].is_string());

    let stats_client = json_addr(&stats["client"]);
    assert_eq!(stats_client, client_local, "stats client addr v6 mismatch");
    let stats_upstream = json_addr(&stats["upstream"]);
    assert_eq!(stats_upstream, up_addr, "stats upstream addr v6 mismatch");
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert!(stats["c2u_avg_us"].is_number());
    assert!(stats["u2c_avg_us"].is_number());
    assert!(stats["c2u_max_us"].is_number());
    assert!(stats["u2c_max_us"].is_number());

    // allow exit
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success());
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }
    let _ = child.kill();
    panic!("forwarder did not exit after idle timeout (v6)");
}
