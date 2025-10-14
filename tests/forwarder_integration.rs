use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

// bind to an ephemeral IPv4 UDP socket and return the socket (client only)
fn bind_udp_v4_client() -> UdpSocket {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind client");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock
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

#[test]
fn single_client_forwarding_ipv4() {
    // upstream echo server
    let (up_addr, _up_thread) = spawn_udp_echo_server();

    // client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client();

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
