// tests/common.rs — shared helpers for integration and stress tests
use serde_json::Value as Json;
use std::io::{self, Read};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, UdpSocket,
};
use std::thread;
use std::time::{Duration, Instant};

pub fn bind_udp_v4_client() -> UdpSocket {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind client");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock
}
pub fn bind_udp_v6_client() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    sock.set_write_timeout(Some(Duration::from_millis(500)))?;
    Ok(sock)
}

pub fn spawn_udp_echo_server_v4() -> (SocketAddr, thread::JoinHandle<()>) {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind v4 echo");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
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
    (addr, handle)
}
pub fn spawn_udp_echo_server_v6() -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    sock.set_write_timeout(Some(Duration::from_millis(500)))?;
    let addr = sock.local_addr().unwrap();
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

pub fn find_forwarder_bin() -> String {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_udp-forwarder") {
        return p;
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_udp_forwarder") {
        return p;
    }

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

pub fn wait_for_listen_addr(child: &mut std::process::Child, max_wait: Duration) -> SocketAddr {
    let start = Instant::now();
    let mut buf = String::new();
    let stdout = child.stdout.as_mut().expect("child stdout missing");
    while start.elapsed() < max_wait {
        let mut chunk = [0u8; 4096];
        match stdout.read(&mut chunk) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if let Some(line) = buf.lines().find(|l| l.starts_with("Listening on ")) {
                    if let Some(rest) = line.strip_prefix("Listening on ") {
                        if let Some((addr_str, _)) = rest.split_once(',') {
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
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    panic!(
        "did not see 'Listening on' line in forwarder stdout within {:?}; saw: {}",
        max_wait, buf
    );
}

pub fn wait_for_stats_json(child: &mut std::process::Child, max_wait: Duration) -> Json {
    let start = Instant::now();
    let stdout = child.stdout.as_mut().expect("child stdout missing");
    let mut buf = String::new();
    while start.elapsed() < max_wait {
        let mut chunk = [0u8; 4096];
        match stdout.read(&mut chunk) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
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
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    panic!(
        "did not see stats JSON within {:?}; saw buffer: {}",
        max_wait, buf
    );
}

pub fn json_addr(v: &Json) -> SocketAddr {
    let s = v.as_str().expect("expected string socket addr in JSON");
    s.parse::<SocketAddr>()
        .expect("invalid socket addr string in JSON")
}
