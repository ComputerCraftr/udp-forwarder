// tests/common.rs — shared helpers for integration and stress tests
use serde_json::Value as Json;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, UdpSocket,
};
use std::ops::{Deref, DerefMut};
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

/// Ensures the spawned child is terminated on drop (e.g., when a test panics).
#[allow(dead_code)]
pub struct ChildGuard(Child);

impl ChildGuard {
    #[allow(dead_code)]
    pub fn new(child: Child) -> Self {
        Self(child)
    }
}

impl Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // If it's still running (or we can't tell), try to kill and wait.
        match self.0.try_wait() {
            Ok(Some(_status)) => {
                // already exited
            }
            Ok(None) | Err(_) => {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
}

pub fn bind_udp_v4_client() -> UdpSocket {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind client");
    sock.set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    sock
}

#[allow(dead_code)]
pub fn bind_udp_v6_client() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))?;
    sock.set_read_timeout(Some(Duration::from_millis(5000)))?;
    sock.set_write_timeout(Some(Duration::from_millis(5000)))?;
    Ok(sock)
}

pub fn spawn_udp_echo_server_v4() -> (SocketAddr, thread::JoinHandle<()>) {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind v4 echo");
    sock.set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_millis(5000)))
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

#[allow(dead_code)]
pub fn spawn_udp_echo_server_v6() -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))?;
    sock.set_read_timeout(Some(Duration::from_millis(5000)))?;
    sock.set_write_timeout(Some(Duration::from_millis(5000)))?;
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

/// Take ownership of the child's stdout, returning the ChildStdout handle.
pub fn take_child_stdout(child: &mut std::process::Child) -> std::process::ChildStdout {
    child.stdout.take().expect("child stdout missing")
}

/// Wait for a "Listening on ..." line from a generic reader, and parse the socket address.
pub fn wait_for_listen_addr_from<R: Read>(reader: &mut R, max_wait: Duration) -> SocketAddr {
    let start = Instant::now();
    let mut buf = String::new();
    let mut r = BufReader::new(reader);
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                buf.push_str(&line);
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
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    panic!(
        "did not see 'Listening on' line within {:?}; saw: {}",
        max_wait, buf
    );
}

/// Wait for a JSON stats line from a generic reader.
pub fn wait_for_stats_json_from<R: Read>(reader: &mut R, max_wait: Duration) -> Json {
    let start = Instant::now();
    let mut buf = String::new();
    let mut r = BufReader::new(reader);
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                buf.push_str(&line);
                for l in buf.lines().rev() {
                    if l.starts_with('{') && l.ends_with('}') {
                        if let Ok(json) = serde_json::from_str::<Json>(l) {
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

#[allow(dead_code)]
pub fn json_addr(v: &Json) -> SocketAddr {
    let s = v.as_str().expect("expected string socket addr in JSON");
    s.parse::<SocketAddr>()
        .expect("invalid socket addr string in JSON")
}
