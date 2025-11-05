/* tests/common.rs — shared helpers for integration and stress tests */
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

/// Try to locate the built forwarder binary across platforms (Linux/macOS/Windows).
pub fn find_forwarder_bin() -> Option<String> {
    use std::env;
    use std::path::{Path, PathBuf};

    fn with_ext(name: &str) -> String {
        if cfg!(windows) {
            if name.ends_with(".exe") {
                name.to_string()
            } else {
                format!("{name}.exe")
            }
        } else {
            name.to_string()
        }
    }

    // 1) Cargo-provided env vars for binaries built in this package.
    // Cargo defines CARGO_BIN_EXE_<bin-name-with-hyphens> (hyphens become underscores).
    // Try both hyphen and underscore forms.
    if let Ok(p) = env::var("CARGO_BIN_EXE_udp-forwarder") {
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    if let Ok(p) = env::var("CARGO_BIN_EXE_udp_forwarder") {
        if Path::new(&p).exists() {
            return Some(p);
        }
    }

    // Helper: check a list of candidate paths.
    fn first_existing(paths: &[PathBuf]) -> Option<String> {
        for p in paths {
            if p.exists() {
                return Some(p.to_string_lossy().to_string());
            }
        }
        None
    }

    // 2) Look next to the test executable (target/{debug,release}/deps/<test>…).
    // Climb up to target/{debug,release} and probe for the bin names.
    if let Ok(mut exe) = env::current_exe() {
        if exe.pop() {
            // deps/
            if exe.pop() {
                // debug/ or release/
                let mut cands = Vec::new();
                for bin in ["udp-forwarder", "udp_forwarder"] {
                    cands.push(exe.join(with_ext(bin)));
                }
                if let Some(p) = first_existing(&cands) {
                    return Some(p);
                }
            }
        }
    }

    // 3) Try paths under CARGO_TARGET_DIR (if set).
    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        let target = PathBuf::from(target_dir);
        let mut cands = Vec::new();
        for profile in ["debug", "release"] {
            for bin in ["udp-forwarder", "udp_forwarder"] {
                cands.push(target.join(profile).join(with_ext(bin)));
            }
        }
        if let Some(p) = first_existing(&cands) {
            return Some(p);
        }
    }

    // 4) Fall back to paths under the manifest directory.
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let md = PathBuf::from(manifest_dir);
        let mut cands = Vec::new();
        for profile in ["debug", "release"] {
            for bin in ["udp-forwarder", "udp_forwarder"] {
                cands.push(md.join("target").join(profile).join(with_ext(bin)));
            }
        }
        if let Some(p) = first_existing(&cands) {
            return Some(p);
        }
    }
    None
}

/// Take ownership of the child's stdout, returning the ChildStdout handle.
pub fn take_child_stdout(child: &mut std::process::Child) -> Option<std::process::ChildStdout> {
    child.stdout.take()
}

/// Wait for a "Listening on ..." line from a generic reader, and parse the socket address.
pub fn wait_for_listen_addr_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let start = Instant::now();
    let mut r = BufReader::new(reader);
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                if let Some(rest) = line.strip_prefix("Listening on ") {
                    if let Some((addr_str, _)) = rest.split_once(',') {
                        let mut it = addr_str.to_string().to_socket_addrs().ok()?;
                        if let Some(sa) = it.next() {
                            return Some(sa);
                        }
                    }
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    None
}

/// Wait for a "Locked to single client ... (connected)" line from a generic reader,
/// and parse the socket address of the newly locked client.
#[allow(dead_code)]
pub fn wait_for_locked_client_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let start = Instant::now();
    let mut r = BufReader::new(reader);
    const PREFIX: &str = "Locked to single client ";
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                if let Some(rest) = line.strip_prefix(PREFIX) {
                    // Expected form: "<addr> (connected)\n"
                    let addr_part = match rest.split_once(' ') {
                        Some((addr, _)) => addr,
                        None => rest.trim_end(),
                    };
                    // Resolve and return the first parsed SocketAddr
                    let mut it = addr_part.to_string().to_socket_addrs().ok()?;
                    if let Some(sa) = it.next() {
                        return Some(sa);
                    }
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    None
}

/// Wait for a JSON stats line from a generic reader.
pub fn wait_for_stats_json_from<R: Read>(reader: &mut R, max_wait: Duration) -> Option<Json> {
    let start = Instant::now();
    let mut buf = String::new();
    let mut r = BufReader::new(reader);
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                buf.push_str(&line);
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    for l in buf.lines().rev() {
        if l.starts_with('{') && l.ends_with('}') {
            if let Ok(json) = serde_json::from_str::<Json>(l) {
                return Some(json);
            }
        }
    }
    None
}

#[allow(dead_code)]
pub fn json_addr(v: &Json) -> SocketAddr {
    let s = v.as_str().expect("expected string socket addr in JSON");

    if s == "null" {
        panic!("null socket addr string in JSON");
    }

    s.parse::<SocketAddr>()
        .expect("invalid socket addr string in JSON")
}
