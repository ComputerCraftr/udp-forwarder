/* tests/common.rs — shared helpers for integration and stress tests */
use serde_json::Value as Json;

use std::io::{self, BufRead, BufReader, Read};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, UdpSocket,
};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, thread};

#[allow(dead_code)]
pub const TIMEOUT_SECS: Duration = Duration::from_secs(2);
#[allow(dead_code)]
pub const MAX_WAIT_SECS: Duration = Duration::from_secs(4);
#[allow(dead_code)]
pub const CLIENT_WAIT_MS: Duration = Duration::from_millis(250);
#[allow(dead_code)]
pub const JSON_WAIT_MS: Duration = Duration::from_millis(50);

fn strip_log_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(idx) = rest.find("] ") {
            return &rest[idx + 2..];
        }
    }
    trimmed
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketMode {
    Connected,
    Unconnected,
}

#[allow(dead_code)]
pub const SOCKET_MODES: [SocketMode; 2] = [SocketMode::Connected, SocketMode::Unconnected];

impl SocketMode {
    #[allow(dead_code)]
    pub fn apply(self, cmd: &mut Command) {
        if matches!(self, SocketMode::Unconnected) {
            cmd.arg("--debug").arg("no-connect");
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    #[allow(dead_code)]
    pub fn bind_client(self) -> io::Result<UdpSocket> {
        bind_udp_client(self)
    }

    #[allow(dead_code)]
    pub fn spawn_echo(self) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
        spawn_udp_echo_server(self)
    }

    #[allow(dead_code)]
    pub const fn listen_arg(self) -> &'static str {
        match self {
            Self::V4 => "UDP:127.0.0.1:0",
            Self::V6 => "UDP:[::1]:0",
        }
    }

    #[allow(dead_code)]
    pub const fn is_v6(self) -> bool {
        matches!(self, Self::V6)
    }
}

#[allow(dead_code)]
pub fn run_cases(protos: &[&str], mut run: impl FnMut(&str, SocketMode) -> bool) -> bool {
    for &proto in protos {
        for &mode in &SOCKET_MODES {
            if !run(proto, mode) {
                return false;
            }
        }
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
#[allow(dead_code)]
pub const SUPPORTED_PROTOCOLS: &[&str] = &["UDP", "ICMP"];

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
#[allow(dead_code)]
pub const SUPPORTED_PROTOCOLS: &[&str] = &["UDP"];

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

fn bind_udp_client_impl(addr: SocketAddr) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(1000)))?;
    sock.set_write_timeout(Some(Duration::from_millis(1000)))?;
    Ok(sock)
}

#[allow(dead_code)]
pub fn bind_udp_client(family: IpFamily) -> io::Result<UdpSocket> {
    match family {
        IpFamily::V4 => {
            bind_udp_client_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
        IpFamily::V6 => bind_udp_client_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
    }
}

#[allow(dead_code)]
pub fn random_unprivileged_port(family: IpFamily) -> io::Result<u16> {
    let sock = bind_udp_client(family)?;
    Ok(sock.local_addr()?.port())
}

fn spawn_udp_echo_server_impl(
    addr: SocketAddr,
) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(1000)))?;
    sock.set_write_timeout(Some(Duration::from_millis(1000)))?;
    let local = sock.local_addr()?;
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
    Ok((local, handle))
}

#[allow(dead_code)]
pub fn spawn_udp_echo_server(family: IpFamily) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    match family {
        IpFamily::V4 => {
            spawn_udp_echo_server_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
        IpFamily::V6 => spawn_udp_echo_server_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
    }
}

/// Try to locate the built forwarder binary across platforms (Linux/macOS/Windows).
pub fn find_app_bin() -> Option<String> {
    // Optional explicit override for CI or local runs.
    // e.g. TEST_APP_BIN=/path/to/bin cargo test
    if let Ok(override_path) = env::var("TEST_APP_BIN") {
        if Path::new(&override_path).exists() {
            return Some(override_path);
        }
    }

    // Helper: add .exe on Windows
    fn with_ext(name: &str) -> String {
        if cfg!(windows) && !name.ends_with(".exe") {
            format!("{name}.exe")
        } else {
            name.to_string()
        }
    }

    // Helper: return the first existing path from candidates
    fn first_existing(paths: impl IntoIterator<Item = PathBuf>) -> Option<String> {
        for p in paths {
            if p.exists() {
                return Some(p.to_string_lossy().to_string());
            }
        }
        None
    }

    // 1) Prefer Cargo's CARGO_BIN_EXE_* variables. This is the most accurate because it
    //    contains the actual, resolved path(s) for bin targets built for this package.
    //    We don't assume the bin name; instead we scan all env vars with that prefix,
    //    and pick the one that exists on disk.
    let mut candidates: Vec<(String, String)> = Vec::new();
    for (k, v) in env::vars() {
        if k.starts_with("CARGO_BIN_EXE_") && Path::new(&v).exists() {
            candidates.push((k, v));
        }
    }

    // If exactly one candidate exists, use it.
    if candidates.len() == 1 {
        return Some(candidates.remove(0).1);
    }

    // If multiple exist (multi-bin workspace), try to pick the one that matches the package name.
    if candidates.len() > 1 {
        if let Ok(pkg) = env::var("CARGO_PKG_NAME") {
            let want1 = pkg.replace('-', "_");
            let want2 = pkg.clone();
            if let Some((_k, v)) = candidates.iter().find(|(k, _)| {
                k == &format!("CARGO_BIN_EXE_{want1}") || k == &format!("CARGO_BIN_EXE_{want2}")
            }) {
                return Some(v.clone());
            }
        }
        // Otherwise, just take the first existing one deterministically (sorted by key).
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        return Some(candidates.remove(0).1);
    }

    // 2) No CARGO_BIN_EXE_* variables were exported (or they didn't exist on disk).
    //    Fall back to guessing from the package name and common target locations.
    let pkg = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| String::from("app"));
    let exe_name = with_ext(&pkg);

    // Try next to the test executable: target/{debug,release}/<exe_name>
    if let Ok(mut exe) = env::current_exe() {
        // .../target/{profile}/deps/<test_exe>
        if exe.pop() && exe.pop() {
            // Now at .../target/{profile}
            let candidate = exe.join(&exe_name);
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    // Try under CARGO_TARGET_DIR if set.
    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        let target = PathBuf::from(target_dir);
        let paths = ["debug", "release"]
            .into_iter()
            .map(|p| target.join(p).join(&exe_name));
        if let Some(p) = first_existing(paths) {
            return Some(p);
        }
    }

    // Fallback to standard target/<profile>/<exe_name> under the manifest dir.
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let md = PathBuf::from(manifest_dir);
        let paths = ["debug", "release"]
            .into_iter()
            .map(|p| md.join("target").join(p).join(&exe_name));
        if let Some(p) = first_existing(paths) {
            return Some(p);
        }
    }

    None
}

/// Take ownership of the child's stdout, returning the ChildStdout handle.
#[allow(dead_code)]
pub fn take_child_stdout(child: &mut std::process::Child) -> Option<std::process::ChildStdout> {
    child.stdout.take()
}

#[allow(dead_code)]
pub fn run_cli_args(args: &[&str]) -> (Option<i32>, String) {
    let bin = find_app_bin().expect("could not find app binary");
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");

    let status = child.wait().expect("wait failed");
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code(), err)
}

/// Wait for a "Listening on ..." line from a generic reader, and parse the socket address.
#[allow(dead_code)]
pub fn wait_for_listen_addr_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let parse_sa = |line: &str| {
        let line = strip_log_prefix(line);
        // Take the left side before the first comma and strip the protocol token
        let addr = line
            .strip_prefix(PREFIX)?
            .split_once(',')
            .map(|(left, _)| left.trim())?
            .split_once(':')
            .map(|(_, right)| right)?;

        // Fast path: direct SocketAddr parse (no DNS, no allocations).
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Some(sa);
        }

        // Fallback: resolve host:port or [IPv6]:port via DNS.
        return addr.to_socket_addrs().ok()?.next();
    };

    let start = Instant::now();
    let mut r = BufReader::new(reader);
    const PREFIX: &str = "Listening on ";
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                if let Some(sa) = parse_sa(&line) {
                    return Some(sa);
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
    let parse_sa = |line: &str| {
        let line = strip_log_prefix(line);
        // Take the left side before the second space
        // Expected form: "<addr> (connected)\n"
        let addr = line
            .strip_prefix(PREFIX)?
            .split_once(' ')
            .map(|(left, _)| left.trim())?;

        // Fast path: direct SocketAddr parse (no DNS, no allocations).
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Some(sa);
        }

        // Fallback: resolve host:port or [IPv6]:port via DNS.
        return addr.to_socket_addrs().ok()?.next();
    };

    let start = Instant::now();
    let mut r = BufReader::new(reader);
    const PREFIX: &str = "Locked to single client ";
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                if let Some(sa) = parse_sa(&line) {
                    return Some(sa);
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    None
}

/// Wait for a JSON stats line from a generic reader.
#[allow(dead_code)]
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
        let line = strip_log_prefix(l);
        if line.starts_with('{') && line.ends_with('}') {
            if let Ok(json) = serde_json::from_str::<Json>(line) {
                return Some(json);
            }
        }
    }
    None
}

#[allow(dead_code)]
pub fn json_addr(v: &Json) -> io::Result<SocketAddr> {
    // Expect a JSON string containing a socket address; propagate detailed errors instead of panicking.
    let s = v.as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "expected string socket addr in JSON",
        )
    })?;

    // Reject explicit "null" or empty strings early with a clear message.
    if s.eq_ignore_ascii_case("null") || s.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing or null socket addr string in JSON",
        ));
    }

    s.parse::<SocketAddr>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid socket addr string in JSON: '{s}': {e}"),
        )
    })
}
