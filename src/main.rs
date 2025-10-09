// Single-client UDP forwarder (IPv4/IPv6) with configurable idle timeout
// Pure L4 forwarder: unprivileged, no payload parsing.
// - Locks to the first client (SocketAddr) that sends a packet.
// - Forwards client->upstream and upstream->client.
// - Uses the listener socket for replies so the client always sees the same source port.
// - If no traffic is seen for --timeout-secs (default 10), either:
//     * drop: drop the locked client and accept a new one
//     * exit: exit the program (status 0)
//
// Build:
//   cargo build --release
//
// Run examples:
//   ./target/release/udp-forwarder 0.0.0.0:5354 1.1.1.1:53
//   ./target/release/udp-forwarder 0.0.0.0:5354 one.one.one.one:53 --timeout-secs 45 --on-timeout drop
//   ./target/release/udp-forwarder 0.0.0.0:5354 [2606:4700:4700::1001]:53 --on-timeout exit

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering},
};
use std::thread;
use std::time::{Duration, Instant};

fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no address resolved"))
}

fn make_udp_socket(bind_addr: SocketAddr, read_timeout_ms: u64) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(bind_addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))?;
    Ok(sock)
}

fn make_upstream_socket(dest: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = match dest {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    make_udp_socket(bind_addr, 250)
}

fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => false,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => false,
        _ => true,
    }
}

fn apply_fresh_upstream(
    fresh: SocketAddr,
    current_up_addr: &Arc<Mutex<SocketAddr>>,
    upstream_sock: &Arc<Mutex<UdpSocket>>,
    context: &str,
) {
    let mut cur = current_up_addr.lock().unwrap();
    let fam_changed = family_changed(*cur, fresh);
    let changed = *cur != fresh;
    *cur = fresh;
    drop(cur);
    if fam_changed {
        match make_upstream_socket(fresh) {
            Ok(new_sock) => {
                *upstream_sock.lock().unwrap() = new_sock;
                println!(
                    "{}: upstream {} (family changed; upstream socket swapped)",
                    context, fresh
                );
            }
            Err(e) => eprintln!(
                "{}: failed to create upstream socket for {}: {}",
                context, fresh, e
            ),
        }
    } else if changed {
        println!("{}: upstream {}", context, fresh);
    }
}

struct Stats {
    start: Instant,
    c2u_pkts: AtomicU64,
    c2u_bytes: AtomicU64,
    c2u_send_errs: AtomicU64,
    u2c_pkts: AtomicU64,
    u2c_bytes: AtomicU64,
    u2c_send_errs: AtomicU64,
    c2u_lat_ns_sum: AtomicU64,
    c2u_lat_ns_max: AtomicU64,
    u2c_lat_ns_sum: AtomicU64,
    u2c_lat_ns_max: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            c2u_pkts: AtomicU64::new(0),
            c2u_bytes: AtomicU64::new(0),
            c2u_send_errs: AtomicU64::new(0),
            u2c_pkts: AtomicU64::new(0),
            u2c_bytes: AtomicU64::new(0),
            u2c_send_errs: AtomicU64::new(0),
            c2u_lat_ns_sum: AtomicU64::new(0),
            c2u_lat_ns_max: AtomicU64::new(0),
            u2c_lat_ns_sum: AtomicU64::new(0),
            u2c_lat_ns_max: AtomicU64::new(0),
        }
    }
    fn add_c2u(&self, bytes: u64, lat_ns: u64) {
        self.c2u_pkts.fetch_add(1, AtomOrdering::Relaxed);
        self.c2u_bytes.fetch_add(bytes, AtomOrdering::Relaxed);
        self.c2u_lat_ns_sum.fetch_add(lat_ns, AtomOrdering::Relaxed);
        // max update (lock-free best-effort)
        loop {
            let cur = self.c2u_lat_ns_max.load(AtomOrdering::Relaxed);
            if lat_ns <= cur {
                break;
            }
            if self
                .c2u_lat_ns_max
                .compare_exchange(cur, lat_ns, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
    fn c2u_err(&self) {
        self.c2u_send_errs.fetch_add(1, AtomOrdering::Relaxed);
    }
    fn add_u2c(&self, bytes: u64, lat_ns: u64) {
        self.u2c_pkts.fetch_add(1, AtomOrdering::Relaxed);
        self.u2c_bytes.fetch_add(bytes, AtomOrdering::Relaxed);
        self.u2c_lat_ns_sum.fetch_add(lat_ns, AtomOrdering::Relaxed);
        loop {
            let cur = self.u2c_lat_ns_max.load(AtomOrdering::Relaxed);
            if lat_ns <= cur {
                break;
            }
            if self
                .u2c_lat_ns_max
                .compare_exchange(cur, lat_ns, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
    fn u2c_err(&self) {
        self.u2c_send_errs.fetch_add(1, AtomOrdering::Relaxed);
    }
}

fn dur_ns(start: Instant, end: Instant) -> u64 {
    let d = end.duration_since(start);
    d.as_nanos().min(u64::MAX as u128) as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimeoutAction {
    Drop,
    Exit,
}

fn parse_args() -> (SocketAddr, String, u64, TimeoutAction, u64, u64) {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <listen_ip:port> <upstream_host_or_ip:port> [--timeout-secs N] [--on-timeout drop|exit] [--reresolve-secs N] [--stats-interval-mins N]",
            args[0]
        );
        process::exit(2);
    }

    let listen_addr: SocketAddr = resolve_first(&args[1]).expect("bad listen addr");
    let upstream_target: String = args[2].clone();

    // Defaults
    let mut timeout_secs: u64 = 10;
    let mut action = TimeoutAction::Drop;
    let mut reresolve_secs: u64 = 0;
    let mut stats_interval_mins: u64 = 60;

    // Simple manual flag parsing
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout-secs" => {
                if i + 1 >= args.len() {
                    eprintln!("--timeout-secs requires a value");
                    process::exit(2);
                }
                timeout_secs = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("invalid timeout");
                    process::exit(2)
                });
                i += 2;
            }
            "--on-timeout" => {
                if i + 1 >= args.len() {
                    eprintln!("--on-timeout requires drop|exit");
                    process::exit(2);
                }
                action = match args[i + 1].as_str() {
                    "drop" => TimeoutAction::Drop,
                    "exit" => TimeoutAction::Exit,
                    other => {
                        eprintln!("invalid --on-timeout value: {} (use drop|exit)", other);
                        process::exit(2)
                    }
                };
                i += 2;
            }
            "--reresolve-secs" => {
                if i + 1 >= args.len() {
                    eprintln!("--reresolve-secs requires a value");
                    process::exit(2);
                }
                reresolve_secs = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("invalid reresolve secs");
                    process::exit(2)
                });
                i += 2;
            }
            "--stats-interval-mins" => {
                if i + 1 >= args.len() {
                    eprintln!("--stats-interval-mins requires a value");
                    process::exit(2);
                }
                stats_interval_mins = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("invalid stats interval");
                    process::exit(2)
                });
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {}", other);
                process::exit(2);
            }
        }
    }

    (
        listen_addr,
        upstream_target,
        timeout_secs,
        action,
        reresolve_secs,
        stats_interval_mins,
    )
}

fn main() -> io::Result<()> {
    let (listen_addr, upstream_target, timeout_secs, action, reresolve_secs, stats_interval_mins) =
        parse_args();

    // Resolve once now to decide family and have an initial destination
    let initial_upstream_addr: SocketAddr =
        resolve_first(&upstream_target).expect("bad upstream addr");
    // Shared current upstream address; will be refreshed on client lock
    let current_up_addr = Arc::new(Mutex::new(initial_upstream_addr));

    // Listener for the local client
    let client_sock = make_udp_socket(listen_addr, 250)?;

    let upstream_sock = make_upstream_socket(initial_upstream_addr)?;
    let upstream_sock = Arc::new(Mutex::new(upstream_sock));

    // Single-client state
    let client_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let locked: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    // Track last seen traffic time for the locked session (either direction).
    let last_seen: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let stats = Arc::new(Stats::new());

    println!(
        "Listening on {}, forwarding to upstream {}. Waiting for first client...",
        client_sock.local_addr()?,
        initial_upstream_addr
    );
    println!("Timeout: {}s, on-timeout: {:?}", timeout_secs, action);
    println!("Re-resolve every: {}s (0=disabled)", reresolve_secs);

    // Thread: client -> upstream
    let client_sock_a = client_sock.try_clone()?;
    let client_peer_a = Arc::clone(&client_peer);
    let locked_a = Arc::clone(&locked);
    let last_seen_a = Arc::clone(&last_seen);
    let upstream_target_a = Arc::new(upstream_target.clone());
    let current_up_addr_a = Arc::clone(&current_up_addr);
    let upstream_sock_m = Arc::clone(&upstream_sock);
    let stats_a = Arc::clone(&stats);

    let _t_up = thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            match client_sock_a.recv_from(&mut buf) {
                Ok((n, src)) => {
                    // Lock to first client
                    if !locked_a.load(AtomOrdering::SeqCst) {
                        let mut slot = client_peer_a.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(src);
                            locked_a.store(true, AtomOrdering::SeqCst);
                            *last_seen_a.lock().unwrap() = Some(Instant::now());
                            println!("Locked to single client {}", src);

                            // Re-resolve upstream target now that a client connected
                            if let Ok(fresh) = resolve_first(&upstream_target_a) {
                                apply_fresh_upstream(
                                    fresh,
                                    &current_up_addr_a,
                                    &upstream_sock_m,
                                    "Re-resolved",
                                );
                            }
                        }
                    }
                    if locked_a.load(AtomOrdering::SeqCst) {
                        let slot = client_peer_a.lock().unwrap();
                        if let Some(locked_client) = *slot {
                            if src == locked_client {
                                let t_recv = Instant::now();
                                let dest = { current_up_addr_a.lock().unwrap().clone() };
                                let sock_clone = {
                                    upstream_sock_m
                                        .lock()
                                        .unwrap()
                                        .try_clone()
                                        .expect("clone upstream socket")
                                };
                                match sock_clone.send_to(&buf[..n], dest) {
                                    Ok(_m) => {
                                        *last_seen_a.lock().unwrap() = Some(Instant::now());
                                        stats_a.add_c2u(n as u64, dur_ns(t_recv, Instant::now()));
                                    }
                                    Err(e) => {
                                        eprintln!("upstream send_to error: {}", e);
                                        stats_a.c2u_err();
                                    }
                                }
                            }
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => {
                    eprintln!("recv_from client error: {}", e);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    // Thread: upstream -> client (reply via listener socket)
    let client_sock_b = client_sock.try_clone()?;
    let client_peer_b = Arc::clone(&client_peer);
    let locked_b = Arc::clone(&locked);
    let last_seen_b = Arc::clone(&last_seen);
    let upstream_sock_m = Arc::clone(&upstream_sock);
    let stats_b = Arc::clone(&stats);

    let _t_down = thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            let sock_clone = {
                upstream_sock_m
                    .lock()
                    .unwrap()
                    .try_clone()
                    .expect("clone upstream socket")
            };
            match sock_clone.recv_from(&mut buf) {
                Ok((n, _src)) => {
                    if locked_b.load(AtomOrdering::SeqCst) {
                        if let Some(dst) = *client_peer_b.lock().unwrap() {
                            let t_recv = Instant::now();
                            if let Err(e) = client_sock_b.send_to(&buf[..n], dst) {
                                eprintln!("send_to client {} error: {}", dst, e);
                                stats_b.u2c_err();
                            } else {
                                *last_seen_b.lock().unwrap() = Some(Instant::now());
                                stats_b.add_u2c(n as u64, dur_ns(t_recv, Instant::now()));
                            }
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => {
                    eprintln!("recv_from upstream error: {}", e);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    // Watchdog: expire the locked client on idle
    let client_peer_w = Arc::clone(&client_peer);
    let locked_w = Arc::clone(&locked);
    let last_seen_w = Arc::clone(&last_seen);
    thread::spawn(move || {
        let timeout = Duration::from_secs(timeout_secs);
        loop {
            thread::sleep(Duration::from_secs(1));
            if locked_w.load(AtomOrdering::SeqCst) {
                let now = Instant::now();
                let expired = {
                    let ls = last_seen_w.lock().unwrap();
                    match *ls {
                        Some(t) => now.duration_since(t) >= timeout,
                        None => false,
                    }
                };
                if expired {
                    match action {
                        TimeoutAction::Drop => {
                            {
                                *client_peer_w.lock().unwrap() = None;
                            }
                            locked_w.store(false, AtomOrdering::SeqCst);
                            {
                                *last_seen_w.lock().unwrap() = None;
                            }
                            eprintln!(
                                "Idle timeout reached ({}s): dropped locked client; waiting for a new client",
                                timeout_secs
                            );
                        }
                        TimeoutAction::Exit => {
                            eprintln!("Idle timeout reached ({}s): exiting", timeout_secs);
                            process::exit(0);
                        }
                    }
                }
            }
        }
    });

    if reresolve_secs > 0 {
        let upstream_target_t = upstream_target.clone();
        let current_up_addr_t = Arc::clone(&current_up_addr);
        let upstream_sock_t = Arc::clone(&upstream_sock);
        let locked_t = Arc::clone(&locked);
        thread::spawn(move || {
            let period = Duration::from_secs(reresolve_secs);
            loop {
                thread::sleep(period);
                if !locked_t.load(AtomOrdering::SeqCst) {
                    continue;
                }
                if let Ok(fresh) = resolve_first(&upstream_target_t) {
                    apply_fresh_upstream(
                        fresh,
                        &current_up_addr_t,
                        &upstream_sock_t,
                        "Periodic re-resolve",
                    );
                }
            }
        });
    }

    // Stats reporter thread (prints JSON lines)
    {
        let stats_r = Arc::clone(&stats);
        let client_peer_r = Arc::clone(&client_peer);
        let current_up_addr_r = Arc::clone(&current_up_addr);
        let locked_r = Arc::clone(&locked);
        thread::spawn(move || {
            let period = Duration::from_secs(60 * stats_interval_mins.max(1));
            loop {
                thread::sleep(period);
                let uptime = stats_r.start.elapsed().as_secs();
                let c2u_pkts = stats_r.c2u_pkts.load(AtomOrdering::Relaxed);
                let c2u_bytes = stats_r.c2u_bytes.load(AtomOrdering::Relaxed);
                let c2u_errs = stats_r.c2u_send_errs.load(AtomOrdering::Relaxed);
                let u2c_pkts = stats_r.u2c_pkts.load(AtomOrdering::Relaxed);
                let u2c_bytes = stats_r.u2c_bytes.load(AtomOrdering::Relaxed);
                let u2c_errs = stats_r.u2c_send_errs.load(AtomOrdering::Relaxed);
                let c2u_lat_sum = stats_r.c2u_lat_ns_sum.load(AtomOrdering::Relaxed);
                let c2u_lat_max = stats_r.c2u_lat_ns_max.load(AtomOrdering::Relaxed);
                let u2c_lat_sum = stats_r.u2c_lat_ns_sum.load(AtomOrdering::Relaxed);
                let u2c_lat_max = stats_r.u2c_lat_ns_max.load(AtomOrdering::Relaxed);
                let c2u_avg_us = if c2u_pkts > 0 {
                    (c2u_lat_sum / c2u_pkts) / 1000
                } else {
                    0
                };
                let u2c_avg_us = if u2c_pkts > 0 {
                    (u2c_lat_sum / u2c_pkts) / 1000
                } else {
                    0
                };
                let c2u_max_us = c2u_lat_max / 1000;
                let u2c_max_us = u2c_lat_max / 1000;
                let locked_now = locked_r.load(AtomOrdering::Relaxed);
                let client_s = {
                    let c = client_peer_r.lock().unwrap();
                    c.map(|a| a.to_string())
                        .unwrap_or_else(|| "null".to_string())
                };
                let up_s = { current_up_addr_r.lock().unwrap().to_string() };
                // JSON line for easy parsing
                println!(
                    "{{\"uptime_s\":{},\"locked\":{},\"client\":\"{}\",\"upstream\":\"{}\",\"c2u_pkts\":{},\"c2u_bytes\":{},\"c2u_avg_us\":{},\"c2u_max_us\":{},\"c2u_errs\":{},\"u2c_pkts\":{},\"u2c_bytes\":{},\"u2c_avg_us\":{},\"u2c_max_us\":{},\"u2c_errs\":{}}}",
                    uptime,
                    locked_now,
                    client_s,
                    up_s,
                    c2u_pkts,
                    c2u_bytes,
                    c2u_avg_us,
                    c2u_max_us,
                    c2u_errs,
                    u2c_pkts,
                    u2c_bytes,
                    u2c_avg_us,
                    u2c_max_us,
                    u2c_errs
                );
            }
        });
    }

    // Keep main alive
    loop {
        thread::park();
    }
}
