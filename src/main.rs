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
    atomic::{AtomicBool, Ordering},
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimeoutAction {
    Drop,
    Exit,
}

fn parse_args() -> (SocketAddr, String, u64, TimeoutAction, u64) {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <listen_ip:port> <upstream_host_or_ip:port> [--timeout-secs N] [--on-timeout drop|exit] [--reresolve-secs N]",
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
    )
}

fn main() -> io::Result<()> {
    let (listen_addr, upstream_target, timeout_secs, action, reresolve_secs) = parse_args();

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

    let _t_up = thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            match client_sock_a.recv_from(&mut buf) {
                Ok((n, src)) => {
                    // Lock to first client
                    if !locked_a.load(Ordering::SeqCst) {
                        let mut slot = client_peer_a.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(src);
                            locked_a.store(true, Ordering::SeqCst);
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
                    if locked_a.load(Ordering::SeqCst) {
                        let slot = client_peer_a.lock().unwrap();
                        if let Some(locked_client) = *slot {
                            if src == locked_client {
                                let dest = { current_up_addr_a.lock().unwrap().clone() };
                                let sock_clone = {
                                    upstream_sock_m
                                        .lock()
                                        .unwrap()
                                        .try_clone()
                                        .expect("clone upstream socket")
                                };
                                if let Err(e) = sock_clone.send_to(&buf[..n], dest) {
                                    eprintln!("upstream send_to error: {}", e);
                                } else {
                                    *last_seen_a.lock().unwrap() = Some(Instant::now());
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
                    if locked_b.load(Ordering::SeqCst) {
                        if let Some(dst) = *client_peer_b.lock().unwrap() {
                            if let Err(e) = client_sock_b.send_to(&buf[..n], dst) {
                                eprintln!("send_to client {} error: {}", dst, e);
                            } else {
                                *last_seen_b.lock().unwrap() = Some(Instant::now());
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
            if locked_w.load(Ordering::SeqCst) {
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
                            locked_w.store(false, Ordering::SeqCst);
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
                if !locked_t.load(Ordering::SeqCst) {
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

    // Keep main alive
    loop {
        thread::park();
    }
}
