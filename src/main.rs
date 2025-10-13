mod cli;
mod net;
mod stats;
mod upstream;

use cli::{TimeoutAction, parse_args};
use net::{make_udp_socket, resolve_first};
use stats::{Stats, dur_ns, spawn_stats_printer};
use upstream::UpstreamManager;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> io::Result<()> {
    let cfg = parse_args();

    // Initial upstream resolution + manager
    let initial_up = resolve_first(&cfg.upstream_target).expect("bad upstream addr");
    let upstream_mgr =
        Arc::new(UpstreamManager::new(&cfg.upstream_target).expect("upstream socket"));

    // Listener for the local client
    let client_sock = make_udp_socket(cfg.listen_addr, 250)?;

    // Single-client state
    let client_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let locked = Arc::new(AtomicBool::new(false));
    let last_seen: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let stats = Stats::new();

    println!(
        "Listening on {}, forwarding to upstream {}. Waiting for first client...",
        client_sock.local_addr()?,
        initial_up
    );
    println!(
        "Timeout: {}s, on-timeout: {:?}",
        cfg.timeout_secs, cfg.on_timeout
    );
    println!("Re-resolve every: {}s (0=disabled)", cfg.reresolve_secs);

    // Client -> Upstream
    {
        let client_sock_a = client_sock.try_clone()?;
        let client_peer_a = Arc::clone(&client_peer);
        let locked_a = Arc::clone(&locked);
        let last_seen_a = Arc::clone(&last_seen);
        let upstream_mgr_a = Arc::clone(&upstream_mgr);
        let upstream_target_a = cfg.upstream_target.clone();
        let stats_a = Arc::clone(&stats);

        thread::spawn(move || {
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
                                upstream_mgr_a.apply_fresh(&upstream_target_a, "Re-resolved");
                            }
                        }
                        if locked_a.load(AtomOrdering::SeqCst) {
                            let slot = client_peer_a.lock().unwrap();
                            if let Some(locked_client) = *slot {
                                if src == locked_client {
                                    let t_recv = Instant::now();
                                    let dest = upstream_mgr_a.current_dest();
                                    let sock = upstream_mgr_a.clone_socket();
                                    match sock.send_to(&buf[..n], dest) {
                                        Ok(_) => {
                                            *last_seen_a.lock().unwrap() = Some(Instant::now());
                                            stats_a
                                                .add_c2u(n as u64, dur_ns(t_recv, Instant::now()));
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
    }

    // Upstream -> Client
    {
        let client_sock_b = client_sock.try_clone()?;
        let client_peer_b = Arc::clone(&client_peer);
        let locked_b = Arc::clone(&locked);
        let last_seen_b = Arc::clone(&last_seen);
        let upstream_mgr_b = Arc::clone(&upstream_mgr);
        let stats_b = Arc::clone(&stats);

        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            loop {
                let sock = upstream_mgr_b.clone_socket();
                match sock.recv_from(&mut buf) {
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
    }

    // Idle timeout watchdog
    {
        let client_peer_w = Arc::clone(&client_peer);
        let locked_w = Arc::clone(&locked);
        let last_seen_w = Arc::clone(&last_seen);
        thread::spawn(move || {
            let timeout = Duration::from_secs(cfg.timeout_secs);
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
                        match cfg.on_timeout {
                            TimeoutAction::Drop => {
                                *client_peer_w.lock().unwrap() = None;
                                locked_w.store(false, AtomOrdering::SeqCst);
                                *last_seen_w.lock().unwrap() = None;
                                eprintln!(
                                    "Idle timeout reached ({}s): dropped locked client; waiting for a new client",
                                    cfg.timeout_secs
                                );
                            }
                            TimeoutAction::Exit => {
                                eprintln!("Idle timeout reached ({}s): exiting", cfg.timeout_secs);
                                std::process::exit(0);
                            }
                        }
                    }
                }
            }
        });
    }

    // Optional periodic re-resolve
    upstream_mgr.spawn_periodic(
        cfg.upstream_target.clone(),
        cfg.reresolve_secs,
        Arc::clone(&locked),
    );

    // Stats thread
    spawn_stats_printer(
        Arc::clone(&stats),
        Arc::clone(&client_peer),
        Arc::clone(&upstream_mgr.current_addr),
        Arc::clone(&locked),
        u64::from(cfg.stats_interval_mins) * 60,
    );

    // Keep main alive
    loop {
        thread::park();
    }
}
