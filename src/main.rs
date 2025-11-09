mod cli;
mod net;
mod stats;
mod upstream;

use cli::{TimeoutAction, parse_args};
use net::{make_udp_socket, resolve_first, send_payload, udp_disconnect};
use socket2::Socket;
use stats::Stats;
use upstream::UpstreamManager;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[inline]
fn as_uninit_mut(buf: &mut [u8]) -> &mut [std::mem::MaybeUninit<u8>] {
    // Safety: socket2::Socket::recv/recv_from promise not to write uninitialised bytes past what they return.
    unsafe {
        std::slice::from_raw_parts_mut(
            buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
            buf.len(),
        )
    }
}

fn run_client_to_upstream_thread(
    t_start: Instant,
    cfg_listen_addr: SocketAddr,
    max_payload: usize,
    client_sock: Arc<Socket>,
    client_peer: Arc<Mutex<Option<SocketAddr>>>,
    locked: Arc<AtomicBool>,
    last_seen_ns: Arc<AtomicU64>,
    upstream_mgr: Arc<UpstreamManager>,
    upstream_target: String,
    stats: Arc<Stats>,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let (mut up_sock, mut dest, mut ver) = upstream_mgr.refresh_handles();
    // Once locked, connect client socket to the peer and switch to recv()
    let mut local_unconnected_client: Option<SocketAddr> = Some(cfg_listen_addr);
    loop {
        // Cheap hot-path check: only refresh when manager version changes
        if ver != upstream_mgr.version() {
            (up_sock, dest, ver) = upstream_mgr.refresh_handles();
        }
        if local_unconnected_client.is_none() {
            // Connected fast path: only packets from the locked client are delivered
            match client_sock.recv(as_uninit_mut(&mut buf)) {
                Ok(len) => {
                    let t_recv = Instant::now();
                    if locked.load(AtomOrdering::Relaxed) {
                        send_payload(
                            true,
                            true,
                            t_start,
                            t_recv,
                            max_payload,
                            &stats,
                            &last_seen_ns,
                            &up_sock,
                            &buf,
                            len,
                            dest,
                        );
                    } else {
                        local_unconnected_client = Some(cfg_listen_addr);
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => {
                    eprintln!("recv client (connected) error: {}", e);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        } else {
            match client_sock.recv_from(as_uninit_mut(&mut buf)) {
                Ok((len, src_sa)) => {
                    let t_recv = Instant::now();
                    let Some(src) = src_sa.as_socket() else {
                        eprintln!(
                            "recv_from client non-IP address family (ignored): {:?}",
                            src_sa
                        );
                        continue;
                    };
                    // First lock: publish client and connect the socket for fast path
                    if !locked.load(AtomOrdering::Relaxed) {
                        local_unconnected_client = Some(src);
                        *client_peer.lock().unwrap() = Some(src);
                        locked.store(true, AtomOrdering::Relaxed);
                        if let Err(e) = client_sock.connect(&src_sa) {
                            eprintln!("connect client_sock to {} failed: {}", src, e);
                        } else {
                            local_unconnected_client = None;
                            println!("Locked to single client {} (connected)", src);
                        }
                        if let Ok((new_sock, new_dest, new_ver)) =
                            upstream_mgr.apply_fresh(&upstream_target, "Re-resolved")
                        {
                            up_sock = new_sock;
                            dest = new_dest;
                            ver = new_ver;
                        }
                    }

                    // Only forward packets from the locked client (recv_from may still deliver before connect succeeds)
                    if Some(src) == local_unconnected_client || local_unconnected_client.is_none() {
                        send_payload(
                            true,
                            local_unconnected_client.is_none(),
                            t_start,
                            t_recv,
                            max_payload,
                            &stats,
                            &last_seen_ns,
                            &up_sock,
                            &buf,
                            len,
                            dest,
                        );
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
    }
}

fn run_upstream_to_client_thread(
    t_start: Instant,
    max_payload: usize,
    client_sock: Arc<Socket>,
    client_peer: Arc<Mutex<Option<SocketAddr>>>,
    locked: Arc<AtomicBool>,
    last_seen_ns: Arc<AtomicU64>,
    upstream_mgr: Arc<UpstreamManager>,
    stats: Arc<Stats>,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let (mut up_sock, _, mut ver) = upstream_mgr.refresh_handles();
    // Local cache of the locked client destination for fast send
    let mut local_dest: Option<SocketAddr> = None;
    loop {
        // Cheap hot-path check: refresh local handles only when version changes
        if ver != upstream_mgr.version() {
            (up_sock, _, ver) = upstream_mgr.refresh_handles();
        }
        match up_sock.recv(as_uninit_mut(&mut buf)) {
            Ok(len) => {
                let t_recv = Instant::now();
                // Refresh local cached destination when global lock state changes
                if !locked.load(AtomOrdering::Relaxed) {
                    local_dest = None;
                } else if let Some(dest) = local_dest.or_else(|| {
                    let v = *client_peer.lock().unwrap();
                    local_dest = v;
                    v
                }) {
                    send_payload(
                        false,
                        true,
                        t_start,
                        t_recv,
                        max_payload,
                        &stats,
                        &last_seen_ns,
                        &client_sock,
                        &buf,
                        len,
                        dest,
                    );
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                eprintln!("recv upstream (connected) error: {}", e);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn run_watchdog_thread(
    t_start: Instant,
    timeout_secs: u64,
    on_timeout: TimeoutAction,
    client_sock: Arc<Socket>,
    client_peer: Arc<Mutex<Option<SocketAddr>>>,
    locked: Arc<AtomicBool>,
    last_seen_ns: Arc<AtomicU64>,
    exit_code_set: Arc<AtomicU32>,
) {
    let timeout_ns = Duration::from_secs(timeout_secs)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    loop {
        thread::sleep(Duration::from_secs(1));
        if locked.load(AtomOrdering::Relaxed) {
            let now = Instant::now();
            let now_ns = Stats::dur_ns(t_start, now);
            let last_ns = last_seen_ns.load(AtomOrdering::Relaxed);
            let expired = last_ns != 0 && now_ns.saturating_sub(last_ns) >= timeout_ns;
            if expired {
                match on_timeout {
                    TimeoutAction::Drop => {
                        eprintln!(
                            "Idle timeout reached ({}s): dropping locked client; waiting for a new client",
                            timeout_secs
                        );
                        if let Err(e) = udp_disconnect(&client_sock) {
                            eprintln!("udp disconnect failed: {}", e);
                            exit_code_set.store((1 << 31) | 1, AtomOrdering::Relaxed);
                            return;
                        }
                        *client_peer.lock().unwrap() = None;
                        locked.store(false, AtomOrdering::Relaxed);
                        last_seen_ns.store(0, AtomOrdering::Relaxed);
                    }
                    TimeoutAction::Exit => {
                        eprintln!("Idle timeout reached ({}s): exiting cleanly", timeout_secs);
                        exit_code_set.store(1 << 31, AtomOrdering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}

fn main() -> io::Result<()> {
    let cfg = parse_args();
    let t_start = Instant::now();

    // Initial upstream resolution + manager
    let initial_up = resolve_first(&cfg.upstream_target).expect("bad upstream addr");
    let upstream_mgr =
        Arc::new(UpstreamManager::new(&cfg.upstream_target).expect("upstream socket"));

    // Listener for the local client
    let client_sock = Arc::new(make_udp_socket(cfg.listen_addr, 5000, false)?);

    // Single-client state
    let client_peer = Arc::new(Mutex::new(None));
    let locked = Arc::new(AtomicBool::new(false));
    let last_seen_ns = Arc::new(AtomicU64::new(0));

    let stats = Stats::new();
    let exit_code_set = Arc::new(AtomicU32::new(0));

    // Graceful shutdown on Ctrl-C / SIGINT (and SIGTERM on Unix via ctrlc)
    {
        let exit_code_set_c = Arc::clone(&exit_code_set);

        // Exit code 130 is the conventional code for SIGINT (128 + SIGINT)
        const SIGINT_EXIT: u32 = (1 << 31) | 130;
        ctrlc::set_handler(move || {
            // Signal the main loop to exit with code 130
            exit_code_set_c.store(SIGINT_EXIT, AtomOrdering::Relaxed);
        })
        .expect("failed to set Ctrl-C handler");
    }

    let local_bind = client_sock.local_addr()?;
    let local_str = match local_bind.as_socket() {
        Some(sa) => sa.to_string(),
        None => format!("{:?}", local_bind),
    };
    println!(
        "Listening on {}, forwarding to upstream {}. Waiting for first client...",
        local_str, initial_up
    );
    println!(
        "Timeout: {}s, on-timeout: {:?}",
        cfg.timeout_secs, cfg.on_timeout
    );
    println!("Re-resolve every: {}s (0=disabled)", cfg.reresolve_secs);

    // Client -> Upstream
    {
        let client_sock_a = Arc::clone(&client_sock);
        let client_peer_a = Arc::clone(&client_peer);
        let locked_a = Arc::clone(&locked);
        let last_seen_a = Arc::clone(&last_seen_ns);
        let upstream_mgr_a = Arc::clone(&upstream_mgr);
        let upstream_target_a = cfg.upstream_target.clone();
        let stats_a = Arc::clone(&stats);

        thread::spawn(move || {
            run_client_to_upstream_thread(
                t_start,
                cfg.listen_addr,
                cfg.max_payload,
                client_sock_a,
                client_peer_a,
                locked_a,
                last_seen_a,
                upstream_mgr_a,
                upstream_target_a,
                stats_a,
            )
        });
    }

    // Upstream -> Client
    {
        let client_sock_b = Arc::clone(&client_sock);
        let client_peer_b = Arc::clone(&client_peer);
        let locked_b = Arc::clone(&locked);
        let last_seen_b = Arc::clone(&last_seen_ns);
        let upstream_mgr_b = Arc::clone(&upstream_mgr);
        let stats_b = Arc::clone(&stats);

        thread::spawn(move || {
            run_upstream_to_client_thread(
                t_start,
                cfg.max_payload,
                client_sock_b,
                client_peer_b,
                locked_b,
                last_seen_b,
                upstream_mgr_b,
                stats_b,
            )
        });
    }

    // Idle timeout watchdog
    {
        let client_sock_w = Arc::clone(&client_sock);
        let client_peer_w = Arc::clone(&client_peer);
        let locked_w = Arc::clone(&locked);
        let last_seen_w = Arc::clone(&last_seen_ns);
        let exit_code_set_w = Arc::clone(&exit_code_set);

        thread::spawn(move || {
            run_watchdog_thread(
                t_start,
                cfg.timeout_secs,
                cfg.on_timeout,
                client_sock_w,
                client_peer_w,
                locked_w,
                last_seen_w,
                exit_code_set_w,
            )
        });
    }

    // Optional periodic re-resolve
    upstream_mgr.spawn_periodic(
        cfg.upstream_target.clone(),
        cfg.reresolve_secs,
        Arc::clone(&locked),
    );

    // Stats thread
    stats.spawn_stats_printer(
        Arc::clone(&client_peer),
        Arc::clone(&upstream_mgr),
        u64::from(cfg.stats_interval_mins).saturating_mul(60),
        Arc::clone(&exit_code_set),
    );

    // Keep main alive
    loop {
        thread::park();
    }
}
