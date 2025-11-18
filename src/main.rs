mod cli;
mod net;
mod stats;
mod upstream;

use cli::{Config, SupportedProtocol, TimeoutAction, parse_args};
use net::{make_socket, send_payload, udp_disconnect};
#[cfg(unix)]
use nix::unistd::{self, Group, User};
use socket2::{SockAddr, Socket, Type};
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
    cfg: &Config,
    client_sock: &Socket,
    client_peer_connected: &Mutex<Option<(SocketAddr, bool)>>,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    upstream_mgr: &UpstreamManager,
    stats: &Stats,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let (mut up_sock, mut dest, mut ver) = upstream_mgr.refresh_handles();
    let mut dest_sa = SockAddr::from(dest);
    let mut dest_port_id = dest.port();
    // Only DGRAM sockets can skip checksums, fall back to RAW
    let mut up_sock_type = up_sock.r#type().unwrap_or(Type::RAW);
    // Once locked, connect client socket to the peer and switch to recv()
    let mut local_unconnected_client: Option<SocketAddr> = Some(cfg.listen_addr);
    loop {
        // Cheap hot-path check: only refresh when manager version changes
        if ver != upstream_mgr.version() {
            (up_sock, dest, ver) = upstream_mgr.refresh_handles();
            dest_sa = SockAddr::from(dest);
            dest_port_id = dest.port();
            up_sock_type = up_sock.r#type().unwrap_or(Type::RAW);
        }
        if local_unconnected_client.is_none() {
            // Connected fast path: only packets from the locked client are delivered
            match client_sock.recv(as_uninit_mut(&mut buf)) {
                Ok(len) => {
                    let t_recv = Instant::now();
                    if !locked.load(AtomOrdering::Relaxed) {
                        local_unconnected_client = Some(cfg.listen_addr);
                    } else {
                        send_payload(
                            true,
                            t_start,
                            t_recv,
                            cfg,
                            stats,
                            last_seen_ns,
                            &up_sock,
                            &buf[..len],
                            true, // Upstream socket is always connected
                            up_sock_type,
                            dest,
                            &dest_sa,
                            dest_port_id,
                            cfg.listen_port_id,
                            cfg.debug_log_drops,
                        );
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
                        if cfg.debug_no_connect {
                            println!("Locked to single client {} (not connected)", src);
                        } else if let Err(e) = client_sock.connect(&src_sa) {
                            eprintln!("connect client_sock to {} failed: {}", src, e);
                            println!("Locked to single client {} (not connected)", src);
                        } else {
                            local_unconnected_client = None;
                            println!("Locked to single client {} (connected)", src);
                        }
                        *client_peer_connected.lock().unwrap() =
                            Some((src, local_unconnected_client.is_none()));
                        locked.store(true, AtomOrdering::Relaxed);
                        if let Ok((new_sock, new_dest, new_ver)) =
                            upstream_mgr.apply_fresh(&cfg.upstream_addr, "Re-resolved")
                        {
                            up_sock = new_sock;
                            dest = new_dest;
                            ver = new_ver;
                            dest_sa = SockAddr::from(dest);
                            dest_port_id = dest.port();
                            up_sock_type = up_sock.r#type().unwrap_or(Type::RAW);
                        }
                    }

                    // Only forward packets from the locked client (recv_from may still deliver before connect succeeds)
                    if Some(src) == local_unconnected_client || local_unconnected_client.is_none() {
                        send_payload(
                            true,
                            t_start,
                            t_recv,
                            cfg,
                            stats,
                            last_seen_ns,
                            &up_sock,
                            &buf[..len],
                            true, // Upstream socket is always connected
                            up_sock_type,
                            dest,
                            &dest_sa,
                            dest_port_id,
                            cfg.listen_port_id,
                            cfg.debug_log_drops,
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
    cfg: &Config,
    client_sock: &Socket,
    client_peer_connected: &Mutex<Option<(SocketAddr, bool)>>,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    upstream_mgr: &UpstreamManager,
    stats: &Stats,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let (mut up_sock, mut up_sock_addr, mut ver) = upstream_mgr.refresh_handles();
    let mut up_sock_port_id = up_sock_addr.port();
    // Only DGRAM sockets can skip checksums, fall back to RAW
    let client_sock_type = client_sock.r#type().unwrap_or(Type::RAW);
    // Local cache of the locked client destination for fast send
    let mut local_dest: Option<(SocketAddr, SockAddr, u16, bool)> = None;
    loop {
        // Cheap hot-path check: refresh local handles only when version changes
        if ver != upstream_mgr.version() {
            (up_sock, up_sock_addr, ver) = upstream_mgr.refresh_handles();
            up_sock_port_id = up_sock_addr.port();
        }
        match up_sock.recv(as_uninit_mut(&mut buf)) {
            Ok(len) => {
                let t_recv = Instant::now();
                // Refresh local cached destination when global lock state changes
                if !locked.load(AtomOrdering::Relaxed) {
                    local_dest = None;
                } else if let Some((dest, dest_sa, dest_port_id, dest_connected)) =
                    local_dest.as_ref()
                {
                    send_payload(
                        false,
                        t_start,
                        t_recv,
                        cfg,
                        stats,
                        last_seen_ns,
                        client_sock,
                        &buf[..len],
                        *dest_connected,
                        client_sock_type,
                        *dest,
                        &dest_sa,
                        *dest_port_id,
                        up_sock_port_id,
                        cfg.debug_log_drops,
                    );
                } else if let Some((dest, connected)) = *client_peer_connected.lock().unwrap() {
                    let dest_sa = SockAddr::from(dest);
                    let dest_port_id = dest.port();
                    let dest_connected = connected;

                    send_payload(
                        false,
                        t_start,
                        t_recv,
                        cfg,
                        stats,
                        last_seen_ns,
                        client_sock,
                        &buf[..len],
                        dest_connected,
                        client_sock_type,
                        dest,
                        &dest_sa,
                        dest_port_id,
                        up_sock_port_id,
                        cfg.debug_log_drops,
                    );

                    local_dest = Some((dest, dest_sa, dest_port_id, dest_connected));
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if !locked.load(AtomOrdering::Relaxed) {
                    local_dest = None;
                }
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
    cfg: &Config,
    client_sock: &Socket,
    client_peer_connected: &Mutex<Option<(SocketAddr, bool)>>,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    exit_code_set: &AtomicU32,
) {
    let timeout_ns = Duration::from_secs(cfg.timeout_secs)
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
                match cfg.on_timeout {
                    TimeoutAction::Drop => {
                        let mut guard = client_peer_connected.lock().unwrap();
                        let was_connected = guard
                            .as_ref()
                            .map(|(_, connected)| *connected)
                            .unwrap_or(false);
                        eprintln!(
                            "Idle timeout reached ({}s): dropping locked client; waiting for a new client",
                            cfg.timeout_secs
                        );
                        if was_connected {
                            if let Err(e) = udp_disconnect(&client_sock) {
                                eprintln!("udp disconnect failed: {}", e);
                                exit_code_set.store((1 << 31) | 1, AtomOrdering::Relaxed);
                                return;
                            }
                        }
                        *guard = None;
                        locked.store(false, AtomOrdering::Relaxed);
                        last_seen_ns.store(0, AtomOrdering::Relaxed);
                    }
                    _ => {
                        eprintln!(
                            "Idle timeout reached ({}s): exiting cleanly",
                            cfg.timeout_secs
                        );
                        exit_code_set.store(1 << 31, AtomOrdering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}

fn print_startup(local_bind: SocketAddr, upstream_mgr: &UpstreamManager, cfg: &Config) {
    let (upstream_addr, upstream_proto) = { upstream_mgr.current_dest() };
    println!(
        "Listening on {}:{}, forwarding to upstream {}:{}. Waiting for first client...",
        cfg.listen_proto, local_bind, upstream_proto, upstream_addr
    );
    println!(
        "Timeout: {}s, on-timeout: {:?}",
        cfg.timeout_secs, cfg.on_timeout
    );
    println!("Re-resolve every: {}s (0=disabled)", cfg.reresolve_secs);
}

fn main() -> io::Result<()> {
    let t_start = Instant::now();
    let mut user_requested_cfg = parse_args();

    // Listener for the local client (this may require root for low ports)
    let (client_sock_raw, actual_listen) = make_socket(
        user_requested_cfg.listen_addr,
        user_requested_cfg.listen_proto,
        1000,
        false,
        user_requested_cfg.listen_proto == SupportedProtocol::ICMP,
    )?;
    user_requested_cfg.listen_addr = actual_listen;
    user_requested_cfg.listen_port_id = actual_listen.port();
    let client_sock = Arc::new(client_sock_raw);

    let cfg = Arc::new(user_requested_cfg);

    // Initial upstream resolution + manager
    let upstream_mgr = Arc::new(UpstreamManager::new(
        &cfg.upstream_addr,
        cfg.upstream_proto,
    )?);

    // Drop privileges (Unix) now that the privileged socket is bound.
    #[cfg(unix)]
    drop_privileges(&cfg)?;

    // Single-client state
    let client_peer_connected = Arc::new(Mutex::new(None));
    let locked = Arc::new(AtomicBool::new(false));
    let last_seen_ns = Arc::new(AtomicU64::new(0));

    let stats = Arc::new(Stats::new());
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
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("ctrlc::set_handler failed: {e}"),
            )
        })?;
    }

    print_startup(cfg.listen_addr, &upstream_mgr, &cfg);

    // Client -> Upstream
    {
        let cfg_a = Arc::clone(&cfg);
        let client_sock_a = Arc::clone(&client_sock);
        let client_peer_a = Arc::clone(&client_peer_connected);
        let locked_a = Arc::clone(&locked);
        let last_seen_a = Arc::clone(&last_seen_ns);
        let upstream_mgr_a = Arc::clone(&upstream_mgr);
        let stats_a = Arc::clone(&stats);

        thread::spawn(move || {
            run_client_to_upstream_thread(
                t_start,
                &cfg_a,
                &client_sock_a,
                &client_peer_a,
                &locked_a,
                &last_seen_a,
                &upstream_mgr_a,
                &stats_a,
            )
        });
    }

    // Upstream -> Client
    {
        let cfg_b = Arc::clone(&cfg);
        let client_sock_b = Arc::clone(&client_sock);
        let client_peer_b = Arc::clone(&client_peer_connected);
        let locked_b = Arc::clone(&locked);
        let last_seen_b = Arc::clone(&last_seen_ns);
        let upstream_mgr_b = Arc::clone(&upstream_mgr);
        let stats_b = Arc::clone(&stats);

        thread::spawn(move || {
            run_upstream_to_client_thread(
                t_start,
                &cfg_b,
                &client_sock_b,
                &client_peer_b,
                &locked_b,
                &last_seen_b,
                &upstream_mgr_b,
                &stats_b,
            )
        });
    }

    // Idle timeout watchdog
    {
        let cfg_w = Arc::clone(&cfg);
        let client_sock_w = Arc::clone(&client_sock);
        let client_peer_w = Arc::clone(&client_peer_connected);
        let locked_w = Arc::clone(&locked);
        let last_seen_w = Arc::clone(&last_seen_ns);
        let exit_code_set_w = Arc::clone(&exit_code_set);

        thread::spawn(move || {
            run_watchdog_thread(
                t_start,
                &cfg_w,
                &client_sock_w,
                &client_peer_w,
                &locked_w,
                &last_seen_w,
                &exit_code_set_w,
            )
        });
    }

    // Optional periodic re-resolve
    upstream_mgr.spawn_periodic(Arc::clone(&cfg), Arc::clone(&locked));

    // Stats thread
    stats.spawn_stats_printer(
        cfg.listen_proto,
        Arc::clone(&client_peer_connected),
        Arc::clone(&upstream_mgr),
        t_start,
        u64::from(cfg.stats_interval_mins).saturating_mul(60),
        Arc::clone(&exit_code_set),
    );

    // Keep main alive
    loop {
        thread::park();
    }
}

#[cfg(unix)]
fn drop_privileges(cfg: &Config) -> io::Result<()> {
    if !unistd::geteuid().is_root() {
        // Not root: ignore any requested run-as flags.
        if cfg.run_as_user.is_some() || cfg.run_as_group.is_some() {
            eprintln!(
                "Warning: --user/--group specified but process is not running as root; ignoring"
            );
        }
        return Ok(());
    }

    let user_name = cfg.run_as_user.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "must specify --user when running as root",
        )
    })?;

    let user = User::from_name(user_name)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("user lookup failed for {user_name}: {e}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, format!("user {user_name} not found"))
        })?;

    // Determine primary group: explicit --group overrides user's primary group.
    let primary_gid = if let Some(group_name) = cfg.run_as_group.as_ref() {
        let grp = Group::from_name(group_name)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("group lookup failed for {group_name}: {e}"),
                )
            })?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("group {group_name} not found"),
                )
            })?;
        grp.gid
    } else {
        user.gid
    };

    let uid = user.uid;
    let gid = primary_gid;

    // Drop supplementary groups entirely to avoid retaining root-level groups.
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        // This function is not available on Apple platforms.
        let empty: &[nix::unistd::Gid] = &[];
        unistd::setgroups(empty)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("setgroups failed: {e}")))?;
    }

    // Order: primary gid -> uid
    unistd::setgid(gid)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("setgid failed: {e}")))?;
    unistd::setuid(uid)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("setuid failed: {e}")))?;

    println!(
        "Dropped privileges to user '{}' (uid={}, gid={})",
        user.name,
        uid.as_raw(),
        gid.as_raw()
    );
    Ok(())
}
