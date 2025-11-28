#[macro_use]
mod logging;
mod cli;
mod net;
mod sock_mgr;
mod stats;

use cli::{Config, SupportedProtocol, TimeoutAction, parse_args};
use net::{make_socket, send_payload, udp_disconnect};
#[cfg(unix)]
use nix::unistd::{self, Group, User};
use sock_mgr::SocketManager;
use socket2::{SockAddr, Socket, Type};
use stats::Stats;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
use std::thread;
use std::time::{Duration, Instant};

#[inline]
fn handle_udp_disconnect(sock: &Socket, context: &str, exit_code_set: Option<&AtomicU32>) -> bool {
    match udp_disconnect(sock) {
        Ok(_) => true,
        Err(e) => {
            if let Some(exit) = exit_code_set {
                log_error!("{context}: udp disconnect failed: {}", e);
                exit.store((1 << 31) | 1, AtomOrdering::Relaxed);
            } else {
                log_warn!("{context}: udp disconnect failed: {}", e);
            }
            false
        }
    }
}

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
    sock_mgr: &SocketManager,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    stats: &Stats,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let mut handles = sock_mgr.refresh_handles();
    let mut dest_sa = SockAddr::from(handles.upstream_addr);
    let mut dest_port_id = handles.upstream_addr.port();
    // Get the client address or fill a placeholder
    let mut client_sa = handles.client_addr.map(|addr| SockAddr::from(addr));
    // Only DGRAM sockets can skip checksums, fall back to RAW
    let mut upstream_sock_type = handles.upstream_sock.r#type().unwrap_or(Type::RAW);
    loop {
        // Cheap hot-path check: only refresh when manager version changes
        if handles.version != sock_mgr.get_version() {
            handles = sock_mgr.refresh_handles();
            dest_sa = SockAddr::from(handles.upstream_addr);
            dest_port_id = handles.upstream_addr.port();
            client_sa = handles.client_addr.map(|addr| SockAddr::from(addr));
            upstream_sock_type = handles.upstream_sock.r#type().unwrap_or(Type::RAW);
        }
        if handles.client_connected {
            // Connected fast path: only packets from the locked client are delivered
            match handles.client_sock.recv(as_uninit_mut(&mut buf)) {
                Ok(len) => {
                    let t_recv = Instant::now();
                    if locked.load(AtomOrdering::Relaxed) {
                        send_payload(
                            true,
                            t_start,
                            t_recv,
                            cfg,
                            stats,
                            last_seen_ns,
                            &handles.upstream_sock,
                            &buf[..len],
                            handles.upstream_connected, // Upstream socket is always connected
                            upstream_sock_type,
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
                    log_error!("recv client (connected) error: {}", e);
                    stats.drop_err(true);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        } else {
            match handles.client_sock.recv_from(as_uninit_mut(&mut buf)) {
                Ok((len, src_sa)) => {
                    let t_recv = Instant::now();
                    // First lock: publish client and connect the socket for fast path
                    if !locked.load(AtomOrdering::Relaxed) {
                        let Some(src) = src_sa.as_socket() else {
                            log_warn!(
                                "recv_from client non-IP address family (ignored): {:?}",
                                src_sa
                            );
                            continue;
                        };

                        handles.client_connected = false;
                        if cfg.debug_no_connect {
                            log_info!("Locked to single client {} (not connected)", src);
                        } else if let Err(e) = handles.client_sock.connect(&src_sa) {
                            log_error!("connect client_sock to {} failed: {}", src, e);
                            log_info!("Locked to single client {} (not connected)", src);
                        } else {
                            handles.client_connected = true;
                            log_info!("Locked to single client {} (connected)", src);
                        }

                        // Once locked, connect client socket to the peer and switch to recv()
                        handles.version = sock_mgr.set_client_addr_connected(
                            Some(src),
                            handles.client_connected,
                            handles.version,
                        );
                        locked.store(true, AtomOrdering::Relaxed);

                        // Only refresh upstream on initial lock; keep listener stable for the new client.
                        if let Ok(new_handles) = sock_mgr
                            .reresolve(cfg.reresolve_mode.allow_upstream(), false, "Re-resolved")
                            .map(|(h, _)| h)
                        {
                            handles = new_handles;
                            dest_sa = SockAddr::from(handles.upstream_addr);
                            dest_port_id = handles.upstream_addr.port();
                            client_sa = handles.client_addr.map(|addr| SockAddr::from(addr));
                            upstream_sock_type =
                                handles.upstream_sock.r#type().unwrap_or(Type::RAW);
                        }

                        // Forward the first packet from the new client
                        send_payload(
                            true,
                            t_start,
                            t_recv,
                            cfg,
                            stats,
                            last_seen_ns,
                            &handles.upstream_sock,
                            &buf[..len],
                            handles.upstream_connected, // Upstream socket is always connected
                            upstream_sock_type,
                            &dest_sa,
                            dest_port_id,
                            cfg.listen_port_id,
                            cfg.debug_log_drops,
                        );
                    } else if Some(src_sa) == client_sa {
                        // Only forward packets from the locked client (recv_from may still deliver before connect succeeds)
                        send_payload(
                            true,
                            t_start,
                            t_recv,
                            cfg,
                            stats,
                            last_seen_ns,
                            &handles.upstream_sock,
                            &buf[..len],
                            handles.upstream_connected, // Upstream socket is always connected
                            upstream_sock_type,
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
                    log_error!("recv_from client error: {}", e);
                    stats.drop_err(true);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

fn run_upstream_to_client_thread(
    t_start: Instant,
    cfg: &Config,
    sock_mgr: &SocketManager,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    stats: &Stats,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let mut handles = sock_mgr.refresh_handles();
    let mut upstream_sock_port_id = handles.upstream_addr.port();
    // Local cache of the locked client destination for fast send
    let (mut dest_sa, mut dest_port_id) = if let Some(addr) = handles.client_addr {
        (SockAddr::from(addr), addr.port())
    } else {
        (SockAddr::from(SocketAddr::new([0, 0, 0, 0].into(), 0)), 0)
    };
    // Only DGRAM sockets can skip checksums, fall back to RAW
    let mut client_sock_type = handles.client_sock.r#type().unwrap_or(Type::RAW);
    loop {
        match handles.upstream_sock.recv(as_uninit_mut(&mut buf)) {
            Ok(len) => {
                let t_recv = Instant::now();

                // Cheap hot-path check: refresh local handles only when version changes
                if handles.version != sock_mgr.get_version() {
                    handles = sock_mgr.refresh_handles();
                    upstream_sock_port_id = handles.upstream_addr.port();
                    (dest_sa, dest_port_id) = if let Some(addr) = handles.client_addr {
                        (SockAddr::from(addr), addr.port())
                    } else {
                        (dest_sa, dest_port_id)
                    };
                    client_sock_type = handles.client_sock.r#type().unwrap_or(Type::RAW);
                }

                if locked.load(AtomOrdering::Relaxed) {
                    if !send_payload(
                        false,
                        t_start,
                        t_recv,
                        cfg,
                        stats,
                        last_seen_ns,
                        &handles.client_sock,
                        &buf[..len],
                        handles.client_connected,
                        client_sock_type,
                        &dest_sa,
                        dest_port_id,
                        upstream_sock_port_id,
                        cfg.debug_log_drops,
                    ) && handles.client_connected
                    {
                        handle_udp_disconnect(&handles.client_sock, "dest-addr-required", None);
                        handles.client_connected = false;
                        handles.version = sock_mgr.set_client_addr_connected(
                            handles.client_addr,
                            false,
                            handles.version,
                        );
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                log_error!("recv upstream (connected) error: {}", e);
                stats.drop_err(false);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn run_watchdog_thread(
    t_start: Instant,
    cfg: &Config,
    sock_mgr: &SocketManager,
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
                        log_warn!(
                            "Idle timeout reached ({}s): dropping locked client; waiting for a new client",
                            cfg.timeout_secs
                        );
                        if sock_mgr.get_client_connected() {
                            let client_sock = sock_mgr.clone_client_socket();
                            if !handle_udp_disconnect(&client_sock, "watchdog", Some(exit_code_set))
                            {
                                return;
                            }
                            sock_mgr.set_client_addr_connected(None, false, 0);
                        }
                        locked.store(false, AtomOrdering::Relaxed);
                        last_seen_ns.store(0, AtomOrdering::Relaxed);
                    }
                    _ => {
                        log_warn!(
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

fn print_startup(cfg: &Config, sock_mgr: &SocketManager) {
    let (_, _, client_proto) = { sock_mgr.get_client_dest() };
    let (upstream_addr, _, upstream_proto) = { sock_mgr.get_upstream_dest() };
    log_info!(
        "Listening on {}:{}, forwarding to upstream {}:{}; waiting for first client",
        client_proto,
        sock_mgr.get_listen_addr(),
        upstream_proto,
        upstream_addr
    );
    log_info!(
        "Timeout: {}s, on-timeout: {:?}",
        cfg.timeout_secs,
        cfg.on_timeout
    );
    log_info!("Re-resolve every: {}s (0=disabled)", cfg.reresolve_secs);
}

fn main() -> io::Result<()> {
    let t_start = Instant::now();
    let mut user_requested_cfg = parse_args();

    // FreeBSD UDP disconnect is unreliable; keep sockets unconnected so we can relock.
    #[cfg(target_os = "freebsd")]
    {
        user_requested_cfg.debug_no_connect = true;
    }

    // Listener for the local client (this may require root for low ports)
    let (client_sock, actual_listen_addr) = make_socket(
        user_requested_cfg.listen_addr,
        user_requested_cfg.listen_proto,
        1000,
        false,
        user_requested_cfg.listen_proto == SupportedProtocol::ICMP,
    )?;
    user_requested_cfg.listen_addr = actual_listen_addr;
    user_requested_cfg.listen_port_id = actual_listen_addr.port();

    let cfg = Arc::new(user_requested_cfg);

    // Initial upstream resolution + socket manager
    let sock_mgr = Arc::new(SocketManager::new(
        client_sock,
        cfg.listen_addr,
        cfg.listen_str.clone(),
        cfg.listen_proto,
        cfg.upstream_str.clone(),
        cfg.upstream_proto,
    )?);

    // Drop privileges (Unix) now that the privileged socket is bound.
    #[cfg(unix)]
    drop_privileges(&cfg)?;

    // Single-client state
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

    print_startup(&cfg, &sock_mgr);

    // Client -> Upstream
    {
        let cfg_a = Arc::clone(&cfg);
        let sock_mgr_a = Arc::clone(&sock_mgr);
        let locked_a = Arc::clone(&locked);
        let last_seen_a = Arc::clone(&last_seen_ns);
        let stats_a = Arc::clone(&stats);

        thread::spawn(move || {
            run_client_to_upstream_thread(
                t_start,
                &cfg_a,
                &sock_mgr_a,
                &locked_a,
                &last_seen_a,
                &stats_a,
            )
        });
    }

    // Upstream -> Client
    {
        let cfg_b = Arc::clone(&cfg);
        let sock_mgr_b = Arc::clone(&sock_mgr);
        let locked_b = Arc::clone(&locked);
        let last_seen_b = Arc::clone(&last_seen_ns);
        let stats_b = Arc::clone(&stats);

        thread::spawn(move || {
            run_upstream_to_client_thread(
                t_start,
                &cfg_b,
                &sock_mgr_b,
                &locked_b,
                &last_seen_b,
                &stats_b,
            )
        });
    }

    // Idle timeout watchdog
    {
        let cfg_w = Arc::clone(&cfg);
        let sock_mgr_w = Arc::clone(&sock_mgr);
        let locked_w = Arc::clone(&locked);
        let last_seen_w = Arc::clone(&last_seen_ns);
        let exit_code_set_w = Arc::clone(&exit_code_set);

        thread::spawn(move || {
            run_watchdog_thread(
                t_start,
                &cfg_w,
                &sock_mgr_w,
                &locked_w,
                &last_seen_w,
                &exit_code_set_w,
            )
        });
    }

    // Optional periodic re-resolve
    sock_mgr.spawn_periodic(
        cfg.reresolve_secs,
        cfg.reresolve_mode.allow_upstream(),
        cfg.reresolve_mode.allow_listen(),
    );

    // Stats thread
    stats.spawn_stats_printer(
        Arc::clone(&sock_mgr),
        Arc::clone(&locked),
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
            log_warn!("--user/--group specified but process is not running as root; ignoring");
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

    log_info!(
        "Dropped privileges to user '{}' (uid={}, gid={})",
        user.name,
        uid.as_raw(),
        gid.as_raw()
    );
    Ok(())
}
