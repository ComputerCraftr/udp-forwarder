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
use sock_mgr::{SocketHandles, SocketManager};
use socket2::{SockAddr, Socket, Type};
use stats::Stats;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
use std::thread;
use std::time::{Duration, Instant};

#[inline]
fn handle_udp_disconnect(
    sock_mgr_opt: Option<&SocketManager>,
    sock_opt: Option<&Socket>,
    context: &str,
    exit_code_set: Option<&AtomicU32>,
) -> bool {
    let res = if let Some(sock_mgr) = sock_mgr_opt {
        sock_mgr.set_client_sock_disconnected()
    } else if let Some(sock) = sock_opt {
        udp_disconnect(sock)
    } else {
        return false;
    };

    match res {
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

struct CachedClientState {
    c2u: bool,
    client_sa: Option<SockAddr>,
    dest_sock_type: Type,
    dest_sa: SockAddr,
    dest_port_id: u16,
    recv_port_id: u16,
}

impl CachedClientState {
    fn new(c2u: bool, handles: &SocketHandles, recv_port_id: u16) -> Self {
        if c2u {
            Self {
                c2u,
                client_sa: handles.client_addr.map(|addr| SockAddr::from(addr)),
                dest_sock_type: handles.upstream_sock.r#type().unwrap_or(Type::RAW),
                dest_sa: SockAddr::from(handles.upstream_addr),
                dest_port_id: handles.upstream_addr.port(),
                recv_port_id,
            }
        } else {
            let (dest_sa, dest_port_id) = handles
                .client_addr
                .map(|addr| (SockAddr::from(addr), addr.port()))
                .unwrap_or_else(|| {
                    (
                        SockAddr::from(SocketAddr::new([0, 0, 0, 0].into(), 0)),
                        0u16,
                    )
                });
            Self {
                c2u,
                client_sa: None,
                dest_sock_type: handles.client_sock.r#type().unwrap_or(Type::RAW),
                dest_sa,
                dest_port_id,
                recv_port_id,
            }
        }
    }

    fn refresh_from_handles(&mut self, handles: &SocketHandles) {
        if self.c2u {
            self.client_sa = handles.client_addr.map(|addr| SockAddr::from(addr));
            self.dest_sock_type = handles.upstream_sock.r#type().unwrap_or(Type::RAW);
            self.dest_sa = SockAddr::from(handles.upstream_addr);
            self.dest_port_id = handles.upstream_addr.port();
        } else {
            self.dest_sock_type = handles.client_sock.r#type().unwrap_or(Type::RAW);
            (self.dest_sa, self.dest_port_id) = handles
                .client_addr
                .map(|addr| (SockAddr::from(addr), addr.port()))
                .unwrap_or_else(|| (self.dest_sa.clone(), self.dest_port_id));
            self.recv_port_id = handles.upstream_addr.port();
        }
    }

    #[inline]
    fn refresh_handles_and_cache(&mut self, sock_mgr: &SocketManager, handles: &mut SocketHandles) {
        if handles.version != sock_mgr.get_version() {
            *handles = sock_mgr.refresh_handles();
            self.refresh_from_handles(handles);
        }
    }
}

fn run_client_to_upstream_thread(
    t_start: Instant,
    cfg: &Config,
    sock_mgr: &SocketManager,
    all_sock_mgrs: &[Arc<SocketManager>],
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    stats: &Stats,
) {
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let mut handles = sock_mgr.refresh_handles();
    let mut cache = CachedClientState::new(true, &handles, cfg.listen_port_id);
    loop {
        // Cheap hot-path check: only refresh when manager version changes
        cache.refresh_handles_and_cache(sock_mgr, &mut handles);
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
                            handles.upstream_connected,
                            cache.dest_sock_type,
                            &cache.dest_sa,
                            cache.dest_port_id,
                            cache.recv_port_id,
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

                        // Signal to other threads that a client is currently being locked
                        locked.store(true, AtomOrdering::Relaxed);
                        cache.client_sa = Some(SockAddr::from(src));
                        let addr_opt = Some(src);

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

                        // Publish lock state to all workers so their sockets connect to the client.
                        handles.version = sock_mgr.set_client_addr_connected(
                            addr_opt,
                            handles.client_connected,
                            handles.version,
                        );

                        // Propagate client connection to workers
                        for mgr in all_sock_mgrs {
                            if !std::ptr::eq(mgr.as_ref(), sock_mgr) {
                                mgr.set_client_addr_connected(
                                    addr_opt,
                                    handles.client_connected,
                                    0,
                                );
                            }
                        }

                        // Only refresh upstream on initial lock; keep listener stable for the new client.
                        if let Ok(new_handles) = sock_mgr.reresolve(
                            cfg.reresolve_mode.allow_upstream(),
                            false,
                            "Re-resolved",
                        ) {
                            handles = new_handles;
                            cache.refresh_from_handles(&handles);
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
                            handles.upstream_connected,
                            cache.dest_sock_type,
                            &cache.dest_sa,
                            cache.dest_port_id,
                            cache.recv_port_id,
                            cfg.debug_log_drops,
                        );
                    } else if Some(src_sa) == cache.client_sa {
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
                            handles.upstream_connected,
                            cache.dest_sock_type,
                            &cache.dest_sa,
                            cache.dest_port_id,
                            cache.recv_port_id,
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
    let mut cache = CachedClientState::new(false, &handles, handles.upstream_addr.port());
    loop {
        match handles.upstream_sock.recv(as_uninit_mut(&mut buf)) {
            Ok(len) => {
                let t_recv = Instant::now();

                // Cheap hot-path check: refresh local handles only when version changes
                cache.refresh_handles_and_cache(sock_mgr, &mut handles);

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
                        cache.dest_sock_type,
                        &cache.dest_sa,
                        cache.dest_port_id,
                        cache.recv_port_id,
                        cfg.debug_log_drops,
                    ) && handles.client_connected
                    {
                        handle_udp_disconnect(
                            None,
                            Some(&handles.client_sock),
                            "dest-addr-required",
                            None,
                        );
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
    sock_mgrs: &[Arc<SocketManager>],
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    exit_code_set: &AtomicU32,
) {
    let timeout_ns = Duration::from_secs(cfg.timeout_secs)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let period = Duration::from_secs(1);
    loop {
        thread::sleep(period);
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
                        for sock_mgr in sock_mgrs {
                            if sock_mgr.get_client_connected() {
                                if !handle_udp_disconnect(
                                    Some(&sock_mgr),
                                    None,
                                    "watchdog",
                                    Some(exit_code_set),
                                ) {
                                    return;
                                }
                                sock_mgr.set_client_addr_connected(None, false, 0);
                            }
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

fn run_reresolve_thread(
    sock_mgrs: &[Arc<SocketManager>],
    reresolve_secs: u64,
    allow_upstream: bool,
    allow_listen_rebind: bool,
) {
    let period = Duration::from_secs(reresolve_secs);
    loop {
        thread::sleep(period);
        for sock_mgr in sock_mgrs {
            let _ = sock_mgr.reresolve(allow_upstream, allow_listen_rebind, "Periodic re-resolve");
        }
    }
}

fn print_startup(cfg: &Config, sock_mgr: &SocketManager) {
    let (_, _, client_proto) = sock_mgr.get_client_dest();
    let (upstream_addr, _, upstream_proto) = sock_mgr.get_upstream_dest();
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
    log_info!("Workers: {}", cfg.workers);
    log_info!("Re-resolve every: {}s (0=disabled)", cfg.reresolve_secs);
}

fn main() -> io::Result<()> {
    let t_start = Instant::now();
    let mut user_requested_cfg = parse_args();
    let worker_count = user_requested_cfg.workers.max(1);

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
        worker_count != 1,
        user_requested_cfg.listen_proto == SupportedProtocol::ICMP,
    )?;
    user_requested_cfg.listen_addr = actual_listen_addr;
    user_requested_cfg.listen_port_id = actual_listen_addr.port();

    let cfg = Arc::new(user_requested_cfg);

    // Initial upstream resolution + socket managers (one per worker)
    let mut sock_mgrs = Vec::with_capacity(worker_count);

    sock_mgrs.push(Arc::new(SocketManager::new(
        client_sock,
        cfg.listen_addr,
        cfg.listen_str.clone(),
        cfg.listen_proto,
        cfg.upstream_str.clone(),
        cfg.upstream_proto,
    )?));

    for _ in 1..worker_count {
        let (extra_sock, _) = make_socket(
            cfg.listen_addr,
            cfg.listen_proto,
            1000,
            true,
            cfg.listen_proto == SupportedProtocol::ICMP,
        )?;
        sock_mgrs.push(Arc::new(SocketManager::new(
            extra_sock,
            cfg.listen_addr,
            cfg.listen_str.clone(),
            cfg.listen_proto,
            cfg.upstream_str.clone(),
            cfg.upstream_proto,
        )?));
    }

    // Drop privileges (Unix) now that the privileged socket is bound.
    #[cfg(unix)]
    drop_privileges(&cfg)?;

    // Global application state
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

    print_startup(&cfg, &sock_mgrs[0]);

    for sock_mgr in &sock_mgrs {
        // Client -> Upstream
        {
            let cfg_a = Arc::clone(&cfg);
            let sock_mgr_a = Arc::clone(&sock_mgr);
            let sock_mgrs_a = sock_mgrs.clone();
            let locked_a = Arc::clone(&locked);
            let last_seen_a = Arc::clone(&last_seen_ns);
            let stats_a = Arc::clone(&stats);

            thread::spawn(move || {
                run_client_to_upstream_thread(
                    t_start,
                    &cfg_a,
                    &sock_mgr_a,
                    &sock_mgrs_a,
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
    }

    // Idle timeout watchdog for all workers
    {
        let cfg_w = Arc::clone(&cfg);
        let sock_mgrs_w = sock_mgrs.clone();
        let locked_w = Arc::clone(&locked);
        let last_seen_w = Arc::clone(&last_seen_ns);
        let exit_code_set_w = Arc::clone(&exit_code_set);

        thread::spawn(move || {
            run_watchdog_thread(
                t_start,
                &cfg_w,
                &sock_mgrs_w,
                &locked_w,
                &last_seen_w,
                &exit_code_set_w,
            )
        });
    }

    // Optional periodic re-resolve across all workers
    let reresolve_secs = cfg.reresolve_secs;
    let allow_upstream = cfg.reresolve_mode.allow_upstream();
    let allow_listen_rebind = cfg.reresolve_mode.allow_listen();
    if reresolve_secs != 0 && (allow_upstream || allow_listen_rebind) {
        let sock_mgrs_r = sock_mgrs.clone();

        thread::spawn(move || {
            run_reresolve_thread(
                &sock_mgrs_r,
                reresolve_secs,
                allow_upstream,
                allow_listen_rebind,
            );
        });
    }

    // Stats thread (report peer info from the first worker)
    stats.spawn_stats_printer(
        Arc::clone(&sock_mgrs[0]),
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
