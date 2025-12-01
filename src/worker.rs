use crate::cli::{Config, TimeoutAction};
use crate::net::{send_payload, udp_disconnect};
use crate::sock_mgr::{SocketHandles, SocketManager};
use crate::stats::Stats;
use socket2::{SockAddr, Socket, Type};

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
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

struct CachedClientState {
    c2u: bool,
    worker_id: usize,
    client_sa: Option<SockAddr>,
    dest_sock_type: Type,
    dest_sa: SockAddr,
    dest_port_id: u16,
    recv_port_id: u16,
    log_handles: bool,
}

impl CachedClientState {
    fn new(
        c2u: bool,
        worker_id: usize,
        handles: &SocketHandles,
        recv_port_id: u16,
        log_handles: bool,
    ) -> Self {
        if c2u {
            Self {
                c2u,
                worker_id,
                client_sa: handles.client_addr.map(|addr| SockAddr::from(addr)),
                dest_sock_type: handles.upstream_sock.r#type().unwrap_or(Type::RAW),
                dest_sa: SockAddr::from(handles.upstream_addr),
                dest_port_id: handles.upstream_addr.port(),
                recv_port_id,
                log_handles,
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
                worker_id,
                client_sa: None,
                dest_sock_type: handles.client_sock.r#type().unwrap_or(Type::RAW),
                dest_sa,
                dest_port_id,
                recv_port_id,
                log_handles,
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
            let prev_ver = handles.version;
            *handles = sock_mgr.refresh_handles();
            self.refresh_from_handles(handles);
            log_debug_w!(
                self.log_handles,
                self.worker_id,
                "refresh_handles_and_cache: stale={}, new_ver={}, c2u={}, client_addr={:?}, client_connected={}, upstream_addr={}, upstream_connected={}",
                prev_ver,
                handles.version,
                self.c2u,
                handles.client_addr,
                handles.client_connected,
                handles.upstream_addr,
                handles.upstream_connected
            );
        }
    }
}

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

pub fn run_reresolve_thread(
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

pub fn run_watchdog_thread(
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
                                let prev = sock_mgr.get_version();
                                let ver = sock_mgr.set_client_addr_connected(None, false, prev);
                                log_debug!(
                                    cfg.debug_log_handles,
                                    "watchdog publish disconnect: ver {}->{}",
                                    prev,
                                    ver
                                );
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

pub fn run_upstream_to_client_thread(
    t_start: Instant,
    cfg: &Config,
    sock_mgr: &SocketManager,
    worker_id: usize,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    stats: &Stats,
) {
    const C2U: bool = false;
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let mut handles = sock_mgr.refresh_handles();
    let mut cache = CachedClientState::new(
        C2U,
        worker_id,
        &handles,
        handles.upstream_addr.port(),
        cfg.debug_log_handles,
    );
    loop {
        match handles.upstream_sock.recv(as_uninit_mut(&mut buf)) {
            Ok(len) => {
                let t_recv = Instant::now();

                // Cheap hot-path check: refresh local handles only when version changes
                cache.refresh_handles_and_cache(sock_mgr, &mut handles);

                if locked.load(AtomOrdering::Relaxed) {
                    if !send_payload(
                        C2U,
                        worker_id,
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
                        let prev_ver = handles.version;
                        log_warn!(
                            "[worker {}] send_payload u2c failed (dest-addr-required); disconnecting client socket",
                            worker_id
                        );
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
                        log_debug_w!(
                            cfg.debug_log_handles,
                            worker_id,
                            "u2c publish disconnect: addr={:?} ver {}->{}",
                            handles.client_addr,
                            prev_ver,
                            handles.version
                        );
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                log_error!("recv upstream (connected) error: {}", e);
                stats.drop_err(C2U);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

pub fn run_client_to_upstream_thread(
    t_start: Instant,
    cfg: &Config,
    sock_mgr: &SocketManager,
    all_sock_mgrs: &[Arc<SocketManager>],
    worker_id: usize,
    locked: &AtomicBool,
    last_seen_ns: &AtomicU64,
    stats: &Stats,
) {
    const C2U: bool = true;
    let mut buf = vec![0u8; 65535];
    // Cache upstream socket and destination; refresh only when version changes
    let mut handles = sock_mgr.refresh_handles();
    let mut cache = CachedClientState::new(
        C2U,
        worker_id,
        &handles,
        cfg.listen_port_id,
        cfg.debug_log_handles,
    );
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
                            C2U,
                            worker_id,
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
                    stats.drop_err(C2U);
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

                        // Publish lock state for this worker
                        handles.version = sock_mgr.set_client_addr_connected(
                            addr_opt,
                            handles.client_connected,
                            handles.version,
                        );
                        log_debug_w!(
                            cfg.debug_log_handles,
                            worker_id,
                            "c2u publish lock: addr={:?} connected={} ver={}",
                            addr_opt,
                            handles.client_connected,
                            handles.version
                        );

                        // Propagate client address to other workers and attempt send/recv before fallback.
                        // Duplicate connect() may cause EADDRINUSE on the same 5-tuple across SO_REUSEPORT sockets.
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
                            C2U,
                            worker_id,
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
                            C2U,
                            worker_id,
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
                    stats.drop_err(C2U);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}
