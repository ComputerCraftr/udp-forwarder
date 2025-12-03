#[macro_use]
mod logging;
mod cli;
mod net;
mod params;
mod sock_mgr;
mod stats;
mod worker;

use cli::{Config, SupportedProtocol, parse_args};
use net::make_socket;
#[cfg(unix)]
use nix::unistd::{self, Group, User};
use sock_mgr::SocketManager;
use stats::Stats;
use worker::{
    run_client_to_upstream_thread, run_reresolve_thread, run_upstream_to_client_thread,
    run_watchdog_thread,
};

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
use std::thread;
use std::time::Instant;

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

    for (idx, sock_mgr) in sock_mgrs.iter().enumerate() {
        let worker_base = idx * 2;
        // Client -> Upstream
        {
            let cfg_a = Arc::clone(&cfg);
            let sock_mgr_a = Arc::clone(&sock_mgr);
            let sock_mgrs_a = sock_mgrs.clone();
            let worker_id = worker_base;
            let locked_a = Arc::clone(&locked);
            let last_seen_a = Arc::clone(&last_seen_ns);
            let stats_a = Arc::clone(&stats);

            thread::spawn(move || {
                run_client_to_upstream_thread(
                    t_start,
                    &cfg_a,
                    &sock_mgr_a,
                    &sock_mgrs_a,
                    worker_id,
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
            let worker_id = worker_base + 1;
            let locked_b = Arc::clone(&locked);
            let last_seen_b = Arc::clone(&last_seen_ns);
            let stats_b = Arc::clone(&stats);

            thread::spawn(move || {
                run_upstream_to_client_thread(
                    t_start,
                    &cfg_b,
                    &sock_mgr_b,
                    worker_id,
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
