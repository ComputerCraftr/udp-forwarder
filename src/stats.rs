use serde_json::json;
use std::io::Write;
use std::net::SocketAddr;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering as AtomOrdering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::upstream::UpstreamManager;

enum StatEvent {
    C2U { bytes: u64, lat_ns: u64 },
    U2C { bytes: u64, lat_ns: u64 },
    C2UErr,
    U2CErr,
    DropC2UOver,
    DropU2COver,
}

pub struct Stats {
    start: OnceLock<Instant>,
    tx: SyncSender<StatEvent>,
    rx: Mutex<Option<Receiver<StatEvent>>>,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = sync_channel::<StatEvent>(8192);
        Arc::new(Self {
            start: OnceLock::new(),
            tx,
            rx: Mutex::new(Some(rx)),
        })
    }

    pub fn dur_ns(start: Instant, end: Instant) -> u64 {
        let d = end.duration_since(start);
        d.as_nanos().min(u128::from(u64::MAX)) as u64
    }

    pub fn add_c2u(&self, bytes: u64, start: Instant, end: Instant) {
        let lat_ns = Self::dur_ns(start, end);
        let _ = self.tx.try_send(StatEvent::C2U { bytes, lat_ns });
    }
    pub fn c2u_err(&self) {
        let _ = self.tx.try_send(StatEvent::C2UErr);
    }
    pub fn add_u2c(&self, bytes: u64, start: Instant, end: Instant) {
        let lat_ns = Self::dur_ns(start, end);
        let _ = self.tx.try_send(StatEvent::U2C { bytes, lat_ns });
    }
    pub fn u2c_err(&self) {
        let _ = self.tx.try_send(StatEvent::U2CErr);
    }
    pub fn drop_c2u_oversize(&self) {
        let _ = self.tx.try_send(StatEvent::DropC2UOver);
    }
    pub fn drop_u2c_oversize(&self) {
        let _ = self.tx.try_send(StatEvent::DropU2COver);
    }

    /// Returns the Instant when the stats thread started, if started.
    #[allow(dead_code)]
    pub fn start_time(&self) -> Option<Instant> {
        self.start.get().cloned()
    }

    /// Returns uptime in seconds since the stats thread started, if started.
    pub fn uptime_seconds(&self) -> Option<u64> {
        self.start.get().map(|s| s.elapsed().as_secs())
    }

    pub fn spawn_stats_printer(
        self: &Arc<Self>,
        client_peer: Arc<Mutex<Option<SocketAddr>>>,
        upstream_mgr: Arc<UpstreamManager>,
        every_secs: u64,
        should_exit: Arc<AtomicBool>,
    ) -> bool {
        let every = every_secs.max(1);
        let stats = Arc::clone(self);
        // Single-init gate: take the receiver once. If None, someone else already spawned the printer.
        let rx = match stats.rx.lock().unwrap().take() {
            Some(rx) => rx,
            None => return false,
        };
        let _ = stats.start.set(Instant::now());
        thread::spawn(move || {
            struct Agg {
                c2u_pkts: u64,
                c2u_bytes: u64,
                c2u_bytes_max: u64,
                c2u_errs: u64,
                u2c_pkts: u64,
                u2c_bytes: u64,
                u2c_bytes_max: u64,
                u2c_errs: u64,
                c2u_lat_sum: u64,
                c2u_lat_max: u64,
                u2c_lat_sum: u64,
                u2c_lat_max: u64,
                c2u_drops_oversize: u64,
                u2c_drops_oversize: u64,
            }

            let mut agg = Agg {
                c2u_pkts: 0,
                c2u_bytes: 0,
                c2u_bytes_max: 0,
                c2u_errs: 0,
                u2c_pkts: 0,
                u2c_bytes: 0,
                u2c_bytes_max: 0,
                u2c_errs: 0,
                c2u_lat_sum: 0,
                c2u_lat_max: 0,
                u2c_lat_sum: 0,
                u2c_lat_max: 0,
                c2u_drops_oversize: 0,
                u2c_drops_oversize: 0,
            };

            // --- DRY helpers ---------------------------------------------------
            // Apply a single StatEvent to local aggregates
            let handle_event = |a: &mut Agg, ev: StatEvent| match ev {
                StatEvent::C2U { bytes, lat_ns } => {
                    a.c2u_pkts += 1;
                    a.c2u_bytes += bytes;
                    a.c2u_lat_sum = a.c2u_lat_sum.saturating_add(lat_ns);
                    if lat_ns > a.c2u_lat_max {
                        a.c2u_lat_max = lat_ns;
                    }
                    if bytes > a.c2u_bytes_max {
                        a.c2u_bytes_max = bytes;
                    }
                }
                StatEvent::U2C { bytes, lat_ns } => {
                    a.u2c_pkts += 1;
                    a.u2c_bytes += bytes;
                    a.u2c_lat_sum = a.u2c_lat_sum.saturating_add(lat_ns);
                    if lat_ns > a.u2c_lat_max {
                        a.u2c_lat_max = lat_ns;
                    }
                    if bytes > a.u2c_bytes_max {
                        a.u2c_bytes_max = bytes;
                    }
                }
                StatEvent::C2UErr => {
                    a.c2u_errs = a.c2u_errs.saturating_add(1);
                }
                StatEvent::U2CErr => {
                    a.u2c_errs = a.u2c_errs.saturating_add(1);
                }
                StatEvent::DropC2UOver => {
                    a.c2u_drops_oversize = a.c2u_drops_oversize.saturating_add(1);
                }
                StatEvent::DropU2COver => {
                    a.u2c_drops_oversize = a.u2c_drops_oversize.saturating_add(1);
                }
            };

            // Non-panicking println that ignores EPIPE/broken pipe during test teardown
            let safe_println = |s: &str| {
                let mut out = std::io::stdout();
                let _ = out.write_all(s.as_bytes());
                let _ = out.write_all(b"\n");
                let _ = out.flush();
            };

            // Print a single JSON snapshot using current aggregates
            let print_snapshot = |a: &Agg| {
                let uptime = Self::uptime_seconds(&stats).unwrap_or(0);
                let c2u_us_avg = if a.c2u_pkts > 0 {
                    (a.c2u_lat_sum / a.c2u_pkts) / 1000
                } else {
                    0
                };
                let u2c_us_avg = if a.u2c_pkts > 0 {
                    (a.u2c_lat_sum / a.u2c_pkts) / 1000
                } else {
                    0
                };
                let c2u_us_max = a.c2u_lat_max / 1000;
                let u2c_us_max = a.u2c_lat_max / 1000;
                let client_opt = { *client_peer.lock().unwrap() };
                let locked = client_opt.is_some();
                let client_addr = client_opt
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "null".to_string());
                let upstream_addr = { upstream_mgr.current_dest().to_string() };
                let line = json!({
                    "uptime_s": uptime,
                    "locked": locked,
                    "client_addr": client_addr,
                    "upstream_addr": upstream_addr,
                    "c2u_pkts": a.c2u_pkts,
                    "c2u_bytes": a.c2u_bytes,
                    "c2u_bytes_max": a.c2u_bytes_max,
                    "c2u_drops_oversize": a.c2u_drops_oversize,
                    "c2u_us_avg": c2u_us_avg,
                    "c2u_us_max": c2u_us_max,
                    "c2u_errs": a.c2u_errs,
                    "u2c_pkts": a.u2c_pkts,
                    "u2c_bytes": a.u2c_bytes,
                    "u2c_bytes_max": a.u2c_bytes_max,
                    "u2c_drops_oversize": a.u2c_drops_oversize,
                    "u2c_us_avg": u2c_us_avg,
                    "u2c_us_max": u2c_us_max,
                    "u2c_errs": a.u2c_errs,
                });
                safe_println(&line.to_string());
            };

            let period = Duration::from_secs(every);
            let mut next_tick = Instant::now() + period;
            loop {
                // Cooperative shutdown: when exit is requested, drain, print once, and exit
                if should_exit.load(AtomOrdering::Relaxed) {
                    loop {
                        let ev = rx.try_recv();
                        match ev {
                            Ok(ev) => handle_event(&mut agg, ev),
                            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
                        }
                    }
                    print_snapshot(&agg);
                    process::exit(0);
                }
                let now = Instant::now();
                let wait = next_tick
                    .saturating_duration_since(now)
                    .max(Duration::from_millis(250));
                let ev = rx.recv_timeout(wait);
                match ev {
                    Ok(ev) => {
                        // process one event then drain any additional queued events
                        handle_event(&mut agg, ev);
                        // drain burst
                        loop {
                            let ev2 = rx.try_recv();
                            match ev2 {
                                Ok(ev2) => handle_event(&mut agg, ev2),
                                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        // time to print a snapshot
                        print_snapshot(&agg);
                        next_tick += period;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        true
    }
}
