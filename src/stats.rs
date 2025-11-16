use crate::cli::SupportedProtocol;
use crate::upstream::UpstreamManager;
use serde_json::json;

use std::io::Write;
use std::net::SocketAddr;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

// EWMA decay constant: ln(beta) where beta = 2^(-1/H) and H is half-life in samples.
const EWMA_LN_BETA: f64 = -std::f64::consts::LN_2 / 200_000.0; // H = 200k

pub struct Stats {
    start: OnceLock<Instant>,
    spawned: AtomicBool, // ensures spawn_stats_printer runs once
    agg: Agg,
}

// Internal accumulator for per-period stats
struct Agg {
    c2u_pkts: AtomicU64,
    c2u_bytes: AtomicU64,
    c2u_bytes_max: AtomicU64,
    c2u_errs: AtomicU64,
    u2c_pkts: AtomicU64,
    u2c_bytes: AtomicU64,
    u2c_bytes_max: AtomicU64,
    u2c_errs: AtomicU64,
    c2u_lat_sum_ns: AtomicU64,
    c2u_lat_max_ns: AtomicU64,
    u2c_lat_sum_ns: AtomicU64,
    u2c_lat_max_ns: AtomicU64,
    c2u_drops_oversize: AtomicU64,
    u2c_drops_oversize: AtomicU64,
    // Exponentially weighted moving averages (nanoseconds)
    c2u_lat_ewma_ns: AtomicU64,
    u2c_lat_ewma_ns: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            start: OnceLock::new(),
            spawned: AtomicBool::new(false),
            agg: Agg {
                c2u_pkts: AtomicU64::new(0),
                c2u_bytes: AtomicU64::new(0),
                c2u_bytes_max: AtomicU64::new(0),
                c2u_errs: AtomicU64::new(0),
                u2c_pkts: AtomicU64::new(0),
                u2c_bytes: AtomicU64::new(0),
                u2c_bytes_max: AtomicU64::new(0),
                u2c_errs: AtomicU64::new(0),
                c2u_lat_sum_ns: AtomicU64::new(0),
                c2u_lat_max_ns: AtomicU64::new(0),
                u2c_lat_sum_ns: AtomicU64::new(0),
                u2c_lat_max_ns: AtomicU64::new(0),
                c2u_drops_oversize: AtomicU64::new(0),
                u2c_drops_oversize: AtomicU64::new(0),
                c2u_lat_ewma_ns: AtomicU64::new(0),
                u2c_lat_ewma_ns: AtomicU64::new(0),
            },
        }
    }

    #[inline]
    pub fn dur_ns(start: Instant, end: Instant) -> u64 {
        let d = end.saturating_duration_since(start);
        d.as_nanos() as u64
    }

    #[inline]
    pub fn send_add(&self, c2u: bool, bytes: u64, start: Instant, end: Instant) {
        let lat_ns = Self::dur_ns(start, end);
        let (atom_pkts, atom_bytes, atom_lat_sum_ns, atom_lat_max_ns, atom_bytes_max) = if c2u {
            (
                &self.agg.c2u_pkts,
                &self.agg.c2u_bytes,
                &self.agg.c2u_lat_sum_ns,
                &self.agg.c2u_lat_max_ns,
                &self.agg.c2u_bytes_max,
            )
        } else {
            (
                &self.agg.u2c_pkts,
                &self.agg.u2c_bytes,
                &self.agg.u2c_lat_sum_ns,
                &self.agg.u2c_lat_max_ns,
                &self.agg.u2c_bytes_max,
            )
        };

        atom_pkts.fetch_add(1, AtomOrdering::Relaxed);
        atom_bytes.fetch_add(bytes, AtomOrdering::Relaxed);
        atom_lat_sum_ns.fetch_add(lat_ns, AtomOrdering::Relaxed);
        Self::atomic_fetch_max(atom_lat_max_ns, lat_ns);
        Self::atomic_fetch_max(atom_bytes_max, bytes);
    }
    #[inline]
    pub fn drop_err(&self, c2u: bool) {
        let atom_errs = if c2u {
            &self.agg.c2u_errs
        } else {
            &self.agg.u2c_errs
        };
        atom_errs.fetch_add(1, AtomOrdering::Relaxed);
    }
    #[inline]
    pub fn drop_oversize(&self, c2u: bool) {
        let atom_drops_oversize = if c2u {
            &self.agg.c2u_drops_oversize
        } else {
            &self.agg.u2c_drops_oversize
        };
        atom_drops_oversize.fetch_add(1, AtomOrdering::Relaxed);
    }

    /// Returns the Instant when the stats thread was spawned, if started.
    pub fn start_time(&self) -> Option<Instant> {
        self.start.get().cloned()
    }

    /// Returns uptime in seconds since the stats thread was spawned, if started.
    pub fn uptime_seconds(&self) -> Option<u64> {
        self.start.get().map(|s| s.elapsed().as_secs())
    }

    #[inline]
    fn atomic_fetch_max(a: &AtomicU64, val: u64) {
        let mut cur = a.load(AtomOrdering::Relaxed);
        while val > cur {
            match a.compare_exchange_weak(cur, val, AtomOrdering::Relaxed, AtomOrdering::Relaxed) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }

    // --- Private stats printer thread helpers ------------------------
    #[inline]
    fn ewma_compute(prev_ns: u64, sample_avg_ns: u64, sample_count: u64) -> u64 {
        if sample_count == 0 {
            return prev_ns;
        }
        if prev_ns == 0 {
            return sample_avg_ns;
        }
        let k = sample_count as f64;
        let x = EWMA_LN_BETA * k; // x is small negative when k is small
        let one_minus_beta_k = -x.exp_m1(); // exact: 1 - exp(x)
        let beta_k = 1.0 - one_minus_beta_k; // exp(x)

        let prev_f = prev_ns as f64;
        let samp_f = sample_avg_ns as f64;
        let newf = beta_k * prev_f + one_minus_beta_k * samp_f;

        if !newf.is_finite() {
            return 0; // guard against NaN/Inf
        }
        // Round to nearest to avoid truncation bias, and saturate on overflow.
        let r = newf.max(0.0).round(); // avoid negatives / -0.0
        if r >= (u64::MAX as f64) {
            u64::MAX
        } else {
            r as u64
        }
    }

    #[inline]
    fn ewma_update_atomic(cell: &AtomicU64, sample_avg_ns: u64, sample_count: u64) {
        let prev = cell.load(AtomOrdering::Relaxed);
        let next = Self::ewma_compute(prev, sample_avg_ns, sample_count);
        if next != prev {
            cell.store(next, AtomOrdering::Relaxed);
        }
    }

    #[inline]
    fn load_snapshot(
        &self,
    ) -> (
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
    ) {
        let a = &self.agg;
        (
            a.c2u_pkts.load(AtomOrdering::Relaxed),
            a.c2u_bytes.load(AtomOrdering::Relaxed),
            a.c2u_bytes_max.load(AtomOrdering::Relaxed),
            a.c2u_errs.load(AtomOrdering::Relaxed),
            a.u2c_pkts.load(AtomOrdering::Relaxed),
            a.u2c_bytes.load(AtomOrdering::Relaxed),
            a.u2c_bytes_max.load(AtomOrdering::Relaxed),
            a.u2c_errs.load(AtomOrdering::Relaxed),
            a.c2u_lat_sum_ns.load(AtomOrdering::Relaxed),
            a.c2u_lat_max_ns.load(AtomOrdering::Relaxed),
            a.u2c_lat_sum_ns.load(AtomOrdering::Relaxed),
            a.u2c_lat_max_ns.load(AtomOrdering::Relaxed),
            a.c2u_drops_oversize.load(AtomOrdering::Relaxed),
            a.u2c_drops_oversize.load(AtomOrdering::Relaxed),
            a.c2u_lat_ewma_ns.load(AtomOrdering::Relaxed),
            a.u2c_lat_ewma_ns.load(AtomOrdering::Relaxed),
        )
    }

    #[inline]
    fn safe_println(s: &str) {
        let mut out = std::io::stdout();
        let _ = out.write_all(s.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }

    fn print_snapshot(
        &self,
        client_proto: SupportedProtocol,
        client_peer: &Mutex<Option<SocketAddr>>,
        upstream_mgr: &UpstreamManager,
    ) {
        let (
            c2u_pkts,
            c2u_bytes,
            c2u_bytes_max,
            c2u_errs,
            u2c_pkts,
            u2c_bytes,
            u2c_bytes_max,
            u2c_errs,
            c2u_lat_sum_ns,
            c2u_lat_max_ns,
            u2c_lat_sum_ns,
            u2c_lat_max_ns,
            c2u_drops_oversize,
            u2c_drops_oversize,
            c2u_lat_ewma_ns,
            u2c_lat_ewma_ns,
        ) = self.load_snapshot();

        let uptime = self.uptime_seconds().unwrap_or(0);
        let c2u_us_avg = if c2u_pkts > 0 {
            c2u_lat_sum_ns / (c2u_pkts * 1000)
        } else {
            0
        };
        let u2c_us_avg = if u2c_pkts > 0 {
            u2c_lat_sum_ns / (u2c_pkts * 1000)
        } else {
            0
        };
        let c2u_us_ewma = c2u_lat_ewma_ns / 1000;
        let u2c_us_ewma = u2c_lat_ewma_ns / 1000;
        let c2u_us_max = c2u_lat_max_ns / 1000;
        let u2c_us_max = u2c_lat_max_ns / 1000;
        let client_opt = { *client_peer.lock().unwrap() };
        let locked = client_opt.is_some();
        let client_addr = client_opt
            .map(|x| x.to_string())
            .unwrap_or_else(|| "null".to_string());
        let (upstream_addr, upstream_proto) = { upstream_mgr.current_dest() };
        let line = json!({
            "uptime_s": uptime,
            "locked": locked,
            "client_addr": client_addr,
            "client_proto": client_proto.to_str(),
            "upstream_addr": upstream_addr,
            "upstream_proto": upstream_proto.to_str(),
            "c2u_pkts": c2u_pkts,
            "c2u_bytes": c2u_bytes,
            "c2u_bytes_max": c2u_bytes_max,
            "c2u_drops_oversize": c2u_drops_oversize,
            "c2u_us_avg": c2u_us_avg,
            "c2u_us_ewma": c2u_us_ewma,
            "c2u_us_max": c2u_us_max,
            "c2u_errs": c2u_errs,
            "u2c_pkts": u2c_pkts,
            "u2c_bytes": u2c_bytes,
            "u2c_bytes_max": u2c_bytes_max,
            "u2c_drops_oversize": u2c_drops_oversize,
            "u2c_us_avg": u2c_us_avg,
            "u2c_us_ewma": u2c_us_ewma,
            "u2c_us_max": u2c_us_max,
            "u2c_errs": u2c_errs,
        });
        Self::safe_println(&line.to_string());
    }

    pub fn spawn_stats_printer(
        self: &Arc<Self>,
        client_proto: SupportedProtocol,
        client_peer: Arc<Mutex<Option<SocketAddr>>>,
        upstream_mgr: Arc<UpstreamManager>,
        start: Instant,
        every_secs: u64,
        exit_code_set: Arc<AtomicU32>,
    ) -> bool {
        let every = every_secs.max(1);
        let stats = Arc::clone(self);
        // Single-init gate: set the bool once. If true, someone else already spawned the printer.
        if self
            .spawned
            .compare_exchange(false, true, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
            .is_err()
        {
            return false; // already running
        }
        let _ = stats.start.set(start);
        thread::spawn(move || {
            // Cadences:
            //  - MAINT_TICK: short cadence (EWMA refresh + shutdown check)
            //  - PRINT_PERIOD: long cadence (JSON printing)
            const MAINT_TICK_MS: u64 = 250;

            // initialize prev snapshot
            let (
                mut ew_prev_c2u_pkts,
                _,
                _,
                _,
                mut ew_prev_u2c_pkts,
                _,
                _,
                _,
                mut ew_prev_c2u_lat_sum_ns,
                _,
                mut ew_prev_u2c_lat_sum_ns,
                _,
                _,
                _,
                _,
                _,
            ) = stats.load_snapshot();

            let print_period = Duration::from_secs(every);
            let mut next_print_at = stats.start_time().unwrap_or_else(Instant::now) + print_period;
            loop {
                // Take one snapshot per tick for both EWMA update and (maybe) printing
                let (
                    c2u_pkts,
                    _,
                    _,
                    _,
                    u2c_pkts,
                    _,
                    _,
                    _,
                    c2u_lat_sum_ns,
                    _,
                    u2c_lat_sum_ns,
                    _,
                    _,
                    _,
                    _,
                    _,
                ) = stats.load_snapshot();

                // Update EWMA from deltas every 250ms tick (not tied to print interval)
                let d_c2u_pkts = c2u_pkts.saturating_sub(ew_prev_c2u_pkts);
                let d_u2c_pkts = u2c_pkts.saturating_sub(ew_prev_u2c_pkts);
                let d_c2u_lat = c2u_lat_sum_ns.saturating_sub(ew_prev_c2u_lat_sum_ns);
                let d_u2c_lat = u2c_lat_sum_ns.saturating_sub(ew_prev_u2c_lat_sum_ns);
                if d_c2u_pkts > 0 {
                    let avg_ns = d_c2u_lat / d_c2u_pkts;
                    Self::ewma_update_atomic(&stats.agg.c2u_lat_ewma_ns, avg_ns, d_c2u_pkts);
                }
                if d_u2c_pkts > 0 {
                    let avg_ns = d_u2c_lat / d_u2c_pkts;
                    Self::ewma_update_atomic(&stats.agg.u2c_lat_ewma_ns, avg_ns, d_u2c_pkts);
                }
                // advance EWMA prevs to the current cumulative totals
                ew_prev_c2u_pkts = c2u_pkts;
                ew_prev_u2c_pkts = u2c_pkts;
                ew_prev_c2u_lat_sum_ns = c2u_lat_sum_ns;
                ew_prev_u2c_lat_sum_ns = u2c_lat_sum_ns;

                // Check for cooperative shutdown **after** EWMA is up to date
                let exit_code_local = exit_code_set.load(AtomOrdering::Relaxed);
                if (exit_code_local & (1 << 31)) != 0 {
                    stats.print_snapshot(client_proto, &client_peer, &upstream_mgr);
                    let exit_code = (exit_code_local & !(1 << 31)) as i32;
                    process::exit(exit_code);
                }

                // Print only on schedule
                let now = Instant::now();
                if now >= next_print_at {
                    stats.print_snapshot(client_proto, &client_peer, &upstream_mgr);
                    // Advance the next print boundary, accounting for any missed periods
                    let elapsed = now.duration_since(next_print_at).as_secs();
                    let skipped = (elapsed / every) + 1; // at least one boundary
                    next_print_at += Duration::from_secs(skipped * every);
                }

                // Maintenance tick: EWMA update + shutdown check cadence
                thread::sleep(Duration::from_millis(MAINT_TICK_MS));
            }
        });
        true
    }
}
