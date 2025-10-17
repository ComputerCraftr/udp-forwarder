use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::upstream::UpstreamManager;

pub struct Stats {
    pub start: Instant,
    pub c2u_pkts: AtomicU64,
    pub c2u_bytes: AtomicU64,
    pub c2u_bytes_max: AtomicU64,
    pub c2u_send_errs: AtomicU64,
    pub u2c_pkts: AtomicU64,
    pub u2c_bytes: AtomicU64,
    pub u2c_bytes_max: AtomicU64,
    pub u2c_send_errs: AtomicU64,
    pub c2u_lat_ns_sum: AtomicU64,
    pub c2u_lat_ns_max: AtomicU64,
    pub u2c_lat_ns_sum: AtomicU64,
    pub u2c_lat_ns_max: AtomicU64,
    pub drops_c2u_oversize: AtomicU64,
    pub drops_u2c_oversize: AtomicU64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            c2u_pkts: AtomicU64::new(0),
            c2u_bytes: AtomicU64::new(0),
            c2u_bytes_max: AtomicU64::new(0),
            c2u_send_errs: AtomicU64::new(0),
            u2c_pkts: AtomicU64::new(0),
            u2c_bytes: AtomicU64::new(0),
            u2c_bytes_max: AtomicU64::new(0),
            u2c_send_errs: AtomicU64::new(0),
            c2u_lat_ns_sum: AtomicU64::new(0),
            c2u_lat_ns_max: AtomicU64::new(0),
            u2c_lat_ns_sum: AtomicU64::new(0),
            u2c_lat_ns_max: AtomicU64::new(0),
            drops_c2u_oversize: AtomicU64::new(0),
            drops_u2c_oversize: AtomicU64::new(0),
        })
    }

    pub fn add_c2u(&self, bytes: u64, lat_ns: u64) {
        self.c2u_pkts.fetch_add(1, AtomOrdering::Relaxed);
        self.c2u_bytes.fetch_add(bytes, AtomOrdering::Relaxed);
        // track max client->upstream packet size
        loop {
            let cur = self.c2u_bytes_max.load(AtomOrdering::Relaxed);
            if bytes <= cur {
                break;
            }
            if self
                .c2u_bytes_max
                .compare_exchange(cur, bytes, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        self.c2u_lat_ns_sum.fetch_add(lat_ns, AtomOrdering::Relaxed);
        loop {
            let cur = self.c2u_lat_ns_max.load(AtomOrdering::Relaxed);
            if lat_ns <= cur {
                break;
            }
            if self
                .c2u_lat_ns_max
                .compare_exchange(cur, lat_ns, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
    pub fn c2u_err(&self) {
        self.c2u_send_errs.fetch_add(1, AtomOrdering::Relaxed);
    }

    pub fn add_u2c(&self, bytes: u64, lat_ns: u64) {
        self.u2c_pkts.fetch_add(1, AtomOrdering::Relaxed);
        self.u2c_bytes.fetch_add(bytes, AtomOrdering::Relaxed);
        // track max upstream->client packet size
        loop {
            let cur = self.u2c_bytes_max.load(AtomOrdering::Relaxed);
            if bytes <= cur {
                break;
            }
            if self
                .u2c_bytes_max
                .compare_exchange(cur, bytes, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        self.u2c_lat_ns_sum.fetch_add(lat_ns, AtomOrdering::Relaxed);
        loop {
            let cur = self.u2c_lat_ns_max.load(AtomOrdering::Relaxed);
            if lat_ns <= cur {
                break;
            }
            if self
                .u2c_lat_ns_max
                .compare_exchange(cur, lat_ns, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
    pub fn u2c_err(&self) {
        self.u2c_send_errs.fetch_add(1, AtomOrdering::Relaxed);
    }

    pub fn drop_c2u_oversize(&self) {
        self.drops_c2u_oversize.fetch_add(1, AtomOrdering::Relaxed);
    }

    pub fn drop_u2c_oversize(&self) {
        self.drops_u2c_oversize.fetch_add(1, AtomOrdering::Relaxed);
    }
}

pub fn dur_ns(start: Instant, end: Instant) -> u64 {
    let d = end.duration_since(start);
    d.as_nanos().min(u128::from(u64::MAX)) as u64
}

pub fn spawn_stats_printer(
    stats: Arc<Stats>,
    client_peer: Arc<Mutex<Option<SocketAddr>>>,
    upstream_mgr: Arc<UpstreamManager>,
    every_secs: u64,
) {
    let every = every_secs.max(1);
    thread::spawn(move || {
        let period = Duration::from_secs(every);
        loop {
            thread::sleep(period);
            let uptime = stats.start.elapsed().as_secs();
            let c2u_pkts = stats.c2u_pkts.load(AtomOrdering::Relaxed);
            let c2u_bytes = stats.c2u_bytes.load(AtomOrdering::Relaxed);
            let c2u_bytes_max = stats.c2u_bytes_max.load(AtomOrdering::Relaxed);
            let c2u_errs = stats.c2u_send_errs.load(AtomOrdering::Relaxed);
            let drops_c2u_oversize = stats.drops_c2u_oversize.load(AtomOrdering::Relaxed);
            let drops_u2c_oversize = stats.drops_u2c_oversize.load(AtomOrdering::Relaxed);
            let u2c_pkts = stats.u2c_pkts.load(AtomOrdering::Relaxed);
            let u2c_bytes = stats.u2c_bytes.load(AtomOrdering::Relaxed);
            let u2c_bytes_max = stats.u2c_bytes_max.load(AtomOrdering::Relaxed);
            let u2c_errs = stats.u2c_send_errs.load(AtomOrdering::Relaxed);
            let c2u_lat_sum = stats.c2u_lat_ns_sum.load(AtomOrdering::Relaxed);
            let c2u_lat_max = stats.c2u_lat_ns_max.load(AtomOrdering::Relaxed);
            let u2c_lat_sum = stats.u2c_lat_ns_sum.load(AtomOrdering::Relaxed);
            let u2c_lat_max = stats.u2c_lat_ns_max.load(AtomOrdering::Relaxed);
            let c2u_avg_us = if c2u_pkts > 0 {
                (c2u_lat_sum / c2u_pkts) / 1000
            } else {
                0
            };
            let u2c_avg_us = if u2c_pkts > 0 {
                (u2c_lat_sum / u2c_pkts) / 1000
            } else {
                0
            };
            let c2u_max_us = c2u_lat_max / 1000;
            let u2c_max_us = u2c_lat_max / 1000;
            // Read client once; derive locked state from it
            let client_opt = { *client_peer.lock().unwrap() };
            let locked_now = client_opt.is_some();
            let client_s = client_opt
                .map(|a| a.to_string())
                .unwrap_or_else(|| "null".to_string());
            let up_s = { upstream_mgr.current_dest().to_string() };
            let line = json!({
                "uptime_s": uptime,
                "locked": locked_now,
                "client": client_s,
                "upstream": up_s,
                "c2u_pkts": c2u_pkts,
                "c2u_bytes": c2u_bytes,
                "c2u_bytes_max": c2u_bytes_max,
                "c2u_drops_oversize": drops_c2u_oversize,
                "c2u_us_avg": c2u_avg_us,
                "c2u_us_max": c2u_max_us,
                "c2u_errs": c2u_errs,
                "u2c_pkts": u2c_pkts,
                "u2c_bytes": u2c_bytes,
                "u2c_bytes_max": u2c_bytes_max,
                "u2c_drops_oversize": drops_u2c_oversize,
                "u2c_us_avg": u2c_avg_us,
                "u2c_us_max": u2c_max_us,
                "u2c_errs": u2c_errs,
            });
            println!("{}", line.to_string());
        }
    });
}
