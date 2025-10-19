use crate::net::{family_changed, make_upstream_socket_for, resolve_first};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Manages current upstream destination and a hot-swappable UdpSocket.
pub struct UpstreamManager {
    current_addr: Arc<Mutex<SocketAddr>>,  // cold-path updates only
    sock: Arc<Mutex<std::net::UdpSocket>>, // cold-path replacement only
    version: AtomicU64,                    // increments on any change
}

impl UpstreamManager {
    pub fn new(initial_target: &str) -> io::Result<Self> {
        let addr = resolve_first(initial_target)?;
        let sock = make_upstream_socket_for(addr)?;
        Ok(Self {
            current_addr: Arc::new(Mutex::new(addr)),
            sock: Arc::new(Mutex::new(sock)),
            version: AtomicU64::new(0),
        })
    }

    pub fn current_dest(&self) -> SocketAddr {
        *self.current_addr.lock().unwrap()
    }

    /// Re-resolve a target string and update: swap socket if family flips.
    pub fn apply_fresh(&self, target: &str, context: &str) {
        if let Ok(fresh) = resolve_first(target) {
            let mut cur = self.current_addr.lock().unwrap();
            let fam_flip = family_changed(*cur, fresh);
            let changed = *cur != fresh;
            *cur = fresh;
            drop(cur);

            if fam_flip {
                match make_upstream_socket_for(fresh) {
                    Ok(new_sock) => {
                        *self.sock.lock().unwrap() = new_sock;
                        println!(
                            "{context}: upstream {fresh} (family changed; upstream socket swapped)"
                        );
                    }
                    Err(e) => {
                        eprintln!("{context}: failed to create upstream socket for {fresh}: {e}")
                    }
                }
            } else if changed {
                println!("{context}: upstream {fresh}");
            }

            if fam_flip || changed {
                // publish that upstream changed; readers can refresh lazily
                self.version.fetch_add(1, AtomOrdering::Relaxed);
            }
        }
    }

    /// Optional periodic re-resolve while locked.
    pub fn spawn_periodic(
        self: &Arc<Self>,
        target: String,
        every_secs: u64,
        locked: Arc<AtomicBool>,
    ) {
        if every_secs == 0 {
            return;
        }
        let mgr = Arc::clone(self);
        thread::spawn(move || {
            let period = Duration::from_secs(every_secs);
            loop {
                thread::sleep(period);
                if !locked.load(AtomOrdering::Relaxed) {
                    continue;
                }
                mgr.apply_fresh(&target, "Periodic re-resolve");
            }
        });
    }

    /// Current version for lock-free checks in hot paths.
    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(AtomOrdering::Relaxed)
    }

    /// Clone current socket and read current dest (cold path under mutexes).
    /// Use this only when your cached version != `version()`.
    pub fn refresh_handles(&self) -> (std::net::UdpSocket, SocketAddr, u64) {
        // lock order: sock then addr (stable and short-lived)
        let sock = Self::clone_socket(self);
        let dest = Self::current_dest(self);
        let v = Self::version(self);
        (sock, dest, v)
    }

    /// Back-compat: clone the socket only (cold path). Prefer `refresh_handles`.
    pub fn clone_socket(&self) -> std::net::UdpSocket {
        self.sock
            .lock()
            .unwrap()
            .try_clone()
            .expect("clone upstream socket")
    }
}
