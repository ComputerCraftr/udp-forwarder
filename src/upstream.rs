use crate::net::{family_changed, make_upstream_socket_for, resolve_first};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Manages current upstream destination and a hot-swappable UdpSocket.
pub struct UpstreamManager {
    current_addr: Arc<Mutex<SocketAddr>>, // cold-path updates only
    sock: Arc<Mutex<UdpSocket>>,          // cold-path replacement only
    version: AtomicU64,                   // increments on any change
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
    pub fn apply_fresh(
        &self,
        target: &str,
        context: &str,
    ) -> io::Result<(UdpSocket, SocketAddr, u64)> {
        let fresh = resolve_first(target)?;

        // Compare against previous before updating to compute correct family flip
        let (fam_flip, changed) = {
            let mut cur = self.current_addr.lock().unwrap();
            let prev = *cur;
            let changed = prev != fresh;
            let fam_flip = if changed {
                *cur = fresh;
                family_changed(prev, fresh)
            } else {
                false
            };
            (fam_flip, changed)
        };

        // Prepare a socket to return while also updating the internal socket state.
        let ret_sock = if fam_flip {
            println!("{context}: upstream {fresh} (family changed; upstream socket swapped)");
            // Family changed: create a new **connected** upstream socket and swap it in.
            let new_sock = make_upstream_socket_for(fresh)?; // already connected
            {
                let mut guard = self.sock.lock().unwrap();
                *guard = new_sock.try_clone()?;
            }
            new_sock
        } else if changed {
            println!("{context}: upstream {fresh}");
            // Same family, different address: reconnect existing socket in place.
            let guard = self.sock.lock().unwrap();
            guard.connect(fresh)?;
            // Return a clone of the now-updated internal socket
            guard.try_clone()?
        } else {
            // No change: just return a clone of the current socket
            self.sock.lock().unwrap().try_clone()?
        };

        let ver = if fam_flip || changed {
            // publish that upstream changed; readers can refresh lazily
            self.version.fetch_add(1, AtomOrdering::Relaxed) + 1
        } else {
            self.version.load(AtomOrdering::Relaxed)
        };

        // Return up-to-date handles to the caller without re-locking other getters
        Ok((ret_sock, fresh, ver))
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
                let _ = mgr.apply_fresh(&target, "Periodic re-resolve");
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
    pub fn refresh_handles(&self) -> (UdpSocket, SocketAddr, u64) {
        // lock order: sock then addr (stable and short-lived)
        let sock = Self::clone_socket(self);
        let dest = Self::current_dest(self);
        let v = Self::version(self);
        (sock, dest, v)
    }

    /// Back-compat: clone the socket only (cold path). Prefer `refresh_handles`.
    pub fn clone_socket(&self) -> UdpSocket {
        self.sock
            .lock()
            .unwrap()
            .try_clone()
            .expect("clone upstream socket")
    }
}
