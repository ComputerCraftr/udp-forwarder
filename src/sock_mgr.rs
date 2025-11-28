use crate::cli::{Config, SupportedProtocol};
use crate::net::{family_changed, make_upstream_socket_for, resolve_first};
use socket2::{SockAddr, Socket};

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Snapshot of sockets and destination used by worker threads.
pub struct SocketHandles {
    pub client_addr: Option<SocketAddr>,
    pub client_connected: bool,
    pub client_sock: Socket,
    pub upstream_addr: SocketAddr,
    pub upstream_connected: bool,
    pub upstream_sock: Socket,
    pub version: u64,
}

/// Manages both local and upstream sockets and publishes versioned updates.
pub struct SocketManager {
    client_addr: Mutex<Option<SocketAddr>>, // cold-path updates only
    client_connected: Mutex<bool>,
    client_proto: SupportedProtocol,   // never changes
    client_sock: Mutex<Socket>,        // shared listener socket
    upstream_addr: Mutex<SocketAddr>,  // cold-path updates only
    upstream_connected: bool,          // connected at creation
    upstream_proto: SupportedProtocol, // never changes
    upstream_sock: Mutex<Socket>,      // cold-path replacement only
    version: AtomicU64,                // increments on any change
    spawned: AtomicBool,               // ensures spawn_periodic runs once
}

impl SocketManager {
    pub fn new(
        client_sock: Socket,
        client_proto: SupportedProtocol,
        upstream_target: &str,
        upstream_proto: SupportedProtocol,
    ) -> io::Result<Self> {
        let dest = resolve_first(upstream_target)?;
        let (sock, _actual_dest) = make_upstream_socket_for(dest, upstream_proto)?;
        Ok(Self {
            client_addr: Mutex::new(None),
            client_connected: Mutex::new(false),
            client_proto,
            client_sock: Mutex::new(client_sock),
            upstream_addr: Mutex::new(dest),
            upstream_connected: true,
            upstream_proto,
            upstream_sock: Mutex::new(sock),
            version: AtomicU64::new(0),
            spawned: AtomicBool::new(false),
        })
    }

    #[inline]
    pub fn get_client_connected(&self) -> bool {
        *self.client_connected.lock().unwrap()
    }

    #[inline]
    pub fn set_client_connected(
        &self,
        addr: Option<SocketAddr>,
        connected: bool,
        prev_ver: u64,
    ) -> u64 {
        *self.client_addr.lock().unwrap() = addr;
        *self.client_connected.lock().unwrap() = connected;
        self.version.fetch_add(1, AtomOrdering::Relaxed);
        prev_ver + 1
    }

    #[inline]
    pub fn client_dest(&self) -> (Option<SocketAddr>, bool, SupportedProtocol) {
        (
            *self.client_addr.lock().unwrap(),
            *self.client_connected.lock().unwrap(),
            self.client_proto,
        )
    }

    #[inline]
    pub fn upstream_dest(&self) -> (SocketAddr, bool, SupportedProtocol) {
        (
            *self.upstream_addr.lock().unwrap(),
            self.upstream_connected,
            self.upstream_proto,
        )
    }

    /// Re-resolve a target string and update: swap socket if family flips.
    pub fn apply_fresh(&self, target: &str, context: &str) -> io::Result<SocketHandles> {
        let fresh = resolve_first(target)?;

        // Compare against previous before updating to compute correct family flip
        let (fam_flip, changed) = {
            let mut cur = self.upstream_addr.lock().unwrap();
            let prev = *cur;
            let changed = prev.ip() != fresh.ip();
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
            log_info!("{context}: upstream {fresh} (family changed; upstream socket swapped)");
            // Family changed: create a new **connected** upstream socket and swap it in.
            let (new_sock, _new_dest) = make_upstream_socket_for(fresh, self.upstream_proto)?;
            {
                let mut guard = self.upstream_sock.lock().unwrap();
                *guard = new_sock.try_clone()?;
            }
            new_sock
        } else if changed {
            log_info!("{context}: upstream {fresh}");
            // Same family, different address: reconnect existing socket in place.
            let saddr = SockAddr::from(fresh);
            let guard = self.upstream_sock.lock().unwrap();
            guard.connect(&saddr)?;
            // Return a clone of the now-updated internal socket
            guard.try_clone()?
        } else {
            // No change: just return a clone of the current socket
            self.upstream_sock.lock().unwrap().try_clone()?
        };

        let ver = if fam_flip || changed {
            // publish that upstream changed; readers can refresh lazily
            self.version.fetch_add(1, AtomOrdering::Relaxed) + 1
        } else {
            self.version.load(AtomOrdering::Relaxed)
        };

        // Return up-to-date handles to the caller without re-locking other getters
        Ok(SocketHandles {
            client_addr: *self.client_addr.lock().unwrap(),
            client_connected: *self.client_connected.lock().unwrap(),
            client_sock: self.clone_client_socket(),
            upstream_addr: fresh,
            upstream_connected: self.upstream_connected,
            upstream_sock: ret_sock,
            version: ver,
        })
    }

    /// Optional periodic re-resolve while locked.
    pub fn spawn_periodic(self: &Arc<Self>, cfg: Arc<Config>, locked: Arc<AtomicBool>) -> bool {
        if cfg.reresolve_secs == 0 {
            return false;
        }
        // Single-init gate like stats thread: only allow one periodic worker.
        if self
            .spawned
            .compare_exchange(false, true, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
            .is_err()
        {
            return false; // already running
        }
        let mgr = Arc::clone(self);
        thread::spawn(move || {
            let period = Duration::from_secs(cfg.reresolve_secs);
            loop {
                thread::sleep(period);
                if !locked.load(AtomOrdering::Relaxed) {
                    continue;
                }
                let _ = mgr.apply_fresh(&cfg.upstream_addr, "Periodic re-resolve");
            }
        });
        true
    }

    /// Current version for lock-free checks in hot paths.
    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(AtomOrdering::Relaxed)
    }

    /// Clone sockets and destination (cold path under mutexes).
    /// Use this only when your cached version != `version()`.
    #[inline]
    pub fn refresh_handles(&self) -> SocketHandles {
        SocketHandles {
            client_addr: *self.client_addr.lock().unwrap(),
            client_connected: *self.client_connected.lock().unwrap(),
            client_sock: self.clone_client_socket(),
            upstream_addr: self.upstream_dest().0,
            upstream_connected: self.upstream_connected,
            upstream_sock: self.clone_upstream_socket(),
            version: self.version(),
        }
    }

    /// Expose the local listener socket.
    #[inline]
    pub fn clone_client_socket(&self) -> Socket {
        let guard = self.client_sock.lock().unwrap();
        guard.try_clone().expect("clone client socket")
    }

    /// Back-compat: clone the upstream socket only (cold path). Prefer `refresh_handles`.
    #[inline]
    pub fn clone_upstream_socket(&self) -> Socket {
        let guard = self.upstream_sock.lock().unwrap();
        guard.try_clone().expect("clone upstream socket")
    }
}
