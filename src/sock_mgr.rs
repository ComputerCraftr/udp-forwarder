use crate::cli::SupportedProtocol;
use crate::net::{family_changed, make_socket, make_upstream_socket_for, resolve_first};
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
    client_sock: Mutex<Socket>,        // shared listener socket
    listen_addr: Mutex<SocketAddr>,    // current bound address
    listen_target: String,             // unresolved --here host:port
    listen_proto: SupportedProtocol,   // never changes
    upstream_target: String,           // unresolved --there host:port
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
        listen_addr: SocketAddr,
        listen_target: String,
        listen_proto: SupportedProtocol,
        upstream_target: String,
        upstream_proto: SupportedProtocol,
    ) -> io::Result<Self> {
        let dest = resolve_first(&upstream_target)?;
        let (sock, _actual_dest) = make_upstream_socket_for(dest, upstream_proto)?;
        Ok(Self {
            client_addr: Mutex::new(None),
            client_connected: Mutex::new(false),
            client_sock: Mutex::new(client_sock),
            listen_addr: Mutex::new(listen_addr),
            listen_target,
            listen_proto,
            upstream_target,
            upstream_addr: Mutex::new(dest),
            upstream_connected: true,
            upstream_proto,
            upstream_sock: Mutex::new(sock),
            version: AtomicU64::new(0),
            spawned: AtomicBool::new(false),
        })
    }

    /// Current version for lock-free checks in hot paths.
    #[inline]
    pub fn get_version(&self) -> u64 {
        self.version.load(AtomOrdering::Relaxed)
    }

    #[inline]
    pub fn get_client_connected(&self) -> bool {
        *self.client_connected.lock().unwrap()
    }

    #[inline]
    pub fn set_client_addr_connected(
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

    /// Current listen bind address.
    #[inline]
    pub fn get_listen_addr(&self) -> SocketAddr {
        *self.listen_addr.lock().unwrap()
    }

    #[inline]
    pub fn get_client_dest(&self) -> (Option<SocketAddr>, bool, SupportedProtocol) {
        (
            *self.client_addr.lock().unwrap(),
            *self.client_connected.lock().unwrap(),
            self.listen_proto,
        )
    }

    #[inline]
    pub fn get_upstream_dest(&self) -> (SocketAddr, bool, SupportedProtocol) {
        (
            *self.upstream_addr.lock().unwrap(),
            self.upstream_connected,
            self.upstream_proto,
        )
    }

    fn reresolve_upstream(&self, context: &str) -> io::Result<(Socket, SocketAddr, bool)> {
        let fresh = resolve_first(&self.upstream_target)?;

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

        Ok((ret_sock, fresh, fam_flip || changed))
    }

    fn reresolve_listen(&self, context: &str) -> io::Result<(Socket, SocketAddr, bool)> {
        let fresh = resolve_first(&self.listen_target)?;

        let (fam_flip, changed) = {
            let mut cur = self.listen_addr.lock().unwrap();
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

        let ret_sock = if fam_flip || changed {
            log_info!("{context}: listen {fresh} (listener swapped)");
            let (new_sock, actual_bind) = make_socket(
                fresh,
                self.listen_proto,
                1000,
                false,
                self.listen_proto == SupportedProtocol::ICMP,
            )?;
            {
                *self.client_addr.lock().unwrap() = None;
                *self.client_connected.lock().unwrap() = false;
                *self.client_sock.lock().unwrap() = new_sock.try_clone()?;
                *self.listen_addr.lock().unwrap() = actual_bind;
            }
            new_sock
        } else {
            self.clone_client_socket()
        };

        Ok((
            ret_sock,
            *self.listen_addr.lock().unwrap(),
            fam_flip || changed,
        ))
    }

    /// Re-resolve both ends and publish any changes. When `allow_listen_rebind`
    /// is true, the listening socket may be swapped if the --here DNS changes.
    /// Returns handles and a flag indicating whether the listener changed.
    pub fn reresolve(
        &self,
        allow_listen_rebind: bool,
        context: &str,
    ) -> io::Result<(SocketHandles, bool)> {
        let (up_sock, up_addr, up_changed) = self.reresolve_upstream(context)?;

        let (client_sock, _listen_addr, listen_changed) = if allow_listen_rebind {
            let res = self.reresolve_listen(context)?;
            (res.0, Some(res.1), res.2)
        } else {
            (self.clone_client_socket(), None, false)
        };

        let changed_any = up_changed || listen_changed;
        let ver = if changed_any {
            self.version.fetch_add(1, AtomOrdering::Relaxed) + 1
        } else {
            self.version.load(AtomOrdering::Relaxed)
        };

        Ok((
            SocketHandles {
                client_addr: *self.client_addr.lock().unwrap(),
                client_connected: *self.client_connected.lock().unwrap(),
                client_sock,
                upstream_addr: up_addr,
                upstream_connected: self.upstream_connected,
                upstream_sock: up_sock,
                version: ver,
            },
            listen_changed,
        ))
    }

    /// Optional periodic re-resolve while locked.
    pub fn spawn_periodic(
        self: &Arc<Self>,
        reresolve_secs: u64,
        allow_listen_rebind: bool,
    ) -> bool {
        if reresolve_secs == 0 {
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
            let period = Duration::from_secs(reresolve_secs);
            loop {
                thread::sleep(period);
                let _ = mgr.reresolve(allow_listen_rebind, "Periodic re-resolve");
            }
        });
        true
    }

    /// Clone sockets and destination (cold path under mutexes).
    /// Use this only when your cached version != `version()`.
    #[inline]
    pub fn refresh_handles(&self) -> SocketHandles {
        SocketHandles {
            client_addr: *self.client_addr.lock().unwrap(),
            client_connected: *self.client_connected.lock().unwrap(),
            client_sock: self.clone_client_socket(),
            upstream_addr: self.get_upstream_dest().0,
            upstream_connected: self.upstream_connected,
            upstream_sock: self.clone_upstream_socket(),
            version: self.get_version(),
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
