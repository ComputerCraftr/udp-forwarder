use crate::cli::SupportedProtocol;
use crate::net::{
    family_changed, make_socket, make_upstream_socket_for, resolve_first, udp_disconnect,
};
use socket2::{SockAddr, Socket};

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};

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

/// Manages both local and upstream sockets and publishes versioned updates. Lock order: _addr -> _addr_connected -> _sock
pub struct SocketManager {
    client_addr_connected: Mutex<(Option<SocketAddr>, bool)>, // cold-path updates only
    client_sock: Mutex<Socket>,                               // shared listener socket
    listen_addr: Mutex<SocketAddr>,                           // current bound address
    listen_target: String,                                    // unresolved --here host:port
    listen_proto: SupportedProtocol,                          // never changes
    upstream_target: String,                                  // unresolved --there host:port
    upstream_addr_connected: Mutex<(SocketAddr, bool)>,       // cold-path updates only
    upstream_proto: SupportedProtocol,                        // never changes
    upstream_sock: Mutex<Socket>,                             // cold-path replacement only
    version: AtomicU64,                                       // increments on any change
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
            client_addr_connected: Mutex::new((None, false)),
            client_sock: Mutex::new(client_sock),
            listen_addr: Mutex::new(listen_addr),
            listen_target,
            listen_proto,
            upstream_target,
            upstream_addr_connected: Mutex::new((dest, true)),
            upstream_proto,
            upstream_sock: Mutex::new(sock),
            version: AtomicU64::new(0),
        })
    }

    /// Current version for lock-free checks in hot paths.
    #[inline]
    pub fn get_version(&self) -> u64 {
        self.version.load(AtomOrdering::Relaxed)
    }

    /// Bump and return the version when `changed` is true; otherwise, return the current version.
    #[inline]
    fn publish_version(&self, changed: bool) -> u64 {
        if changed {
            self.version.fetch_add(1, AtomOrdering::Relaxed) + 1
        } else {
            self.version.load(AtomOrdering::Relaxed)
        }
    }

    /// Whether the listener socket is currently connected to a client.
    #[inline]
    pub fn get_client_connected(&self) -> bool {
        self.client_addr_connected.lock().unwrap().1
    }

    /// Update the locked client address/connected state and publish a new version.
    ///
    /// Returns `prev_ver + 1` so callers with a stale cached version stay stale
    /// and will refresh on the next hot-path check, even if other updates raced
    /// and advanced the global version further.
    #[inline]
    pub fn set_client_addr_connected(
        &self,
        addr: Option<SocketAddr>,
        connected: bool,
        prev_ver: u64,
    ) -> u64 {
        *self.client_addr_connected.lock().unwrap() = (addr, connected);
        self.publish_version(true);
        prev_ver + 1
    }

    /// Disconnect the local listener socket.
    #[inline]
    pub fn set_client_sock_disconnected(&self) -> io::Result<()> {
        // Use a clone because the original may not be marked as connected
        udp_disconnect(&self.client_sock.lock().unwrap().try_clone()?)
    }

    /// Current listen bind address.
    #[inline]
    pub fn get_listen_addr(&self) -> SocketAddr {
        *self.listen_addr.lock().unwrap()
    }

    /// Snapshot the current client destination/connected state and protocol.
    #[inline]
    pub fn get_client_dest(&self) -> (Option<SocketAddr>, bool, SupportedProtocol) {
        let (addr, connected) = *self.client_addr_connected.lock().unwrap();
        (addr, connected, self.listen_proto)
    }

    /// Snapshot the current upstream destination and protocol.
    #[inline]
    pub fn get_upstream_dest(&self) -> (SocketAddr, bool, SupportedProtocol) {
        let (addr, connected) = *self.upstream_addr_connected.lock().unwrap();
        (addr, connected, self.upstream_proto)
    }

    fn reresolve_upstream(&self, context: &str) -> io::Result<(Socket, SocketAddr, bool)> {
        let fresh = resolve_first(&self.upstream_target)?;

        // Compare against previous before updating to compute correct family flip
        let mut upstream_guard = self.upstream_addr_connected.lock().unwrap();
        let (fam_flip, changed) = {
            let (prev_addr, _prev_conn) = *upstream_guard;
            let changed = prev_addr.ip() != fresh.ip();
            let fam_flip = if changed {
                *upstream_guard = (fresh, true);
                family_changed(prev_addr, fresh)
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
            *self.upstream_sock.lock().unwrap() = new_sock.try_clone()?;
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

    fn reresolve_listen(
        &self,
        context: &str,
    ) -> io::Result<(Socket, Option<SocketAddr>, bool, SocketAddr, bool)> {
        let fresh = resolve_first(&self.listen_target)?;

        let mut listen_guard = self.listen_addr.lock().unwrap();
        let (fam_flip, changed) = {
            let prev_addr = *listen_guard;
            let changed = prev_addr.ip() != fresh.ip();
            let fam_flip = if changed {
                *listen_guard = fresh;
                family_changed(prev_addr, fresh)
            } else {
                false
            };
            (fam_flip, changed)
        };

        let (ret_sock, caddr, cconn, laddr) = if fam_flip || changed {
            log_info!("{context}: listen {fresh} (listener swapped)");
            let (new_sock, actual_bind) = make_socket(
                fresh,
                self.listen_proto,
                1000,
                false,
                self.listen_proto == SupportedProtocol::ICMP,
            )?;

            // Update the internal socket state
            let mut client_guard = self.client_addr_connected.lock().unwrap();
            let mut client_sock_guard = self.client_sock.lock().unwrap();
            *listen_guard = actual_bind;
            *client_guard = (None, false);
            *client_sock_guard = new_sock.try_clone()?;
            (new_sock, None, false, actual_bind)
        } else {
            let client_guard = self.client_addr_connected.lock().unwrap();
            let client_sock_guard = self.client_sock.lock().unwrap();
            (
                client_sock_guard.try_clone()?,
                client_guard.0,
                client_guard.1,
                fresh,
            )
        };

        Ok((ret_sock, caddr, cconn, laddr, fam_flip || changed))
    }

    /// Re-resolve both ends and publish any changes. When `allow_listen_rebind`
    /// is true, the listening socket may be swapped if the --here DNS changes.
    /// Returns handles and a flag indicating whether the listener changed.
    pub fn reresolve(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
    ) -> io::Result<SocketHandles> {
        if !allow_upstream && !allow_listen_rebind {
            return Ok(self.refresh_handles());
        }

        let (client_sock, client_addr, client_connected, listen_changed) = if allow_listen_rebind {
            let res = self.reresolve_listen(context)?;
            (res.0, res.1, res.2, res.4)
        } else {
            let client_guard = self.client_addr_connected.lock().unwrap();
            let client_sock_guard = self.client_sock.lock().unwrap();
            (
                client_sock_guard.try_clone()?,
                client_guard.0,
                client_guard.1,
                false,
            )
        };

        let (upstream_sock, upstream_addr, upstream_connected, upstream_changed) = if allow_upstream
        {
            let res = self.reresolve_upstream(context)?;
            (res.0, res.1, true, res.2)
        } else {
            let upstream_guard = self.upstream_addr_connected.lock().unwrap();
            let upstream_sock_guard = self.upstream_sock.lock().unwrap();
            (
                upstream_sock_guard.try_clone()?,
                upstream_guard.0,
                upstream_guard.1,
                false,
            )
        };

        let changed_any = listen_changed || upstream_changed;
        let version = self.publish_version(changed_any);

        Ok(SocketHandles {
            client_addr,
            client_connected,
            client_sock,
            upstream_addr,
            upstream_connected,
            upstream_sock,
            version,
        })
    }

    /// Clone sockets and destination (cold path under mutexes).
    /// Use this only when your cached version != `version()`.
    #[inline]
    pub fn refresh_handles(&self) -> SocketHandles {
        // Snapshot all mutable state while holding the relevant locks so the
        // returned version matches the handles we hand back.
        let client_guard = self.client_addr_connected.lock().unwrap();
        let client_sock_guard = self.client_sock.lock().unwrap();
        let upstream_guard = self.upstream_addr_connected.lock().unwrap();
        let upstream_sock_guard = self.upstream_sock.lock().unwrap();

        SocketHandles {
            client_addr: client_guard.0,
            client_connected: client_guard.1,
            client_sock: client_sock_guard.try_clone().expect("clone client socket"),
            upstream_addr: upstream_guard.0,
            upstream_connected: upstream_guard.1,
            upstream_sock: upstream_sock_guard
                .try_clone()
                .expect("clone upstream socket"),
            version: self.get_version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::thread;

    fn make_mgr() -> SocketManager {
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (client_sock, actual_listen) =
            make_socket(listen_addr, SupportedProtocol::UDP, 1000, false, false).unwrap();

        let upstream_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind upstream udp");
        let upstream_addr = upstream_sock.local_addr().unwrap();

        SocketManager::new(
            client_sock,
            actual_listen,
            actual_listen.to_string(),
            SupportedProtocol::UDP,
            upstream_addr.to_string(),
            SupportedProtocol::UDP,
        )
        .expect("create socket manager")
    }

    #[test]
    fn client_setter_keeps_callers_stale() {
        let mgr = Arc::new(make_mgr());
        let v0 = mgr.get_version();

        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11111);
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22222);

        let a = {
            let mgr = Arc::clone(&mgr);
            thread::spawn(move || mgr.set_client_addr_connected(Some(addr_a), true, v0))
        };
        let b = {
            let mgr = Arc::clone(&mgr);
            thread::spawn(move || mgr.set_client_addr_connected(Some(addr_b), false, v0))
        };

        let ra = a.join().unwrap();
        let rb = b.join().unwrap();

        assert_eq!(ra, v0 + 1);
        assert_eq!(rb, v0 + 1);
        assert_eq!(mgr.get_version(), v0 + 2);
    }

    #[test]
    fn refresh_notices_raced_updates() {
        let mgr = make_mgr();
        let mut cached = mgr.refresh_handles();
        let v0 = cached.version;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
        let _ = mgr.set_client_addr_connected(Some(addr), true, v0);
        let _ = mgr.set_client_addr_connected(Some(addr), false, v0);

        assert_ne!(cached.version, mgr.get_version());
        cached = mgr.refresh_handles();
        assert_eq!(cached.version, mgr.get_version());
        assert_eq!(cached.client_addr, Some(addr));
        assert!(!cached.client_connected);
    }
}
