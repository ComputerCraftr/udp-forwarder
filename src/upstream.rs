use crate::net::{family_changed, make_upstream_socket_for, resolve_first};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Manages current upstream destination and a hot-swappable UdpSocket.
pub struct UpstreamManager {
    pub current_addr: Arc<Mutex<SocketAddr>>,
    pub sock: Arc<Mutex<std::net::UdpSocket>>,
}

impl UpstreamManager {
    pub fn new(initial_target: &str) -> io::Result<Self> {
        let addr = resolve_first(initial_target)?;
        let sock = make_upstream_socket_for(addr)?;
        Ok(Self {
            current_addr: Arc::new(Mutex::new(addr)),
            sock: Arc::new(Mutex::new(sock)),
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
                if !locked.load(AtomOrdering::SeqCst) {
                    continue;
                }
                mgr.apply_fresh(&target, "Periodic re-resolve");
            }
        });
    }

    /// Clone the socket cheaply for a send/recv call.
    pub fn clone_socket(&self) -> std::net::UdpSocket {
        self.sock
            .lock()
            .unwrap()
            .try_clone()
            .expect("clone upstream socket")
    }
}
