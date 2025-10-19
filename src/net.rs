use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::time::{Duration, Instant};

use crate::stats::Stats;

#[inline]
pub fn send_payload(
    c2u: bool,
    t_start: Instant,
    t_recv: Instant,
    max_payload: usize,
    stats: &Stats,
    last_seen: &AtomicU64,
    sock: &UdpSocket,
    buf: &[u8],
    len: usize,
    dest: SocketAddr,
) {
    if max_payload != 0 && len > max_payload {
        eprintln!("dropping packet: {} bytes exceeds max {}", len, max_payload);
        if c2u {
            stats.drop_c2u_oversize();
        } else {
            stats.drop_u2c_oversize();
        }
    } else if let Err(e) = sock.send_to(&buf[..len], dest) {
        eprintln!("send_to {} error: {}", dest, e);
        if c2u {
            stats.c2u_err();
        } else {
            stats.u2c_err();
        }
    } else {
        let t_send = Instant::now();
        last_seen.store(Stats::dur_ns(t_start, t_send), AtomOrdering::Relaxed);
        if c2u {
            stats.add_c2u(len as u64, t_recv, t_send);
        } else {
            stats.add_u2c(len as u64, t_recv, t_send);
        }
    }
}

pub fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no address resolved"))
}

pub fn make_udp_socket(bind_addr: SocketAddr, read_timeout_ms: u64) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(bind_addr)?;
    if read_timeout_ms == 0 {
        sock.set_read_timeout(None)?; // block forever
    } else {
        sock.set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))?;
    }
    Ok(sock)
}

pub fn make_upstream_socket_for(dest: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = match dest {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    make_udp_socket(bind_addr, 5000)
}

pub fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    !matches!(
        (a, b),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}
