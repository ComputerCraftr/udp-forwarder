use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

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
