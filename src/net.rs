use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::time::{Duration, Instant};

use crate::stats::Stats;

use socket2::{Domain, Protocol, Socket, Type};

#[inline]
pub fn send_payload(
    c2u: bool,
    connected: bool,
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
    let stats_drop_oversize = |c2u, stats: &Stats| {
        if c2u {
            stats.drop_c2u_oversize();
        } else {
            stats.drop_u2c_oversize();
        }
    };

    let stats_err = |c2u, stats: &Stats| {
        if c2u {
            stats.c2u_err();
        } else {
            stats.u2c_err();
        }
    };

    let payload_send =
        |connected: bool, sock: &UdpSocket, buf: &[u8], len: usize, dest: SocketAddr| {
            if connected {
                return sock.send(&buf[..len]);
            } else {
                return sock.send_to(&buf[..len], dest);
            }
        };

    let stats_add = |c2u, stats: &Stats, len: usize, t_recv: Instant, t_send: Instant| {
        if c2u {
            stats.add_c2u(len as u64, t_recv, t_send);
        } else {
            stats.add_u2c(len as u64, t_recv, t_send);
        }
    };

    if max_payload != 0 && len > max_payload {
        eprintln!("dropping packet: {} bytes exceeds max {}", len, max_payload);
        stats_drop_oversize(c2u, stats);
    } else if let Err(e) = payload_send(connected, sock, buf, len, dest) {
        eprintln!("send {} error: {}", dest, e);
        stats_err(c2u, stats);
    } else {
        let t_send = Instant::now();
        last_seen.store(Stats::dur_ns(t_start, t_send), AtomOrdering::Relaxed);
        stats_add(c2u, stats, len, t_recv, t_send);
    }
}

pub fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no address resolved"))
}

pub fn make_udp_socket(
    bind_addr: SocketAddr,
    read_timeout_ms: u64,
    reuseaddr: bool,
) -> io::Result<UdpSocket> {
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    // Construct a socket from scratch
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Allow SO_REUSEADDR for multi-threading
    if reuseaddr {
        sock.set_reuse_address(true)?;
    }

    // Best-effort bigger buffers
    sock.set_recv_buffer_size(1 << 20)?;
    sock.set_send_buffer_size(1 << 20)?;

    // Convert into UdpSocket
    sock.bind(&bind_addr.into())?;
    let udp_sock: UdpSocket = sock.into();

    // Set inactive timeout between upstream manager refreshes
    if read_timeout_ms == 0 {
        udp_sock.set_read_timeout(None)?; // block forever
    } else {
        udp_sock.set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))?;
    }
    Ok(udp_sock)
}

pub fn make_upstream_socket_for(dest: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = match dest {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let sock = make_udp_socket(bind_addr, 5000, false)?;
    sock.connect(dest)?;
    Ok(sock)
}

pub fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    !matches!(
        (a, b),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

/// Disconnect a connected UDP socket so it returns to wildcard receive state.
///
/// macOS/*BSD man page: datagram sockets may dissolve the association by
/// connecting to an invalid address (NULL or AF_UNSPEC). The error
/// EAFNOSUPPORT may be harmlessly returned; consider it success.
#[cfg(unix)]
pub fn udp_disconnect(sock: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();

    // Interpret connect() rc correctly per platform.
    #[inline]
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn ok_or_eafnosupport(rc: i32) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAFNOSUPPORT) {
                // macOS/*BSD man page: harmless when disconnecting UDP
                Ok(())
            } else {
                Err(err)
            }
        }
    }

    // On non-BSD Unix (Linux/Android), do NOT ignore EAFNOSUPPORT.
    #[inline]
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    fn ok_or_eafnosupport(rc: i32) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    // --- macOS / iOS / *BSD: try AF_UNSPEC first, then NULL ---
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    {
        // sockaddr WITH sa_len on these platforms
        let addr = libc::sockaddr {
            sa_len: std::mem::size_of::<libc::sockaddr>() as u8,
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr,
                addr.sa_len as libc::socklen_t,
            )
        };
        if ok_or_eafnosupport(rc).is_ok() {
            return Ok(());
        }

        // Fallback: connect(fd, NULL, 0)
        let rc2 = unsafe { libc::connect(fd, std::ptr::null(), 0) };
        return ok_or_eafnosupport(rc2);
    }

    // --- Linux/Android: AF_UNSPEC is the standard way; no sa_len field. ---
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    {
        let addr = libc::sockaddr {
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };
        return ok_or_eafnosupport(rc);
    }
}

/// Windows: disconnect a UDP socket by connecting to INADDR_ANY/IN6ADDR_ANY and port 0.
#[cfg(windows)]
pub fn udp_disconnect(sock: &UdpSocket) -> io::Result<()> {
    let local = sock.local_addr()?;
    let any = match local {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    // Winsock treats connect(INADDR_ANY/IN6ADDR_ANY:0) as clearing the UDP peer
    sock.connect(any)
}

/// Fallback: not supported on this platform.
#[cfg(all(not(unix), not(windows)))]
pub fn udp_disconnect(_sock: &UdpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "udp_disconnect is not supported on this OS",
    ))
}
