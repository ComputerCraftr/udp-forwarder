use crate::cli::{Config, SupportedProtocol};
use crate::stats::Stats;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering as AtomOrdering};
use std::time::{Duration, Instant};

#[inline(always)]
fn be16_16(b0: u8, b1: u8) -> u16 {
    ((b0 as u16) << 8) | (b1 as u16)
}

#[inline(always)]
fn be16_32(b0: u8, b1: u8) -> u32 {
    ((b0 as u32) << 8) | (b1 as u32)
}

/// Create a socket (UDP datagram or raw ICMP) bound to `bind_addr`.
pub fn make_socket(
    bind_addr: SocketAddr,
    proto: SupportedProtocol,
    read_timeout_ms: u64,
    reuseaddr: bool,
) -> io::Result<Socket> {
    // Raw ICMP: use well-known protocol numbers cross-platform
    // IPv4: 1, IPv6: 58
    let (domain, pnum) = match bind_addr {
        SocketAddr::V6(_) => (Domain::IPV6, 58),
        _ => (Domain::IPV4, 1),
    };

    // Select socket type and protocol per requested transport
    let (sock_type, sock_proto) = match proto {
        SupportedProtocol::ICMP => (Type::from(3), Some(Protocol::from(pnum))), // SOCK_RAW = 3
        _ => (Type::DGRAM, Some(Protocol::UDP)),
    };

    let sock = Socket::new(domain, sock_type, sock_proto)?;

    if reuseaddr {
        sock.set_reuse_address(true)?;
    }

    // Best-effort bigger buffers
    sock.set_recv_buffer_size(1 << 20)?;
    sock.set_send_buffer_size(1 << 20)?;

    // Bind
    let bind_sa = SockAddr::from(bind_addr);
    sock.bind(&bind_sa)?;

    // Read timeout
    sock.set_read_timeout(if read_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(read_timeout_ms))
    })?;

    Ok(sock)
}

#[inline]
pub fn send_payload(
    c2u: bool,
    connected: bool,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &Stats,
    last_seen: &AtomicU64,
    sock: &Socket,
    buf: &[u8],
    dest: SocketAddr,
    recv: SocketAddr,
    debug: bool,
) {
    // Direction-local helpers
    let stats_drop_oversize = |c2u: bool, stats: &Stats| {
        if c2u {
            stats.drop_c2u_oversize()
        } else {
            stats.drop_u2c_oversize()
        }
    };
    let stats_err = |c2u: bool, stats: &Stats| {
        if c2u {
            stats.c2u_err()
        } else {
            stats.u2c_err()
        }
    };
    let stats_add = |c2u: bool, stats: &Stats, len: usize, t_recv: Instant, t_send: Instant| {
        if c2u {
            stats.add_c2u(len as u64, t_recv, t_send)
        } else {
            stats.add_u2c(len as u64, t_recv, t_send)
        }
    };

    // Determine source/destination protocol for this direction once.
    let (src_proto, dst_proto) = if c2u {
        (cfg.listen_proto, cfg.upstream_proto)
    } else {
        (cfg.upstream_proto, cfg.listen_proto)
    };

    // If the source side was ICMP, strip the 8-byte Echo header before forwarding.
    let (payload, src_ident, src_is_req) = if matches!(src_proto, SupportedProtocol::ICMP) {
        match parse_icmp_echo_header(buf) {
            Ok((p, ident, is_req)) => (p, ident, is_req),
            Err(e) => {
                if debug {
                    eprintln!("Dropping packet: Invalid ICMP echo frame ({e})");
                }
                stats_err(c2u, stats);
                return;
            }
        }
    } else {
        (buf, recv.port(), c2u)
    };
    // If this is the client->upstream direction and we received an ICMP Echo *reply* or
    // upstream->client and we received an ICMP Echo *request*, drop it to avoid feedback loops.
    // Also, ignore all packets with the wrong identity field.
    if c2u != src_is_req || src_ident != recv.port() {
        // Not an error; just ignore replies from the client side.
        return;
    }

    // Size check on the normalized payload.
    let len = payload.len();
    if cfg.max_payload != 0 && len > cfg.max_payload {
        if debug {
            eprintln!(
                "Dropping packet: {} bytes exceeds max {}",
                len, cfg.max_payload
            );
        }
        stats_drop_oversize(c2u, stats);
        return;
    }

    // Send according to destination protocol and connection state.
    let send_res = match dst_proto {
        SupportedProtocol::ICMP => {
            send_icmp_echo(sock, dest, dest.port(), !c2u, payload, connected)
        }
        _ => {
            if connected {
                sock.send(payload)
            } else {
                let dest_sa = SockAddr::from(dest);
                sock.send_to(payload, &dest_sa)
            }
        }
    };

    match send_res {
        Ok(_) => {
            let t_send = Instant::now();
            last_seen.store(Stats::dur_ns(t_start, t_send), AtomOrdering::Relaxed);
            stats_add(c2u, stats, len, t_recv, t_send);
        }
        Err(e) => {
            if debug {
                eprintln!("Send to '{}' error: {}", dest, e);
            }
            stats_err(c2u, stats);
        }
    }
}

#[inline]
fn parse_icmp_echo_header(buf: &[u8]) -> io::Result<(&[u8], u16, bool)> {
    // Some OSes (notably Linux for IPv4 raw sockets) deliver the full IP header
    // followed by the ICMP message. Others deliver only the ICMP message.
    // We normalize by skipping an IP header if present, validate it's ICMP(v6),
    // then verify Echo type/code and strip the 8-byte ICMP Echo header.

    if buf.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP frame too short",
        ));
    }

    let mut off = 0usize;

    // Detect IPv4 header (version 4 in high nibble). If present, skip it.
    let v = buf[0] >> 4;
    if v == 4 {
        if buf.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPv4 header too short",
            ));
        }
        let ihl = ((buf[0] & 0x0F) as usize) * 4; // IHL in 32-bit words
        if ihl < 20 || buf.len() < ihl + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid IPv4 IHL or short frame",
            ));
        }
        // IPv4 protocol field must be ICMP (1)
        if buf[9] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPv4 next protocol is not ICMP",
            ));
        }
        off = ihl;
    } else if v == 6 {
        // Some stacks may include the IPv6 header; many deliver only the ICMPv6 msg.
        // If an IPv6 header seems present (version 6 and length >= 40), and Next Header is 58 (ICMPv6), skip 40.
        if buf.len() >= 40 {
            let next_header = buf[6]; // IPv6 Next Header
            if next_header == 58 {
                off = 40;
            }
        }
        if buf.len() < off + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Short ICMPv6 frame",
            ));
        }
    }
    // Else no IP header; assume buf starts at ICMP header.

    // Validate ICMP/ICMPv6 Echo [request/reply] and strip 8-byte header.
    // ICMPv4 Echo: type=8 (req) / 0 (reply), code=0
    // ICMPv6 Echo: type=128 (req) / 129 (reply), code=0
    let t = buf[off];
    let c = buf[off + 1];
    if c != 0 || !matches!(t, 8 | 0 | 128 | 129) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected ICMP type/code: {t}/{c}"),
        ));
    }
    // Identifier is bytes 4..6 of the ICMP Echo header (for both v4 and v6 Echo).
    let ident = be16_16(buf[off + 4], buf[off + 5]);
    let is_request = matches!(t, 8 | 128);
    Ok((&buf[off + 8..], ident, is_request))
}

/// Send an ICMP Echo Request or Reply (IPv4 or IPv6).
fn send_icmp_echo(
    sock: &Socket,
    dest: SocketAddr,
    ident: u16,
    reply: bool,
    payload: &[u8],
    connected: bool,
) -> io::Result<usize> {
    static ICMP_SEQ: AtomicU16 = AtomicU16::new(1);

    let mut buf: Vec<u8> = Vec::with_capacity(8 + payload.len());
    let seq = ICMP_SEQ.fetch_add(1, AtomOrdering::Relaxed);

    match dest {
        SocketAddr::V6(_) => {
            // ICMPv6 Echo Request: type=128, code=0, checksum kernel-calculated (IPV6_CHECKSUM)
            let t = 128u8 + (reply as u8); // 128=req, 129=rep
            buf.extend_from_slice(&[t, 0u8, 0, 0]); // checksum filled by kernel if supported
            buf.extend_from_slice(&ident.to_be_bytes());
            buf.extend_from_slice(&seq.to_be_bytes());
            buf.extend_from_slice(payload);
        }
        _ => {
            // ICMPv4 Echo Request: type=8, code=0, cksum (later), id, seq
            let t = 8u8.wrapping_mul((!reply) as u8); // 8=req, 0=rep
            buf.extend_from_slice(&[t, 0u8, 0, 0]); // type, code, checksum placeholder
            buf.extend_from_slice(&ident.to_be_bytes());
            buf.extend_from_slice(&seq.to_be_bytes());
            buf.extend_from_slice(payload);
            let cksum = checksum16(&buf);
            buf[2] = (cksum >> 8) as u8;
            buf[3] = (cksum & 0xFF) as u8;
        }
    }

    if connected {
        sock.send(&buf)
    } else {
        let dest_sa = SockAddr::from(dest);
        sock.send_to(&buf, &dest_sa)
    }
}

/// Create and connect a socket suitable for forwarding data to `dest`.
pub fn make_upstream_socket_for(dest: SocketAddr, proto: SupportedProtocol) -> io::Result<Socket> {
    let bind_addr = match dest {
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };

    let sock = make_socket(bind_addr, proto, 5000, false)?;

    let dest_sa = SockAddr::from(dest);
    sock.connect(&dest_sa)?;

    Ok(sock)
}

#[inline]
pub fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    // Fast path: direct SocketAddr parse (no DNS, no allocations).
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }

    // Fallback: resolve host:port or [IPv6]:port via DNS.
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No address resolved"))
}

#[inline]
pub fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => false,
        _ => true,
    }
}

/// Disconnect a connected UDP socket so it returns to wildcard receive state.
///
/// macOS/*BSD man page: datagram sockets may dissolve the association by
/// connecting to an invalid address (NULL or AF_UNSPEC). The error
/// EAFNOSUPPORT may be harmlessly returned; consider it success.
#[cfg(unix)]
pub fn udp_disconnect(sock: &Socket) -> io::Result<()> {
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
pub fn udp_disconnect(sock: &Socket) -> io::Result<()> {
    let local = sock.local_addr()?;
    let any_std = match local.as_socket() {
        Some(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    // Winsock treats connect(INADDR_ANY/IN6ADDR_ANY:0) as clearing the UDP peer
    let any = SockAddr::from(any_std);
    sock.connect(&any)
}

/// Fallback: not supported on this platform.
#[cfg(all(not(unix), not(windows)))]
pub fn udp_disconnect(_sock: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Function udp_disconnect is not supported on this OS",
    ))
}

/// Compute the Internet Checksum (RFC 1071) for ICMPv4 header+payload.
#[inline(always)]
fn checksum16(data: &[u8]) -> u16 {
    // 32-bit accumulator is fine with periodic carry fold; keep in u32 for register fit.
    let mut sum: u32 = 0;
    let n = data.len();

    if n < 128 {
        // Small/latency path: tight 2-byte pairs loop; no arrays, no extra branches.
        let mut pairs = data.chunks_exact(2);
        for p in &mut pairs {
            // p has length 2 exactly
            sum = sum.wrapping_add(be16_32(p[0], p[1]));
        }
        // Odd tail: last byte is the high byte of the final 16-bit word
        if (n & 1) != 0 {
            sum = sum.wrapping_add((data[n - 1] as u32) << 8);
        }
    } else if n < 256 {
        // Mid-size: 16-byte unroll (8 words per iter)
        let mut chunks16 = data.chunks_exact(16);
        for c in &mut chunks16 {
            sum = sum
                .wrapping_add(be16_32(c[0], c[1]))
                .wrapping_add(be16_32(c[2], c[3]))
                .wrapping_add(be16_32(c[4], c[5]))
                .wrapping_add(be16_32(c[6], c[7]))
                .wrapping_add(be16_32(c[8], c[9]))
                .wrapping_add(be16_32(c[10], c[11]))
                .wrapping_add(be16_32(c[12], c[13]))
                .wrapping_add(be16_32(c[14], c[15]));
        }
        let rem = chunks16.remainder();
        let mut pairs = rem.chunks_exact(2);
        for p in &mut pairs {
            sum = sum.wrapping_add(be16_32(p[0], p[1]));
        }
        if (rem.len() & 1) != 0 {
            sum = sum.wrapping_add((rem[rem.len() - 1] as u32) << 8);
        }
    } else {
        // Throughput path for larger payloads.
        // Use a 32-byte unroll when really large (reduces loop/branch overhead),
        // else keep the 16-byte unroll to limit code size/pressure.
        let mut chunks32 = data.chunks_exact(32); // 16 words per iter
        for c in &mut chunks32 {
            sum = sum
                .wrapping_add(be16_32(c[0], c[1]))
                .wrapping_add(be16_32(c[2], c[3]))
                .wrapping_add(be16_32(c[4], c[5]))
                .wrapping_add(be16_32(c[6], c[7]))
                .wrapping_add(be16_32(c[8], c[9]))
                .wrapping_add(be16_32(c[10], c[11]))
                .wrapping_add(be16_32(c[12], c[13]))
                .wrapping_add(be16_32(c[14], c[15]))
                .wrapping_add(be16_32(c[16], c[17]))
                .wrapping_add(be16_32(c[18], c[19]))
                .wrapping_add(be16_32(c[20], c[21]))
                .wrapping_add(be16_32(c[22], c[23]))
                .wrapping_add(be16_32(c[24], c[25]))
                .wrapping_add(be16_32(c[26], c[27]))
                .wrapping_add(be16_32(c[28], c[29]))
                .wrapping_add(be16_32(c[30], c[31]));
        }
        // Remainder after 32B blocks
        let rem = chunks32.remainder();
        let mut pairs = rem.chunks_exact(2);
        for p in &mut pairs {
            sum = sum.wrapping_add(be16_32(p[0], p[1]));
        }
        if (rem.len() & 1) != 0 {
            sum = sum.wrapping_add((rem[rem.len() - 1] as u32) << 8);
        }
    }

    // Final fold to 16 bits and one's complement
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}
