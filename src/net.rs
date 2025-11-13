use crate::cli::{Config, SupportedProtocol};
use crate::stats::Stats;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering as AtomOrdering};
use std::time::{Duration, Instant};

static ZERO_ARRAY: [u8; 1] = [0];

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
    dest_sa: &SockAddr,
    recv: SocketAddr,
    debug: bool,
) {
    // Determine source/destination protocol for this direction once.
    let (src_proto, dst_proto) = if c2u {
        (cfg.listen_proto, cfg.upstream_proto)
    } else {
        (cfg.upstream_proto, cfg.listen_proto)
    };

    // If the source side was ICMP, strip the 8-byte Echo header before forwarding.
    let (icmp_success, payload, src_ident, src_is_req) =
        if matches!(src_proto, SupportedProtocol::ICMP) {
            parse_icmp_echo_header(buf)
        } else {
            (true, buf, recv.port(), c2u)
        };

    // Size check on the normalized payload.
    let len = payload.len();

    if !icmp_success {
        if debug {
            eprintln!("Dropping packet: Invalid or truncated ICMP Echo header");
        }
        if c2u {
            stats.c2u_err()
        } else {
            stats.u2c_err()
        }
        return;
    } else if c2u != src_is_req || src_ident != recv.port() {
        // If this is the client->upstream direction and we received an ICMP Echo *reply* or
        // upstream->client and we received an ICMP Echo *request*, drop it to avoid feedback loops.
        // Also, ignore all packets with the wrong identity field.

        // Not an error; just ignore replies from the client side.
        return;
    } else if cfg.max_payload != 0 && len > cfg.max_payload {
        if debug {
            eprintln!(
                "Dropping packet: {} bytes exceeds max {}",
                len, cfg.max_payload
            );
        }
        if c2u {
            stats.drop_c2u_oversize()
        } else {
            stats.drop_u2c_oversize()
        }
        return;
    }

    // Send according to destination protocol and connection state.
    let send_res = match dst_proto {
        SupportedProtocol::ICMP => {
            send_icmp_echo(sock, dest, dest_sa, dest.port(), !c2u, payload, connected)
        }
        _ => {
            if connected {
                sock.send(payload)
            } else {
                sock.send_to(payload, &dest_sa)
            }
        }
    };

    match send_res {
        Ok(_) => {
            let t_send = Instant::now();
            last_seen.store(Stats::dur_ns(t_start, t_send), AtomOrdering::Relaxed);
            if c2u {
                stats.add_c2u(len as u64, t_recv, t_send)
            } else {
                stats.add_u2c(len as u64, t_recv, t_send)
            }
        }
        Err(e) => {
            if debug {
                eprintln!("Send to '{}' error: {}", dest, e);
            }
            if c2u {
                stats.c2u_err()
            } else {
                stats.u2c_err()
            }
        }
    }
}

/// Some OSes (notably Linux for IPv4 raw sockets) deliver the full IP header
/// followed by the ICMP message. Others deliver only the ICMP message.
///
/// This helper normalizes those cases by:
///   * detecting an IPv4/IPv6 header using only header-structure fields
///   * advancing `off` to the start of the ICMP Echo header *only* when a full
///     IP header and 8-byte Echo header fit in the buffer
///   * treating the buffer as starting at the ICMP header when no valid IP
///     header is detected
///   * validating ICMP(v6) Echo type/code (v4: 8/0; v6: 128/129 with code 0)
///   * stripping the 8-byte ICMP Echo header and returning the remaining payload
///
/// The return tuple is `(ok, payload, ident, is_request)` where:
///   * `ok` is `true` iff a complete ICMP(v6) Echo {request, reply} header with
///     code 0 was found and validated.
///   * `payload` is the slice after the Echo header when `ok == true`, or an
///     empty slice otherwise.
///   * `ident` is the Echo identifier field (undefined when `ok == false`).
///   * `is_request` is `true` for Echo Request and `false` for Echo Reply
///     (undefined when `ok == false`).
///
/// The mask-based arithmetic (`is_v4`, `is_v6`, `room_v4`, `room_v6`,
/// `have_hdr`, `success`) is intentional: this function runs on the ICMP
/// hot path and has been shaped to minimize unpredictable branches and bounds
/// checks. If you change it, re-benchmark under load before simplifying the
/// control flow.
#[inline]
fn parse_icmp_echo_header(payload: &[u8]) -> (bool, &[u8], u16, bool) {
    let n = payload.len();
    // Probe bytes: read 0,6,9 only when available; otherwise treat as zeroes.
    let has0 = (n >= 1) as usize;
    let buf = if has0 != 0 { payload } else { &ZERO_ARRAY };
    let has9 = (n >= 10) as usize; // need index 6+9
    let b9 = buf[9 * has9];
    let b6 = buf[6 * has9];
    let b0 = buf[0];

    // Version nibble and IPv4 IHL (header length in bytes, from 4-byte words)
    let ver = (b0 >> 4) as usize;
    let ihl = ((b0 as usize) & 0x0F) << 2;

    // Boolean masks as 0/1 integers
    let is_v4 = (ver == 4) as usize;
    let is_v6 = (ver == 6) as usize;

    // Sanity / length masks (0 or 1).
    // With a sane IHL (>=20), `room_v4` implies n >= ihl + 8 >= 28 total bytes
    // (IPv4 header + 8-byte ICMP Echo header).
    let sane_ihl = (ihl >= 20) as usize;
    let proto_icmp = (b9 == 1) as usize; // IPv4 protocol == ICMP
    let room_v4 = (n >= ihl + 8) as usize; // requires sane_ihl to be useful

    // For IPv6, `room_v6` (n >= 48) ensures a 40-byte IPv6 header plus 8-byte ICMPv6 Echo fits.
    let next_icmp6 = (b6 == 58) as usize; // IPv6 Next Header == ICMPv6
    let room_v6 = (n >= 48) as usize; // 40 (IPv6) + 8 (ICMPv6)

    // Compute offsets multiplied by masks (either ihl or 40, else 0).
    // If no header path matches, both masks are 0 and `off` stays 0
    // (treat buffer as starting at the ICMP header).
    let off_v4 = ihl * (is_v4 & sane_ihl & proto_icmp & room_v4);
    let off_v6 = 40usize * (is_v6 & next_icmp6 & room_v6);

    // Since ver is either 4 or 6 (or neither), these are mutually exclusive; adding is safe.
    let off = off_v4 + off_v6;

    // Consolidated validation: `have_hdr` gates all ICMP header reads.
    // When `have_hdr == 0`, indices collapse to 0 and we read buf[0] (harmless).
    // When `have_hdr == 1`, we know an 8-byte Echo header fits at `off`.
    let have_hdr = (n >= off + 8) as usize;
    let icmp_code = buf[(off + 1) * have_hdr];
    let icmp_type = buf[off * have_hdr];

    // `success` gates all further ICMP-field indexing and the payload slice bounds.
    let success_bool = have_hdr == 1 && icmp_code == 0 && matches!(icmp_type, 8 | 0 | 128 | 129);
    let success = success_bool as usize;

    // Identifier is bytes 4..6 of the ICMP Echo header (for both v4 and v6 Echo).
    let ident_b1 = buf[(off + 5) * success];
    let ident_b0 = buf[(off + 4) * success];
    let ident = be16_16(ident_b0, ident_b1);
    let is_request = matches!(icmp_type, 8 | 128);

    // On failure, `success == 0` collapses the slice to 0..0 (empty) rather than indexing at `off`.
    (
        success_bool,
        &buf[(off + 8) * success..n * success],
        ident,
        is_request,
    )
}

/// Send an ICMP Echo Request or Reply (IPv4 or IPv6).
fn send_icmp_echo(
    sock: &Socket,
    dest: SocketAddr,
    dest_sa: &SockAddr,
    ident: u16,
    reply: bool,
    payload: &[u8],
    connected: bool,
) -> io::Result<usize> {
    static ICMP_SEQ: AtomicU16 = AtomicU16::new(1);

    let seq = ICMP_SEQ.fetch_add(1, AtomOrdering::Relaxed);
    let mut hdr = [0u8; 8];

    match dest {
        SocketAddr::V6(_) => {
            // ICMPv6 Echo: type=128(req)/129(rep), code=0, checksum handled by kernel on many OSes
            hdr[0] = 128u8 + (reply as u8);
            // hdr[1] = 0; hdr[2..4] left 0 for checksum (kernel may fill)
            let idb = ident.to_be_bytes();
            let sqb = seq.to_be_bytes();
            hdr[4] = idb[0];
            hdr[5] = idb[1];
            hdr[6] = sqb[0];
            hdr[7] = sqb[1];

            let iov = [IoSlice::new(&hdr), IoSlice::new(payload)];
            if connected {
                sock.send_vectored(&iov)
            } else {
                sock.send_to_vectored(&iov, &dest_sa)
            }
        }
        _ => {
            // ICMPv4 Echo: type=8(req)/0(rep), code=0, checksum over header+payload
            hdr[0] = 8u8 * ((!reply) as u8);
            // hdr[1] = 0; hdr[2..4] = 0 (placeholder for checksum)
            let idb = ident.to_be_bytes();
            let sqb = seq.to_be_bytes();
            hdr[4] = idb[0];
            hdr[5] = idb[1];
            hdr[6] = sqb[0];
            hdr[7] = sqb[1];

            // Compute checksum without copying payload
            let cksum = checksum16(&hdr, payload);
            hdr[2] = (cksum >> 8) as u8;
            hdr[3] = (cksum & 0xFF) as u8;

            let iov = [IoSlice::new(&hdr), IoSlice::new(payload)];
            if connected {
                sock.send_vectored(&iov)
            } else {
                sock.send_to_vectored(&iov, &dest_sa)
            }
        }
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
#[inline]
fn checksum16(hdr: &[u8; 8], data: &[u8]) -> u16 {
    // Accumulate 16-bit words over header (with zeroed checksum) then payload.
    let mut sum: u32 = 0;

    // Header: type,code ; checksum(0) ; ident ; seq
    sum = sum
        .wrapping_add(be16_32(hdr[0], hdr[1]))
        .wrapping_add(be16_32(0, 0)) // checksum field treated as zero
        .wrapping_add(be16_32(hdr[4], hdr[5]))
        .wrapping_add(be16_32(hdr[6], hdr[7]));

    // Payload
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
