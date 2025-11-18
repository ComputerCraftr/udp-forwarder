mod common;

use crate::common::*;
#[cfg(unix)]
use nix::unistd;

use std::io::ErrorKind;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn enforce_max_payload_all() {
    for &proto in SUPPORTED_PROTOCOLS {
        let proto_slice = std::slice::from_ref(&proto);
        let _ = run_enforce_max_payload(IpFamily::V4, proto_slice, 548, 2048);
        let _ = run_enforce_max_payload(IpFamily::V6, proto_slice, 1232, 4096);
    }
}

fn run_enforce_max_payload(
    family: IpFamily,
    protos: &[&str],
    max_payload: usize,
    recv_buf_len: usize,
) -> bool {
    run_cases(protos, |proto, mode| {
        let client_sock = match family.bind_client() {
            Ok(sock) => sock,
            Err(e) => {
                if family.is_v6() {
                    eprintln!("IPv6 loopback not available; skipping IPv6 test: {e}");
                    return false;
                }
                panic!("IPv4 loopback not available: {e}");
            }
        };

        let (up_addr, _up_thread) = match family.spawn_echo() {
            Ok(pair) => pair,
            Err(e) => {
                if family.is_v6() {
                    eprintln!("IPv6 echo server could not bind; skipping IPv6 test: {e}");
                    return false;
                }
                panic!("IPv4 echo server could not bind: {e}");
            }
        };

        let bin = find_app_bin().expect("could not find app binary");
        let mut cmd = Command::new(bin);
        cmd.arg("--here")
            .arg(family.listen_arg())
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg(TIMEOUT_SECS.as_secs().to_string())
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .arg("--max-payload")
            .arg(max_payload.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        mode.apply(&mut cmd);

        #[cfg(unix)]
        if unistd::geteuid().is_root() {
            cmd.arg("--user").arg("nobody");
        }

        let mut child = ChildGuard::new(cmd.spawn().expect("spawn app binary"));
        let mut out = take_child_stdout(&mut child).expect("child stdout missing");
        let listen_addr = wait_for_listen_addr_from(&mut out, MAX_WAIT_SECS).expect(&format!(
            "did not see listening address line within {:?}",
            MAX_WAIT_SECS
        ));
        client_sock
            .connect(listen_addr)
            .expect("connect to forwarder (max payload)");

        let ok = vec![0u8; max_payload];
        client_sock.send(&ok).unwrap();
        let mut buf = vec![0u8; recv_buf_len];
        let _ = client_sock
            .recv(&mut buf)
            .expect("recv from forwarder (max payload)");

        let over = vec![0u8; max_payload + 1];
        client_sock.send(&over).unwrap();
        client_sock.set_read_timeout(Some(CLIENT_WAIT_MS)).unwrap();
        let drop_expected = client_sock.recv(&mut buf).is_err();
        assert!(drop_expected, "oversize payload should be dropped");

        let start = Instant::now();
        while start.elapsed() < MAX_WAIT_SECS {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "forwarder did not exit cleanly: {status}");
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("wait error: {e}"),
            }
        }

        let status_opt = child
            .try_wait()
            .expect("wait error while checking forwarder exit status");
        match status_opt {
            Some(status) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}",);
            }
            None => {
                panic!("forwarder did not exit within {:?}", MAX_WAIT_SECS);
            }
        }

        let stats = wait_for_stats_json_from(&mut out, JSON_WAIT_MS).expect(&format!(
            "did not see stats JSON line within {:?}",
            JSON_WAIT_MS
        ));
        assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
        true
    })
}

#[test]
fn single_client_forwarding_all() {
    for &proto in SUPPORTED_PROTOCOLS {
        let proto_slice = std::slice::from_ref(&proto);
        let _ = run_single_client_forwarding(IpFamily::V4, proto_slice, b"hello-through-forwarder");
        let _ =
            run_single_client_forwarding(IpFamily::V6, proto_slice, b"hello-through-forwarder-v6");
    }
}

fn run_single_client_forwarding(family: IpFamily, protos: &[&str], payload: &[u8]) -> bool {
    const COUNT: usize = 5;
    run_cases(protos, |proto, mode| {
        let client_sock = match family.bind_client() {
            Ok(sock) => sock,
            Err(e) => {
                if family.is_v6() {
                    eprintln!("IPv6 loopback not available; skipping IPv6 test: {e}");
                    return false;
                }
                panic!("IPv4 loopback not available: {e}");
            }
        };
        let client_local = match client_sock.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                if family.is_v6() {
                    eprintln!("IPv6 loopback address not available; skipping IPv6 test: {e}");
                    return false;
                }
                panic!("IPv4 loopback address not available: {e}");
            }
        };

        let (up_addr, _up_thread) = match family.spawn_echo() {
            Ok(pair) => pair,
            Err(e) => {
                if family.is_v6() {
                    eprintln!("IPv6 echo server could not bind; skipping IPv6 test: {e}");
                    return false;
                }
                panic!("IPv4 echo server could not bind: {e}");
            }
        };

        let bin = find_app_bin().expect("could not find app binary");
        let mut cmd = Command::new(bin);
        cmd.arg("--here")
            .arg(family.listen_arg())
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg(TIMEOUT_SECS.as_secs().to_string())
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        mode.apply(&mut cmd);

        #[cfg(unix)]
        if unistd::geteuid().is_root() {
            cmd.arg("--user").arg("nobody");
        }

        let mut child = ChildGuard::new(cmd.spawn().expect("spawn app binary"));
        let mut out = take_child_stdout(&mut child).expect("child stdout missing");
        let listen_addr = wait_for_listen_addr_from(&mut out, MAX_WAIT_SECS).expect(&format!(
            "did not see listening address line within {:?}",
            MAX_WAIT_SECS
        ));
        client_sock
            .connect(listen_addr)
            .expect("connect to forwarder (single client)");

        for _ in 0..COUNT {
            client_sock
                .send(payload)
                .expect("send to forwarder (single client)");
            let mut buf = [0u8; 2048];
            let n = client_sock
                .recv(&mut buf)
                .expect("recv from forwarder (single client)");
            assert_eq!(&buf[..n], payload, "echo payload mismatch");
        }

        let start = Instant::now();
        while start.elapsed() < MAX_WAIT_SECS {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "forwarder did not exit cleanly: {status}");
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("wait error: {e}"),
            }
        }

        let status_opt = child
            .try_wait()
            .expect("wait error while checking forwarder exit status");
        match status_opt {
            Some(status) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}",);
            }
            None => {
                panic!("forwarder did not exit within {:?}", MAX_WAIT_SECS);
            }
        }

        let stats = wait_for_stats_json_from(&mut out, JSON_WAIT_MS).expect(&format!(
            "did not see stats JSON line within {:?}",
            JSON_WAIT_MS
        ));
        assert!(stats["uptime_s"].is_number());
        assert!(stats["locked"].as_bool().unwrap_or(false));
        assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), COUNT as u64);
        assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), COUNT as u64);
        assert!(stats["client_addr"].is_string());
        assert!(stats["upstream_addr"].is_string());

        let stats_client = json_addr(&stats["client_addr"]).expect("parse stats client_addr");
        assert_eq!(stats_client, client_local, "stats client_addr mismatch");
        let stats_upstream = json_addr(&stats["upstream_addr"]).expect("parse stats upstream_addr");
        assert_eq!(stats_upstream, up_addr, "stats upstream_addr mismatch");

        assert_eq!(
            stats["c2u_bytes"].as_u64().unwrap_or(0),
            payload.len() as u64 * COUNT as u64
        );
        assert_eq!(
            stats["u2c_bytes"].as_u64().unwrap_or(0),
            payload.len() as u64 * COUNT as u64
        );
        assert_eq!(
            stats["c2u_bytes_max"].as_u64().unwrap_or(0),
            payload.len() as u64
        );
        assert_eq!(
            stats["u2c_bytes_max"].as_u64().unwrap_or(0),
            payload.len() as u64
        );

        assert!(stats["c2u_us_max"].is_number());
        assert!(stats["u2c_us_max"].is_number());
        assert!(stats["c2u_us_avg"].is_number());
        assert!(stats["u2c_us_avg"].is_number());
        assert!(stats["c2u_us_ewma"].is_number());
        assert!(stats["u2c_us_ewma"].is_number());

        let c2u_us_max = stats["c2u_us_max"].as_u64().unwrap();
        let u2c_us_max = stats["u2c_us_max"].as_u64().unwrap();
        let c2u_us_avg = stats["c2u_us_avg"].as_u64().unwrap();
        let u2c_us_avg = stats["u2c_us_avg"].as_u64().unwrap();
        let c2u_us_ewma = stats["c2u_us_ewma"].as_u64().unwrap();
        let u2c_us_ewma = stats["u2c_us_ewma"].as_u64().unwrap();

        assert!(
            c2u_us_avg > 0,
            "expected c2u_us_avg > 0, got {}",
            c2u_us_avg
        );
        assert!(
            u2c_us_avg > 0,
            "expected u2c_us_avg > 0, got {}",
            u2c_us_avg
        );
        assert!(
            c2u_us_ewma > 0,
            "expected c2u_us_ewma > 0, got {}",
            c2u_us_ewma
        );
        assert!(
            u2c_us_ewma > 0,
            "expected u2c_us_ewma > 0, got {}",
            u2c_us_ewma
        );

        assert!(
            c2u_us_max >= c2u_us_avg,
            "impossible: c2u_us_avg {} > c2u_us_max {}",
            c2u_us_avg,
            c2u_us_max
        );
        assert!(
            u2c_us_max >= u2c_us_avg,
            "impossible: u2c_us_avg {} > u2c_us_max {}",
            u2c_us_avg,
            u2c_us_max
        );
        assert!(
            c2u_us_max >= c2u_us_ewma,
            "impossible: c2u_us_ewma {} > c2u_us_max {}",
            c2u_us_ewma,
            c2u_us_max
        );
        assert!(
            u2c_us_max >= u2c_us_ewma,
            "impossible: u2c_us_ewma {} > u2c_us_max {}",
            u2c_us_ewma,
            u2c_us_max
        );
        true
    })
}

#[test]
fn relock_after_timeout_drop_all() {
    run_cases(SUPPORTED_PROTOCOLS, |proto, mode| {
        relock_after_timeout_drop_ipv4_case(proto, mode);
        true
    });
}

fn relock_after_timeout_drop_ipv4_case(proto: &str, mode: SocketMode) {
    // Two client sockets (different ephemeral ports)
    let client_a = bind_udp_client(IpFamily::V4).expect("client_a IPv4 loopback not available");
    let client_b = bind_udp_client(IpFamily::V4).expect("client_b IPv4 loopback not available");

    // Upstream echo server
    let up_addr = spawn_udp_echo_server(IpFamily::V4)
        .expect("IPv4 echo server could not bind")
        .0;

    // Spawn the app binary
    let bin = find_app_bin().expect("could not find app binary");

    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");
    let mut cmd = Command::new(bin);
    cmd.arg("--here")
        .arg(format!("UDP:127.0.0.1:{here_port}"))
        .arg("--there")
        .arg(format!("{proto}:{up_addr}"))
        .arg("--timeout-secs")
        .arg(TIMEOUT_SECS.as_secs().to_string())
        .arg("--on-timeout")
        .arg("drop")
        .arg("--stats-interval-mins")
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    mode.apply(&mut cmd);

    #[cfg(unix)]
    if unistd::geteuid().is_root() {
        cmd.arg("--user").arg("nobody");
    }

    let mut child = ChildGuard::new(cmd.spawn().expect("spawn app binary"));

    // Read the forwarder's listen address and connect client A
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let listen_addr = wait_for_listen_addr_from(&mut out, MAX_WAIT_SECS).expect(&format!(
        "did not see listening address line within {:?}",
        MAX_WAIT_SECS
    ));

    client_a
        .connect(listen_addr)
        .expect("connect A -> forwarder");

    // Send a packet from client A; wait for the forwarder to announce the lock, then expect echo
    let payload_a = b"first-client";
    client_a.send(payload_a).expect("send A");

    // Confirm the forwarder locked to client A
    let a_locked_opt = wait_for_locked_client_from(&mut out, MAX_WAIT_SECS);
    assert!(
        a_locked_opt.is_some(),
        "did not see lock line for client A within {:?}",
        MAX_WAIT_SECS
    );
    let a_locked = a_locked_opt.unwrap();
    let client_a_local = client_a.local_addr().expect("client A local addr");
    assert_eq!(
        a_locked, client_a_local,
        "forwarder locked to unexpected client A address"
    );

    let mut buf = [0u8; 1024];
    let n = client_a.recv(&mut buf).expect("recv echo A");
    assert_eq!(&buf[..n], payload_a);

    // Now go idle > timeout so watchdog drops the lock and disconnects
    thread::sleep(MAX_WAIT_SECS);

    // Ensure process did NOT exit under on-timeout=drop
    if let Ok(Some(status)) = child.try_wait() {
        panic!("forwarder exited unexpectedly with status: {status}");
    }

    // Connect client B and send a packet; then wait for the lock line and expect echo
    client_b
        .connect(listen_addr)
        .expect("connect B -> forwarder");
    let payload_b = b"second-client";
    client_b
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout on client B");

    // Trigger relock by sending a few datagrams, then wait explicitly for the lock line.
    let mut b_locked_opt = None;

    // Stage 1: send until we see the forwarder announce the new locked client.
    for _ in 0..40 {
        let _ = client_b.send(payload_b);
        if let Some(locked) = wait_for_locked_client_from(&mut out, CLIENT_WAIT_MS) {
            b_locked_opt = Some(locked);
            break;
        }
        // Socket/forwarder might be busy; brief backoff and retry.
        thread::sleep(Duration::from_millis(50));
    }

    assert!(
        b_locked_opt.is_some(),
        "did not see lock line for client B within {:?}",
        CLIENT_WAIT_MS
    );
    let b_locked = b_locked_opt.unwrap();
    let client_b_local = client_b.local_addr().expect("client B local addr");
    assert_eq!(
        b_locked, client_b_local,
        "forwarder locked to unexpected client B address"
    );

    // Stage 2: now that the forwarder is relocked, receive the echo.
    // Allow brief transient conditions by retrying and re-sending.
    client_b
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout on client B");

    let mut got: Option<usize> = None;
    for _ in 0..40 {
        match client_b.recv(&mut buf) {
            Ok(n) => {
                got = Some(n);
                break;
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::ConnectionRefused =>
            {
                // Nudge pipeline and try again
                let _ = client_b.send(payload_b);
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => panic!("recv echo B: {e}"),
        }
    }
    let n = got.expect("did not receive echo from forwarder after re-lock");
    assert_eq!(&buf[..n], payload_b);

    // Give forwarder a moment to print stats, then tear it down for test cleanup
    let stats = wait_for_stats_json_from(&mut out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    let _ = child.kill();

    // The last locked client should be B (its local addr)
    let stats_client =
        json_addr(&stats["client_addr"]).expect("parse stats client_addr after relock");
    assert_eq!(
        stats_client, client_b_local,
        "forwarder did not relock to client B"
    );

    // Sanity: we sent at least one pkt each direction for A and B (echo path), totals >= 2
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap_or(0);
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    assert!(
        c2u_pkts >= 2 && u2c_pkts >= 2,
        "unexpected low packet counts: c2u={c2u_pkts} u2c={u2c_pkts}"
    );
}
