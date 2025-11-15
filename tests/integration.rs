mod common;

use crate::common::*;

use std::io::ErrorKind;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn enforce_max_payload_ipv4_udp() {
    enforce_max_payload_ipv4("UDP");
}

#[test]
#[ignore] // requires root for raw sockets, pings localhost
fn enforce_max_payload_ipv4_icmp() {
    enforce_max_payload_ipv4("ICMP");
}

fn enforce_max_payload_ipv4(proto: &str) {
    // Client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client().expect("IPv4 loopback not available");

    // Upstream echo server
    let up_addr = spawn_udp_echo_server_v4()
        .expect("IPv4 echo server could not bind")
        .0;

    // Spawn the app binary
    let bin = find_app_bin().expect("could not find app binary");

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("--here")
            .arg("UDP:127.0.0.1:0")
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg("2")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .arg("--max-payload")
            .arg("548")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn app binary"),
    );

    // Read the forwarder's listen address and connect the client
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let max_wait = Duration::from_secs(3);
    let listen_addr = wait_for_listen_addr_from(&mut out, max_wait).expect(&format!(
        "did not see listening address line within {:?}",
        max_wait
    ));
    client_sock
        .connect(listen_addr)
        .expect("connect to forwarder (IPv4)");

    // Exactly-safe payload should be echoed
    let ok = vec![0u8; 548];
    client_sock.send(&ok).unwrap();
    let mut buf = [0u8; 2048];
    let _ = client_sock
        .recv(&mut buf)
        .expect("recv from forwarder (IPv4)");

    // One byte over should be dropped (no echo)
    let over = vec![0u8; 549];
    client_sock.send(&over).unwrap();
    client_sock
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let drop_expected = client_sock.recv(&mut buf).is_err();
    assert!(drop_expected, "oversize payload should be dropped");

    // After ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < max_wait {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // Ensure that the process has exited successfully by now; this validates
    // the --timeout-secs + --on-timeout=exit watchdog behavior.
    let status_opt = child
        .try_wait()
        .expect("wait error while checking forwarder exit status");
    match status_opt {
        Some(status) => {
            assert!(status.success(), "forwarder did not exit cleanly: {status}",);
        }
        None => {
            panic!("forwarder did not exit within {:?}", max_wait);
        }
    }

    // Check that the stats show one drop
    let json_wait = Duration::from_millis(50);
    let stats = wait_for_stats_json_from(&mut out, json_wait).expect(&format!(
        "did not see stats JSON line within {:?}",
        json_wait
    ));
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn enforce_max_payload_ipv6_udp() {
    enforce_max_payload_ipv6("UDP");
}

#[test]
#[ignore] // requires root for raw sockets, pings localhost
fn enforce_max_payload_ipv6_icmp() {
    enforce_max_payload_ipv6("ICMP");
}

fn enforce_max_payload_ipv6(proto: &str) {
    // If IPv6 loopback is unavailable on this host, skip gracefully
    // Client socket bound to ephemeral local port
    let Ok(client_sock) = bind_udp_v6_client() else {
        eprintln!("IPv6 loopback not available; skipping IPv6 test");
        return;
    };

    // Upstream echo server
    let Ok((up_addr, _up_thread)) = spawn_udp_echo_server_v6() else {
        eprintln!("IPv6 echo server could not bind; skipping IPv6 test");
        return;
    };

    // Spawn the app binary
    let bin = find_app_bin().expect("could not find app binary");

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("--here")
            .arg("UDP:[::1]:0")
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg("2")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .arg("--max-payload")
            .arg("1232")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn app binary"),
    );

    // Read the forwarder's listen address and connect the client
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let max_wait = Duration::from_secs(3);
    let listen_addr = wait_for_listen_addr_from(&mut out, max_wait).expect(&format!(
        "did not see listening address line within {:?}",
        max_wait
    ));
    client_sock
        .connect(listen_addr)
        .expect("connect to forwarder (IPv6)");

    // Exactly-safe payload should be echoed
    let ok = vec![0u8; 1232];
    client_sock.send(&ok).unwrap();
    let mut buf = [0u8; 4096];
    let _ = client_sock
        .recv(&mut buf)
        .expect("recv from forwarder (IPv6)");

    // One byte over should be dropped (no echo)
    let over = vec![0u8; 1233];
    client_sock.send(&over).unwrap();
    client_sock
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let drop_expected = client_sock.recv(&mut buf).is_err();
    assert!(drop_expected, "oversize payload should be dropped");

    // After ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < max_wait {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // Ensure that the process has exited successfully by now; this validates
    // the --timeout-secs + --on-timeout=exit watchdog behavior.
    let status_opt = child
        .try_wait()
        .expect("wait error while checking forwarder exit status");
    match status_opt {
        Some(status) => {
            assert!(status.success(), "forwarder did not exit cleanly: {status}",);
        }
        None => {
            panic!("forwarder did not exit within {:?}", max_wait);
        }
    }

    // Check that the stats show one drop
    let json_wait = Duration::from_millis(50);
    let stats = wait_for_stats_json_from(&mut out, json_wait).expect(&format!(
        "did not see stats JSON line within {:?}",
        json_wait
    ));
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn single_client_forwarding_ipv4_udp() {
    single_client_forwarding_ipv4("UDP");
}

#[test]
#[ignore] // requires root for raw sockets, pings localhost
fn single_client_forwarding_ipv4_icmp() {
    single_client_forwarding_ipv4("ICMP");
}

fn single_client_forwarding_ipv4(proto: &str) {
    // Client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client().expect("IPv4 loopback not available");
    let client_local = client_sock
        .local_addr()
        .expect("IPv4 loopback address not available");

    // Upstream echo server
    let up_addr = spawn_udp_echo_server_v4()
        .expect("IPv4 echo server could not bind")
        .0;

    // Spawn the app binary
    let bin = find_app_bin().expect("could not find app binary");

    // Run with small timeout & auto-exit on idle
    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("--here")
            .arg("UDP:127.0.0.1:0")
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg("2")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn app binary"),
    );

    // Read the forwarder's listen address and connect the client
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let max_wait = Duration::from_secs(3);
    let listen_addr = wait_for_listen_addr_from(&mut out, max_wait).expect(&format!(
        "did not see listening address line within {:?}",
        max_wait
    ));
    client_sock
        .connect(listen_addr)
        .expect("connect to forwarder (IPv4)");

    // Send multiple datagrams and expect the same payloads back (echo via upstream)
    let count = 5;
    let payload = b"hello-through-forwarder";
    for _ in 0..count {
        client_sock.send(payload).expect("send to forwarder (IPv4)");
        let mut buf = [0u8; 1024];
        let n = client_sock
            .recv(&mut buf)
            .expect("recv from forwarder (IPv4)");
        assert_eq!(&buf[..n], payload, "echo payload mismatch");
    }

    // After ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < max_wait {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // Ensure that the process has exited successfully by now; this validates
    // the --timeout-secs + --on-timeout=exit watchdog behavior.
    let status_opt = child
        .try_wait()
        .expect("wait error while checking forwarder exit status");
    match status_opt {
        Some(status) => {
            assert!(status.success(), "forwarder did not exit cleanly: {status}",);
        }
        None => {
            panic!("forwarder did not exit within {:?}", max_wait);
        }
    }

    // Validate stats snapshot fields
    let json_wait = Duration::from_millis(50);
    let stats = wait_for_stats_json_from(&mut out, json_wait).expect(&format!(
        "did not see stats JSON line within {:?}",
        json_wait
    ));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), count);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), count);
    assert!(stats["client_addr"].is_string());
    assert!(stats["upstream_addr"].is_string());

    // Validate exact addresses (client local addr and upstream addr)
    let stats_client = json_addr(&stats["client_addr"]).expect("parse stats client_addr");
    assert_eq!(stats_client, client_local, "stats client_addr mismatch");
    let stats_upstream = json_addr(&stats["upstream_addr"]).expect("parse stats upstream_addr");
    assert_eq!(stats_upstream, up_addr, "stats upstream_addr mismatch");

    // Validate byte counters for multiple packets
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64 * count
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64 * count
    );
    assert_eq!(
        stats["c2u_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );

    // Latency fields: parse once, then assert in a sensible order
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

    // Averages and EWMAs should be strictly positive
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

    // Per-direction relational sanity: max >= avg, max >= ewma, and avg < max
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
}

#[test]
fn single_client_forwarding_ipv6_udp() {
    single_client_forwarding_ipv6("UDP");
}

#[test]
#[ignore] // requires root for raw sockets, pings localhost
fn single_client_forwarding_ipv6_icmp() {
    single_client_forwarding_ipv6("ICMP");
}

fn single_client_forwarding_ipv6(proto: &str) {
    // If IPv6 loopback is unavailable on this host, skip gracefully
    // Client socket bound to ephemeral local port
    let Ok(client_sock) = bind_udp_v6_client() else {
        eprintln!("IPv6 loopback not available; skipping IPv6 test");
        return;
    };
    let Ok(client_local) = client_sock.local_addr() else {
        eprintln!("IPv6 loopback address not available; skipping IPv6 test");
        return;
    };

    // Upstream echo server
    let Ok((up_addr, _up_thread)) = spawn_udp_echo_server_v6() else {
        eprintln!("IPv6 echo server could not bind; skipping IPv6 test");
        return;
    };

    // Spawn the app binary
    let bin = find_app_bin().expect("could not find app binary");

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("--here")
            .arg("UDP:[::1]:0")
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg("2")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn app binary"),
    );

    // Read the forwarder's listen address and connect the client
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let max_wait = Duration::from_secs(3);
    let listen_addr = wait_for_listen_addr_from(&mut out, max_wait).expect(&format!(
        "did not see listening address line within {:?}",
        max_wait
    ));
    client_sock
        .connect(listen_addr)
        .expect("connect to forwarder (IPv6)");

    // Send multiple datagrams and expect the same payloads back (echo via upstream)
    let count = 5;
    let payload = b"hello-through-forwarder-v6";
    for _ in 0..count {
        client_sock.send(payload).expect("send to forwarder (IPv6)");
        let mut buf = [0u8; 1024];
        let n = client_sock
            .recv(&mut buf)
            .expect("recv from forwarder (IPv6)");
        assert_eq!(&buf[..n], payload, "echo v6 payload mismatch");
    }

    // After ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < max_wait {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // Ensure that the process has exited successfully by now; this validates
    // the --timeout-secs + --on-timeout=exit watchdog behavior.
    let status_opt = child
        .try_wait()
        .expect("wait error while checking forwarder exit status");
    match status_opt {
        Some(status) => {
            assert!(status.success(), "forwarder did not exit cleanly: {status}",);
        }
        None => {
            panic!("forwarder did not exit within {:?}", max_wait);
        }
    }

    // Validate stats snapshot fields
    let json_wait = Duration::from_millis(50);
    let stats = wait_for_stats_json_from(&mut out, json_wait).expect(&format!(
        "did not see stats JSON line within {:?}",
        json_wait
    ));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), count);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), count);
    assert!(stats["client_addr"].is_string());
    assert!(stats["upstream_addr"].is_string());

    // Validate exact addresses (client local addr and upstream addr)
    let stats_client = json_addr(&stats["client_addr"]).expect("parse stats client_addr v6");
    assert_eq!(stats_client, client_local, "stats client_addr v6 mismatch");
    let stats_upstream = json_addr(&stats["upstream_addr"]).expect("parse stats upstream_addr v6");
    assert_eq!(stats_upstream, up_addr, "stats upstream_addr v6 mismatch");
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64 * count
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64 * count
    );
    assert_eq!(
        stats["c2u_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );

    // Latency fields: parse once, then assert in a sensible order
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

    // Averages and EWMAs should be strictly positive
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

    // Per-direction relational sanity: max >= avg, max >= ewma, and avg < max
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
}

#[test]
fn relock_after_timeout_drop_ipv4_udp() {
    relock_after_timeout_drop_ipv4("UDP");
}

#[test]
#[ignore] // requires root for raw sockets, pings localhost
fn relock_after_timeout_drop_ipv4_icmp() {
    relock_after_timeout_drop_ipv4("ICMP");
}

fn relock_after_timeout_drop_ipv4(proto: &str) {
    // Two client sockets (different ephemeral ports)
    let client_a = bind_udp_v4_client().expect("client_a IPv4 loopback not available");
    let client_b = bind_udp_v4_client().expect("client_b IPv4 loopback not available");

    // Upstream echo server
    let up_addr = spawn_udp_echo_server_v4()
        .expect("IPv4 echo server could not bind")
        .0;

    // Spawn the forwarder with short timeout and on-timeout=drop
    let bin = find_app_bin().expect("could not find app binary");

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("--here")
            .arg("UDP:127.0.0.1:22798")
            .arg("--there")
            .arg(format!("{proto}:{up_addr}"))
            .arg("--timeout-secs")
            .arg("2")
            .arg("--on-timeout")
            .arg("drop")
            .arg("--stats-interval-mins")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn app binary"),
    );

    // Read the forwarder's listen address and connect client A
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let max_wait = Duration::from_secs(2);
    let listen_addr = wait_for_listen_addr_from(&mut out, max_wait).expect(&format!(
        "did not see listening address line within {:?}",
        max_wait
    ));

    client_a
        .connect(listen_addr)
        .expect("connect A -> forwarder");

    // Send a packet from client A; wait for the forwarder to announce the lock, then expect echo
    let payload_a = b"first-client";
    client_a.send(payload_a).expect("send A");

    // Confirm the forwarder locked to client A
    let a_locked_opt = wait_for_locked_client_from(&mut out, max_wait);
    assert!(
        a_locked_opt.is_some(),
        "did not see lock line for client A within {:?}",
        max_wait
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
    thread::sleep(max_wait + Duration::from_millis(250));

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
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("set read timeout on client B");

    // Trigger relock by sending a few datagrams, then wait explicitly for the lock line.
    let client_wait = Duration::from_millis(250);

    // Stage 1: send until we see the forwarder announce the new locked client.
    let mut b_locked_opt = None;
    for _ in 0..40 {
        let _ = client_b.send(payload_b);
        if let Some(locked) = wait_for_locked_client_from(&mut out, client_wait) {
            b_locked_opt = Some(locked);
            break;
        }
        // Socket/forwarder might be busy; brief backoff and retry.
        thread::sleep(Duration::from_millis(20));
    }

    assert!(
        b_locked_opt.is_some(),
        "did not see lock line for client B within {:?}",
        client_wait
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
        .set_read_timeout(Some(Duration::from_millis(250)))
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
                thread::sleep(Duration::from_millis(30));
                continue;
            }
            Err(e) => panic!("recv echo B: {e}"),
        }
    }
    let n = got.expect("did not receive echo from forwarder after re-lock");
    assert_eq!(&buf[..n], payload_b);

    // Give forwarder a moment to print stats, then tear it down for test cleanup
    let json_wait = Duration::from_millis(50);
    let stats = wait_for_stats_json_from(&mut out, json_wait).expect(&format!(
        "did not see stats JSON line within {:?}",
        json_wait
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
