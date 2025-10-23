mod common;
use common::*;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn enforce_max_payload_ipv4() {
    // upstream echo server
    let (up_addr, _up_thread) = spawn_udp_echo_server_v4();

    // client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client();

    // spawn the forwarder binary
    let bin_opt = find_forwarder_bin();
    assert!(
        bin_opt.is_some(),
        "could not find forwarder binary; tried env(CARGO_BIN_EXE_udp[-_]forwarder) and ./target"
    );
    let bin = bin_opt.unwrap();

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("127.0.0.1:0")
            .arg(up_addr.to_string())
            .arg("--timeout-secs")
            .arg("1")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .arg("--max-payload")
            .arg("548")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn forwarder"),
    );

    // Read the forwarder's listen address and connect the client
    let out_opt = take_child_stdout(&mut child);
    assert!(out_opt.is_some(), "child stdout missing");
    let mut out = out_opt.unwrap();

    let max_wait = Duration::from_secs(2);
    let listen_addr_opt = wait_for_listen_addr_from(&mut out, max_wait);
    assert!(
        listen_addr_opt.is_some(),
        "did not see listening address line within {:?}",
        max_wait
    );
    let listen_addr = listen_addr_opt.unwrap();
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
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // if it didn't exit, kill for cleanliness
    let _ = child.kill();

    // check stats reflect one drop
    let stats_opt = wait_for_stats_json_from(&mut out, max_wait);
    assert!(
        stats_opt.is_some(),
        "did not see stats JSON line within {:?}",
        max_wait
    );
    let stats = stats_opt.unwrap();
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn enforce_max_payload_ipv6() {
    let client_sock = match bind_udp_v6_client() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("IPv6 loopback not available; skipping IPv6 test");
            return;
        }
    };
    let (up_addr, _up) = match spawn_udp_echo_server_v6() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("IPv6 echo server could not bind; skipping IPv6 test");
            return;
        }
    };

    // spawn the forwarder binary
    let bin_opt = find_forwarder_bin();
    assert!(
        bin_opt.is_some(),
        "could not find forwarder binary; tried env(CARGO_BIN_EXE_udp[-_]forwarder) and ./target"
    );
    let bin = bin_opt.unwrap();

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("[::1]:0")
            .arg(up_addr.to_string())
            .arg("--timeout-secs")
            .arg("1")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .arg("--max-payload")
            .arg("1232")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn forwarder"),
    );

    // Read the forwarder's listen address and connect the client
    let out_opt = take_child_stdout(&mut child);
    assert!(out_opt.is_some(), "child stdout missing");
    let mut out = out_opt.unwrap();

    let max_wait = Duration::from_secs(2);
    let listen_addr_opt = wait_for_listen_addr_from(&mut out, max_wait);
    assert!(
        listen_addr_opt.is_some(),
        "did not see listening address line within {:?}",
        max_wait
    );
    let listen_addr = listen_addr_opt.unwrap();
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
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // if it didn't exit, kill for cleanliness
    let _ = child.kill();

    // check stats reflect one drop
    let stats_opt = wait_for_stats_json_from(&mut out, max_wait);
    assert!(
        stats_opt.is_some(),
        "did not see stats JSON line within {:?}",
        max_wait
    );
    let stats = stats_opt.unwrap();
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn single_client_forwarding_ipv4() {
    // upstream echo server
    let (up_addr, _up_thread) = spawn_udp_echo_server_v4();

    // client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client();
    let client_local = client_sock.local_addr().expect("client local addr");

    // spawn the forwarder binary
    let bin_opt = find_forwarder_bin();
    assert!(
        bin_opt.is_some(),
        "could not find forwarder binary; tried env(CARGO_BIN_EXE_udp[-_]forwarder) and ./target"
    );
    let bin = bin_opt.unwrap();

    // run with small timeout & auto-exit on idle
    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("127.0.0.1:0")
            .arg(up_addr.to_string())
            .arg("--timeout-secs")
            .arg("1")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn forwarder"),
    );

    // Read the forwarder's listen address and connect the client
    let out_opt = take_child_stdout(&mut child);
    assert!(out_opt.is_some(), "child stdout missing");
    let mut out = out_opt.unwrap();

    let max_wait = Duration::from_secs(2);
    let listen_addr_opt = wait_for_listen_addr_from(&mut out, max_wait);
    assert!(
        listen_addr_opt.is_some(),
        "did not see listening address line within {:?}",
        max_wait
    );
    let listen_addr = listen_addr_opt.unwrap();
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
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // if it didn't exit, kill for cleanliness
    let _ = child.kill();

    // Validate stats snapshot fields
    let stats_opt = wait_for_stats_json_from(&mut out, max_wait);
    assert!(
        stats_opt.is_some(),
        "did not see stats JSON line within {:?}",
        max_wait
    );
    let stats = stats_opt.unwrap();
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), count);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), count);
    assert!(stats["client_addr"].is_string());
    assert!(stats["upstream_addr"].is_string());

    // Validate exact addresses (client local addr and upstream addr)
    let stats_client = json_addr(&stats["client_addr"]);
    assert_eq!(stats_client, client_local, "stats client_addr mismatch");
    let stats_upstream = json_addr(&stats["upstream_addr"]);
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

    // Latency fields should be numeric
    assert!(stats["c2u_us_avg"].is_number());
    assert!(stats["u2c_us_avg"].is_number());
    assert!(stats["c2u_us_max"].is_number());
    assert!(stats["u2c_us_max"].is_number());
}

#[test]
fn single_client_forwarding_ipv6() {
    // if IPv6 loopback is unavailable on this host, skip gracefully
    let client_sock = match bind_udp_v6_client() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("IPv6 loopback not available; skipping IPv6 test");
            return;
        }
    };
    let client_local = client_sock.local_addr().expect("client local addr v6");
    let (up_addr, _up_thread) = match spawn_udp_echo_server_v6() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("IPv6 echo server could not bind; skipping IPv6 test");
            return;
        }
    };

    // spawn the forwarder binary
    let bin_opt = find_forwarder_bin();
    assert!(
        bin_opt.is_some(),
        "could not find forwarder binary; tried env(CARGO_BIN_EXE_udp[-_]forwarder) and ./target"
    );
    let bin = bin_opt.unwrap();

    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("[::1]:0")
            .arg(up_addr.to_string())
            .arg("--timeout-secs")
            .arg("1")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn forwarder"),
    );

    // Read the forwarder's listen address and connect the client
    let out_opt = take_child_stdout(&mut child);
    assert!(out_opt.is_some(), "child stdout missing");
    let mut out = out_opt.unwrap();

    let max_wait = Duration::from_secs(2);
    let listen_addr_opt = wait_for_listen_addr_from(&mut out, max_wait);
    assert!(
        listen_addr_opt.is_some(),
        "did not see listening address line within {:?}",
        max_wait
    );
    let listen_addr = listen_addr_opt.unwrap();
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
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // if it didn't exit, kill for cleanliness
    let _ = child.kill();

    // Validate stats snapshot fields
    let stats_opt = wait_for_stats_json_from(&mut out, max_wait);
    assert!(
        stats_opt.is_some(),
        "did not see stats JSON line within {:?}",
        max_wait
    );
    let stats = stats_opt.unwrap();
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), count);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), count);
    assert!(stats["client_addr"].is_string());
    assert!(stats["upstream_addr"].is_string());

    // Validate exact addresses (client local addr and upstream addr)
    let stats_client = json_addr(&stats["client_addr"]);
    assert_eq!(stats_client, client_local, "stats client_addr v6 mismatch");
    let stats_upstream = json_addr(&stats["upstream_addr"]);
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
    // Latency fields should be numeric
    assert!(stats["c2u_us_avg"].is_number());
    assert!(stats["u2c_us_avg"].is_number());
    assert!(stats["c2u_us_max"].is_number());
    assert!(stats["u2c_us_max"].is_number());
}
