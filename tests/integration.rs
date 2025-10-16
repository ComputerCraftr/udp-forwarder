mod common;
use common::*;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn enforce_max_payload_ipv4() {
    let (up_addr, _up_thread) = spawn_udp_echo_server_v4();
    let client = bind_udp_v4_client();
    let bin = find_forwarder_bin();
    let mut child = Command::new(bin)
        .arg("127.0.0.1:0")
        .arg(up_addr.to_string())
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
        .expect("spawn forwarder");

    let listen_addr = wait_for_listen_addr(&mut child, Duration::from_secs(3));

    // exactly safe payload (548) should pass
    let ok = vec![0u8; 548];
    client.send_to(&ok, listen_addr).unwrap();
    let mut buf = [0u8; 2048];
    let (_n, _src) = client.recv_from(&mut buf).expect("recv ok v4");

    // one byte over should be dropped (no echo)
    let over = vec![0u8; 549];
    client.send_to(&over, listen_addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let drop_expected = client.recv_from(&mut buf).is_err();
    assert!(drop_expected, "oversize v4 payload should be dropped");

    // check stats reflect one drop
    let stats = wait_for_stats_json(&mut child, Duration::from_secs(2));
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn enforce_max_payload_ipv6() {
    let client = match bind_udp_v6_client() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("no v6; skip");
            return;
        }
    };
    let (up_addr, _up) = match spawn_udp_echo_server_v6() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("no v6; skip");
            return;
        }
    };
    let bin = find_forwarder_bin();
    let mut child = Command::new(bin)
        .arg("[::1]:0")
        .arg(up_addr.to_string())
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
        .expect("spawn forwarder");

    let listen_addr = wait_for_listen_addr(&mut child, Duration::from_secs(3));

    // exactly safe payload (1232) should pass
    let ok = vec![0u8; 1232];
    client.send_to(&ok, listen_addr).unwrap();
    let mut buf = [0u8; 4096];
    let (_n, _src) = client.recv_from(&mut buf).expect("recv ok v6");

    // one byte over should be dropped
    let over = vec![0u8; 1233];
    client.send_to(&over, listen_addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let drop_expected = client.recv_from(&mut buf).is_err();
    assert!(drop_expected, "oversize v6 payload should be dropped");

    let stats = wait_for_stats_json(&mut child, Duration::from_secs(2));
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
    let bin = find_forwarder_bin();

    // run with small timeout & auto-exit on idle
    let mut child = Command::new(bin)
        .arg("127.0.0.1:0")
        .arg(up_addr.to_string())
        .arg("--timeout-secs")
        .arg("2")
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn forwarder");

    let listen_addr = wait_for_listen_addr(&mut child, Duration::from_secs(3));

    // send one datagram to the forwarder; expect to receive same payload back (echo through upstream)
    let payload = b"hello-through-forwarder";
    client_sock
        .send_to(payload, listen_addr)
        .expect("send to forwarder");

    let mut buf = [0u8; 1024];
    let (n, _src) = client_sock
        .recv_from(&mut buf)
        .expect("recv from forwarder");
    assert_eq!(&buf[..n], payload, "echo payload mismatch");

    // Wait for a stats line and validate fields
    let stats = wait_for_stats_json(&mut child, Duration::from_secs(2));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), 1);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), 1);
    assert!(stats["client"].is_string());
    assert!(stats["upstream"].is_string());

    // Validate addresses exactly (listen is random port, but client local addr is known)
    let stats_client = json_addr(&stats["client"]);
    assert_eq!(stats_client, client_local, "stats client addr mismatch");
    let stats_upstream = json_addr(&stats["upstream"]);
    assert_eq!(stats_upstream, up_addr, "stats upstream addr mismatch");

    // Validate byte counters for one packet
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["c2u_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );

    // Latency fields should be numbers (≥ 0)
    assert!(stats["c2u_us_avg"].is_number());
    assert!(stats["u2c_us_avg"].is_number());
    assert!(stats["c2u_us_max"].is_number());
    assert!(stats["u2c_us_max"].is_number());

    // after ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    // if it didn't exit, kill for cleanliness
    let _ = child.kill();
    panic!("forwarder did not exit after idle timeout");
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
            eprintln!("IPv6 echo server could not bind; skipping");
            return;
        }
    };
    let bin = find_forwarder_bin();

    let mut child = Command::new(bin)
        .arg("[::1]:0")
        .arg(up_addr.to_string())
        .arg("--timeout-secs")
        .arg("2")
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn forwarder");

    let listen_addr = wait_for_listen_addr(&mut child, Duration::from_secs(3));

    let payload = b"hello-through-forwarder-v6";
    client_sock.send_to(payload, listen_addr).expect("send v6");
    let mut buf = [0u8; 1024];
    let (n, _src) = client_sock.recv_from(&mut buf).expect("recv v6");
    assert_eq!(&buf[..n], payload);

    // stats line
    let stats = wait_for_stats_json(&mut child, Duration::from_secs(2));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), 1);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), 1);
    assert!(stats["client"].is_string());
    assert!(stats["upstream"].is_string());

    let stats_client = json_addr(&stats["client"]);
    assert_eq!(stats_client, client_local, "stats client addr v6 mismatch");
    let stats_upstream = json_addr(&stats["upstream"]);
    assert_eq!(stats_upstream, up_addr, "stats upstream addr v6 mismatch");
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["c2u_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert!(stats["c2u_us_avg"].is_number());
    assert!(stats["u2c_us_avg"].is_number());
    assert!(stats["c2u_us_max"].is_number());
    assert!(stats["u2c_us_max"].is_number());

    // allow exit
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success());
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("wait error: {e}"),
        }
    }
    let _ = child.kill();
    panic!("forwarder did not exit after idle timeout (v6)");
}
