mod common;
use common::*;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore] // opt-in: `cargo test --test stress -- --ignored --nocapture`
fn stress_ipv4_one_minute() {
    let bin = find_forwarder_bin();

    // IPv4 echo upstream
    let (upstream_addr, _echo_thr) = spawn_udp_echo_server_v4();

    // Launch forwarder with stats every 1 minute
    let mut child = Command::new(bin)
        .arg("127.0.0.1:0")
        .arg(upstream_addr.to_string())
        .arg("--timeout-secs")
        .arg("2")
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn forwarder");

    let mut out = take_child_stdout(&mut child);
    let listen_addr = wait_for_listen_addr_from(&mut out, Duration::from_secs(2));

    // Load gen for 60 seconds
    let client = bind_udp_v4_client();
    let payload = vec![0u8; 200];
    client.send_to(&payload, listen_addr).unwrap(); // lock to this client

    let end = Instant::now() + Duration::from_secs(60);
    let mut sent = 0u64;

    // Drain echoes
    let recv_sock = client.try_clone().unwrap();
    let recv_thr = thread::spawn(move || {
        let mut rcvd = 0u64;
        let mut buf = [0u8; 65535];
        while Instant::now() < end {
            if let Ok((_n, _src)) = recv_sock.recv_from(&mut buf) {
                rcvd += 1;
            }
        }
        rcvd
    });

    while Instant::now() < end {
        // burst of N datagrams per loop to reduce syscall overhead a bit
        for _ in 0..64 {
            let _ = client.send_to(&payload, listen_addr);
            sent += 1;
        }
        // tiny sleep to keep host responsive; remove for 100% load
        thread::sleep(Duration::from_micros(50));
    }

    let rcvd = recv_thr.join().unwrap();

    // after ~2s of idle it should exit; give it a moment
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
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

    // Sanity check via stats snapshot
    let stats = wait_for_stats_json_from(&mut out, Duration::from_secs(2));
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap();
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap();
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap();
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap();

    // Sanity: the forwarder should have seen at least some of what we sent/received.
    assert!(
        c2u_pkts >= sent / 2,
        "c2u_pkts too low: {} vs sent ~{}",
        c2u_pkts,
        sent
    );
    assert!(
        u2c_pkts >= rcvd / 2,
        "u2c_pkts too low: {} vs got ~{}",
        u2c_pkts,
        rcvd
    );
    assert_eq!(c2u_bytes, c2u_pkts * (payload.len() as u64));
    assert_eq!(u2c_bytes, u2c_pkts * (payload.len() as u64));
}
