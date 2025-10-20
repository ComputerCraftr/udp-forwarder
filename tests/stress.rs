mod common;
use common::*;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore] // opt-in: `cargo test --test stress -- --ignored --nocapture`
fn stress_one_minute_ipv4() {
    // upstream echo server
    let (up_addr, _up_thread) = spawn_udp_echo_server_v4();

    // client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client();

    // spawn the forwarder binary
    let bin = find_forwarder_bin();

    // run with small timeout & auto-exit on idle
    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("127.0.0.1:0")
            .arg(up_addr.to_string())
            .arg("--timeout-secs")
            .arg("2")
            .arg("--on-timeout")
            .arg("exit")
            .arg("--stats-interval-mins")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn forwarder"),
    );

    let mut out = take_child_stdout(&mut child);
    let listen_addr = wait_for_listen_addr_from(&mut out, Duration::from_secs(2));
    client_sock
        .connect(listen_addr)
        .expect("connect to forwarder (IPv4)");

    // Load gen for 60 seconds
    let payload = vec![0u8; 200];
    client_sock
        .send(&payload)
        .expect("send to forwarder (IPv4)"); // lock to this client

    let end = Instant::now() + Duration::from_secs(60);
    let mut sent = 0;

    // Drain echoes
    let recv_sock = client_sock.try_clone().unwrap();
    let recv_thr = thread::spawn(move || {
        let mut rcvd = 0;
        let mut buf = [0u8; 65535];
        while Instant::now() < end {
            recv_sock
                .recv(&mut buf)
                .expect("recv from forwarder (IPv4)");
            rcvd += 1;
        }
        rcvd
    });

    while Instant::now() < end {
        // burst of N datagrams per loop to reduce syscall overhead a bit
        for _ in 0..64 {
            client_sock
                .send(&payload)
                .expect("send to forwarder (IPv4)");
            sent += 1;
        }
        // tiny sleep to keep host responsive; remove for 100% load
        thread::sleep(Duration::from_micros(50));
    }

    let rcvd = recv_thr.join().unwrap();

    // After ~2s of idle it should exit; give it a moment
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
        c2u_pkts >= sent * 3 / 4,
        "c2u_pkts too low: {} vs sent ~{}\n{}",
        c2u_pkts,
        sent,
        stats.to_string()
    );
    assert!(
        u2c_pkts >= rcvd * 3 / 4,
        "u2c_pkts too low: {} vs got ~{}\n{}",
        u2c_pkts,
        rcvd,
        stats.to_string()
    );
    assert_eq!(c2u_bytes, c2u_pkts * (payload.len() as u64));
    assert_eq!(u2c_bytes, u2c_pkts * (payload.len() as u64));
    // assert!(false, "sent:{}\nrcvd:{}\n{}", sent, rcvd, stats.to_string());
}
