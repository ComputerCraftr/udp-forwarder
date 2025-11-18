mod common;

use crate::common::{
    ChildGuard, JSON_WAIT_MS, MAX_WAIT_SECS, TIMEOUT_SECS, bind_udp_v4_client, find_app_bin,
    random_unprivileged_port_v4, spawn_udp_echo_server_v4, take_child_stdout,
    wait_for_listen_addr_from, wait_for_stats_json_from,
};
#[cfg(unix)]
use nix::unistd;

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore] // opt-in: `cargo test --test stress stress_one_minute_ipv4_udp -- --ignored`
fn stress_one_minute_ipv4_udp() {
    stress_one_minute_ipv4("UDP");
}

#[test]
#[ignore] // opt-in: `cargo test --test stress stress_one_minute_ipv4_icmp -- --ignored`
fn stress_one_minute_ipv4_icmp() {
    stress_one_minute_ipv4("ICMP");
}

fn stress_one_minute_ipv4(proto: &str) {
    // Client socket bound to ephemeral local port
    let client_sock = bind_udp_v4_client().expect("IPv4 loopback not available");

    // Upstream echo server
    let up_addr = if !proto.eq_ignore_ascii_case("icmp") {
        spawn_udp_echo_server_v4()
            .expect("IPv4 echo server could not bind")
            .0
    } else {
        let ident = random_unprivileged_port_v4().expect("random ICMP identifier");
        format!("127.0.0.1:{ident}")
            .parse::<SocketAddr>()
            .expect("IPv4 socket address could not be parsed")
    };

    // Spawn the app binary
    let bin = find_app_bin().expect("could not find app binary");

    let mut cmd = Command::new(bin);
    cmd.arg("--here")
        .arg("UDP:127.0.0.1:0")
        .arg("--there")
        .arg(format!("{proto}:{up_addr}"))
        .arg("--timeout-secs")
        .arg(TIMEOUT_SECS.as_secs().to_string())
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    #[cfg(unix)]
    if unistd::geteuid().is_root() {
        cmd.arg("--user").arg("nobody");
    }

    let mut child = ChildGuard::new(cmd.spawn().expect("spawn app binary"));

    // Read the forwarder's listen address and connect the client
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");

    let listen_addr = wait_for_listen_addr_from(&mut out, MAX_WAIT_SECS).expect(&format!(
        "did not see listening address line within {:?}",
        MAX_WAIT_SECS
    ));
    client_sock
        .connect(listen_addr)
        .expect("connect to forwarder (IPv4)");

    // Load gen for 60 seconds
    let payload = vec![0u8; 1400];
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

    // After TIMEOUT_SECS of idle it should exit; give it a moment
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
            panic!("forwarder did not exit within {:?}", MAX_WAIT_SECS);
        }
    }

    // Sanity check via stats snapshot
    let stats = wait_for_stats_json_from(&mut out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap();
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap();
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap();
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap();

    // Sanity: the forwarder should have seen at least some of what we sent/received.
    assert!(
        u2c_pkts >= rcvd,
        "u2c_pkts too low: {} vs 100% of rcvd ~{}\n{}",
        u2c_pkts,
        rcvd,
        stats.to_string()
    );
    assert!(
        c2u_pkts >= sent * 3 / 4,
        "c2u_pkts too low: {} vs 75% of sent ~{}\n{}",
        c2u_pkts,
        sent * 3 / 4,
        stats.to_string()
    );
    assert_eq!(c2u_bytes, c2u_pkts * (payload.len() as u64));
    assert_eq!(u2c_bytes, u2c_pkts * (payload.len() as u64));
    // assert!(false, "sent:{}\nrcvd:{}\n{}", sent, rcvd, stats.to_string());
}
