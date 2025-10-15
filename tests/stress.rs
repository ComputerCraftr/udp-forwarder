use serde_json::Value as Json;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn find_forwarder_bin() -> String {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_udp-forwarder") {
        return p;
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_udp_forwarder") {
        return p;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    for c in [
        format!("{}/target/release/udp-forwarder", manifest_dir),
        format!("{}/target/debug/udp-forwarder", manifest_dir),
    ] {
        if std::path::Path::new(&c).exists() {
            return c;
        }
    }
    panic!("forwarder binary not found");
}

fn wait_listen(child: &mut std::process::Child, max_wait: Duration) -> SocketAddr {
    let start = Instant::now();
    let stdout = child.stdout.as_mut().expect("no stdout");
    let mut buf = String::new();
    while start.elapsed() < max_wait {
        let mut chunk = [0u8; 4096];
        match stdout.read(&mut chunk) {
            Ok(0) => thread::sleep(Duration::from_millis(10)),
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if let Some(line) = buf.lines().find(|l| l.starts_with("Listening on ")) {
                    let addr_part = line.split_once(',').unwrap().0.replace("Listening on ", "");
                    return addr_part.parse().unwrap();
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    panic!("did not see Listening line; got:\n{}", buf);
}

fn wait_stats(child: &mut std::process::Child, deadline: Instant) -> Option<Json> {
    let stdout = child.stdout.as_mut().expect("no stdout");
    let mut buf = String::new();
    while Instant::now() < deadline {
        let mut chunk = [0u8; 4096];
        match stdout.read(&mut chunk) {
            Ok(0) => thread::sleep(Duration::from_millis(5)),
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                for line in buf.lines().rev() {
                    if line.starts_with('{') && line.ends_with('}') {
                        if let Ok(j) = serde_json::from_str::<Json>(line) {
                            return Some(j);
                        }
                    }
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
    None
}

#[test]
#[ignore] // opt-in: `cargo test --test stress -- --ignored --nocapture`
fn stress_ipv4_one_minute() {
    let bin = find_forwarder_bin();

    // Start a tiny IPv4 echo upstream
    let upstream = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let _echo = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        loop {
            if let Ok((n, src)) = upstream.recv_from(&mut buf) {
                let _ = upstream.send_to(&buf[..n], src);
            }
        }
    });

    // Launch forwarder on ephemeral port; stats every 1 minute; don't exit on idle
    let mut child = Command::new(bin)
        .arg("127.0.0.1:0")
        .arg(upstream_addr.to_string())
        .arg("--timeout-secs")
        .arg("5")
        .arg("--on-timeout")
        .arg("exit")
        .arg("--stats-interval-mins")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn forwarder");
    let listen = wait_listen(&mut child, Duration::from_secs(2));

    // Traffic generator: hammer for 60s with batch sends and recv echoes
    let client = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();

    // first packet to “lock” the forwarder to this client
    let payload = vec![0u8; 200]; // small payload; adjust to test MTU/EDNS
    client.send_to(&payload, listen).unwrap();

    // run for 60s
    let end = Instant::now() + Duration::from_secs(60);
    let mut sent = 0u64;

    // background receiver to drain echoes
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

    // tight send loop
    while Instant::now() < end {
        // burst of N datagrams per loop to reduce syscall overhead a bit
        for _ in 0..64 {
            let _ = client.send_to(&payload, listen);
            sent += 1;
        }
        // tiny sleep to keep host responsive; remove for 100% load
        thread::sleep(Duration::from_micros(50));
    }

    let rcvd = recv_thr.join().unwrap();

    // Grab a stats snapshot
    let stats =
        wait_stats(&mut child, Instant::now() + Duration::from_secs(2)).expect("no stats printed");
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap();
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap();
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap();
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap();

    // Sanity: the forwarder should have seen at least some of what we sent/received.
    assert!(
        c2u_pkts >= sent / 3,
        "c2u_pkts too low: {} vs sent ~{}",
        c2u_pkts,
        sent
    );
    assert!(
        u2c_pkts >= rcvd / 3,
        "u2c_pkts too low: {} vs got ~{}",
        u2c_pkts,
        rcvd
    );
    assert!(c2u_bytes == c2u_pkts * (payload.len() as u64));
    assert!(u2c_bytes == u2c_pkts * (payload.len() as u64));
}
