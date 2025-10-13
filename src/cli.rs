use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Drop,
    Exit,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub upstream_target: String,   // FQDN:port or IP:port
    pub timeout_secs: u64,         // idle timeout for single client
    pub on_timeout: TimeoutAction, // drop | exit
    pub reresolve_secs: u64,       // 0 = disabled
    pub stats_interval_mins: u32,  // JSON stats print interval
}

pub fn parse_args() -> Config {
    use std::{env, io, net::ToSocketAddrs, process};

    fn resolve_first(s: &str) -> io::Result<SocketAddr> {
        let mut it = s.to_socket_addrs()?;
        it.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no address resolved"))
    }

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <listen_ip:port> <upstream_host_or_ip:port> \
             [--timeout-secs N] [--on-timeout drop|exit] \
             [--reresolve-secs N] [--stats-interval-mins N]",
            args[0]
        );
        process::exit(2);
    }

    let listen_addr = resolve_first(&args[1]).expect("bad listen addr");
    let upstream_target = args[2].clone();

    // Defaults
    let mut timeout_secs: u64 = 10;
    let mut on_timeout = TimeoutAction::Drop;
    let mut reresolve_secs: u64 = 0;
    let mut stats_interval_mins: u32 = 60;

    // Flags
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout-secs" => {
                timeout_secs = args
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("invalid --timeout-secs");
                        process::exit(2)
                    });
                i += 2;
            }
            "--on-timeout" => {
                on_timeout = match args.get(i + 1).map(|s| s.as_str()) {
                    Some("drop") => TimeoutAction::Drop,
                    Some("exit") => TimeoutAction::Exit,
                    _ => {
                        eprintln!("--on-timeout must be drop|exit");
                        process::exit(2)
                    }
                };
                i += 2;
            }
            "--reresolve-secs" => {
                reresolve_secs =
                    args.get(i + 1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| {
                            eprintln!("invalid --reresolve-secs");
                            process::exit(2)
                        });
                i += 2;
            }
            "--stats-interval-mins" => {
                stats_interval_mins =
                    args.get(i + 1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| {
                            eprintln!("invalid --stats-interval-mins");
                            process::exit(2)
                        });
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {}", other);
                process::exit(2);
            }
        }
    }

    Config {
        listen_addr,
        upstream_target,
        timeout_secs,
        on_timeout,
        reresolve_secs,
        stats_interval_mins,
    }
}
