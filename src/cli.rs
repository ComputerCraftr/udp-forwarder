use std::net::{SocketAddr, ToSocketAddrs};
use std::{env, process};

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
    pub stats_interval_mins: u32,  // JSON stats print interval
    pub max_payload: usize,        // optional user-specified MTU/payload limit
    pub reresolve_secs: u64,       // 0 = disabled
}

pub fn parse_args() -> Config {
    // One place for usage. Program name is filled dynamically.
    fn print_usage_and_exit(code: i32) -> ! {
        let prog = env::args().next().unwrap_or_else(|| "udp-forwarder".into());
        eprintln!(
            "Usage: {prog} --here <listen_ip:port> --there <upstream_host_or_ip:port>\n\
             \n\
             Options:\n\
             \t--timeout-secs N         Idle timeout for the single client (default: 10)\n\
             \t--on-timeout drop|exit   What to do on timeout (default: drop)\n\
             \t--stats-interval-mins N  JSON stats print interval minutes (default: 60)\n\
             \t--max-payload N          Payload limit (0=unlimited)\n\
             \t--reresolve-secs N       Re-resolve upstream host every N seconds (0=disabled)\n\
             \t-h, --help               Show this help and exit"
        );
        process::exit(code)
    }

    // Generic number parser with good errors.
    fn parse_num<T>(s: &str, flag: &str) -> T
    where
        T: std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Display,
    {
        s.parse::<T>().unwrap_or_else(|e| {
            eprintln!("invalid {flag}: {e}");
            print_usage_and_exit(2)
        })
    }

    // Address helpers.
    fn parse_listen(s: &str) -> SocketAddr {
        match s.to_socket_addrs() {
            Ok(mut it) => it.next().unwrap_or_else(|| {
                eprintln!("--here: no address resolved from '{s}'");
                print_usage_and_exit(2)
            }),
            Err(e) => {
                eprintln!("--here: failed to parse '{s}': {e}");
                print_usage_and_exit(2)
            }
        }
    }
    fn validate_there(s: &str) -> String {
        match s.to_socket_addrs() {
            Ok(mut it) => {
                if it.next().is_some() {
                    s.to_string()
                } else {
                    eprintln!("--there: must be a resolvable host:port or ip:port (got '{s}')");
                    print_usage_and_exit(2)
                }
            }
            Err(_) => {
                eprintln!("--there: must be a resolvable host:port or ip:port (got '{s}')");
                print_usage_and_exit(2)
            }
        }
    }

    // Helper function: consume the next value from the iterator or exit.
    fn get_next_value<I: Iterator<Item = String>>(
        it: &mut std::iter::Peekable<I>,
        flag: &str,
    ) -> String {
        it.next().unwrap_or_else(|| {
            eprintln!("{flag} requires a value");
            print_usage_and_exit(2)
        })
    }

    // Required
    let mut listen_addr_opt: Option<SocketAddr> = None;
    let mut upstream_target_opt: Option<String> = None;

    // Optional defaults
    let mut timeout_secs: u64 = 10;
    let mut on_timeout: TimeoutAction = TimeoutAction::Drop;
    let mut stats_interval_mins: u32 = 60;
    let mut max_payload: usize = 0; // unlimited
    let mut reresolve_secs: u64 = 0;

    // Parse flags using an iterator (no manual index math)
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--here" => {
                let val = get_next_value(&mut args_iter, "--here");
                listen_addr_opt = Some(parse_listen(&val));
            }
            "--there" => {
                let val = get_next_value(&mut args_iter, "--there");
                upstream_target_opt = Some(validate_there(&val));
            }
            "--timeout-secs" => {
                let val = get_next_value(&mut args_iter, "--timeout-secs");
                timeout_secs = parse_num::<u64>(&val, "--timeout-secs");
            }
            "--on-timeout" => {
                let val = get_next_value(&mut args_iter, "--on-timeout");
                on_timeout = match val.as_str() {
                    "drop" => TimeoutAction::Drop,
                    "exit" => TimeoutAction::Exit,
                    _ => {
                        eprintln!("--on-timeout must be drop|exit");
                        print_usage_and_exit(2)
                    }
                };
            }
            "--stats-interval-mins" => {
                let val = get_next_value(&mut args_iter, "--stats-interval-mins");
                stats_interval_mins = parse_num::<u32>(&val, "--stats-interval-mins");
            }
            "--max-payload" => {
                let val = get_next_value(&mut args_iter, "--max-payload");
                max_payload = parse_num::<usize>(&val, "--max-payload");
            }
            "--reresolve-secs" => {
                let val = get_next_value(&mut args_iter, "--reresolve-secs");
                reresolve_secs = parse_num::<u64>(&val, "--reresolve-secs");
            }
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                eprintln!("unknown arg: {other}");
                print_usage_and_exit(2)
            }
        }
    }

    let listen_addr = match listen_addr_opt {
        Some(a) => a,
        None => {
            eprintln!("missing required flag: --here <listen_ip:port>");
            print_usage_and_exit(2)
        }
    };
    let upstream_target = match upstream_target_opt {
        Some(s) => s,
        None => {
            eprintln!("missing required flag: --there <upstream_host_or_ip:port>");
            print_usage_and_exit(2)
        }
    };

    Config {
        listen_addr,
        upstream_target,
        timeout_secs,
        on_timeout,
        stats_interval_mins,
        max_payload,
        reresolve_secs,
    }
}
