use crate::net::resolve_first;

use std::net::SocketAddr;
use std::{env, process};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedProtocol {
    UDP,
    ICMP,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Drop,
    Exit,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub listen_proto: SupportedProtocol,   // UDP | ICMP
    pub upstream_addr: String,             // FQDN:port or IP:port
    pub upstream_proto: SupportedProtocol, // UDP | ICMP
    pub timeout_secs: u64,                 // idle timeout for single client
    pub on_timeout: TimeoutAction,         // Drop | Exit
    pub stats_interval_mins: u32,          // JSON stats print interval
    pub max_payload: usize,                // optional user-specified MTU/payload limit
    pub reresolve_secs: u64,               // 0 = disabled
}

pub fn parse_args() -> Config {
    // One place for usage. Program name is filled dynamically.
    fn print_usage_and_exit(code: i32) -> ! {
        let prog = env::args().next().unwrap_or_else(|| "pkthere".into());
        eprintln!(
            "Usage: {prog} --here <protocol:listen_ip:port_id> --there <protocol:upstream_host_or_ip:port_id>\n\
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

    // DRY helper: set an Option<T> once; error if the flag was already provided
    fn set_once<T>(slot: &mut Option<T>, val: T, flag: &str) {
        if slot.is_some() {
            eprintln!("{flag} specified multiple times");
            print_usage_and_exit(2)
        }
        *slot = Some(val);
    }

    // Split "UDP:host:port" / "ICMP:host:id" into (proto, "host:port")
    fn split_proto<'a>(s: &'a str, flag: &str) -> (SupportedProtocol, &'a str) {
        if let Some(rest) = s.strip_prefix("UDP:") {
            (SupportedProtocol::UDP, rest)
        } else if let Some(rest) = s.strip_prefix("ICMP:") {
            (SupportedProtocol::ICMP, rest)
        } else {
            eprintln!("{flag} must be UDP:<ip>:<port> or ICMP:<ip>:<id> (got '{s}')");
            print_usage_and_exit(2)
        }
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
    fn parse_here(s: &str) -> (SupportedProtocol, SocketAddr) {
        let (proto, addr_str) = split_proto(s, "--here");
        match resolve_first(addr_str) {
            Ok(sa) => (proto, sa),
            Err(e) => {
                eprintln!(
                    "--here: failed to parse and resolve host:port or ip:port (got '{s}'): {e}"
                );
                print_usage_and_exit(2)
            }
        }
    }
    fn validate_there(s: &str) -> (SupportedProtocol, String) {
        let (proto, addr_str) = split_proto(s, "--there");
        match resolve_first(addr_str) {
            Ok(sa) => (proto, sa.to_string()),
            Err(e) => {
                eprintln!(
                    "--there: failed to parse and resolve host:port or ip:port (got '{s}'): {e}"
                );
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
    let mut listen_opt: Option<(SupportedProtocol, SocketAddr)> = None;
    let mut upstream_opt: Option<(SupportedProtocol, String)> = None;

    // Optional (track presence to reject duplicates cleanly)
    let mut timeout_secs: Option<u64> = None;
    let mut on_timeout: Option<TimeoutAction> = None;
    let mut stats_interval_mins: Option<u32> = None;
    let mut max_payload: Option<usize> = None; // unlimited if None
    let mut reresolve_secs: Option<u64> = None; // 0 if None

    // Parse flags using an iterator (no manual index math)
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--here" => {
                let val = get_next_value(&mut args_iter, "--here");
                let parsed = parse_here(&val);
                set_once(&mut listen_opt, parsed, "--here");
            }
            "--there" => {
                let val = get_next_value(&mut args_iter, "--there");
                let parsed = validate_there(&val);
                set_once(&mut upstream_opt, parsed, "--there");
            }
            "--timeout-secs" => {
                let val = get_next_value(&mut args_iter, "--timeout-secs");
                let parsed = parse_num::<u64>(&val, "--timeout-secs");
                set_once(&mut timeout_secs, parsed, "--timeout-secs");
            }
            "--on-timeout" => {
                let val = get_next_value(&mut args_iter, "--on-timeout");
                let action = match val.as_str() {
                    "drop" => TimeoutAction::Drop,
                    "exit" => TimeoutAction::Exit,
                    _ => {
                        eprintln!("--on-timeout must be drop|exit");
                        print_usage_and_exit(2)
                    }
                };
                set_once(&mut on_timeout, action, "--on-timeout");
            }
            "--stats-interval-mins" => {
                let val = get_next_value(&mut args_iter, "--stats-interval-mins");
                let parsed = parse_num::<u32>(&val, "--stats-interval-mins");
                set_once(&mut stats_interval_mins, parsed, "--stats-interval-mins");
            }
            "--max-payload" => {
                let val = get_next_value(&mut args_iter, "--max-payload");
                let parsed = parse_num::<usize>(&val, "--max-payload");
                set_once(&mut max_payload, parsed, "--max-payload");
            }
            "--reresolve-secs" => {
                let val = get_next_value(&mut args_iter, "--reresolve-secs");
                let parsed = parse_num::<u64>(&val, "--reresolve-secs");
                set_once(&mut reresolve_secs, parsed, "--reresolve-secs");
            }
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                eprintln!("unknown arg: {other}");
                print_usage_and_exit(2)
            }
        }
    }

    let (listen_proto, listen_addr) = match listen_opt {
        Some(t) => t,
        None => {
            eprintln!("missing required flag: --here <protocol:listen_ip:port>");
            print_usage_and_exit(2)
        }
    };
    let (upstream_proto, upstream_addr) = match upstream_opt {
        Some(t) => t,
        None => {
            eprintln!("missing required flag: --there <protocol:upstream_host_or_ip:port>");
            print_usage_and_exit(2)
        }
    };

    // Defaults
    let timeout_secs = timeout_secs.unwrap_or(10);
    let on_timeout = on_timeout.unwrap_or(TimeoutAction::Drop);
    let stats_interval_mins = stats_interval_mins.unwrap_or(60);
    let max_payload = max_payload.unwrap_or(0);
    let reresolve_secs = reresolve_secs.unwrap_or(0);

    Config {
        listen_addr,
        listen_proto,
        upstream_addr,
        upstream_proto,
        timeout_secs,
        on_timeout,
        stats_interval_mins,
        max_payload,
        reresolve_secs,
    }
}
