use crate::net::resolve_first;

use std::net::SocketAddr;
use std::{env, process};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedProtocol {
    UDP,
    ICMP,
}

impl SupportedProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            s if s.eq_ignore_ascii_case("udp") => Some(Self::UDP),
            s if s.eq_ignore_ascii_case("icmp") => Some(Self::ICMP),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::UDP => "UDP",
            Self::ICMP => "ICMP",
        }
    }
}

impl std::fmt::Display for SupportedProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Drop,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReresolveMode {
    None,
    Upstream,
    Listen,
    Both,
}

impl ReresolveMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(ReresolveMode::None),
            "upstream" => Some(ReresolveMode::Upstream),
            "listen" => Some(ReresolveMode::Listen),
            "both" => Some(ReresolveMode::Both),
            _ => None,
        }
    }

    #[inline]
    pub fn allow_upstream(self) -> bool {
        matches!(self, ReresolveMode::Upstream | ReresolveMode::Both)
    }

    #[inline]
    pub fn allow_listen(self) -> bool {
        matches!(self, ReresolveMode::Listen | ReresolveMode::Both)
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub listen_port_id: u16,             // Cached UDP port or ICMP identifier
    pub listen_proto: SupportedProtocol, // UDP | ICMP
    pub listen_str: String,              // original --here host:port string
    pub upstream_proto: SupportedProtocol, // UDP | ICMP
    pub upstream_str: String,            // FQDN:port or IP:port
    pub timeout_secs: u64,               // idle timeout for single client
    pub on_timeout: TimeoutAction,       // Drop | Exit
    pub stats_interval_mins: u32,        // JSON stats print interval
    pub max_payload: usize,              // optional user-specified MTU/payload limit
    pub reresolve_secs: u64,             // 0 = disabled
    pub reresolve_mode: ReresolveMode,   // which side(s) to re-resolve
    #[cfg(unix)]
    pub run_as_user: Option<String>,
    #[cfg(unix)]
    pub run_as_group: Option<String>,
    pub debug_no_connect: bool,
    pub debug_log_drops: bool,
}

pub fn parse_args() -> Config {
    // One place for usage. Program name is filled dynamically.
    fn print_usage_and_exit(code: i32) -> ! {
        let prog = env::args().next().unwrap_or_else(|| "pkthere".into());
        log_error!(
            "Usage: {prog} --here <protocol:listen_ip:port_id> --there <protocol:upstream_host_or_ip:port_id>\n\
             \n\
             Options:\n\
             \t--timeout-secs N         Idle timeout for the single client (default: 10)\n\
             \t--on-timeout drop|exit   What to do on timeout (default: drop)\n\
             \t--stats-interval-mins N  JSON stats print interval minutes (default: 60)\n\
             \t--max-payload N          Payload limit (0=unlimited)\n\
             \t--reresolve-secs N       Re-resolve host(s) every N seconds (0=disabled)\n\
             \t--reresolve-mode WHAT    Which sockets to re-resolve: upstream|listen|both|none (default: upstream)\n\
             \t--user NAME              Drop privileges to this user (Unix only)\n\
             \t--group NAME             Drop privileges to this group (Unix only)\n\
             \t--debug WHAT             Enable debug behavior (repeatable); WHAT = no-connect|log-drops\n\
             \t-h, --help               Show this help and exit"
        );
        process::exit(code)
    }

    // DRY helper: set an Option<T> once; error if the flag was already provided
    fn set_once<T>(slot: &mut Option<T>, val: T, flag: &str) {
        if slot.is_some() {
            log_error!("{flag} specified multiple times");
            print_usage_and_exit(2)
        }
        *slot = Some(val);
    }

    // Split "UDP:host:port" / "ICMP:host:id" into (proto, "host:port")
    fn split_proto<'a>(s: &'a str, flag: &str) -> (SupportedProtocol, &'a str) {
        s.split_once(':')
            .and_then(|(proto_str, rest)| SupportedProtocol::from_str(proto_str).map(|p| (p, rest)))
            .unwrap_or_else(|| {
                log_error!("{flag} must be UDP:<ip>:<port> or ICMP:<ip>:<id> (got '{s}')");
                print_usage_and_exit(2)
            })
    }

    // Generic number parser with good errors.
    fn parse_num<T>(s: &str, flag: &str) -> T
    where
        T: std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Display,
    {
        s.parse::<T>().unwrap_or_else(|e| {
            log_error!("invalid {flag}: {e}");
            print_usage_and_exit(2)
        })
    }

    // Address helpers.
    fn parse_here(s: &str) -> (String, SocketAddr, u16, SupportedProtocol) {
        let (proto, addr_str) = split_proto(s, "--here");
        match resolve_first(addr_str) {
            Ok(sa) => (sa.to_string(), sa, sa.port(), proto),
            Err(e) => {
                log_error!(
                    "--here: failed to parse and resolve host:port or ip:port (got '{s}'): {e}"
                );
                print_usage_and_exit(2)
            }
        }
    }
    fn validate_there(s: &str) -> (String, u16, SupportedProtocol) {
        let (proto, addr_str) = split_proto(s, "--there");
        match resolve_first(addr_str) {
            Ok(sa) => (sa.to_string(), sa.port(), proto),
            Err(e) => {
                log_error!(
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
            log_error!("{flag} requires a value");
            print_usage_and_exit(2)
        })
    }

    // Required
    let mut listen_opt: Option<(String, SocketAddr, u16, SupportedProtocol)> = None;
    let mut upstream_opt: Option<(String, u16, SupportedProtocol)> = None;

    // Optional (track presence to reject duplicates cleanly)
    let mut timeout_secs: Option<u64> = None;
    let mut on_timeout: Option<TimeoutAction> = None;
    let mut stats_interval_mins: Option<u32> = None;
    let mut max_payload: Option<usize> = None; // unlimited if None
    let mut reresolve_secs: Option<u64> = None; // 0 if None
    let mut reresolve_mode: Option<ReresolveMode> = None; // default upstream

    #[cfg(unix)]
    let mut run_as_user: Option<String> = None;
    #[cfg(unix)]
    let mut run_as_group: Option<String> = None;
    let mut debug_no_connect = false;
    let mut debug_log_drops = false;

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
                        log_error!("--on-timeout must be drop|exit");
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
            "--reresolve-mode" => {
                let val = get_next_value(&mut args_iter, "--reresolve-mode");
                let parsed = ReresolveMode::from_str(&val).unwrap_or_else(|| {
                    log_error!("--reresolve-mode must be upstream|listen|both|none (got '{val}')");
                    print_usage_and_exit(2)
                });
                set_once(&mut reresolve_mode, parsed, "--reresolve-mode");
            }
            #[cfg(unix)]
            "--user" => {
                let val = get_next_value(&mut args_iter, "--user");
                set_once(&mut run_as_user, val, "--user");
            }
            #[cfg(unix)]
            "--group" => {
                let val = get_next_value(&mut args_iter, "--group");
                set_once(&mut run_as_group, val, "--group");
            }
            "--debug" => {
                let val = get_next_value(&mut args_iter, "--debug");
                for part in val.split(',') {
                    let flag = part.trim();
                    if flag.is_empty() {
                        continue;
                    }
                    match flag {
                        "no-connect" => debug_no_connect = true,
                        "log-drops" => debug_log_drops = true,
                        _ => {
                            log_error!("--debug expects no-connect or log-drops (got '{flag}')");
                            print_usage_and_exit(2)
                        }
                    }
                }
            }
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                log_error!("unknown arg: {other}");
                print_usage_and_exit(2)
            }
        }
    }

    let (listen_str, listen_addr, listen_port_id, listen_proto) = match listen_opt {
        Some(t) => t,
        None => {
            log_error!("missing required flag: --here <protocol:listen_ip:port>");
            print_usage_and_exit(2)
        }
    };
    let (upstream_str, _upstream_port_id, upstream_proto) = match upstream_opt {
        Some(t) => t,
        None => {
            log_error!("missing required flag: --there <protocol:upstream_host_or_ip:port>");
            print_usage_and_exit(2)
        }
    };

    // Defaults
    let timeout_secs = timeout_secs.unwrap_or(10);
    let on_timeout = on_timeout.unwrap_or(TimeoutAction::Drop);
    let stats_interval_mins = stats_interval_mins.unwrap_or(60);
    let max_payload = max_payload.unwrap_or(0);
    let reresolve_secs = reresolve_secs.unwrap_or(0);
    let reresolve_mode = reresolve_mode.unwrap_or(ReresolveMode::Upstream);

    Config {
        listen_addr,
        listen_port_id,
        listen_proto,
        listen_str,
        upstream_proto,
        upstream_str,
        timeout_secs,
        on_timeout,
        stats_interval_mins,
        max_payload,
        reresolve_secs,
        reresolve_mode,
        #[cfg(unix)]
        run_as_user,
        #[cfg(unix)]
        run_as_group,
        debug_no_connect,
        debug_log_drops,
    }
}
