mod common;

use crate::common::run_cli_args;

#[test]
fn rejects_missing_required_flags_here() {
    let (code, err) = run_cli_args(&["--there", "UDP:127.0.0.1:53"]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.to_lowercase().contains("missing") && err.contains("--here"),
        "stderr: {}",
        err
    );
}

#[test]
fn rejects_missing_required_flags_there() {
    let (code, err) = run_cli_args(&["--here", "UDP:127.0.0.1:12345"]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.to_lowercase().contains("missing") && err.contains("--there"),
        "stderr: {}",
        err
    );
}

#[test]
fn rejects_duplicate_here() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--here",
        "UDP:127.0.0.1:2",
        "--there",
        "UDP:127.0.0.1:53",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.contains("--here specified multiple times"),
        "stderr: {}",
        err
    );
}

#[test]
fn rejects_duplicate_there() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:53",
        "--there",
        "UDP:127.0.0.1:54",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.contains("--there specified multiple times"),
        "stderr: {}",
        err
    );
}

#[test]
fn rejects_duplicate_optional_flags() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:53",
        "--timeout-secs",
        "5",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.contains("--timeout-secs specified multiple times"),
        "stderr: {}",
        err
    );
}

#[test]
fn rejects_invalid_on_timeout_value() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:53",
        "--on-timeout",
        "nope",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.contains("--on-timeout") && err.to_lowercase().contains("must be"),
        "stderr: {}",
        err
    );
}

#[test]
fn rejects_invalid_numeric_values() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:53",
        "--max-payload",
        "notanumber",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(err.contains("--max-payload"), "stderr: {}", err);
}

#[test]
fn rejects_invalid_here_value() {
    let (code, err) = run_cli_args(&["--here", "XYZ:127.0.0.1:abc", "--there", "UDP:127.0.0.1:53"]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(err.contains("--here"), "stderr: {}", err);
}

#[test]
fn rejects_invalid_there_value() {
    let (code, err) = run_cli_args(&["--here", "UDP:127.0.0.1:1", "--there", "UDP:not-an-addr"]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(err.contains("--there"), "stderr: {}", err);
}

#[test]
fn rejects_invalid_debug_value() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:2",
        "--debug",
        "foo",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.contains("--debug") && err.contains("no-connect") && err.contains("log-drops"),
        "stderr: {}",
        err
    );
}

#[cfg(unix)]
#[test]
fn rejects_duplicate_user_flags() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:2",
        "--user",
        "nobody",
        "--user",
        "daemon",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(
        err.contains("--user specified multiple times"),
        "stderr: {}",
        err
    );
}

#[cfg(unix)]
#[test]
fn rejects_missing_user_value() {
    let (code, err) = run_cli_args(&[
        "--here",
        "UDP:127.0.0.1:1",
        "--there",
        "UDP:127.0.0.1:2",
        "--user",
    ]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(err.contains("--user requires a value"), "stderr: {}", err);
}
