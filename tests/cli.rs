mod common;

use crate::common::find_app_bin;

use std::io::Read;
use std::process::{Command, Stdio};

fn run_args(args: &[&str]) -> (Option<i32>, String) {
    let bin = find_app_bin().expect("could not find app binary");
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");

    let status = child.wait().expect("wait failed");
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code(), err)
}

#[test]
fn rejects_missing_required_flags_here() {
    let (code, err) = run_args(&["--there", "UDP:127.0.0.1:53"]);
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
    let (code, err) = run_args(&["--here", "UDP:127.0.0.1:12345"]);
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
    let (code, err) = run_args(&[
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
    let (code, err) = run_args(&[
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
    let (code, err) = run_args(&[
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
    let (code, err) = run_args(&[
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
    let (code, err) = run_args(&[
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
    let (code, err) = run_args(&["--here", "XYZ:127.0.0.1:abc", "--there", "UDP:127.0.0.1:53"]);
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
    let (code, err) = run_args(&["--here", "UDP:127.0.0.1:1", "--there", "UDP:not-an-addr"]);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );
    assert!(err.contains("--there"), "stderr: {}", err);
}
