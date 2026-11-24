use std::fs;
use std::path::PathBuf;
use std::thread;

use assert_cmd::Command;
use drawproof_lib::{commitment::Commitment, keyfile};
use predicates::str::contains;
use serde_json::{Value, json};
use tiny_http::{Header, Response, Server};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn mock_latest(latest: u64, requests: usize) -> String {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    thread::spawn(move || {
        for _ in 0..requests {
            let request = server.recv().unwrap();
            let charge = request.url().rsplit('/').next().unwrap_or_default();
            if charge == "latest" {
                let bytes = fs::read(fixture(&format!("quicknet-{latest}.json"))).unwrap();
                let header =
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                let _ = request.respond(Response::from_data(bytes).with_header(header));
            } else {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
            }
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn mock_pair(latest: u64, target: u64) -> String {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    thread::spawn(move || {
        for _ in 0..2 {
            let request = server.recv().unwrap();
            let charge = request.url().rsplit('/').next().unwrap_or_default();
            let round = if charge == "latest" { latest } else { target };
            let bytes = fs::read(fixture(&format!("quicknet-{round}.json"))).unwrap();
            let header =
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
            let _ = request.respond(Response::from_data(bytes).with_header(header));
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn sign_refuses_when_selection_round_is_fetchable() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path());
    let commitment = write_commitment(dir.path(), 34_230_592);
    let out = dir.path().join("receipt.json");
    let url = mock_pair(34_230_592, 34_230_594);
    Command::cargo_bin("drawproof-server")
        .unwrap()
        .args([
            "sign",
            "--key",
            key.to_str().unwrap(),
            "--commitment",
            commitment.to_str().unwrap(),
            "--beacon-url",
            &url,
            "--timeout",
            "10",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("already available"));
}

fn write_key(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("server.key");
    let generated = keyfile::generate("server-a").unwrap();
    keyfile::write(&path, &generated).unwrap();
    path
}

fn write_commitment(dir: &std::path::Path, round: u64) -> PathBuf {
    let path = dir.join("commitment.json");
    let commitment = Commitment::new([1u8; 32], 10, 3, round, [2u8; 32]);
    fs::write(&path, serde_json::to_vec(&commitment).unwrap()).unwrap();
    path
}

#[test]
fn sign_returns_a_bound_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path());
    let commitment = write_commitment(dir.path(), 34_230_592);
    let out = dir.path().join("receipt.json");
    let url = mock_latest(34_230_592, 2);
    Command::cargo_bin("drawproof-server")
        .unwrap()
        .args([
            "sign",
            "--key",
            key.to_str().unwrap(),
            "--commitment",
            commitment.to_str().unwrap(),
            "--beacon-url",
            &url,
            "--timeout",
            "10",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let receipt: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    assert_eq!(receipt["server"], json!("server-a"));
    assert_eq!(receipt["signed_at_round"], json!(34_230_592));
}

#[test]
fn sign_refuses_after_the_selection_round_exists() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path());
    let commitment = write_commitment(dir.path(), 34_230_590);
    let out = dir.path().join("receipt.json");
    let url = mock_latest(34_230_592, 1);
    Command::cargo_bin("drawproof-server")
        .unwrap()
        .args([
            "sign",
            "--key",
            key.to_str().unwrap(),
            "--commitment",
            commitment.to_str().unwrap(),
            "--beacon-url",
            &url,
            "--timeout",
            "10",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("selection round"));
}
