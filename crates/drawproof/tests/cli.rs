use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use assert_cmd::Command;
use drawproof_lib::keyfile;
use predicates::str::contains;
use serde_json::{Value, json};
use tiny_http::{Header, Response, Server};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn mock_beacon(latest: u64, rounds: &[u64], requests: usize) -> String {
    mock_beacon_gated(latest, rounds, requests, Arc::new(AtomicBool::new(true)))
}

fn mock_beacon_gated(
    latest: u64,
    rounds: &[u64],
    requests: usize,
    gate: Arc<AtomicBool>,
) -> String {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let rounds = rounds.to_vec();
    thread::spawn(move || {
        for _ in 0..requests {
            let request = server.recv().unwrap();
            let charge = request
                .url()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
            let body = if charge == "latest" {
                fs::read(fixture(&format!("quicknet-{latest}.json"))).ok()
            } else {
                charge
                    .parse::<u64>()
                    .ok()
                    .filter(|r| rounds.contains(r))
                    .filter(|_| gate.load(Ordering::Relaxed))
                    .and_then(|r| fs::read(fixture(&format!("quicknet-{r}.json"))).ok())
            };
            match body {
                Some(bytes) => {
                    let header =
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                    let _ = request.respond(Response::from_data(bytes).with_header(header));
                }
                None => {
                    let _ =
                        request.respond(Response::from_string("not found").with_status_code(404));
                }
            }
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn write_manifest(dir: &Path) -> PathBuf {
    let path = dir.join("manifest.jsonl");
    let lines: Vec<String> = (0..10)
        .map(|i| format!(r#"{{"id":"item-{i:03}","sha256":"{:064x}"}}"#, i + 1))
        .collect();
    fs::write(&path, lines.join("\n")).unwrap();
    path
}

fn keygen(dir: &Path, name: &str) -> PathBuf {
    keygen_named(dir, name, "server.key")
}

fn keygen_named(dir: &Path, name: &str, file: &str) -> PathBuf {
    let path = dir.join(file);
    Command::cargo_bin("drawproof")
        .unwrap()
        .args(["keygen", "--name", name, "--out", path.to_str().unwrap()])
        .assert()
        .success();
    path
}

#[test]
fn independent_signers_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    let key_a = keygen_named(dir.path(), "signer-a", "a.key");
    let key_b = keygen_named(dir.path(), "signer-b", "b.key");
    let gate = Arc::new(AtomicBool::new(false));
    let url = mock_beacon_gated(34_230_592, &[34_230_594], 6, gate.clone());
    let commitment = dir.path().join("commitment.json");
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "commit",
            "--manifest",
            manifest.to_str().unwrap(),
            "--k",
            "3",
            "--beacon-url",
            &url,
            "--timeout",
            "10",
            "--out",
            commitment.to_str().unwrap(),
        ])
        .assert()
        .success();
    let server = PathBuf::from(env!("CARGO_BIN_EXE_drawproof")).with_file_name("drawproof-server");
    let receipt_a = dir.path().join("receipt-a.json");
    let receipt_b = dir.path().join("receipt-b.json");
    for (key, out) in [(&key_a, &receipt_a), (&key_b, &receipt_b)] {
        Command::new(&server)
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
    }
    gate.store(true, Ordering::Relaxed);
    let bundle = dir.path().join("multi.json");
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "draw",
            "--manifest",
            manifest.to_str().unwrap(),
            "--k",
            "3",
            "--commitment",
            commitment.to_str().unwrap(),
            "--receipt",
            receipt_a.to_str().unwrap(),
            "--receipt",
            receipt_b.to_str().unwrap(),
            "--required",
            "2",
            "--beacon-url",
            &url,
            "--timeout",
            "10",
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();
    let public_a = hex::encode(keyfile::load(&key_a).unwrap().1.verifying_key().to_bytes());
    let public_b = hex::encode(keyfile::load(&key_b).unwrap().1.verifying_key().to_bytes());
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "verify",
            bundle.to_str().unwrap(),
            "--signer",
            &public_a,
            "--signer",
            &public_b,
        ])
        .assert()
        .success()
        .stdout(contains("2 timely"))
        .stdout(contains("valid under"));
}

fn draw(dir: &Path, manifest: &Path, key: &Path, beacon_url: &str) -> PathBuf {
    let bundle = dir.join("bundle.json");
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "draw",
            "--manifest",
            manifest.to_str().unwrap(),
            "--k",
            "5",
            "--signer-key",
            key.to_str().unwrap(),
            "--beacon-url",
            beacon_url,
            "--timeout",
            "10",
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();
    bundle
}

#[test]
fn draw_verify_report_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    let key = keygen(dir.path(), "<script>alert(1)</script>");
    let url = mock_beacon(34_230_592, &[34_230_594], 3);
    let bundle = draw(dir.path(), &manifest, &key, &url);

    Command::cargo_bin("drawproof")
        .unwrap()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .code(3)
        .stdout(contains("consistent"))
        .stderr(contains("signer policy"));

    Command::cargo_bin("drawproof")
        .unwrap()
        .args(["verify", bundle.to_str().unwrap(), "--allow-unpinned"])
        .assert()
        .success()
        .stdout(contains("consistent"));

    let report = dir.path().join("report.html");
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "report",
            bundle.to_str().unwrap(),
            "--out",
            report.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(contains("signer policy"));

    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "report",
            bundle.to_str().unwrap(),
            "--out",
            report.to_str().unwrap(),
            "--allow-unpinned",
        ])
        .assert()
        .success();
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Assumptions"));
    assert!(html.contains("quicknet"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<script>alert"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}

#[test]
fn verify_rejects_tampered_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    let key = keygen(dir.path(), "server-a");
    let url = mock_beacon(34_230_592, &[34_230_594], 3);
    let bundle = draw(dir.path(), &manifest, &key, &url);

    let mut value: Value = serde_json::from_slice(&fs::read(&bundle).unwrap()).unwrap();
    value["commitment"]["nonce"] = json!("00");
    let bad = dir.path().join("tampered.json");
    fs::write(&bad, serde_json::to_vec(&value).unwrap()).unwrap();

    Command::cargo_bin("drawproof")
        .unwrap()
        .args(["verify", bad.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("commitment.nonce"));
}

#[test]
fn commit_writes_bound_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    let url = mock_beacon(34_230_592, &[], 1);
    let out = dir.path().join("commitment.json");
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "commit",
            "--manifest",
            manifest.to_str().unwrap(),
            "--k",
            "3",
            "--lead-rounds",
            "10",
            "--beacon-url",
            &url,
            "--timeout",
            "10",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let value: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    assert_eq!(value["round"], json!(34_230_602));
    assert_eq!(value["n"], json!(10));
    assert_eq!(value["k"], json!(3));
}

#[test]
fn draw_requires_a_signer_or_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    Command::cargo_bin("drawproof")
        .unwrap()
        .args([
            "draw",
            "--manifest",
            manifest.to_str().unwrap(),
            "--k",
            "5",
            "--beacon-url",
            "http://127.0.0.1:1",
            "--out",
            dir.path().join("bundle.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("signer"));
}
