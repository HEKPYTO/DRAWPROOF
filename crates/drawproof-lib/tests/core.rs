use std::fs;
use std::path::PathBuf;

use drawproof_lib::{
    beacon, bundle, commitment::Commitment, derive, files, keyfile, manifest::Manifest, merkle,
    receipt, report,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

const ROOT: &str = "453d177f91e1a8557aceec50adc13f7d87601fa1dd203877160492b90a9cbcfb";
const NONCE: &str = "3cb175a043137ab5206fef13acf0df3f02aadc3f5cbc851068ba25cd45d4c35d";
const RANDOMNESS: &str = "9e6019434f1c7146624a7c4450f3dadae496260065974001747033bd7d8cfd13";
const REGISTRATION_ROUND: u64 = 34_230_592;
const BEACON_ROUND: u64 = 34_230_594;

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn verified_beacon() -> drand::VerifiedBeacon {
    let bytes = fs::read(fixture("quicknet-34230594.json")).unwrap();
    beacon::verify_json(&bytes, BEACON_ROUND).unwrap()
}

fn manifest(n: usize) -> Manifest {
    let lines: Vec<String> = (0..n)
        .map(|i| format!(r#"{{"id":"item-{i:03}","sha256":"{:064x}"}}"#, i + 1))
        .collect();
    Manifest::from_jsonl(lines.join("\n").as_bytes()).unwrap()
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn fixed_commitment() -> Commitment {
    Commitment::new(hex32(ROOT), 10, 5, 100, hex32(NONCE))
}

fn working_bundle() -> bundle::Bundle {
    let m = manifest(10);
    let c = Commitment::new(m.root, m.len(), 5, REGISTRATION_ROUND, hex32(NONCE));
    let b = verified_beacon();
    let r = receipt::sign(&c, &signing_key(), "server-a", BEACON_ROUND - 1).unwrap();
    bundle::build(&m, &c, &b, vec![r], 1).unwrap()
}

fn tampered<F: Fn(&mut Value)>(b: &bundle::Bundle, mutate: F) -> String {
    let mut v = serde_json::to_value(b).unwrap();
    mutate(&mut v);
    let t: bundle::Bundle = serde_json::from_value(v).unwrap();
    bundle::verify(&t).unwrap_err().to_string()
}

#[test]
fn commitment_golden() {
    let c = fixed_commitment();
    let bytes = c.canonical_bytes().unwrap();
    assert_eq!(
        bytes,
        b"drawproof/v1\nroot=453d177f91e1a8557aceec50adc13f7d87601fa1dd203877160492b90a9cbcfb\nn=10\nk=5\nround=100\nnonce=3cb175a043137ab5206fef13acf0df3f02aadc3f5cbc851068ba25cd45d4c35d".to_vec()
    );
    assert_eq!(
        hex::encode(c.sha256().unwrap()),
        "e596c1a6a894e2e712c401fb9d908da483683d8edc1aa31be4af76ab3774cae0"
    );
}

#[test]
fn commitment_rejects_short_hex() {
    let mut c = fixed_commitment();
    c.root = "00".to_string();
    let err = c.validate().unwrap_err().to_string();
    assert!(err.contains("commitment.root"), "{err}");
}

#[test]
fn derivation_matches_vectors() {
    let root = hex32(ROOT);
    let randomness = hex32(RANDOMNESS);
    assert_eq!(
        derive::indices(&randomness, &root, 10, 5).unwrap(),
        vec![6, 1, 2, 4, 3]
    );
    assert_eq!(
        derive::indices(&randomness, &root, 3, 2).unwrap(),
        vec![2, 0]
    );
    assert_eq!(
        derive::indices(&randomness, &root, 7, 7).unwrap(),
        vec![2, 3, 6, 5, 0, 1, 4]
    );
    assert_eq!(
        derive::indices(&randomness, &root, 1000, 10).unwrap(),
        vec![796, 381, 851, 992, 764, 483, 743, 2, 319, 202]
    );
}

#[test]
fn derivation_rejects_bad_bounds() {
    let root = hex32(ROOT);
    let randomness = hex32(RANDOMNESS);
    assert!(derive::indices(&randomness, &root, 0, 1).is_err());
    assert!(derive::indices(&randomness, &root, 3, 0).is_err());
    assert!(derive::indices(&randomness, &root, 3, 4).is_err());
}

#[test]
fn merkle_golden_and_proofs() {
    let leaves = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
        .iter()
        .map(|data| merkle::leaf_hash(data))
        .collect::<Vec<_>>();
    assert_eq!(
        hex::encode(merkle::root(&leaves)),
        "36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1"
    );
    for index in 0..leaves.len() {
        let proof = merkle::proof(&leaves, index);
        assert!(merkle::verify_inclusion(
            leaves[index],
            index as u64,
            leaves.len() as u64,
            &proof,
            merkle::root(&leaves)
        ));
    }
}

#[test]
fn merkle_rejects_tampered_proof() {
    let leaves = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
        .iter()
        .map(|data| merkle::leaf_hash(data))
        .collect::<Vec<_>>();
    let root = merkle::root(&leaves);
    let mut proof = merkle::proof(&leaves, 1);
    proof[0][0] ^= 0xff;
    assert!(!merkle::verify_inclusion(
        leaves[1],
        1,
        leaves.len() as u64,
        &proof,
        root
    ));
}

#[test]
fn manifest_sorts_and_hashes() {
    let m = Manifest::from_jsonl(
        br#"{"id":"b","sha256":"0000000000000000000000000000000000000000000000000000000000000002"}
{"id":"a","sha256":"0000000000000000000000000000000000000000000000000000000000000001"}"#,
    )
    .unwrap();
    assert_eq!(m.entries[0].id, "a");
    assert_eq!(m.entries[1].id, "b");
    assert_eq!(m.root, merkle::root(&[m.leaf(0), m.leaf(1)]));
}

#[test]
fn manifest_rejects_duplicates() {
    let err = Manifest::from_jsonl(
        br#"{"id":"a","sha256":"0000000000000000000000000000000000000000000000000000000000000001"}
{"id":"a","sha256":"0000000000000000000000000000000000000000000000000000000000000002"}"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("manifest"), "{err}");
}

#[test]
fn manifest_rejects_bad_hash() {
    let err = Manifest::from_jsonl(br#"{"id":"a","sha256":"00"}"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("manifest"), "{err}");
}

#[test]
fn beacon_fixture_verifies_offline() {
    let bytes = fs::read(fixture("quicknet-34230594.json")).unwrap();
    let verified = beacon::verify_json(&bytes, BEACON_ROUND).unwrap();
    assert_eq!(verified.round(), BEACON_ROUND);
    let raw: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        hex::encode(verified.randomness()),
        raw["randomness"].as_str().unwrap()
    );
}

#[test]
fn beacon_rejects_tampered_signature() {
    let bytes = fs::read(fixture("quicknet-34230594.json")).unwrap();
    let mut raw: Value = serde_json::from_slice(&bytes).unwrap();
    raw["signature"] = json!("00");
    let err = beacon::verify_json(&serde_json::to_vec(&raw).unwrap(), BEACON_ROUND)
        .unwrap_err()
        .to_string();
    assert!(err.contains("beacon.signature"), "{err}");
}

#[test]
fn receipt_roundtrip_and_tamper() {
    let c = fixed_commitment();
    let r = receipt::sign(&c, &signing_key(), "server-a", 99).unwrap();
    receipt::verify(&c, &r).unwrap();
    let mut wrong_server = r.clone();
    wrong_server.server = "server-b".to_string();
    assert!(receipt::verify(&c, &wrong_server).is_err());
    let mut wrong_round = r.clone();
    wrong_round.signed_at_round = 101;
    assert!(receipt::verify(&c, &wrong_round).is_err());
}

#[test]
fn receipt_rejects_wrong_commitment() {
    let c = fixed_commitment();
    let r = receipt::sign(&c, &signing_key(), "server-a", 99).unwrap();
    let mut other = c.clone();
    other.nonce = "11".repeat(32);
    let err = receipt::verify(&other, &r).unwrap_err().to_string();
    assert!(err.contains("receipt"), "{err}");
}

#[test]
fn bundle_build_and_verify() {
    let b = working_bundle();
    let verified = bundle::verify(&b).unwrap();
    assert_eq!(verified.sample_count, 5);
    assert_eq!(verified.receipts_present, 1);
    assert_eq!(verified.timely_receipts, 1);
    assert_eq!(verified.beacon_round, BEACON_ROUND);
    assert_eq!(verified.required, 1);
}

type Case = (&'static str, fn(&mut Value));

#[test]
fn bundle_rejects_each_tampered_field() {
    let b = working_bundle();
    let cases: Vec<Case> = vec![
        ("version", |v| v["version"] = json!("other")),
        ("chain.hash", |v| v["chain"]["hash"] = json!("00")),
        ("chain.public_key", |v| {
            v["chain"]["public_key"] = json!("00")
        }),
        ("chain.network", |v| v["chain"]["network"] = json!("other")),
        ("commitment.root", |v| v["commitment"]["root"] = json!("00")),
        ("sample", |v| v["commitment"]["n"] = json!(11)),
        ("sample.length", |v| v["commitment"]["k"] = json!(6)),
        ("beacon.round", |v| v["commitment"]["round"] = json!(1)),
        ("commitment.nonce", |v| {
            v["commitment"]["nonce"] = json!("00")
        }),
        ("beacon.round", |v| v["beacon"]["round"] = json!(1)),
        ("beacon.signature", |v| {
            v["beacon"]["signature"] = json!("00")
        }),
        ("beacon.randomness", |v| {
            v["beacon"]["randomness"] = json!("00")
        }),
        ("bundle.required", |v| v["required"] = json!(2)),
        ("receipt.public_key", |v| {
            v["receipts"][0]["public_key"] = json!("00")
        }),
        ("receipt.signature", |v| {
            v["receipts"][0]["signature"] = json!("00")
        }),
        ("receipt.signature", |v| {
            v["receipts"][0]["signed_at_round"] = json!(BEACON_ROUND)
        }),
        ("receipt.signature", |v| {
            v["receipts"][0]["server"] = json!("server-b")
        }),
        ("receipt.commitment_sha256", |v| {
            v["receipts"][0]["commitment_sha256"] = json!("00")
        }),
        ("sample.index", |v| v["sample"][0]["index"] = json!(9)),
        ("sample.proof", |v| {
            v["sample"][0]["item_id"] = json!("evil")
        }),
        ("sample.item_hash", |v| {
            v["sample"][0]["item_hash"] = json!("00")
        }),
        ("sample.proof", |v| v["sample"][0]["proof"][0] = json!("00")),
    ];
    for (field, mutate) in cases {
        let err = tampered(&b, mutate);
        assert!(err.contains(field), "{field}: {err}");
    }
}

#[test]
fn report_escapes_server_name() {
    let m = manifest(10);
    let c = Commitment::new(m.root, m.len(), 5, REGISTRATION_ROUND, hex32(NONCE));
    let b = verified_beacon();
    let r = receipt::sign(
        &c,
        &signing_key(),
        "<script>alert(1)</script>",
        BEACON_ROUND - 1,
    )
    .unwrap();
    let built = bundle::build(&m, &c, &b, vec![r], 1).unwrap();
    let verified = bundle::verify(&built).unwrap();
    let html = report::html(&verified);
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("Internally consistent"));
    assert!(html.contains("No signer policy was supplied"));
}

#[test]
fn keyfile_roundtrip_and_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.key");
    let generated = keyfile::generate("server-a").unwrap();
    keyfile::write(&path, &generated).unwrap();
    let (name, key) = keyfile::load(&path).unwrap();
    assert_eq!(name, "server-a");
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        hex::encode(generated.signing_key().unwrap().verifying_key().to_bytes())
    );
    assert!(keyfile::write(&path, &generated).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}

#[test]
#[ignore = "requires network access to api.drand.sh"]
fn live_quicknet_beacon_verifies() {
    let verified =
        beacon::fetch_latest(beacon::DEFAULT_URL, std::time::Duration::from_secs(20)).unwrap();
    assert!(verified.round() > 0);
}

#[test]
fn capped_reader_rejects_oversized_documents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.json");
    fs::write(&path, b"0123456789").unwrap();
    let err = files::read_capped(&path, 4, "bundle")
        .unwrap_err()
        .to_string();
    assert!(err.contains("bundle"), "{err}");
    assert!(files::read_capped(&path, 10, "bundle").is_ok());
}

#[test]
fn bundle_rejects_duplicate_receipt_keys() {
    let m = manifest(10);
    let c = Commitment::new(m.root, m.len(), 5, REGISTRATION_ROUND, hex32(NONCE));
    let b = verified_beacon();
    let first = receipt::sign(&c, &signing_key(), "server-a", BEACON_ROUND - 1).unwrap();
    let second = receipt::sign(&c, &signing_key(), "server-b", BEACON_ROUND - 1).unwrap();
    let err = bundle::build(&m, &c, &b, vec![first, second], 1)
        .unwrap_err()
        .to_string();
    assert!(err.contains("receipt.public_key"), "{err}");
}

#[test]
fn single_item_bundle_verifies() {
    let m = manifest(1);
    let c = Commitment::new(m.root, 1, 1, REGISTRATION_ROUND, hex32(NONCE));
    let b = verified_beacon();
    let r = receipt::sign(&c, &signing_key(), "server-a", BEACON_ROUND - 1).unwrap();
    let built = bundle::build(&m, &c, &b, vec![r], 1).unwrap();
    let verified = bundle::verify(&built).unwrap();
    assert_eq!(verified.sample_count, 1);
    assert!(built.sample[0].proof.is_empty());
}

#[test]
fn policy_requires_allowlisted_signers() {
    let b = working_bundle();
    let key = signing_key().verifying_key().to_bytes();
    let verified = bundle::verify_with_policy(&b, &[key], None).unwrap();
    assert!(verified.policy_applied);
    assert_eq!(verified.required, 1);
    let html = report::html(&verified);
    assert!(html.contains("Verified."));
    assert!(html.contains("allowlisted signers"));
    let other = SigningKey::from_bytes(&[8u8; 32])
        .verifying_key()
        .to_bytes();
    let err = bundle::verify_with_policy(&b, &[other], Some(1))
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy.required"), "{err}");
    let err = bundle::verify_with_policy(&b, &[key], Some(2))
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy.required"), "{err}");
}

#[test]
fn late_receipt_is_not_timely() {
    let m = manifest(10);
    let c = Commitment::new(m.root, m.len(), 5, REGISTRATION_ROUND, hex32(NONCE));
    let b = verified_beacon();
    let r = receipt::sign(&c, &signing_key(), "server-a", BEACON_ROUND).unwrap();
    let err = bundle::build(&m, &c, &b, vec![r], 1)
        .unwrap_err()
        .to_string();
    assert!(err.contains("bundle.required"), "{err}");
}

#[test]
fn policy_ignores_non_allowlisted_receipts() {
    let m = manifest(10);
    let c = Commitment::new(m.root, m.len(), 5, REGISTRATION_ROUND, hex32(NONCE));
    let b = verified_beacon();
    let first = receipt::sign(&c, &signing_key(), "server-a", BEACON_ROUND - 1).unwrap();
    let second_key = SigningKey::from_bytes(&[8u8; 32]);
    let second = receipt::sign(&c, &second_key, "server-b", BEACON_ROUND - 1).unwrap();
    let built = bundle::build(&m, &c, &b, vec![first, second], 1).unwrap();
    let allowed = signing_key().verifying_key().to_bytes();
    let verified = bundle::verify_with_policy(&built, &[allowed], Some(1)).unwrap();
    assert_eq!(verified.timely_receipts, 1);
    assert!(verified.receipts[0].counted);
    assert!(verified.receipts[0].timely);
    assert!(!verified.receipts[1].counted);
    assert!(!verified.receipts[1].timely);
    assert!(report::html(&verified).contains("<td><code>no</code></td>"));
}
