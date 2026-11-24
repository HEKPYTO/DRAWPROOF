# DrawProof

![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![rust](https://img.shields.io/badge/rust-1.92%2B-orange)
![version](https://img.shields.io/badge/version-0.1.0-green)
![offline](https://img.shields.io/badge/verify-offline-black)

DrawProof makes "we sampled at random" checkable. A data holder commits to every
item hash, waits for two rounds of the public drand beacon, derives the sample
from that randomness, and ships a JSON bundle that an auditor verifies with no
network and no trust in the issuer.

Product implementation around:

> Muhammed Karamuk, Ruben Wolff, *Verifiable Random Sampling of Private Data
> Without a Trusted Single Party*, arXiv:2611.21222, 16 Nov 2026.
> https://arxiv.org/abs/2611.21222

Independent work. Not affiliated with or endorsed by the authors.

## What it does

- Commits a sorted `(id, sha256)` manifest with an RFC 6962 style Merkle root.
- Pins drand quicknet, verifies its BLS12-381 proof, and enforces the two-round
  delay: selection round equals registration round plus two.
- Derives indices by rejection sampling over the beacon randomness, with no
  modulo bias.
- Records Ed25519 receipts and requires enough receipts signed before the
  selection round existed.
- Accepts an external signer policy at verification time: repeatable
  `--signer` public keys and an optional `--required` threshold. Without a
  policy, verification reports internal consistency only.
- Verifies the bundle offline: beacon proof, commitments, receipts, derivation,
  Merkle inclusion proofs, and sample hashes.
- Produces a one-page HTML audit report with the assumptions and non-goals.

## Quick start

Prerequisites: Rust 1.92 or newer and network access only for `draw`/`commit`.
Verification is fully offline.

```sh
cargo install --path crates/drawproof --locked
drawproof keygen --name demo --out signer.key
drawproof draw --manifest examples/manifest.jsonl --k 3 --signer-key signer.key
drawproof verify bundle.json --allow-unpinned
drawproof report bundle.json --out report.html --allow-unpinned
```

`draw` waits for the two-round drand delay, about six to nine seconds. The
bundle contains everything the verifier needs. `signer.key` is written with mode
0600 and is ignored by git.

The quick start signs locally, so `verify` without `--signer` checks internal
consistency and exits 3; `--allow-unpinned` opts into a local-only exit 0. For
independent evidence, pass the expected public keys with `--signer`, as shown
below. Without a policy, the bundle's keys and required count are self-declared.

Use independent signers when the claim must survive the holder:

```sh
cargo install --path crates/drawproof-server --locked
drawproof keygen --name signer-a --out signer-a.key
drawproof keygen --name signer-b --out signer-b.key
drawproof commit --manifest examples/manifest.jsonl --k 3 --lead-rounds 10 --out commitment.json
drawproof-server sign --key signer-a.key --commitment commitment.json --out receipt-a.json
drawproof-server sign --key signer-b.key --commitment commitment.json --out receipt-b.json
drawproof draw --manifest examples/manifest.jsonl --k 3 --commitment commitment.json \
  --receipt receipt-a.json --receipt receipt-b.json --required 2 --out bundle.json
drawproof verify bundle.json --signer <public-key-a> --signer <public-key-b> --required 2
```

## Measured results

Release build, macOS arm64, 100 verification runs per row with a supplied
signer policy, process startup included.

| Dataset items | Sample size | Bundle size | Offline verify (median) |
|---:|---:|---:|---:|
| 10 | 3 | 2.7 KB | 4.5 ms |
| 10,000 | 100 | 120 KB | 6.2 ms |

A live 10,000-item draw took 6.4 s wall time, including the enforced two-round
wait. Verification made no network requests.

## Trust model

DrawProof verifies that the sample is the deterministic output of the pinned
drand quicknet round over the committed dataset. The security statement assumes:

- Fewer than the threshold of drand quicknet nodes colluded.
- At least the required number of receipt signers observed the commitment before
  the selection round was published and signed honestly.
- The committed dataset is the dataset the holder disclosed.
- SHA-256 is collision resistant and Ed25519 is unforgeable.

Local signing with `--signer-key` is a demonstration mode, not a trustless
setup: the holder signs its own receipt. Use independent `drawproof-server`
signers and supply their public keys to `verify` for the stated guarantee.

An offline bundle proves that this commitment produced this sample. It does not
prove that the holder registered no other commitments. Without a public
registration log, a holder can obtain several timely commitments and disclose
only the most favourable one. Add a public append-only registration log when
non-abandonment must be proven.

DrawProof does not prove that the dataset is complete or true, does not hide
dataset size or membership, and is not intended for elections, lotteries, or
other legally binding draws without counsel.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo test -p drawproof-lib --locked -- --ignored
cargo build --release --locked
pre-commit install
```

CI runs format, clippy with warnings denied, the full test suite, the markdown
policy, and a release build. The ignored test fetches a live quicknet beacon and
runs on demand or on the nightly job.

## Documentation

- [`crates/drawproof/README.md`](crates/drawproof/README.md): CLI commands and modes.
- [`crates/drawproof-lib/README.md`](crates/drawproof-lib/README.md): formats and verification rules.
- [`crates/drawproof-server/README.md`](crates/drawproof-server/README.md): receipt signer.
- [`examples/README.md`](examples/README.md): manifest format and synthetic example.
- [`fixtures/README.md`](fixtures/README.md): pinned quicknet beacon fixtures.

## License

Apache License 2.0. See [LICENSE](LICENSE).
