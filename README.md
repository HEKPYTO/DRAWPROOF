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
>
> Section and page map: [Paper map](#paper-map).

Independent work. Not affiliated with or endorsed by the authors.

## What it does

- Commits a sorted `(id, sha256)` manifest with an RFC 6962 style Merkle root.
- Pins drand quicknet, verifies its BLS12-381 proof, and enforces the two-round
  delay: selection round equals registration round plus two.
- Derives indices by rejection sampling over the beacon randomness, with no
  modulo bias.
- Records Ed25519 receipts and counts only receipts whose declared signing
  round precedes the selection round.
- Accepts an external signer policy at verification time: repeatable
  `--signer` public keys and an optional `--required` threshold. Without a
  policy, verification reports internal consistency only.
- Verifies the bundle offline: beacon proof, commitments, receipts, derivation,
  Merkle inclusion proofs, and sample hashes.
- Produces a one-page HTML audit report with the assumptions and non-goals.

## Quick start

Prerequisites: Rust 1.92 or newer; the repository pins 1.100.0 in
`rust-toolchain.toml`. Network access is needed only for `draw`/`commit`.
Verification is fully offline.

```sh
cargo install --path crates/drawproof --locked
cargo install --path crates/drawproof-server --locked
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

## Paper map

Paper: arXiv:2611.21222v1, *Verifiable Random Sampling of Private Data Without a
Trusted Single Party* (12 pages, 16 Nov 2026). Page numbers are the arXiv PDF
pages; section numbers match the HTML build. "Partial" means the code checks a
subset; "deviation" means a different construction.

| Paper claim | Section, pages | Code | Status and deviation |
|---|---|---|---|
| Signed commitment to salted item hashes; commitment carries n, reveal rate π, mode, beacon. | §3.1, p. 3 | `commitment.rs`, `manifest.rs` | Deviation: no committer signature; Merkle root over sorted `(id, sha256)`; no salts, π, mode, or beacon fields. |
| Registration with independent servers; server records t_reg, rejects duplicates, applies anchor rule; selection round r = a + 2. | §3.2, p. 4 | `bundle.rs::build`, `receipt.rs` | Partial: signers sign commitments; no server registry, duplicate rejection, t_reg, or anchor rule; only round + 2. |
| Receipts signed before selection; relying party fixes the required server set. | §3.2, p. 4; §3.4, pp. 4–5; §A.1, p. 8 | `receipt.rs`, `bundle.rs::verify_with_policy`, `--signer` | Partial: Ed25519 receipts and optional allowlist; quick start self-signs; no authenticated server clock. |
| Security goals and trust assumptions: beacon threshold, honest required server, no single party. | §2.3–2.4, pp. 2–3 | README trust model, `bundle.rs::verify_with_policy` | Partial: policy is optional; without `--signer` the result is internal consistency only. |
| Selection: HMAC-SHA256 per-item threshold or batch without replacement; reveal rate π. | §3.3, p. 4; §A.4, p. 9 | `derive.rs::indices` | Deviation: SHA-256 counter rejection over sorted indices; explicit k; no π, mode, HMAC, or batch formula. |
| Offline verify commitment, receipts, beacon, anchor/t_reg, selection, openings. | §3.4, pp. 4–5; §A.5, p. 9 | `bundle.rs::verify_with_policy`, `beacon.rs::verify`, `merkle.rs::verify_inclusion` | Partial: checks commitment, receipts, BLS beacon, r = a + 2, selection, inclusion; no t_reg, anchor, reveal, or opening checks. |
| Detection probability P_batch and P_item. | §4.1, pp. 4–5; §B.6, p. 11 | — | Not implemented: the report shows counts, not detection probability. |
| Name rule stops repeated commitments; public registration. | §4.2.1, p. 5 | `manifest.rs` | Deviation: duplicate IDs rejected within one manifest only; no cross-commitment name rule or public log. |
| Server clock trust; required server set. | §B.2, p. 10 | `receipt.rs`, `--signer/--required` | Partial: no timestamp; `signed_at_round` is self-declared; only allowlisted receipt count. |
| Anchor freshness from relay and local clock; relay lag. | §C.2, p. 11 | `beacon.rs::ensure_fresh`, `wait_for_round` | Partial: default URL checks latest within 4 rounds; no local-clock anchor, relay agreement, or custom-URL freshness. |
| Beacon is replaceable; other randomness sources. | §C.4, p. 12 | `beacon.rs::chain`, `bundle.rs::verify_with_policy` | Deviation: quicknet only; chain hash and public key pinned. |
| Privacy/refusal: salted commitments, openings, refusal handling. | §B.3, p. 10; §3.1, p. 3 | `manifest.rs`, bundle | Deviation: hashes only; no salts, openings, or refusal workflow; dataset size and metadata visible. |
| Reference implementation and multi-server evaluation. | §5, pp. 5–6; §C.1–C.3, pp. 11–12 | independent Rust | Deviation: not NoCherry; no multi-server or relay evaluation. |

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
policy, a release build, and a gitleaks secret scan with full history. The
ignored test fetches a live quicknet beacon and runs on demand or on the nightly
job.

## Documentation

- [`crates/drawproof/README.md`](crates/drawproof/README.md): CLI commands and modes.
- [`crates/drawproof-lib/README.md`](crates/drawproof-lib/README.md): formats and verification rules.
- [`crates/drawproof-server/README.md`](crates/drawproof-server/README.md): receipt signer.
- [`examples/README.md`](examples/README.md): manifest format and synthetic example.
- [`fixtures/README.md`](fixtures/README.md): pinned quicknet beacon fixtures.

## License

Apache License 2.0. See [LICENSE](LICENSE).
