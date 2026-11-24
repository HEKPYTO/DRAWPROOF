# drawproof

Command line client for commitments, draws, offline verification, and audit
reports.

## Commands

| Command | Purpose |
|---|---|
| `drawproof keygen` | Generate a mode-0600 Ed25519 signer key |
| `drawproof commit` | Fetch the latest quicknet round and write a commitment |
| `drawproof draw` | Collect receipts, wait for the selection round, write a bundle |
| `drawproof verify` | Verify a bundle offline, optionally against a signer policy |
| `drawproof report` | Verify a bundle and write a self-contained HTML report |

## Verification policy

A bundle declares its own signer keys and required count. Those values are not
independent evidence. Supply the expected keys out of band:

```sh
drawproof verify bundle.json --signer <public-key-a> --signer <public-key-b> --required 2
```

- `--signer` is repeatable and takes a 32-byte Ed25519 public key as hex.
- `--required` defaults to the number of `--signer` values.
- Without `--signer`, verification is internal consistency only and exits 3.
- `--allow-unpinned` accepts that local-only result with exit 0.
- `report` accepts the same flags and defaults to `report.html`.

`keygen` prints the public key. The private key stays in the key file.

## Quick start

```sh
cargo install --path . --locked
drawproof keygen --name demo --out signer.key
drawproof draw --manifest ../examples/manifest.jsonl --k 3 --signer-key signer.key
drawproof verify bundle.json --allow-unpinned
drawproof report bundle.json --out report.html --allow-unpinned
```

`draw` uses `https://api.drand.sh` and the pinned quicknet chain. The two-round
delay is enforced by the protocol and by the verifier.

## Independent signers

```sh
drawproof commit --manifest ../examples/manifest.jsonl --k 3 --lead-rounds 10 --out commitment.json
drawproof-server sign --key signer-a.key --commitment commitment.json --out receipt-a.json
drawproof-server sign --key signer-b.key --commitment commitment.json --out receipt-b.json
drawproof draw --manifest ../examples/manifest.jsonl --k 3 --commitment commitment.json \
  --receipt receipt-a.json --receipt receipt-b.json --required 2 --out bundle.json
```

`--lead-rounds` moves the registration round forward so independent signers have
time to sign before the selection round exists. A signer refuses once the
selection round has been published.

## Exit codes

- `0`: success, or a policy-backed valid bundle
- `1`: operational or verification failure; the message names the failed field
- `2`: command line usage error
- `3`: internally consistent but no signer policy; add `--signer` or `--allow-unpinned`

## Tests

```sh
cargo test -p drawproof --locked
```
