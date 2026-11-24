# drawproof-lib

Core library behind the `drawproof` and `drawproof-server` binaries.

## Modules

| Module | Responsibility |
|---|---|
| `manifest` | Parse JSONL entries, validate unique ids and 32-byte hashes, sort by id, build leaves and root |
| `merkle` | RFC 6962 leaf and node hashing, root, inclusion proof, proof verification |
| `commitment` | Canonical commitment bytes, SHA-256, random nonce |
| `derive` | Rejection-sampled indices from beacon randomness, root, `n`, and `k` |
| `receipt` | Ed25519 receipt message, signing, verification, commitment binding |
| `keyfile` | Mode-0600 signer key generation and loading |
| `beacon` | Pinned quicknet chain, relay fetch, BLS verification, round wait |
| `bundle` | Build, serialize, and verify the complete receipt bundle |
| `report` | Self-contained HTML audit report with escaped fields |

## Canonical commitment

The exact bytes signed by every receipt are:

```
drawproof/v1
root=<64 lowercase hex>
n=<decimal>
k=<decimal>
round=<decimal>
nonce=<64 lowercase hex>
```

No trailing newline. `root` and `nonce` must be lowercase canonical hex. The
canonical bytes are the only representation accepted by the verifier.

## Merkle leaves

A manifest leaf hashes:

```
SHA256(0x00 || "drawproof/v1/item" || u32be(id length) || id || item hash)
```

Internal nodes hash `SHA256(0x01 || left || right)`. The tree uses the RFC 6962
split rule: the largest power of two strictly smaller than the number of leaves.

## Derivation

For attempt counter `i`, starting at zero:

```
seed = SHA256("drawproof/v1" || randomness || root || u64be(i))
u    = first 8 bytes of seed, big-endian
limit = floor(2^64 / n) * n
accept when u < limit, index = u mod n, then reject duplicates
```

The counter advances on every attempt. Accepted indices preserve draw order.
`k` must be positive and must not exceed `n`.

## Receipt message

```
drawproof/v1/receipt
server=<name>
signed_at_round=<decimal>
<canonical commitment bytes>
```

A receipt carries the server name, public key, signature, signing round, and the
commitment SHA-256. `signed_at_round` must be below the selection round for the
receipt to count as timely. The verifier requires at least `required` timely,
distinct server keys.

## Bundle verification

`bundle::verify` checks, in order: version, pinned chain identity, commitment
canonicality, beacon round relation, BLS proof, randomness, sample length,
derived indices, inclusion proofs, receipt threshold, distinct keys, and timely
signing. Every error names the failed field. No network call occurs.

Input caps: bundles and manifests 64 MiB; key files, commitments, and receipts
4 KiB. The bundle cap bounds the sample and proof work a hostile file can
request.

The bundle's own signer keys and required count are self-declared.
`bundle::verify_with_policy` takes the expected Ed25519 public keys and an
optional threshold; when supplied, only allowlisted keys count. Without a
policy, verification proves internal consistency, not independent signer
honesty.

## Test

```sh
cargo test -p drawproof-lib --locked
cargo test -p drawproof-lib --locked -- --ignored
```
