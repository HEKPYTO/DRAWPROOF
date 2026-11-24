# examples

Synthetic example data. No real dataset is included.

`manifest.jsonl` has ten items. Each line is one JSON object:

```json
{"id":"example-item-00","sha256":"822dd813af251494ac321200b293f66e63687218d965d883043b292086f68d5a"}
```

- `id` must be non-empty UTF-8, at most 1024 bytes, without control characters,
  and unique after sorting by byte order.
- `sha256` is the 32-byte SHA-256 of the item, as 64 hex characters. Lowercase is
  canonical; input case is normalized.
- Empty lines are ignored.
- An empty manifest is rejected.

Run the example from the repository root:

```sh
cargo install --path crates/drawproof --locked
drawproof keygen --name demo --out signer.key
drawproof draw --manifest examples/manifest.jsonl --k 3 --signer-key signer.key
drawproof verify bundle.json
```
