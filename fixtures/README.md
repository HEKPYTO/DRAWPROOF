# fixtures

Two real drand quicknet rounds, frozen for offline tests.

| File | Round | Use |
|---|---:|---|
| `quicknet-34230592.json` | 34,230,592 | Registration round in bundle tests |
| `quicknet-34230594.json` | 34,230,594 | Selection round, two rounds later |

The tests verify both BLS proofs against the pinned quicknet chain in the
`drand` crate. The fixtures contain only public beacon data.

Regenerate a fixture from a relay:

```sh
curl -fsS "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/34230594" | jq . > quicknet-34230594.json
```

Replacing a fixture changes the golden test vectors and the bundle tests. Keep
the two-round relation intact.
