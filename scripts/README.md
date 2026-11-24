# scripts

`release-build.sh <tag>` builds the tagged source at the fixed path
`/tmp/drawproof-release`, with fixed `CARGO_HOME`, `RUSTUP_HOME`, and target
paths. It removes and recreates that path before each build, builds both
binaries with the committed lockfile, and prints their SHA-256 sums.

The script needs network access to fetch the pinned Rust toolchain and crates.
The same tag at this path produces the same hashes.
