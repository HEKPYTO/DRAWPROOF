#!/bin/sh
set -eu

tag=${1:-v0.1.0}
build=/tmp/drawproof-release
repo=$(git rev-parse --show-toplevel)

if [ -z "$build" ] || [ "$build" = "/" ]; then
    echo "refusing build path: $build" >&2
    exit 1
fi

git -C "$repo" worktree remove --force "$build/src" 2>/dev/null || true
rm -rf "$build"
git -C "$repo" worktree prune
mkdir -p "$build"
git -C "$repo" worktree add --detach "$build/src" "$tag"

export CARGO_HOME="$build/cargo"
export RUSTUP_HOME="$build/rustup"
export CARGO_TARGET_DIR="$build/target"
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS=
unset RUSTUP_TOOLCHAIN CARGO_ENCODED_RUSTFLAGS

(cd "$build/src" && rustup toolchain install 1.100.0 --profile minimal && rustup run 1.100.0 cargo build --release --locked)

cd "$build/target/release"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum drawproof drawproof-server
else
    shasum -a 256 drawproof drawproof-server
fi