#!/usr/bin/env bash

set -ex

target=$1

if [[ "$target" == *"mips"* ]]; then
  cross build --release --target $target --manifest-path leaf-cli/Cargo.toml --no-default-features --features "default-openssl"
else
  cross build --release --target $target --manifest-path leaf-cli/Cargo.toml --no-default-features --features "default-ring"
fi
