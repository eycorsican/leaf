#!/usr/bin/env bash

target=$1

if [[ "$target" == *"mips"* ]]; then
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "default-openssl"
else
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "default-ring"
fi
