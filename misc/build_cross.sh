#!/usr/bin/env bash

target=$1

if [[ "$target" == *"mips"* ]]; then
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "common config openssl-aead openssl-tls"
else
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "common config ring-aead rustls-tls"
fi
