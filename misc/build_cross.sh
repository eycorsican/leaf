#!/usr/bin/env bash

target=$1

if [[ "$target" == *"mips"* ]]; then
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "leaf/all-configs leaf/all-endpoints leaf/openssl-aead leaf/openssl-tls"
else
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "leaf/all-configs leaf/all-endpoints leaf/ring-aead leaf/rustls-tls"
fi
