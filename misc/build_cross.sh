#!/usr/bin/env bash

target=$1

if [[ "$target" == *"mips"* ]]; then
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "leaf/all-configs leaf/all-endpoints leaf/openssl-aead leaf/openssl-tls"
#  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "\
#	  leaf/config-json \
#	  leaf/inbound-socks \
#	  leaf/inbound-tun \
#	  leaf/outbound-chain \
#	  leaf/outbound-failover \
#	  leaf/outbound-random \
#	  leaf/outbound-direct \
#	  leaf/outbound-drop \
#	  leaf/outbound-tls \
#	  leaf/outbound-shadowsocks \
#	  leaf/outbound-ws \
#	  leaf/outbound-trojan \
#	  leaf/openssl-aead \
#	  leaf/openssl-tls"
else
  cross build --release --target $target --manifest-path leaf-bin/Cargo.toml --no-default-features --features "leaf/all-configs leaf/all-endpoints leaf/ring-aead leaf/rustls-tls"
fi
