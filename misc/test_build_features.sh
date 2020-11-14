#!/usr/bin/env bash

set -x

outbounds=(
    "leaf/outbound-direct"
    "leaf/outbound-shadowsocks leaf/ring-aead"
    "leaf/outbound-drop"
    "leaf/outbound-redirect"
    "leaf/outbound-socks"
    "leaf/outbound-trojan"
    "leaf/outbound-vmess leaf/ring-aead"
    "leaf/outbound-vmess leaf/openssl-aead"
    "leaf/outbound-tls leaf/rustls-tls"
    "leaf/outbound-tls leaf/openssl-tls"
    "leaf/outbound-ws"
    "leaf/outbound-vless"
    "leaf/outbound-h2"
    "leaf/outbound-failover"
    "leaf/outbound-random"
    "leaf/outbound-tryall"
    "leaf/outbound-chain"
)

for ((i = 0; i < ${#outbounds[@]}; i++ )); do
    cargo build --manifest-path leaf-bin/Cargo.toml --no-default-features --features "leaf/config-json leaf/inbound-socks leaf/inbound-http ${outbounds[$i]}"
done
