![releases](https://github.com/eycorsican/leaf/workflows/releases/badge.svg)
![ci](https://github.com/eycorsican/leaf/workflows/ci/badge.svg)

# Leaf
A lightweight and fast proxy utility tries to include any useful features.

## Features
Inbounds are proxy servers and outbounds are clients.

- HTTP inbound supports CONNECT method
- SOCKS 5 inbound and outbound with UDP ASSOCIATE support
- TUN inbound
- Trojan inbound and outbound
- Direct outbound sends a proxy request directly to it's destination
- Drop outbound rejects a proxy request
- Shadowsocks outbound
- VMess outbound

- WebSocket inbound and outbound
- TLS outbound
- H2 outbound

- Chain inbound and outbound for chaining other inbounds and outbounds
- Failover outbound tries a proxy request on a group of outbounds one by one
- Random outbound sends a proxy request to one of the outbounds randomly
- Tryall outbound tries a proxy request on a group of outbounds simultaneously

- A router routes requests from inbounds to outbounds base on domain or IP rules
- Full cone NAT
- TUN-based transport proxy
- Fake DNS
- Load balancing / high availability through failover/random/tryall outbounds

## Getting Started
A local HTTP server redirects accepted requests to a SOCKS 5 server:

```json
{
    "inbounds": [
        {
            "address": "127.0.0.1",
            "port": 1087,
            "protocol": "http"
        }
    ],
    "log": {
        "level": "trace"
    },
    "outbounds": [
        {
            "protocol": "socks",
            "settings": {
                "address": "127.0.0.1",
                "port": 1080
            }
        }
    ]
}
```

A SOCKS 5 server sends out accepted requests directly:

```json
{
    "inbounds": [
        {
            "address": "127.0.0.1",
            "port": 1080,
            "protocol": "socks"
        }
    ],
    "log": {
        "level": "trace"
    },
    "outbounds": [
        {
            "protocol": "direct"
        }
    ]
}
```

Tests the setup:

```sh
https_proxy=127.0.0.1:1087 curl "https://example.org"
```

## Usage
You may find some configuration samples [here](https://github.com/eycorsican/leaf/blob/master/README.zh.md), it also serves as a reference for the JSON config format.

## Build
Install Rust: https://www.rust-lang.org/tools/install

Install nightly toolchain:
```sh
rustup default nightly
```

Install a C compiler, e.g. GCC:
```sh
apt update && apt install gcc

# Or clang on macOS
# brew update && brew install clang
```

Clone & Build:
```sh
git clone https://github.com/eycorsican/leaf.git
cd leaf
git submodule init
git submodule update
cargo build -p leaf-bin
```

Run:
```sh
./target/debug/leaf -h
```

## Customizing Build
You may build leaf with a selected set of features.

By including only the demanded features, you will get an optimized artifact with smaller binary size and lower runtime memory footprint.

For example, this build command,
```sh
cargo build --release --manifest-path leaf-bin/Cargo.toml --no-default-features --features "leaf/config-json leaf/inbound-socks leaf/outbound-direct leaf/outbound-shadowsocks leaf/ring-aead"
```
will result in an executable supports only the JSON config format, `socks` inbound, `direct` and `shadowsocks` outbounds.

Note that for proxy protocols with AEAD crypto functions, one of the `leaf/ring-aead` and `leaf/openssl-aead` features must be included. Similarly, one of the `leaf/rustls-tls` and `leaf/openssl-tls` must be included for `leaf/outbound-tls` feature.

Refer to `leaf/Cargo.toml` for a full list of available features.

## iOS
App Store: https://apps.apple.com/us/app/leaf-lightweight-proxy/id1534109007

TestFlight: https://testflight.apple.com/join/std0FFCS

Demo for Developer: https://github.com/eycorsican/ileaf

## OpenWrt
Running as transparent proxy on OpenWrt:
```sh
# Install the TUN package.
opkg update && opkg install kmod-tun

# Install certificates if you use TLS outbounds.
opkg update && opkg install ca-certificates

# Get the default interface address.
ADDRESS=`ip route get 1 | awk '{print $7;exit}'`

# Get the default gateway address.
GATEWAY=`ip route get 1 | awk '{print $3;exit}'`

TUN_NAME=tun8
TUN_ADDRESS=172.16.0.2
TUN_GATEWAY=172.16.0.1

# Properly configure the config file.
cat <<EOF > cfg.conf
[General]
loglevel = debug
dns-server = 223.5.5.5, 1.1.1.1
dns-interface = $ADDRESS
always-fake-ip = *
tun = $TUN_NAME, $TUN_ADDRESS, 255.255.255.0, $TUN_GATEWAY, 1500

[Proxy]
Direct = direct, interface=$ADDRESS
Proxy = ss, 1.2.3.4, 9999, encrypt-method=chacha20-ietf-poly1305, password=9999, interface=$ADDRESS

[Rule]
DOMAIN-SUFFIX, google.com, Proxy
FINAL, Direct
EOF

# Open another SSH session to run leaf with the config.
# It's important to run in a seperate window since we still need
# the variables defined above to continue our setup process.
# I suggest you use `screen`: opkg update && opkg install screen
leaf -c cfg.conf

# Route traffic initiated from leaf to the original gateway.
ip route add default via $GATEWAY table default
ip rule add from $ADDRESS table default

# Route local traffic to TUN.
ip route del default table main
ip route add default via $TUN_GATEWAY

# Route traffic from other deivces to TUN.
iptables -I FORWARD -o $TUN_NAME -j ACCEPT
```

Re-run:
```sh
# Stop leaf via ctrl+c.

# Make some changes to your `cfg.conf`.

# Re-run leaf.
leaf -c cfg.conf

# Re-add the default route to TUN.
ip route add default via $TUN_GATEWAY
```

Recover the original network:
```sh
# Stop leaf via ctrl+c.

# Remove iptables rules.
iptables -D FORWARD -o $TUN_NAME -j ACCEPT

# Cleanup the routing table.
ip rule del from $ADDRESS
ip route del default table default

# Recover the original default route.
ip route add default via $GATEWAY
```

Check if everything looks fine:
```sh
iptables -L FORWARD -n
ip route show table main
ip route show table default
ip rule show
```
