![releases](https://github.com/eycorsican/leaf/workflows/releases/badge.svg)
![ci](https://github.com/eycorsican/leaf/workflows/ci/badge.svg)

# Leaf

A versatile and efficient proxy framework with nice features suitable for various use cases.

### Multiplexing

There are 2 transports for traffic multiplexing:

* AMux: A multiplexd transport based on reliable streams suitable for TCP-based protocols and transports
* QUIC: A UDP-based, multiplexed and secure transport

The benefit of `amux` is that we can reuse connections to reduce handshake overhead, it's not designed to be memory efficient because it focus only on reusing connections and not reducing the number of connections. While `quic` can reduce both handshake overhead and memory usage without suffering the head-of-line blocking issue.

### Transparent Proxying

There's the TUN inbound for this purpose, which is also of fundamental importance for VPN-like proxying use cases such as VPN apps on iOS and Android.

### High Availability

Outbounds such as `failover`, `tryall`, `retry`, `random` and their combinations are able to flexibly deliver reqeusts to other outbounds based on their own metrics to achieve high availability or load balancing behaviors.

### Request Routing

Rule-based request routing is also supported. Requests can be routed to different outbounds based on domain, IP, GEOIP and port rules.

## Getting Started

```ini
[General]
dns-server = 223.5.5.5
socks-interface = 127.0.0.1
socks-port = 1080

[Proxy]
Direct = direct
Proxy = ss, 1.2.3.4, 8123, encrypt-method=aes-256-gcm, password=123456

[Rule]
IP-CIDR, 8.8.8.8/32, Proxy
DOMAIN-SUFFIX, google.com, Proxy
FINAL, Direct
```

More configuration examples can be found [here](https://github.com/eycorsican/leaf/blob/master/README.zh.md).

## Windows

* [Maple](https://github.com/YtFlow/Maple): A lightweight Universal Windows proxy app based on leaf

## iOS & Android

* [Leaf](https://apps.apple.com/us/app/leaf-lightweight-proxy/id1534109007): A simple iOS VPN app built with leaf

There are example projects demonstrating how you could easily build VPN apps for iOS and Android with leaf:
 
* iOS: https://github.com/eycorsican/ileaf
* Android: https://github.com/eycorsican/aleaf

## Build

Install Rust: https://www.rust-lang.org/tools/install

Install GCC or Clang.

Clone & Build:
```sh
git clone --recursive https://github.com/eycorsican/leaf.git
cd leaf
cargo build -p leaf-bin
```

Run:
```sh
./target/debug/leaf -h
```

## License

This project is licensed under the [Apache License 2.0](https://github.com/eycorsican/leaf/blob/master/LICENSE).
