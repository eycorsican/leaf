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
```

More configuration examples can be found [here](https://github.com/eycorsican/leaf/blob/master/README.zh.md). If you want more flexible control on the config options, the JSON format should be used, up-to-date examples for the JSON format could be found in the [tests](https://github.com/eycorsican/leaf/blob/master/leaf/tests), both client-side and server-side config examples are presented there.

## TUN Mode and Gateway Mode

### TUN Mode

This syntax (`tun = auto`) is supported on macOS and Linux.

```ini
[General]
dns-server = 223.5.5.5
tun = auto

[Proxy]
Direct = direct
```

### Gateway Mode

Running in gateway mode requires a configuration with TUN mode enabled. Gateway mode can be enabled by an environment variable.

```sh
GATEWAY_MODE=true leaf -c config.conf
```

## Windows

* [Maple](https://github.com/YtFlow/Maple): A lightweight Universal Windows proxy app based on leaf

## iOS & Android

<a href="https://play.google.com/store/apps/details?id=com.leaf.and.aleaf"><img src="https://upload.wikimedia.org/wikipedia/commons/7/78/Google_Play_Store_badge_EN.svg" height="70"></a>

<a href="https://apps.apple.com/us/app/leaf-lightweight-proxy/id1534109007"><img src="https://upload.wikimedia.org/wikipedia/commons/3/3c/Download_on_the_App_Store_Badge.svg" height="70"></a>

## Build

Install Rust: https://www.rust-lang.org/tools/install

Install GCC or Clang.

Clone & Build:
```sh
git clone --recursive https://github.com/eycorsican/leaf.git
cd leaf
cargo build -p leaf-cli
```

Run:
```sh
./target/debug/leaf --help
```

## License

This project is licensed under the [Apache License 2.0](https://github.com/eycorsican/leaf/blob/master/LICENSE).
