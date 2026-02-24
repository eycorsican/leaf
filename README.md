<p align="center">
<img src="https://github.com/eycorsican/leaf/workflows/releases/badge.svg">
<img src="https://github.com/eycorsican/leaf/workflows/ci/badge.svg">
</p>

<h1 align="center">Leaf</h1>

<p align="center">
A versatile and efficient proxy framework.
</p>

## Supported Protocols

### Proxy Protocols

| Protocol | Inbound | Outbound |
|---|---|---|
| HTTP | ✅ | ❌ |
| SOCKS5 | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ |
| Trojan | ✅ | ✅ |
| VMess | ❌ | ✅ |
| Vless | ❌ | ✅ |

### Transports & Security

| Transport | Inbound | Outbound | Notes |
|---|---|---|---|
| WebSocket | ✅ | ✅ | |
| TLS | ✅ | ✅ | |
| QUIC | ✅ | ✅ | |
| AMux | ✅ | ✅ | Leaf specific multiplexing |
| Obfs | ❌ | ✅ | Simple obfuscation |
| Reality | ❌ | ✅ | Xray Reality |
| MPTP | ✅ | ✅ | Multi-path Transport Protocol (Aggregation) |

### Traffic Control

| Feature | Inbound | Outbound | Notes |
|---|---|---|---|
| Chain | ✅ | ✅ | Proxy chaining |
| Failover | ❌ | ✅ | Failover with health check |

### Transparent Proxying

| Mechanism | Inbound | Outbound | Notes |
|---|---|---|---|
| TUN | ✅ | ❌ | Linux, macOS, Windows, iOS, Android; lwip, smoltcp |
| NF | ✅ | ❌ | Windows, [NetFilter SDK](https://netfiltersdk.com/) |
| TPROXY | ❌ | ❌ | Linux; Coming soon |

## Building

```sh
cargo build -p leaf-cli --release
./target/debug/leaf --help
```

## License

This project is licensed under the [Apache License 2.0](https://github.com/eycorsican/leaf/blob/master/LICENSE).
