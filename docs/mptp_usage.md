# MPTP Usage

## Overview

MPTP (Multipath Transport Protocol) combines multiple outbound paths into one logical transport channel.
In Leaf, the common deployment is:

- Client side: local `socks` inbound + `mptp` outbound
- Server side: `mptp` inbound + `direct` outbound

## Configuration

### JSON Config

Client example (`client.json`):

```json
{
  "inbounds": [
    {
      "protocol": "socks",
      "address": "127.0.0.1",
      "port": 1086
    }
  ],
  "outbounds": [
    {
      "protocol": "mptp",
      "settings": {
        "actors": [
          "direct1",
          "direct2"
        ],
        "address": "127.0.0.1",
        "port": 3001
      }
    },
    {
      "protocol": "direct",
      "tag": "direct1"
    },
    {
      "protocol": "direct",
      "tag": "direct2"
    }
  ]
}
```

Server example (`server.json`):

```json
{
  "inbounds": [
    {
      "protocol": "mptp",
      "address": "0.0.0.0",
      "port": 3001
    }
  ],
  "outbounds": [
    {
      "protocol": "direct"
    }
  ]
}
```

Key fields:

- `outbounds[].protocol = "mptp"`: enables MPTP client outbound
- `settings.actors`: list of outbound tags used as sub-connections
- `settings.address`, `settings.port`: MPTP server address and port
- `inbounds[].protocol = "mptp"`: enables MPTP server inbound listener

### conf Config

MPTP outbound can also be configured in `[Proxy Group]`:

```conf
[Proxy Group]
MptpOutTag = mptp, actor1, actor2, actor3, address=1.2.3.4, port=10000
```

## Running

Build:

```bash
cargo build -p leaf-cli --release
```

Run server:

```bash
./target/release/leaf -c server.json
```

Run client:

```bash
./target/release/leaf -c client.json
```

## Validation

1. Configure your app to use local SOCKS5 proxy `127.0.0.1:1086`.
2. Start with simple connectivity checks:

```bash
curl --socks5 127.0.0.1:1086 https://example.com
```

3. Verify configuration syntax before production startup:

```bash
./target/release/leaf -c client.json -T
./target/release/leaf -c server.json -T
```

## Notes

- `actors` should include at least two outbounds to achieve multipath aggregation.
- Ensure each actor tag exists in `outbounds`.
- Open server listening port (for example `3001`) in firewall/security group.
