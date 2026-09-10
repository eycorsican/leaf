# Shadowsocks C ABI Examples

This directory shows how to use the `shadowsocks-cabi-rs` plugin as a Leaf outbound.

This directory currently includes the following runnable example:

- `client.json`
  - Uses the Rust `shadowsocks-cabi-rs` plugin for both TCP and UDP traffic

The local SOCKS5 inbound listens on `127.0.0.1:1080`.

## Files

### `client.json`

Configuration for the Rust `shadowsocks-cabi-rs` plugin. The plugin path defaults to:

```text
./target/debug/libshadowsocks_cabi_rs.dylib
```

## Quick Test

The macOS/Linux blocks below assume you run them from the project root `/opt/rust/leaf`.

For Windows, open PowerShell in the repository root and copy the PowerShell blocks directly. They generate a temporary `client.windows.json` file so you do not need to edit the plugin `.dylib` path by hand.

macOS/Linux, Terminal 1:

```bash
cd /opt/rust/leaf
cargo build -p shadowsocks-cabi-rs
cargo run -p leaf-cli --features leaf/plugin -- -c examples/shadowsocks-cabi/client.json
```

macOS/Linux, Terminal 2:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

Windows PowerShell, Terminal 1:

```powershell
$config = Get-Content .\examples\shadowsocks-cabi\client.json -Raw
$config = $config.Replace("./target/debug/libshadowsocks_cabi_rs.dylib", "./target/debug/shadowsocks_cabi_rs.dll")
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "examples\shadowsocks-cabi\client.windows.json"), $config, [System.Text.UTF8Encoding]::new($false))
cargo build -p shadowsocks-cabi-rs
cargo run -p leaf-cli --features leaf/plugin -- -c .\examples\shadowsocks-cabi\client.windows.json
```

Windows PowerShell, Terminal 2:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

On success you should see output similar to:

```text
HTTP/2 200
```

## Change Server Parameters

If you want to use your own Shadowsocks server, update these fields in `client.json`:

```json
"host": "remote_host",
"port": 8388,
"args": "cipher;password"
```

Optional prefix form:

```text
cipher;password;prefix
```

Example:

```text
host = 203.0.113.10
port = 8388
args = aes-128-gcm;test-password
```

## Build Only

If you only want to build the plugin without starting Leaf:

macOS/Linux:

```bash
cd /opt/rust/leaf
cargo build -p shadowsocks-cabi-rs
```

Windows PowerShell:

```powershell
cargo build -p shadowsocks-cabi-rs
```

## Notes

- The same plugin dynamic library exports both the TCP stream engine and the UDP datagram engine.
- The example keeps a single `client.json`, which covers both TCP and UDP traffic.

## Troubleshooting

- If Leaf reports that the plugin file does not exist, make sure the dynamic library path matches the `path` field in `client.json`.
- On Windows, the example config in this directory still points to `.dylib`, so use the PowerShell commands above to generate `client.windows.json` with the matching `.dll` path.
- If `leaf-cli` reports that the `plugin` feature is missing, use `-F leaf/plugin` or `--features leaf/plugin`.
- If the remote server does not respond, double-check the `args` value in `client.json`, especially the host, port, cipher, and password.
