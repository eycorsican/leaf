# TLS C ABI Examples

This directory shows how to use the `tls-cabi-rs` transport plugin together with Leaf's built-in `ws` and `trojan` outbounds.

This directory currently includes the following runnable examples:

- `trojan-ws-rust.json`
  - Uses the Rust `tls-cabi-rs` plugin
- `trojan-ws-go.json`
  - Uses the Go `tls-cabi-go` plugin
- `trojan-ws-go-trojan-go.json`
  - Uses the Go `tls-cabi-go` plugin together with the Go `trojan-cabi-go` plugin
- `trojan-ws-native-tls.json`
  - Uses Leaf's native TLS for comparison and troubleshooting

Source config:

```conf
[proxy]
Proxy = trojan, www.shocktraffic.org, 443, password=humanity, sni=www.shocktraffic.org, ws=true, ws-path=/assignment, ws-host=www.shocktraffic.org
```

The corresponding Leaf outbound chain is:

```text
chain = [tls-cabi-rs, ws, trojan]
```

Each config tags its outbounds after the implementation it uses, so the Go
configs read `chain = [tls-cabi-go, ws, trojan]` instead.

Each stage in the chain is responsible for:

- `tls-cabi-rs` or `tls-cabi-go` handles the TLS client handshake and TLS record I/O
- `ws` handles WebSocket framing
- `trojan` or `trojan-cabi-go` handles the Trojan header and target address encoding

The current `trojan-cabi-go` plugin implements both the Trojan stream/TCP path and the Trojan UDP path for this WebSocket-based chain.
The plugin datagram path is registered as `Reliable`, so Leaf routes UDP through the existing `tls-cabi-go -> ws -> trojan-cabi-go` stream transport and lets the plugin encode/decode Trojan UDP frames.

The local SOCKS5 inbound listens on:

- `127.0.0.1:1080` for `trojan-ws-rust.json`
- `127.0.0.1:1080` for `trojan-ws-go.json`
- `127.0.0.1:1080` for `trojan-ws-go-trojan-go.json`
- `127.0.0.1:1080` for `trojan-ws-native-tls.json`

## Files

### `trojan-ws-rust.json`

Configuration for the Rust `engine` TLS C ABI plugin. The plugin path defaults to:

```text
./target/debug/libtls_cabi_rs.dylib
```

### `trojan-ws-go.json`

Configuration for the Go TLS C ABI plugin. The plugin path defaults to:

```text
./leaf-plugins/tls-cabi-go/libtls_cabi_go.dylib
```

### `trojan-ws-go-trojan-go.json`

Configuration for using both Go plugins in a single chain:

```text
./leaf-plugins/tls-cabi-go/libtls_cabi_go.dylib
./leaf-plugins/trojan-cabi-go/libtrojan_cabi_go.dylib
```

### `trojan-ws-native-tls.json`

Configuration for the built-in Leaf TLS outbound used as a baseline for comparison.

## Quick Test

The macOS/Linux blocks below assume you run them from the project root `/opt/rust/leaf`.

For Windows, the Rust plugin and the native TLS baseline can be started directly from PowerShell.

For the Go plugin, this README assumes a practical Windows-on-ARM setup:

- the host OS is Windows ARM64
- Go is installed as the `amd64` build
- the Go plugin is built as `amd64`
- Leaf must also run as `amd64` for the DLL to load

In other words, the Go plugin example below uses the Windows `x64` path, even on an ARM64 host.

### Rust Plugin

macOS/Linux, Terminal 1:

```bash
cd /opt/rust/leaf
cargo build -p tls-cabi-rs
cargo run -p leaf-cli --features leaf/plugin -- -c examples/tls-cabi/trojan-ws-rust.json
```

macOS/Linux, Terminal 2:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

Windows PowerShell, Terminal 1:

```powershell
$config = Get-Content .\examples\tls-cabi\trojan-ws-rust.json -Raw
$config = $config.Replace("./target/debug/libtls_cabi_rs.dylib", "./target/debug/tls_cabi_rs.dll")
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "examples\tls-cabi\trojan-ws-rust.windows.json"), $config, [System.Text.UTF8Encoding]::new($false))
cargo build -p tls-cabi-rs
cargo run -p leaf-cli --features leaf/plugin -- -c .\examples\tls-cabi\trojan-ws-rust.windows.json
```

Windows PowerShell, Terminal 2:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

### Go Plugin

The Go plugin example is directly runnable on macOS/Linux.

If you want to validate the full Go chain, build both plugins and start:

```bash
cd /opt/rust/leaf
(cd leaf-plugins/tls-cabi-go && go build -buildmode=c-shared -o libtls_cabi_go.dylib .)
(cd leaf-plugins/trojan-cabi-go && go build -buildmode=c-shared -o libtrojan_cabi_go.dylib .)
cargo run -p leaf-cli --features leaf/plugin -- -c examples/tls-cabi/trojan-ws-go-trojan-go.json
```

Then validate both TCP and UDP from another terminal:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
python3 -c 'import socket,struct,random; qid=random.randint(0,65535); qname=b"".join(bytes([len(p)])+p.encode() for p in "example.com".split("."))+b"\\x00"; dns=struct.pack("!HHHHHH",qid,0x0100,1,0,0,0)+qname+struct.pack("!HH",1,1); s=socket.create_connection(("127.0.0.1",1080),timeout=5); s.sendall(b"\\x05\\x01\\x00"); s.recv(2); s.sendall(b"\\x05\\x03\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"); r=s.recv(10); host=socket.inet_ntoa(r[4:8]); port=struct.unpack("!H",r[8:10])[0]; u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(8); pkt=b"\\x00\\x00\\x00\\x01"+socket.inet_aton("1.1.1.1")+struct.pack("!H",53)+dns; u.sendto(pkt,(host,port)); data,_=u.recvfrom(4096); print("udp response bytes", len(data)); u.close(); s.close()'
```

On Windows, `go build -buildmode=c-shared` is not a single universal copy-paste command because the generated DLL must match all of the following:

- the architecture of `leaf.exe`
- `go env GOARCH`
- the C toolchain used by `cgo`

If these do not match, Windows fails while loading `tls_cabi_go.dll`.

For a Windows ARM64 host with an `amd64` Go installation, the recommended path is to keep the whole Go plugin example on `x64`:

- build the plugin as `amd64`
- use the `amd64` `gcc/g++` toolchain
- run an `amd64` `leaf.exe`
- make sure the Go DLL exports `leaf_plugin_get_descriptor`

macOS/Linux, Terminal 1:

```bash
cd /opt/rust/leaf
(cd leaf-plugins/tls-cabi-go && go build -buildmode=c-shared -o libtls_cabi_go.dylib .)
cargo run -p leaf-cli --features leaf/plugin -- -c examples/tls-cabi/trojan-ws-go.json
```

macOS/Linux, Terminal 2:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

Windows PowerShell, Terminal 1:

```powershell
$config = Get-Content .\examples\tls-cabi\trojan-ws-go.json -Raw
$config = $config.Replace("./leaf-plugins/tls-cabi-go/libtls_cabi_go.dylib", "./leaf-plugins/tls-cabi-go/tls_cabi_go.dll")
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "examples\tls-cabi\trojan-ws-go.windows.json"), $config, [System.Text.UTF8Encoding]::new($false))
Write-Host "Choose one of the architecture-specific build blocks below."
```

Windows on ARM64 Host, using `amd64` Go, PowerShell, Terminal 1:

```powershell
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "1"
$env:CC = "gcc"
$env:CXX = "g++"
$config = Get-Content .\examples\tls-cabi\trojan-ws-go.json -Raw
$config = $config.Replace("./leaf-plugins/tls-cabi-go/libtls_cabi_go.dylib", "./leaf-plugins/tls-cabi-go/tls_cabi_go.dll")
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "examples\tls-cabi\trojan-ws-go.windows.json"), $config, [System.Text.UTF8Encoding]::new($false))
Push-Location .\leaf-plugins\tls-cabi-go
go build -buildmode=c-shared -o tls_cabi_go.dll .
$dllDeps = @("libwinpthread-1.dll", "libgcc_s_seh-1.dll", "libstdc++-6.dll")
foreach ($dll in $dllDeps) {
    $dllPath = (& gcc "-print-file-name=$dll").Trim()
    if ($dllPath -and $dllPath -ne $dll -and (Test-Path $dllPath)) {
        Copy-Item $dllPath .\ -Force
    }
}
Pop-Location
```

If you continue in the same PowerShell session after building the Go DLL, clear the Go and C toolchain environment variables before running Cargo. Otherwise `cargo run` may inherit `CC=gcc` and related settings, and Rust dependencies such as `aws-lc-sys` may fail to build with the wrong toolchain.

Same PowerShell session, clear the environment first:

```powershell
Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
Remove-Item Env:CC -ErrorAction SilentlyContinue
Remove-Item Env:CXX -ErrorAction SilentlyContinue
```

If your Rust toolchain currently builds ARM64 binaries by default, do not use that `leaf.exe` with this `amd64` Go plugin DLL. Use an `amd64` Rust environment, or build and run `leaf-cli` as `amd64` first.

Example:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo run -p leaf-cli --target x86_64-pc-windows-msvc --features leaf/plugin -- -c .\examples\tls-cabi\trojan-ws-go.windows.json
```

If you want to verify the exact `x86_64` binary that was built, or avoid ambiguity when the default host target is still ARM64, you can start the built executable directly:

```powershell
cargo build -p leaf-cli --target x86_64-pc-windows-msvc --features leaf/plugin
.\target\x86_64-pc-windows-msvc\debug\leaf.exe -c .\examples\tls-cabi\trojan-ws-go.windows.json
```

Windows PowerShell, Terminal 2:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

### Native TLS Baseline

macOS/Linux, Terminal 1:

```bash
cd /opt/rust/leaf
cargo run -p leaf-cli --features leaf/plugin -- -c examples/tls-cabi/trojan-ws-native-tls.json
```

macOS/Linux, Terminal 2:

```bash
curl --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

Windows PowerShell, Terminal 1:

```powershell
cargo run -p leaf-cli --features leaf/plugin -- -c .\examples\tls-cabi\trojan-ws-native-tls.json
```

Windows PowerShell, Terminal 2:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 -I https://example.com/ --max-time 20
```

On success you should see output similar to:

```text
HTTP/2 200
```

For the Windows Go plugin example, a successful run may also show:

```text
HTTP/1.1 200 OK
```

## Build Only

If you only want to build the plugins without starting Leaf:

macOS/Linux:

```bash
cd /opt/rust/leaf
cargo build -p tls-cabi-rs
```

Windows PowerShell:

```powershell
cargo build -p tls-cabi-rs
```

macOS/Linux:

```bash
cd /opt/rust/leaf
(cd leaf-plugins/tls-cabi-go && go build -buildmode=c-shared -o libtls_cabi_go.dylib .)
```

Windows PowerShell:

```powershell
Write-Host "On Windows ARM64 with amd64 Go, use the amd64 Go plugin block from Quick Test and make sure leaf-cli also runs as amd64."
```

## Troubleshooting

- If Leaf reports that the plugin file does not exist, make sure the dynamic library path matches the `path` field in the config.
- On Windows, the example configs in this directory still point to `.dylib`, so use the PowerShell commands above to generate the matching `*.windows.json` files with `.dll` paths.
- This README assumes a Windows ARM64 host with an `amd64` Go installation. In that setup, build the Go plugin as `amd64` and run `leaf.exe` as `amd64` too.
- The Go plugin build blocks copy common MinGW runtime DLLs next to `tls_cabi_go.dll`, because `go build -buildmode=c-shared` may produce a DLL that depends on them.
- If you build the Go DLL and then run `cargo` in the same PowerShell session, clear `GOOS`, `GOARCH`, `CGO_ENABLED`, `CC`, and `CXX` first so Rust does not inherit the Go plugin toolchain settings.
- If `tls_cabi_go.dll` loads but Leaf cannot read the plugin descriptor on Windows, verify that the DLL exports `leaf_plugin_get_descriptor`.
- If your Rust toolchain builds ARM64 binaries by default, `cargo run` without `--target x86_64-pc-windows-msvc` may produce an ARM64 `leaf.exe`, which cannot load the `amd64` Go plugin DLL.
- If you want to rule out target-selection confusion on Windows, run the built `x86_64` executable directly from `.\target\x86_64-pc-windows-msvc\debug\leaf.exe`.
- The Go plugin example no longer assumes an ARM64 `cgo` compiler is installed on Windows.
- If `leaf-cli` reports that the `plugin` feature is missing, use `-F leaf/plugin` or `--features leaf/plugin`.
- If you want to compare against the built-in implementation, run `trojan-ws-native-tls.json` first.
