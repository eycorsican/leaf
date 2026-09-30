<p align="center">
<img src=".github/assets/leaf-logo-horizontal-white-bg.png" alt="Leaf Logo" width="360">
</p>

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
| MPTP | ✅ | ✅ | Multi-path Transport Protocol (Aggregation) ([Architecture](docs/mptp_architecture.md), [Usage](docs/mptp_usage.md)) |

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

## Plugins

Protocols and transports can also live outside the binary. A plugin is a shared
library that exports a small C ABI, which leaf loads at startup and drives as an
ordinary outbound -- so a plugin can be written in any language that can produce
one, and shipped without rebuilding leaf.

| Plugin | Language | Kind |
|---|---|---|
| [`shadowsocks-cabi-rs`](leaf-plugins/shadowsocks-cabi-rs) | Rust | Shadowsocks, TCP and UDP |
| [`tls-cabi-rs`](leaf-plugins/tls-cabi-rs) | Rust | TLS transport |
| [`tls-cabi-go`](leaf-plugins/tls-cabi-go) | Go | TLS transport |
| [`trojan-cabi-go`](leaf-plugins/trojan-cabi-go) | Go | Trojan, TCP and UDP |
| [`socks5-cabi-c`](leaf-plugins/socks5-cabi-c) | C | SOCKS5, TCP |
| [`socks5-cabi-zig`](leaf-plugins/socks5-cabi-zig) | Zig | SOCKS5, TCP |

The two SOCKS5 plugins are the same protocol written twice, in two languages
with no runtime of their own, and both are held to the same end-to-end suite as
leaf's own SOCKS5 outbound.

A plugin is configured as an outbound like any other, and can be chained with
built-in ones:

```json
{
  "tag": "ss-plugin",
  "protocol": "plugin",
  "settings": {
    "path": "./target/release/libshadowsocks_cabi_rs.dylib",
    "host": "example.com",
    "port": 8388,
    "args": "chacha20-ietf-poly1305;password",
    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  }
}
```

`args` is passed to the plugin untouched; `host` and `port` are required by
plugins that connect to a server of their own, and rejected by transport plugins
that layer on the previous outbound in a chain.

`path` must have a directory part -- a bare library name would let the dynamic
loader search `LD_LIBRARY_PATH` or the DLL search order, which is not a choice a
config file gets to hand to the environment -- and leaf refuses a library that
anyone on the host can rewrite, whether that is the file's own mode or a
world-writable directory with no sticky bit around it.

There is no plugin directory and nothing is scanned. Every plugin leaf loads is
one an outbound named, which is the same decision as refusing a bare name: what
runs inside the proxy should be what the config says outright, not what the
filesystem happened to be holding.

`sha256` is optional and worth setting. Loading a shared library runs whatever
its last writer put there, in leaf's process with leaf's privileges; the digest
is the one check that still holds if that writer was not you. Get it with
`shasum -a 256 <file>`, or from `--verify-plugin` below, and leaf refuses to
load anything else.

None of this contains a plugin that is actually hostile, and it is not meant
to. A plugin runs in leaf's process with leaf's privileges, so deploying one is
the same decision as running any other binary on the host. What the checks above
buy you is knowing *which* file you loaded; what the host's own defences buy you
-- a validated descriptor, bounded buffers, clamped size hints, panic barriers
around every callback, an opaque instance id rather than a pointer -- is
surviving a plugin that is merely wrong.

- The ABI, and the contract both sides must keep, is defined in
  [`leaf-plugin-abi`](leaf-plugin-abi/src/lib.rs) and in the canonical C header
  [`leaf_plugin_abi.h`](leaf-plugin-abi/include/leaf_plugin_abi.h). C and Zig
  plugins include that header directly; a Rust plugin depends on the crate.
- Go plugins are written against [`leaf-abi-go`](leaf-plugins/leaf-abi-go), the
  SDK that keeps the descriptor, the vtables, cgo's const-pointer shims, panic
  recovery and the blocking-`net.Conn` adapter out of the plugin.
- Runnable examples:
  [shadowsocks](examples/shadowsocks-cabi/README.md),
  [TLS and Trojan chains](examples/tls-cabi/README.md).
- The [end-to-end suite](leaf-e2e/README.md) exercises the host against
  cooperative and deliberately hostile plugins; `make e2e` runs it, and
  `make plugin-test` runs each plugin's own unit tests.

### Plugins in a conf file, and downloading them

A conf file declares each plugin once, in `[Plugin]`, and refers to it by name
from `[Proxy]`. The proxy lines say what a proxy does and are the same on every
platform; only `[Plugin]` says how this client gets hold of the code.

```ini
[Plugin]
tls = url=https://cdn.example.com/plugins/1.2.0/tls_cabi_rs.dll, sha256=9f86d0..., size=3145728
ss  = path=./plugins/shadowsocks_cabi_rs.dll

[Proxy]
; A layer inside a chain: no address or port.
TLS = plugin, plugin=tls, args-b64=eyJzZXJ2ZXJfbmFtZSI6ImV4YW1wbGUuY29tIn0
; A plugin with a server of its own: address and port, as for any proxy.
SS  = plugin, 1.2.3.4, 8388, plugin=ss, args=chacha20-ietf-poly1305;password
```

A `[Plugin]` entry takes `path`, `url`, `sha256` and `size`, and anything else
is an error rather than being skipped: this is the section that says where
executable code comes from. `args` is passed to the plugin as it is written;
`args-b64` is for arguments that contain a comma -- JSON, usually -- and accepts
either base64 alphabet, padded or not. The JSON config takes the same `url`,
`size` and `name` in a plugin outbound's settings.

With the `plugin-fetch` feature, a plugin given by `url` is downloaded before
any outbound is built, into a cache keyed by its digest:
`<cache>/<sha256>/<file>`. The digest is the version -- the same one is never
fetched twice, and a start whose cache already holds everything needs no
network. What makes that safe:

- `https` only, redirects included, and only with `sha256`. The config vouches
  for the file, so it has to say which file.
- The download goes to a temporary file, hashed as it arrives, and is renamed
  into place only once the digest matches; nothing partial or unverified is ever
  where the loader looks. A download that runs past `size` -- or past 64 MiB
  when no size is given -- is stopped there.
- There is no default cache directory. Whether a directory is safe to load code
  from depends on who can write to it, which only the app embedding leaf knows:
  set `PLUGIN_CACHE_DIR` (and optionally `PLUGIN_FETCH_TIMEOUT`, in seconds;
  30 by default). A service running as SYSTEM wants a directory only
  administrators can write to, such as one under `%ProgramData%` set up by the
  installer.
- A reload uses the cache and never the network. A reload that needs a plugin
  the cache does not have is refused, and asks for a restart.

The download happens on the way into a start, before any listener or TUN route
exists, so it goes over the network directly rather than through the proxy
being started. To keep that start instant, an app can fetch ahead of time with
`leaf_prefetch_plugins` (in `leaf-ffi`, built with `--features plugin-fetch`)
as soon as it has the config, and show progress while it does. Its callback
runs on the calling thread, never concurrently and never after the call
returns, and gets:

- one `QUEUED` or `CACHED` event per plugin, all of them before any download
  starts, so the whole list -- and, with `size` in the config, the total -- is
  known from the first events;
- for each download, `STARTED`, some `PROGRESS` (repeated about once a second
  while a download waits on the server -- before `STARTED` too, while it is
  still connecting -- so that a stalled one can still be cancelled), and
  exactly one `DONE` or `FAILED`;
- per-plugin and overall byte counts, with -1 for a size not yet known.

The callback returns `false` to cancel. The call returns `ERR_OK`,
`ERR_PLUGIN_FETCH` (some failed; the others are in the cache), `ERR_CANCELLED`,
or `ERR_CONFIG`.

### Plugins compiled into the client

iOS will not load code from a file, and Android will not load it from anywhere
an app can write. On those platforms a plugin is linked into the app at build
time and registered under a name, and a config refers to it with `builtin`:

```ini
[Plugin]
; A mobile client with the builtin uses it; a desktop client without it
; downloads the url instead. One config serves both.
socks = builtin=socks5-c, url=https://cdn.example.com/plugins/1.2.0/socks5_cabi_c.dll, sha256=9f86d0...
```

A registered builtin wins: `path` and `url` are then not looked at, nothing is
downloaded, and no cache directory is needed. A client without it falls back to
`path`, then `url`; one with neither fails to start and lists the builtins it
does have. A builtin's descriptor is validated exactly as a loaded library's
is.

`leaf-ffi` links the in-tree plugins through cargo features, and registers each
one on the first call that reads a config:

```sh
cargo build -p leaf-ffi --release --target aarch64-apple-ios \
    --features plugin-socks5-c
```

| Feature | `builtin=` |
|---|---|
| `plugin-socks5-c` | `socks5-c` |

A plugin the app links itself is registered with
`leaf_register_plugin(name, get_descriptor)` before `leaf_run_*`. How it gets
linked depends on the language:

- **Rust** plugins are not linked in. Plugins exist for protocols written in
  other languages; one written in Rust belongs in leaf as an outbound of its
  own. Linking one in would also merge its dependencies' features with leaf's
  -- two rustls crypto providers, for one, which leaves rustls unable to pick
  a default. The in-tree Rust plugins stay loadable libraries, for tests and
  as examples of the ABI.
- **C**: compile with `-DLEAF_PLUGIN_STATIC_NAME=<name>`, and
  `leaf_plugin_abi.h` renames the descriptor function to
  `leaf_plugin_<name>_get_descriptor`, unexported. The source does not change;
  everything else in it should already be `static`.
- **Zig and Go** plugins cannot be linked in yet. A Go one in particular brings
  a runtime of its own, and one binary can hold only one, so Go plugins would
  have to be built together as a single archive.

[`docs/plugin-verification.md`](docs/plugin-verification.md) walks through
both -- downloads with their progress and failure modes, and builtins with
their fallback -- step by step, with the `leaf-plugin-verify` tool.

### Checking a plugin before you deploy it

`--verify-plugin` runs the loader's own checks -- the path, the file's
permissions, the digest, the descriptor -- without a config file and without
starting a proxy, and prints what the plugin declares:

```sh
$ leaf --verify-plugin ./target/release/libshadowsocks_cabi_rs.dylib
path:      /opt/rust/leaf/target/release/libshadowsocks_cabi_rs.dylib
sha256:    3263ea158c1557731f7b3347cd38e31e563937f08acef9caa653a5fde3fd21fe
name:      leaf-shadowsocks-cabi-rs-plugin
version:   0.1.0
abi:       2.1 (host 2.1)
stream:    connect_type=proxy-tcp
           the outbound must set host and port
datagram:  transport_type=unreliable
           the outbound must set host and port
```

The `connect_type` lines are the ones to read before writing the outbound: a
plugin that dials a server of its own needs `host` and `port`, and a transport
plugin that layers on whatever precedes it in a chain is refused if you give it
any. The `sha256` line is the value to pin.

It exits non-zero on anything leaf would refuse to load, and with the same
message the proxy would have failed to start with, so it works as a deployment
check. `--verify-plugin-sha256 <hex>` additionally requires the file to match a
digest you already hold.

Reading a descriptor means opening the library, which runs its initialisers in
this process -- so this is a check to run on a build you were going to deploy,
not a way to triage one you suspect.

### Building a leaf that can load plugins

Plugin support is behind a cargo feature, since it is what pulls in dynamic
loading:

```sh
cargo build -p leaf-cli --release --features leaf/plugin
```

Neither the released binaries nor CI build that, so a leaf that loads plugins is
one you build. On macOS and Windows the line above is the whole story. On Linux
it is not: the releases are statically linked against musl, and a static binary
has no dynamic loader to call, so `dlopen` fails whatever the config says. Build
for a dynamically linked target instead -- `x86_64-unknown-linux-gnu` or
`aarch64-unknown-linux-gnu` -- with cargo on the host, or with `cross` and the
matching toolchain image.

To download plugins named by `url`, add `leaf/plugin-fetch`, which implies
`leaf/plugin` and needs the rustls TLS backend the default features already
select.

`leaf --verify-plugin <path>` on the result is the quickest way to tell a build
that can load plugins from one that cannot: a build without the feature says so
and exits non-zero.

The plugins themselves are built from `leaf-plugins/`, each with its own
toolchain -- `cargo build -p <name>` for the Rust ones, `go build
-buildmode=c-shared` for the Go ones, and see each plugin's README for C and
Zig. A plugin and the leaf that loads it must agree on the ABI major version,
which `--verify-plugin` prints for both.

## Building

```sh
cargo build -p leaf-cli --release
./target/debug/leaf --help
```

## License

This project is licensed under the [Apache License 2.0](https://github.com/eycorsican/leaf/blob/master/LICENSE).
