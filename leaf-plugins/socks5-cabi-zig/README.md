# socks5-cabi-zig

A SOCKS5 outbound plugin for the leaf C ABI, in Zig.

It is the counterpart of [`socks5-cabi-c`](../socks5-cabi-c) and does the same
thing the same way, on purpose: the two together are what says the ABI is a
contract rather than a Rust or a Go interface with a C-shaped hole in it.

Zig reads the ABI header directly through `@cImport`, so there is no binding
layer and no second copy of the declarations to keep in step. Like the C plugin
it has no runtime, no threads and no allocator of its own beyond libc's, so
every call returns immediately and `LEAF_STREAM_ENGINE_STATE_BLOCKED` is never
needed.

It exports one stream engine with `LEAF_STREAM_CONNECT_TYPE_PROXY_TCP` and no
datagram engine, so the outbound handles TCP only.

## Configuration

The same as the C plugin's:

```json
{
  "tag": "socks5-plugin",
  "protocol": "plugin",
  "settings": {
    "path": "./zig-out/lib/libsocks5_cabi_zig.so",
    "host": "127.0.0.1",
    "port": 1080,
    "args": ""
  }
}
```

`args` is empty for a server that wants no authentication, or
`username:password` for one that wants credentials.

## Building and testing

```sh
zig build                    # the shared library, under zig-out
zig build test               # the unit tests in src/main.zig
```

The end-to-end harness calls `zig build-lib` directly instead, because it has to
name the output path; `build.zig` is here so the plugin can be built and tested
on its own, the way a third-party plugin would be.

## One thing the header cannot say in Zig

`LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE` and its siblings are `offsetof` macros,
which `translate-c` cannot follow. `src/main.zig` restates them with
`@offsetOf` and `@FieldType`; the ABI crate's header-parity test is what keeps
the header and its Rust mirror honest, and the descriptor test here checks the
sizes it computes against the vtable it publishes.
