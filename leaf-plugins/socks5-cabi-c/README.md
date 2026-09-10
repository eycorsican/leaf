# socks5-cabi-c

A SOCKS5 outbound plugin for the leaf C ABI, in plain C11.

It is the reference for what a plugin looks like in a language with no runtime
of its own: no threads, no dependencies beyond libc, and a single source file.
The engine is a state machine over the buffers the host supplies, which is the
shape the ABI was designed for -- every call returns immediately, so
`LEAF_STREAM_ENGINE_STATE_BLOCKED` and the wake callback are never needed.

It exports one stream engine with `LEAF_STREAM_CONNECT_TYPE_PROXY_TCP`: the host
connects a TCP socket to the host and port in the outbound's settings, and this
engine performs the SOCKS5 handshake over it and then carries the session
transparently. There is no datagram engine, so the outbound handles TCP only.

## Configuration

```json
{
  "tag": "socks5-plugin",
  "protocol": "plugin",
  "settings": {
    "path": "./libsocks5_cabi_c.so",
    "host": "127.0.0.1",
    "port": 1080,
    "args": ""
  }
}
```

`args` is empty for a server that wants no authentication, or
`username:password` for one that wants credentials. The password may contain
colons; the username may not, since the first colon is the separator.

## Building

```sh
cc -std=c11 -O2 -fPIC -shared -I../../leaf-plugin-abi/include \
   -o libsocks5_cabi_c.so socks5.c
```

## Tests

```sh
cc -std=c11 -I../../leaf-plugin-abi/include -o socks5_test socks5_test.c
./socks5_test
```

`socks5_test.c` includes `socks5.c` and drives the engine through its own
vtable, the way the host does, with the server's half of the conversation
supplied by hand: the handshake arriving a byte at a time, every way a server
can refuse, the states the engine reports in between, and the buffer under all
of it. `make plugin-test` runs it from the workspace root, and the end-to-end
suite runs the plugin against a real leaf SOCKS5 server.
