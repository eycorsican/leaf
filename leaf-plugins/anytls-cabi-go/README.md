# anytls-cabi-go

An [AnyTLS](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)
client plugin for the leaf C ABI.

AnyTLS is a proxy protocol that runs inside TLS and pads the first packets of
every session according to a *padding scheme*. The scheme decides how the
authentication, the session setup and the first writes of the application are
cut into TLS records and how much padding each one carries, so the record sizes
of a proxied TLS-in-TLS session stop looking like one. The server can hand out
a scheme of its own, and the client uses it from the next session on.

## What is here, and what is not

The plugin does not implement AnyTLS. The protocol is
[`github.com/anytls/sing-anytls`](https://github.com/anytls/sing-anytls) — the
AnyTLS author's own library, at v0.0.13, used as it is. The plugin is the
adapter between it and the ABI, and is small on purpose:

| File | What it does |
| --- | --- |
| `main.go` | Parses `args`, keeps one library client per outbound, opens one AnyTLS stream per engine instance |
| `tls.go` | The TLS client: Go's own, or a uTLS ClientHello when `fingerprint` is set |

Everything blocking runs inside `leafabi.ConnEngine`, which gives the library
the `net.Conn` it expects and gives the host an engine that never blocks.

Two choices in the adapter are worth knowing about:

- **TLS is inside the plugin, not a separate outbound.** The padding scheme is
  defined in TLS records, and only the code writing the records controls where
  they are cut. Under a separate TLS layer the host merges and splits the
  plugin's writes, and the padding no longer means anything. The unit tests read
  the records off the wire and check them against the scheme.
- **One library client per outbound.** The client is where the server's padding
  scheme is kept. One client per connection would forget the scheme every time,
  and go on sending the default to a server that asked for another. Session
  reuse is off: every engine instance is one connection the host owns, so there
  is no idle session to keep.

## Configuration

```json
{
  "tag": "anytls",
  "protocol": "plugin",
  "settings": {
    "path": "./libanytls_cabi_go.so",
    "host": "server.example.com",
    "port": 443,
    "args": "{\"password\":\"...\",\"server_name\":\"server.example.com\",\"fingerprint\":\"chrome\"}"
  }
}
```

`host` and `port` are the AnyTLS server. `args` is JSON:

| Key | Required | Meaning |
| --- | --- | --- |
| `password` | yes | The user's password |
| `server_name` | unless `insecure` | SNI, and the name the certificate is checked against. The engine is never told which server the host dialled, so this is the only name it has |
| `certificate` | no | A PEM file, or PEM text, to trust instead of the system roots |
| `insecure` | no | Accept any certificate. Testing only: a client that does not verify its server can be impersonated by anything in the path |
| `alpn` | no | ALPN protocols to offer |
| `fingerprint` | no | Present a browser's ClientHello instead of Go's: `chrome`, `firefox`, `safari`, `ios`, `edge`, `android`, `360`, `qq`, `random`. The names are the ones sing-box and mihomo use |

Unknown keys are rejected rather than ignored.

## Limitations

- **TCP only.** AnyTLS carries UDP as udp-over-tcp inside a stream, behind the
  same TLS handshake. A datagram engine cannot run a handshake — it produces
  output only when handed a datagram — so the plugin has none, and the host
  registers the outbound for TCP. Supporting it needs a datagram path in the ABI
  that rides on a stream engine.
- **No session reuse.** The reference client keeps idle sessions and opens new
  streams on them; the ABI gives each engine instance its own connection, owned
  by the host, so every connection is a new session. This is a protocol-level
  difference an observer could see — more TLS handshakes than the reference
  client makes — and it needs ABI support to remove. None of the servers tested
  rejects it.
- **No half close.** This is AnyTLS, not the plugin: a FIN frame ends a stream
  in both directions, so ending the application's sending side ends the
  connection.

## Building

```sh
go build -buildmode=c-shared -o libanytls_cabi_go.so .
```

## Tests

```sh
go test -race ./...
```

The unit tests run the plugin against the server half of the same library in
process, with the engine driven the way the host drives it
(`leaf-abi-go/enginetest`): every address kind, 4 MiB in both directions, each
fingerprint, the exact sizes of the first records against the default scheme, a
server's own scheme taking effect on the next connection, a wrong password, a
refused destination, certificate verification, and `Destroy` while a handshake
is pending.

The end-to-end suite runs it through a real leaf against the servers people
deploy — anytls-go's own server, sing-box (the stable release, and the
`testing` branch that replaced the library with sing-box's own), and mihomo —
with every stream behaviour, the server-scheme check on the wire, and a wrong
password:

```sh
make interop E2E_ARGS="interop/anytls"
```

## License

The library this links is GPL-3.0-or-later, and so is a binary built from this
directory. leaf itself is not affected: the plugin is a separate library, loaded
at run time.
