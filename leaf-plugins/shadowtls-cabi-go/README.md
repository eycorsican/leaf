# shadowtls-cabi-go

A [ShadowTLS v3](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md)
client plugin for the leaf C ABI.

ShadowTLS borrows the TLS handshake of a real site. The client sends a
ClientHello to the ShadowTLS server, which relays the handshake to the site, so
an observer sees a complete, genuine TLS 1.3 handshake with that site's
certificate. An HMAC in the ClientHello's session ID tells the server which
clients are its own; anyone else — a censor's probe — is handed to the site
whole and sees nothing but the site. After the handshake, data travels in
records that look like TLS application data and carry an HMAC chained over
everything before them. The records are authenticated, not encrypted, so the
protocol inside has to encrypt itself: usually Shadowsocks.

## What is here, and what is not

The plugin does not implement ShadowTLS. The protocol is
[`github.com/sagernet/sing-shadowtls`](https://github.com/SagerNet/sing-shadowtls),
at the version sing-box v1.14.4 ships, and the ClientHello is
[`github.com/metacubex/utls`](https://github.com/metacubex/utls), the uTLS fork
both sing-box and mihomo use for it. The plugin is the adapter:

| File | What it does |
| --- | --- |
| `main.go` | Parses `args`, keeps one library client per outbound, runs the handshake in `leafabi.ConnEngine` |
| `tls.go` | The handshake with the site, and the session ID put into it |

### A fix the adapter carries

`tls.go` does not use uTLS's own hook for the session ID
(`Config.SessionIDGenerator`). In every metacubex/utls release up to
v1.9.0-alpha.1, that hook re-encodes the ClientHello with Go's encoder to
compute the HMAC. With a browser fingerprint the result is that the
fingerprint is silently dropped — the ClientHello on the wire is Go's, with the
same 13 extensions whichever browser was asked for — and when the site answers
with a HelloRetryRequest, the second ClientHello carries a different session ID
from the first, which RFC 8446 forbids and the site rejects.

The adapter builds the browser's ClientHello first, computes the HMAC over its
own bytes and sets the session ID in its own state, so both ClientHellos are the
browser's and carry the same signed ID. `TestFingerprintReachesTheWire` and
`TestHelloRetryRequest` fail against the hook and pass against this. sing-box and
mihomo use the hook as it is.

## Configuration

ShadowTLS is a transport: it carries whatever the chain puts inside it, and the
next actor in the chain names the server.

```json
"outbounds": [
  {
    "tag": "shadowtls-chain",
    "protocol": "chain",
    "settings": { "actors": ["shadowtls", "ss"] }
  },
  {
    "tag": "shadowtls",
    "protocol": "plugin",
    "settings": {
      "path": "./libshadowtls_cabi_go.so",
      "args": "{\"password\":\"...\",\"server_name\":\"www.example.com\",\"fingerprint\":\"chrome\"}"
    }
  },
  {
    "tag": "ss",
    "protocol": "shadowsocks",
    "settings": {
      "address": "shadowtls-server.example.com",
      "port": 443,
      "method": "aes-128-gcm",
      "password": "..."
    }
  }
]
```

`args` is JSON:

| Key | Required | Meaning |
| --- | --- | --- |
| `password` | yes | The ShadowTLS user's password |
| `server_name` | yes | The site whose handshake is borrowed, sent as SNI, and the name its certificate is checked against |
| `certificate` | no | A PEM file, or PEM text, to trust instead of the system roots |
| `insecure` | no | Accept any certificate. Testing only |
| `alpn` | no | ALPN protocols to offer, with Go's ClientHello. A fingerprint brings its own |
| `fingerprint` | no | Present a browser's ClientHello: `chrome`, `firefox`, `safari`, `ios`, `edge`, `android`, `360`, `qq`, `random`. Without one the ClientHello is Go's, which is easy to tell apart from a browser's; set one |
| `strict` | no, default `true` | Refuse a site that does not negotiate TLS 1.3. Version 3 detects a hijacked connection through TLS 1.3, so turning this off weakens it |

Unknown keys are rejected rather than ignored. Only protocol version 3 is
offered.

## Behaviour on failure

A connection that reaches the real site instead of the ShadowTLS server — a
wrong password, or a connection hijacked on the way — fails the handshake check
and ends. The library reports it as `traffic hijacked`. The original Rust client
additionally sends a short fake HTTP request to the site before closing, so the
connection looks like a browser's to the end; the library does not, and neither
does this plugin.

## Building

```sh
go build -buildmode=c-shared -o libshadowtls_cabi_go.so .
```

## Tests

```sh
go test -race ./...
```

The unit tests run the plugin against the server half of the same library, in
process, with a real TLS server standing in for the site and the engine driven
the way the host drives it (`leaf-abi-go/enginetest`): every fingerprint, 4 MiB
in both directions, a HelloRetryRequest, the fingerprint as it reaches the wire,
a wrong password, a connection hijacked to the site, a TLS 1.2 site with and
without strict mode, an untrusted certificate, a record with one byte changed,
and `Destroy` while a handshake is pending.

The end-to-end suite runs it through a real leaf, under Shadowsocks, against the
original shadow-tls server, sing-box and mihomo, with every stream behaviour and
the three ways a connection must fail:

```sh
make interop E2E_ARGS="interop/shadowtls"
```

## License

The library this links is GPL-3.0-or-later, and so is a binary built from this
directory. leaf itself is not affected: the plugin is a separate library, loaded
at run time.
