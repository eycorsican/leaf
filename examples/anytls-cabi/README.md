# AnyTLS through a plugin

`client.json` runs a SOCKS5 proxy on `127.0.0.1:1080` that sends everything
through an AnyTLS server, with the protocol supplied by the
[`anytls-cabi-go`](../../leaf-plugins/anytls-cabi-go) plugin.

## Build

From the repository root:

```sh
cargo build -p leaf-cli --features leaf/plugin
(cd leaf-plugins/anytls-cabi-go && \
  go build -buildmode=c-shared -o ../../target/debug/libanytls_cabi_go.dylib .)
```

On Linux the library is `libanytls_cabi_go.so`; change `path` to match.

## A server to try it against

Any AnyTLS server will do. With sing-box:

```json
{
  "inbounds": [
    {
      "type": "anytls",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "name": "me", "password": "change-me" }],
      "tls": {
        "enabled": true,
        "server_name": "server.example.com",
        "certificate_path": "/etc/ssl/server.example.com.crt",
        "key_path": "/etc/ssl/server.example.com.key"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
```

mihomo's `anytls` listener and anytls-go's own server work the same way; the
end-to-end suite runs the plugin against all three (`make interop`).

## Run

```sh
./target/debug/leaf -c examples/anytls-cabi/client.json
curl -x socks5h://127.0.0.1:1080 https://example.com
```

Set `host`, `server_name` and `password` to your server's. The certificate is
checked against `server_name`; for a server with a private CA, add
`"certificate": "/path/to/ca.pem"` to `args`.
