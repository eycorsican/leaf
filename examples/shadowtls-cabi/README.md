# ShadowTLS v3 through a plugin

`client.json` runs a SOCKS5 proxy on `127.0.0.1:1080` that sends everything
through Shadowsocks carried by ShadowTLS v3. leaf's own Shadowsocks outbound
names the server; the [`shadowtls-cabi-go`](../../leaf-plugins/shadowtls-cabi-go)
plugin layers ShadowTLS under it as the first actor of the chain.

## Build

From the repository root:

```sh
cargo build -p leaf-cli --features leaf/plugin
(cd leaf-plugins/shadowtls-cabi-go && \
  go build -buildmode=c-shared -o ../../target/debug/libshadowtls_cabi_go.dylib .)
```

On Linux the library is `libshadowtls_cabi_go.so`; change `path` to match.

## A server to try it against

The server needs a site whose handshake to borrow: a real HTTPS site that
negotiates TLS 1.3, named in the client's `server_name`. With sing-box:

```json
{
  "inbounds": [
    {
      "type": "shadowtls",
      "listen": "::",
      "listen_port": 443,
      "version": 3,
      "users": [{ "name": "me", "password": "change-me" }],
      "handshake": { "server": "www.example.com", "server_port": 443 },
      "strict_mode": true,
      "detour": "ss-in"
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "127.0.0.1",
      "listen_port": 8388,
      "method": "aes-128-gcm",
      "password": "change-me-too"
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
```

With the original server, in front of any Shadowsocks server on port 8388:

```sh
shadow-tls --v3 --strict server --listen [::]:443 \
  --server 127.0.0.1:8388 --tls www.example.com:443 --password change-me
```

mihomo takes it as the `shadow-tls` option of a `shadowsocks` listener. The
end-to-end suite runs the plugin against all three (`make interop`).

## Run

```sh
./target/debug/leaf -c examples/shadowtls-cabi/client.json
curl -x socks5h://127.0.0.1:1080 https://example.com
```

Set the Shadowsocks `address`, both passwords, and `server_name` to match the
server. Keep `fingerprint` set: without it the ClientHello is Go's, which a
censor can tell from a browser's.
