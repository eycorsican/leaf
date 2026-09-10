# leaf-abi-go

The Go SDK for writing leaf plugins.

A plugin built on it is an ordinary Go package that registers one or two engines
and implements them over byte slices. Everything the C ABI needs -- the
descriptor, the vtables, the const-pointer shims cgo cannot express, handle
management, panic recovery, the two-pass error protocol -- lives here, and none
of it appears in the plugin.

## A plugin, whole

```go
package main

import leafabi "leaf-plugins/leaf-abi-go"

func main() {}

func init() {
    leafabi.Register(leafabi.Plugin{
        Name:    "example",
        Version: "0.1.0",
        Stream: &leafabi.StreamEngineSpec{
            ConnectType: leafabi.ConnectProxyTCP,
            New:         newEngine,
        },
    })
}
```

`newEngine` returns something implementing `leafabi.StreamEngine`: `PollState`,
`Push`, `Pull`, `Close`, `Destroy`, all over `[]byte`. A `go.mod` with

```
require leaf-plugins/leaf-abi-go v0.0.0
replace leaf-plugins/leaf-abi-go => ../leaf-abi-go
```

and `go build -buildmode=c-shared -o libexample.so .` produces a plugin leaf can
load.

## What it is for

Two things that are easy to get wrong, and one that is easy to get wrong
silently.

**Blocking.** Engine calls run on the host's executor and must return at once,
but most of Go's protocol and transport libraries -- `crypto/tls` above all --
are written against a blocking `net.Conn`. `leafabi.ConnEngine` bridges that: it
runs the blocking implementation on goroutines of its own over an in-memory
pipe, reports `StateBlocked` with a call to `Host.Wake` while those goroutines
are what it is waiting on, and joins them in `Destroy` as the ABI requires.
`tls-cabi-go` is four lines of it.

An engine that is a pure state machine over buffers -- most protocol codecs are
-- wants none of that and implements `StreamEngine` directly, as
`trojan-cabi-go` does.

**Panics.** Nothing may unwind across the boundary. Every entry recovers and
reports `StatusPluginFailure` with the panic in the message.

**Callback lifetime.** The host's `log` and `wake` pointers are valid only until
`destroy_instance` returns. The SDK revokes its `Host` handle once `Destroy` has
returned, so a goroutine that outlives its engine drops a log line instead of
calling into memory the host has reclaimed.

## The one rule about direction

`Register` must be called from `init`, and the SDK calls out to C from there to
fill the descriptor in.

It cannot work the other way round. A thread that enters Go is bound to the Go
runtime for good and can never exit -- it parks forever in its own TLS
destructor -- and the thread that loads a plugin belongs to the host. A host
that reads its configuration on a pooled thread would then hang on shutdown,
waiting to join a thread that cannot finish. So `leaf_plugin_get_descriptor`
contains no call into Go: it waits on a flag that Go sets from its own thread.

## Tests

```sh
go test -race ./...
```

They drive `ConnEngine` through a real TLS handshake the way the host drives an
engine -- one call at a time, the network side wired to a conn -- and cover the
address encoding every SOCKS-shaped protocol shares.
