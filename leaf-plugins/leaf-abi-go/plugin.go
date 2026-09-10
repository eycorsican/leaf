// Package leafabi is the Go SDK for writing leaf plugins.
//
// A plugin built on it is an ordinary Go package that registers one or two
// engines and implements them in terms of byte slices; everything the C ABI
// needs -- the descriptor, the vtables, the const-pointer shims, handle
// management, panic recovery, the two-pass error protocol -- lives here.
//
// A minimal plugin is a main package that does nothing but register:
//
//	package main
//
//	import leafabi "leaf-plugins/leaf-abi-go"
//
//	func main() {}
//
//	func init() {
//		leafabi.Register(leafabi.Plugin{
//			Name:    "example",
//			Version: "0.1.0",
//			Stream: &leafabi.StreamEngineSpec{
//				ConnectType: leafabi.ConnectProxyTCP,
//				New:         newEngine,
//			},
//		})
//	}
//
// and is built the way every Go plugin is:
//
//	go build -buildmode=c-shared -o libexample.so .
//
// # The contract the SDK keeps for you
//
// Engine methods run on the host's executor, so they must return promptly:
// no sleeping, no I/O, no waiting on another goroutine. An engine that cannot
// finish immediately reports [StateBlocked] and calls [Host.Wake] once it can
// -- see [ConnEngine], which does exactly that for implementations that insist
// on a blocking [net.Conn].
//
// The SDK recovers any panic an engine method raises and turns it into
// [StatusPluginFailure], so nothing unwinds across the boundary. It also
// revokes the [Host] handle once Destroy has returned, so a stray goroutine
// cannot call a host callback the host has already taken back.
//
// Slices handed to an engine method are views of the host's own buffers and are
// valid only for that call. Keep the bytes, not the slice.
package leafabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
#include "abi.h"
*/
import "C"

import (
	"fmt"
	"sync"
)

// Status is a code the ABI defines for every entry that reports one.
type Status int32

const (
	StatusOK Status = C.LEAF_ENGINE_STATUS_OK
	// StatusInvalidArgument reports something the engine does not implement,
	// such as an address kind or a side. The host treats it as fatal.
	StatusInvalidArgument Status = C.LEAF_ENGINE_STATUS_INVALID_ARGUMENT
	// StatusBufferTooSmall reports that the output buffer could not hold the
	// result. The engine must consume nothing, so the host can grow the buffer
	// and retry the same input.
	StatusBufferTooSmall Status = C.LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL
	// StatusUnsupported reports an operation the engine does not implement at
	// all, so retrying cannot help.
	StatusUnsupported Status = C.LEAF_ENGINE_STATUS_UNSUPPORTED
	// StatusPluginFailure reports a failure of the engine's own. The host turns
	// it into an I/O error and tears the connection down.
	StatusPluginFailure Status = C.LEAF_ENGINE_STATUS_PLUGIN_FAILURE
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusInvalidArgument:
		return "invalid argument"
	case StatusBufferTooSmall:
		return "buffer too small"
	case StatusUnsupported:
		return "unsupported"
	case StatusPluginFailure:
		return "plugin failure"
	default:
		return fmt.Sprintf("status(%d)", int32(s))
	}
}

// Level is a log level the host understands. A message logged above the level
// the host is configured for is dropped.
type Level uint32

const (
	LevelError Level = C.LEAF_LOG_LEVEL_ERROR
	LevelWarn  Level = C.LEAF_LOG_LEVEL_WARN
	LevelInfo  Level = C.LEAF_LOG_LEVEL_INFO
	LevelDebug Level = C.LEAF_LOG_LEVEL_DEBUG
	LevelTrace Level = C.LEAF_LOG_LEVEL_TRACE
)

// Side names one end of a stream engine.
type Side uint32

const (
	// SideApp is the plaintext the proxy carries.
	SideApp Side = C.LEAF_STREAM_SIDE_APP
	// SideNet is the encoded bytes on the socket.
	SideNet Side = C.LEAF_STREAM_SIDE_NET
)

func (s Side) String() string {
	switch s {
	case SideApp:
		return "app"
	case SideNet:
		return "net"
	default:
		return fmt.Sprintf("side(%d)", uint32(s))
	}
}

// StateFlags is what an engine reports from PollState.
type StateFlags uint32

const (
	// StateWantAppInput says there is room for more application input.
	// Advisory: a short count from Push is the authoritative signal.
	StateWantAppInput StateFlags = C.LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT
	// StateWantNetInput says the engine is waiting on bytes from the peer.
	// This, not StateBlocked, is what waiting for the other end looks like.
	StateWantNetInput StateFlags = C.LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT
	// StateHasAppOutput says decoded bytes are ready for the application.
	StateHasAppOutput StateFlags = C.LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT
	// StateHasNetOutput says bytes are ready for the socket. Set it during a
	// handshake too: the host keeps that side moving while the application is
	// only reading.
	StateHasNetOutput StateFlags = C.LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT
	// StateHandshaking is informational.
	StateHandshaking StateFlags = C.LEAF_STREAM_ENGINE_STATE_HANDSHAKING
	// StateEstablished is informational.
	StateEstablished StateFlags = C.LEAF_STREAM_ENGINE_STATE_ESTABLISHED
	// StatePeerClosed says the peer closed. Once no application output is
	// left, the host reports end of stream.
	StatePeerClosed StateFlags = C.LEAF_STREAM_ENGINE_STATE_PEER_CLOSED
	// StateFatal says the engine is unusable and the connection must fail.
	StateFatal StateFlags = C.LEAF_STREAM_ENGINE_STATE_FATAL
	// StateBlocked says the engine cannot make progress from anything the host
	// can hand it now and will call Host.Wake once that changes. Reporting it
	// without a wake callback would park the host forever, so the SDK masks it
	// off when the host offered none.
	StateBlocked StateFlags = C.LEAF_STREAM_ENGINE_STATE_BLOCKED
)

// Has reports whether every flag in other is set.
func (f StateFlags) Has(other StateFlags) bool { return f&other == other }

// CloseFlags says which sides of a stream engine are finished.
type CloseFlags uint32

const (
	// CloseApp means the application has finished writing, so the engine
	// should emit whatever its protocol uses to say so.
	CloseApp CloseFlags = C.LEAF_STREAM_ENGINE_CLOSE_APP
	// CloseNet means the socket reached end of file and nothing more will
	// arrive from the peer.
	CloseNet CloseFlags = C.LEAF_STREAM_ENGINE_CLOSE_NET
)

// Has reports whether every flag in other is set.
func (f CloseFlags) Has(other CloseFlags) bool { return f&other == other }

// ConnectType says what stream the host hands a stream engine.
type ConnectType uint32

const (
	// ConnectProxyTCP is a TCP connection to the host and port in the
	// outbound's settings, which must be configured.
	ConnectProxyTCP ConnectType = C.LEAF_STREAM_CONNECT_TYPE_PROXY_TCP
	// ConnectDirect is a connection straight to the session's destination.
	// The outbound must not configure a host or port.
	ConnectDirect ConnectType = C.LEAF_STREAM_CONNECT_TYPE_DIRECT
	// ConnectNext is whatever the previous outbound in the chain produced, as
	// a TLS engine wants. The outbound must not configure a host or port.
	ConnectNext ConnectType = C.LEAF_STREAM_CONNECT_TYPE_NEXT
)

// TransportType says what carries a datagram engine's frames.
type TransportType uint32

const (
	// TransportReliable puts the engine on top of the stream transport the
	// chain established; the engine frames each datagram itself, which is why
	// DecodePacket reports how much it consumed.
	TransportReliable TransportType = C.LEAF_DATAGRAM_TRANSPORT_TYPE_RELIABLE
	// TransportUnreliable gets one whole frame per call in each direction.
	TransportUnreliable TransportType = C.LEAF_DATAGRAM_TRANSPORT_TYPE_UNRELIABLE
)

// Direction says which way a datagram size hint is about.
type Direction uint32

const (
	DirectionEncode Direction = C.LEAF_DATAGRAM_DIRECTION_ENCODE
	DirectionDecode Direction = C.LEAF_DATAGRAM_DIRECTION_DECODE
)

// ABIMajor and ABIMinor are the ABI version this SDK was built against. The
// host loads a plugin only when the major versions match exactly.
const (
	ABIMajor = uint32(C.LEAF_PLUGIN_ABI_MAJOR)
	ABIMinor = uint32(C.LEAF_PLUGIN_ABI_MINOR)
)

// StreamEngineSpec describes a plugin's stream engine.
type StreamEngineSpec struct {
	// ConnectType is a property of the plugin, read once at load time.
	ConnectType ConnectType
	// New builds one engine instance, once per connection.
	New func(CreateArgs) (StreamEngine, error)
}

// DatagramEngineSpec describes a plugin's datagram engine.
type DatagramEngineSpec struct {
	// TransportType is a property of the plugin, read once at load time.
	TransportType TransportType
	// New builds one engine instance, once per session.
	New func(CreateArgs) (DatagramEngine, error)
}

// Plugin is what a plugin registers. Exactly one of Stream and Datagram may be
// nil: a plugin with neither has nothing to offer and the host rejects it.
type Plugin struct {
	// Name and Version appear in the host's logs and diagnostics.
	Name    string
	Version string
	// LogTarget is the target the host files this plugin's messages under.
	// Defaults to Name.
	LogTarget string

	Stream   *StreamEngineSpec
	Datagram *DatagramEngineSpec
}

var (
	registerOnce sync.Once
	registered   Plugin
)

// Register declares what this plugin exports. Call it from init in the
// plugin's main package: with -buildmode=c-shared every package init runs
// while the host is still inside dlopen, which is before it can ask for the
// descriptor. Registering later would be too late, and registering from
// leaf_plugin_get_descriptor instead would bind the host's loading thread to
// the Go runtime for the life of the process.
//
// It panics on a registration the ABI cannot express -- an empty name, no
// engine at all, an engine with no constructor -- because that is a mistake in
// the plugin rather than a condition the host could report usefully. Calling it
// twice panics for the same reason.
func Register(p Plugin) {
	validateRegistration(p)
	claimed := false
	registerOnce.Do(func() {
		registered = p
		claimed = true
	})
	if !claimed {
		panic("leafabi: Register called more than once")
	}
	publish(p)
}

// publish hands the registration to the C descriptor.
func publish(p Plugin) {
	target := p.LogTarget
	if target == "" {
		target = p.Name
	}
	// These three outlive the library on purpose: the ABI requires the
	// descriptor's strings to stay valid until it is unloaded, so they are
	// allocated once and never freed.
	logTarget = staticCString(target)
	var connect ConnectType
	var transport TransportType
	if p.Stream != nil {
		connect = p.Stream.ConnectType
	}
	if p.Datagram != nil {
		transport = p.Datagram.TransportType
	}
	C.leafabi_descriptor_configure(
		staticCString(p.Name),
		staticCString(p.Version),
		cbool(p.Stream != nil),
		C.leaf_stream_connect_type_t(connect),
		cbool(p.Datagram != nil),
		C.leaf_datagram_transport_type_t(transport),
	)
}

func validateRegistration(p Plugin) {
	if p.Name == "" {
		panic("leafabi: Plugin.Name must not be empty")
	}
	if p.Version == "" {
		panic("leafabi: Plugin.Version must not be empty")
	}
	if p.Stream == nil && p.Datagram == nil {
		panic("leafabi: a plugin must export a stream engine, a datagram engine, or both")
	}
	if p.Stream != nil {
		if p.Stream.New == nil {
			panic("leafabi: StreamEngineSpec.New must not be nil")
		}
		switch p.Stream.ConnectType {
		case ConnectProxyTCP, ConnectDirect, ConnectNext:
		default:
			panic(fmt.Sprintf("leafabi: invalid StreamEngineSpec.ConnectType %d", p.Stream.ConnectType))
		}
	}
	if p.Datagram != nil {
		if p.Datagram.New == nil {
			panic("leafabi: DatagramEngineSpec.New must not be nil")
		}
		switch p.Datagram.TransportType {
		case TransportReliable, TransportUnreliable:
		default:
			panic(fmt.Sprintf("leafabi: invalid DatagramEngineSpec.TransportType %d", p.Datagram.TransportType))
		}
	}
}

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}
