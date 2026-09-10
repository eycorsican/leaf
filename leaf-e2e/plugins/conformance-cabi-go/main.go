// Command conformance-cabi-go is the Go counterpart of conformance-cabi: a
// plugin that relays faithfully until asked to misbehave.
//
// The Rust one covers what the host does with a wrong plugin. This one exists
// for the part only a Go plugin has -- the SDK's boundary, which turns a panic
// or a fault inside Go into a status code instead of letting it cross into the
// host, and the Go runtime that boundary belongs to. Neither is reachable from
// a Rust plugin, and both are what a second Go runtime in the same process
// would disturb if Go's arbitration between them did not hold.
//
// Faults are chosen per instance through the outbound's plugin arguments,
// `fault=<name>`:
//
//	panic-in-push    a Go panic inside Push, on the first application bytes
//	fault-in-push    a nil dereference inside Push, which arrives as a
//	                 hardware exception and has to be claimed by this
//	                 module's runtime rather than by another one's
//	panic-in-pull    a Go panic inside Pull
//	panic-in-create  a panic before the instance exists at all
//
// Without a fault it is a plain byte-for-byte relay, so a fault is judged
// against the same traffic that works without one.
package main

import "C"

import (
	"strings"

	leafabi "leaf-plugins/leaf-abi-go"
)

func main() {}

func init() {
	leafabi.Register(leafabi.Plugin{
		Name:      "leaf-conformance-go-plugin",
		Version:   "0.1.0",
		LogTarget: "leaf.plugin.conformance.go",
		Stream: &leafabi.StreamEngineSpec{
			// The host dials the endpoint the outbound names and hands us the
			// socket; everything below is about what we do with the bytes.
			ConnectType: leafabi.ConnectProxyTCP,
			New:         newEngine,
		},
	})
}

type fault string

const (
	faultNone          fault = ""
	faultPanicInPush   fault = "panic-in-push"
	faultNilDerefPush  fault = "fault-in-push"
	faultPanicInPull   fault = "panic-in-pull"
	faultPanicInCreate fault = "panic-in-create"
)

func parseFault(args string) fault {
	for _, field := range strings.Split(args, ";") {
		field = strings.TrimSpace(field)
		if rest, ok := strings.CutPrefix(field, "fault="); ok {
			return fault(strings.TrimSpace(rest))
		}
	}
	return faultNone
}

// engine is a relay: what the application writes goes to the network
// unchanged, and back.
type engine struct {
	fault    fault
	appOut   []byte
	netOut   []byte
	appEnded bool
	netEnded bool
}

func newEngine(args leafabi.CreateArgs) (leafabi.StreamEngine, error) {
	f := parseFault(args.Args)
	if f == faultPanicInCreate {
		panic("conformance-go: asked to panic before the instance exists")
	}
	return &engine{fault: f}, nil
}

func (e *engine) PollState() leafabi.StateFlags {
	flags := leafabi.StateEstablished
	if len(e.netOut) > 0 {
		flags |= leafabi.StateHasNetOutput
	}
	if len(e.appOut) > 0 {
		flags |= leafabi.StateHasAppOutput
	}
	if !e.appEnded {
		flags |= leafabi.StateWantAppInput
	}
	if !e.netEnded {
		flags |= leafabi.StateWantNetInput
	}
	return flags
}

func (e *engine) Push(side leafabi.Side, input []byte) (int, error) {
	if side == leafabi.SideApp {
		switch e.fault {
		case faultPanicInPush:
			panic("conformance-go: asked to panic in Push")
		case faultNilDerefPush:
			// A hardware exception rather than a panic, which is the half a
			// Go runtime has to claim through its own exception handler --
			// and the half another runtime in the process must not claim.
			var p *int
			_ = *p
		}
		e.netOut = append(e.netOut, input...)
	} else {
		e.appOut = append(e.appOut, input...)
	}
	return len(input), nil
}

func (e *engine) Pull(side leafabi.Side, output []byte) (int, error) {
	if e.fault == faultPanicInPull && side == leafabi.SideNet {
		panic("conformance-go: asked to panic in Pull")
	}
	buf := &e.netOut
	if side == leafabi.SideApp {
		buf = &e.appOut
	}
	n := copy(output, *buf)
	*buf = (*buf)[n:]
	return n, nil
}

func (e *engine) Close(flags leafabi.CloseFlags) error {
	if flags&leafabi.CloseApp != 0 {
		e.appEnded = true
	}
	if flags&leafabi.CloseNet != 0 {
		e.netEnded = true
	}
	return nil
}

func (e *engine) Destroy() {}
