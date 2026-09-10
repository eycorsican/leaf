package leafabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
#include <stdlib.h>
#include "abi.h"
*/
import "C"

import (
	"runtime/cgo"
	"sync"
	"unsafe"
)

// Default output hints, used for an engine that does not implement
// OutputHinter. The host clamps whatever it is told, so these only decide how
// efficiently it reads, never how much memory it commits.
const (
	defaultAppOutputSize = 16 * 1024
	defaultNetOutputSize = 18 * 1024
	defaultOutputBatch   = 4
	fallbackOutputSize   = 4096
)

// CreateArgs is what the host knows about one engine instance at the moment it
// asks for one. Nothing in it borrows the host's memory: Args and Destination
// are copies, and Host stays valid until Destroy returns.
type CreateArgs struct {
	// Args is the outbound's `args` setting, verbatim. Its shape is the
	// plugin's own business -- the host never looks inside.
	Args string
	// Destination is where the session is ultimately headed, which is what a
	// protocol engine encodes into its header. Not the server the host
	// connected to.
	Destination Address
	// Host is how this instance logs and wakes the host.
	Host Host
	// HostABIMajor and HostABIMinor are the host's own ABI version, so a
	// plugin built against a newer minor version can tell what the host will
	// actually understand.
	HostABIMajor uint32
	HostABIMinor uint32
}

// StreamEngine is a byte-stream codec with two sides. The host owns the socket
// and drives the engine in a loop: read PollState, push what it asks for, pull
// what it offers, repeat.
//
// Every method must return promptly. Input and output slices are views of the
// host's buffers and are valid only for the call they were passed to.
type StreamEngine interface {
	// PollState reports what the engine wants next. It is called between every
	// other operation, so it must be cheap and must not itself advance the
	// protocol.
	PollState() StateFlags
	// Push offers input for one side and reports how much was taken. A short
	// count is backpressure, not failure: the host keeps the rest and offers it
	// again.
	Push(side Side, input []byte) (int, error)
	// Pull fills output for one side and reports how much. Zero means nothing
	// more is available right now, even if PollState advertised output.
	Pull(side Side, output []byte) (int, error)
	// Close says one or both sides are finished. The engine may still have
	// output afterwards -- a close notify, say -- and the host still drains it.
	Close(flags CloseFlags) error
	// Destroy releases the instance. It is the one method that may block, and
	// only briefly: it must not return until no goroutine of the engine's can
	// still call back into the host.
	Destroy()
}

// DatagramEngine is a packet codec: one datagram and its address in, wire bytes
// out, and back.
type DatagramEngine interface {
	// EncodePacket encodes one datagram for target and reports its length.
	// Returning ErrBufferTooSmall makes the host grow the buffer and retry the
	// same datagram.
	EncodePacket(payload []byte, target Address, output []byte) (int, error)
	// DecodePacket decodes at most one datagram out of input, reporting how
	// much of input it consumed, how many bytes it wrote into payload, and
	// where the datagram came from.
	//
	// On a reliable transport a single read can carry a partial frame or
	// several. Returning ErrIncomplete says the frame is not all there yet: the
	// host reads more and calls again with the frame still at the front.
	// Consuming bytes while writing no payload is how a frame that carries no
	// datagram, such as a keepalive, is dropped.
	//
	// Returning ErrBufferTooSmall must consume nothing, so the host can retry
	// the same input with a larger buffer.
	DecodePacket(input []byte, payload []byte) (consumed int, produced int, address Address, err error)
	// MaxOutputSize is the buffer size the engine wants for an input of
	// inputLen bytes in that direction. Advisory and clamped by the host.
	MaxOutputSize(inputLen int, direction Direction) int
	// MaxAddressSize is the largest address the engine can write into the
	// buffer the host supplies to DecodePacket.
	MaxAddressSize(direction Direction) int
	// Destroy releases the instance, under the same rule as
	// StreamEngine.Destroy.
	Destroy()
}

// OutputHinter is the optional half of StreamEngine: an engine that implements
// it gets to say how big a buffer it wants for a pull and how many pulls of
// that size the host should make in a row. Both are advisory and clamped, so a
// wild hint costs efficiency rather than memory.
type OutputHinter interface {
	SuggestOutputSize(side Side) int
	SuggestOutputBatch(side Side) int
}

// instance is what a plugin instance pointer resolves to.
//
// It carries no lock: the ABI promises the host never makes two calls on one
// instance at once, and get_last_error is one of those calls. An engine with
// goroutines of its own still has to lock its own state, which is what
// ConnEngine does.
type instance struct {
	host    Host
	stream  StreamEngine
	dgram   DatagramEngine
	errCode Status
	errText string
}

func (i *instance) setError(status Status, message string) Status {
	i.errCode = status
	i.errText = message
	return status
}

func (i *instance) clearError() {
	i.errCode = StatusOK
	i.errText = ""
}

// fail records err against the instance and returns the status to report.
func (i *instance) fail(err error) C.leaf_engine_status_t {
	status := statusOf(err)
	i.setError(status, err.Error())
	return C.leaf_engine_status_t(status)
}

// createError holds the reason a create_instance call returned nil.
//
// There is no instance to ask at that point, so the host calls get_last_error
// with a null instance and this is what answers. One slot per engine kind: the
// host asks immediately after the failure, and two concurrent creates failing
// at once can only cost the more precise of two true messages.
type createError struct {
	mu     sync.Mutex
	status Status
	text   string
}

func (c *createError) set(status Status, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.text = status, text
}

func (c *createError) clear() { c.set(StatusOK, "") }

func (c *createError) get() (Status, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.text
}

var (
	streamCreateError   createError
	datagramCreateError createError
)

// allocInstance boxes a cgo handle in a word of C memory. A cgo.Handle is an
// integer, not a pointer, so it cannot be handed to the host as one directly.
func allocInstance(i *instance) unsafe.Pointer {
	handle := cgo.NewHandle(i)
	mem := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	if mem == nil {
		handle.Delete()
		return nil
	}
	*(*uintptr)(mem) = uintptr(handle)
	return mem
}

func loadInstance(p unsafe.Pointer) (*instance, cgo.Handle, bool) {
	if p == nil {
		return nil, 0, false
	}
	handle := cgo.Handle(*(*uintptr)(p))
	value, ok := handle.Value().(*instance)
	if !ok || value == nil {
		return nil, handle, false
	}
	return value, handle, true
}

func freeInstance(p unsafe.Pointer, handle cgo.Handle, ok bool) {
	if ok {
		handle.Delete()
	}
	if p != nil {
		C.free(p)
	}
}

// hostBytes views a buffer the host owns. The slice is valid only for the call
// it was made in, which is why every engine method is documented to copy what
// it keeps.
func hostBytes(ptr *C.uint8_t, n C.size_t) []byte {
	if ptr == nil || n == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(n))
}

func createArgsFrom(args *C.EngineCreateArgs) (CreateArgs, error) {
	if args == nil {
		return CreateArgs{}, Errorf(StatusInvalidArgument, "missing create args")
	}
	if uintptr(args.size) < uintptr(C.LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE) {
		return CreateArgs{}, Errorf(
			StatusInvalidArgument,
			"engine create args are %d bytes, need at least %d",
			uintptr(args.size), uintptr(C.LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE),
		)
	}
	out := CreateArgs{
		Host:         hostFromCallbacks(args.host_callbacks),
		HostABIMajor: uint32(args.host_abi_major),
		HostABIMinor: uint32(args.host_abi_minor),
	}
	if args.plugin_args != nil {
		out.Args = C.GoString(args.plugin_args)
	}
	destination, err := addressFromC(args.destination)
	if err != nil {
		return CreateArgs{}, err
	}
	out.Destination = destination
	return out, nil
}

func outputSizeHint(engine StreamEngine, side Side) int {
	if hinter, ok := engine.(OutputHinter); ok {
		return hinter.SuggestOutputSize(side)
	}
	switch side {
	case SideApp:
		return defaultAppOutputSize
	case SideNet:
		return defaultNetOutputSize
	default:
		return fallbackOutputSize
	}
}

func outputBatchHint(engine StreamEngine, side Side) int {
	if hinter, ok := engine.(OutputHinter); ok {
		return hinter.SuggestOutputBatch(side)
	}
	return defaultOutputBatch
}
