package leafabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
#include <stdlib.h>
#include "abi.h"
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// logTarget is the target every message from this plugin is filed under. Set
// once, from leafabi_prepare_descriptor, before any engine exists.
var logTarget *C.char

// staticCString copies s into memory that is never freed.
//
// The ABI requires the descriptor's strings to stay valid for as long as the
// library is loaded, and the log target is handed to the host on every call, so
// neither may be owned by the Go heap or by anything with a shorter life.
func staticCString(s string) *C.char {
	return C.CString(s)
}

// hostState holds the callbacks one engine instance may use, and the flag that
// takes them away again.
//
// The ABI keeps host_ctx and the two function pointers valid only until
// destroy_instance returns. An engine with goroutines of its own is supposed to
// join them first, but a plugin that gets that wrong would be calling into
// memory the host has reclaimed. Revoking here turns that mistake into a
// dropped log line.
type hostState struct {
	mu      sync.RWMutex
	revoked bool
	log     C.leaf_host_log_fn
	wake    C.leaf_host_wake_fn
	ctx     unsafe.Pointer
}

// Host is what an engine uses to talk back to leaf. The zero value is valid and
// does nothing, which is what a plugin's own tests get.
type Host struct {
	s *hostState
}

// Log writes one message into the host's log.
//
// It is safe to call from any goroutine, and safe to call after the instance
// has been destroyed -- it does nothing then.
func (h Host) Log(level Level, message string) {
	if h.s == nil {
		return
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	if h.s.revoked || h.s.log == nil {
		return
	}
	buf := []byte(message)
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	}
	C.leafabi_host_log(
		h.s.log,
		h.s.ctx,
		C.leaf_log_level_t(level),
		logTarget,
		ptr,
		C.size_t(len(buf)),
	)
}

// Logf is Log with formatting.
func (h Host) Logf(level Level, format string, args ...any) {
	if h.s == nil {
		return
	}
	// Checked before formatting: a trace message the host would drop should
	// not cost an allocation.
	h.s.mu.RLock()
	live := !h.s.revoked && h.s.log != nil
	h.s.mu.RUnlock()
	if !live {
		return
	}
	h.Log(level, fmt.Sprintf(format, args...))
}

// Wake tells the host that an engine which reported StateBlocked can make
// progress again.
//
// It is safe to call from any goroutine, from inside another engine method, and
// when the host is not actually waiting. It does nothing once the instance has
// been destroyed.
func (h Host) Wake() {
	if h.s == nil {
		return
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	if h.s.revoked || h.s.wake == nil {
		return
	}
	C.leafabi_host_wake(h.s.wake, h.s.ctx)
}

// CanWake reports whether this host offered a wake callback. An engine that
// cannot wake the host must never report StateBlocked; the SDK masks the flag
// off in that case, but an engine is better off not entering a state it cannot
// leave.
func (h Host) CanWake() bool {
	if h.s == nil {
		return false
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	return !h.s.revoked && h.s.wake != nil
}

// revoke stops every later callback. Called once destroy_instance has taken the
// engine down, which is the last moment the pointers are guaranteed valid.
func (h Host) revoke() {
	if h.s == nil {
		return
	}
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.s.revoked = true
}

// hostFromCallbacks copies the callbacks out of the create arguments. The
// struct is borrowed only for the create call, so nothing may point into it
// afterwards.
func hostFromCallbacks(callbacks *C.HostCallbacks) Host {
	state := &hostState{}
	if callbacks != nil && uintptr(callbacks.size) >= uintptr(C.LEAF_HOST_CALLBACKS_REQUIRED_SIZE) {
		state.log = callbacks.log
		state.wake = callbacks.wake
		state.ctx = callbacks.host_ctx
	}
	return Host{s: state}
}
