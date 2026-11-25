package leafabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
#include <stdint.h>
#include <unistd.h>
#include "abi.h"

// Callbacks for the SDK's own tests, which cannot define C functions: cgo is
// not available in _test.go files. They take a moment, so the collector that
// runs beside the test overlaps them.
static void leafabi_test_wake(void* host_ctx) {
    (void)host_ctx;
    usleep(1);
}

static void leafabi_test_log(
    void* host_ctx,
    leaf_log_level_t level,
    const char* target,
    const uint8_t* message,
    size_t message_len) {
    (void)host_ctx; (void)level; (void)target; (void)message; (void)message_len;
    usleep(1);
}

static HostCallbacks leafabi_test_callbacks(uintptr_t host_ctx) {
    HostCallbacks callbacks;
    callbacks.size = sizeof(HostCallbacks);
    callbacks.log = leafabi_test_log;
    callbacks.wake = leafabi_test_wake;
    callbacks.host_ctx = (void*)host_ctx;
    return callbacks;
}
*/
import "C"

// testHost is a Host whose callbacks are real C functions and whose host_ctx
// is the given value. leaf passes an instance number there, not an address;
// the ABI says the value is the host's own business.
func testHost(hostCtx uintptr) Host {
	callbacks := C.leafabi_test_callbacks(C.uintptr_t(hostCtx))
	return hostFromCallbacks(&callbacks)
}
