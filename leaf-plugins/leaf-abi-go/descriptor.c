/*
 * The descriptor and the two vtables the host reads, plus the shims that let
 * cgo-exported Go functions sit in them.
 *
 * The ABI wants a descriptor that is static and immutable for as long as the
 * library is loaded. These structures are static; what is not known at compile
 * time -- the plugin's name, which engines it has -- is filled in once by
 * leafabi_descriptor_configure, which the plugin's Go init calls.
 *
 * That leaves one thing to arrange. With -buildmode=c-shared the Go runtime
 * starts on a thread of its own and dlopen returns without waiting for it, so
 * the host can ask for the descriptor before any Go code has run. The obvious
 * fix -- calling into Go from leaf_plugin_get_descriptor to force the wait --
 * is the one thing that must not happen: a thread that enters Go is bound to
 * the Go runtime from then on and can never exit, it parks forever in its own
 * TLS destructor, and the thread that loads a plugin belongs to the host. A
 * host that loads its configuration on a pooled thread would then hang on
 * shutdown, waiting to join a thread that cannot finish.
 *
 * So the wait goes the other way round: this file waits for Go rather than
 * calling it. leaf_plugin_get_descriptor spins on a flag that Go sets from its
 * own thread, which costs the loading thread a few milliseconds once and binds
 * nothing.
 */

#include "abi.h"

#include <stdatomic.h>
#include <stddef.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

/* cgo cannot export a Go function whose parameter is a `const` pointer, so
 * every ABI entry that takes one goes through a shim. None of them writes
 * through the pointer it casts. */

static void* stream_create_shim(const EngineCreateArgs* args) {
    return leafabi_stream_create((EngineCreateArgs*)args);
}

static leaf_engine_status_t stream_push_shim(
    void* instance,
    leaf_stream_side_t side,
    const uint8_t* input,
    size_t input_len,
    size_t* consumed) {
    return leafabi_stream_push(instance, side, (uint8_t*)input, input_len, consumed);
}

static void* datagram_create_shim(const EngineCreateArgs* args) {
    return leafabi_datagram_create((EngineCreateArgs*)args);
}

static leaf_engine_status_t datagram_encode_shim(
    void* instance,
    const uint8_t* payload,
    size_t payload_len,
    const PluginAddress* target,
    uint8_t* output,
    size_t output_cap,
    size_t* produced) {
    return leafabi_datagram_encode(
        instance,
        (uint8_t*)payload,
        payload_len,
        (PluginAddress*)target,
        output,
        output_cap,
        produced);
}

static leaf_engine_status_t datagram_decode_shim(
    void* instance,
    const uint8_t* input,
    size_t input_len,
    size_t* consumed,
    uint8_t* payload_out,
    size_t payload_cap,
    size_t* payload_len,
    PluginAddress* address_out) {
    return leafabi_datagram_decode(
        instance,
        (uint8_t*)input,
        input_len,
        consumed,
        payload_out,
        payload_cap,
        payload_len,
        address_out);
}

static StreamEnginePlugin STREAM_ENGINE = {
    .size = sizeof(StreamEnginePlugin),
    /* Replaced by leafabi_descriptor_configure; never left at zero, which the
     * host rejects as an invalid connect_type. */
    .connect_type = LEAF_STREAM_CONNECT_TYPE_PROXY_TCP,
    .create_instance = stream_create_shim,
    .destroy_instance = leafabi_stream_destroy,
    .poll_state = leafabi_stream_poll_state,
    .push = stream_push_shim,
    .pull = leafabi_stream_pull,
    .close = leafabi_stream_close,
    .get_last_error = leafabi_stream_last_error,
    .suggest_output_size = leafabi_stream_output_size,
    .suggest_output_batch = leafabi_stream_output_batch,
};

static DatagramEnginePlugin DATAGRAM_ENGINE = {
    .size = sizeof(DatagramEnginePlugin),
    .transport_type = LEAF_DATAGRAM_TRANSPORT_TYPE_RELIABLE,
    .create_instance = datagram_create_shim,
    .destroy_instance = leafabi_datagram_destroy,
    .encode_packet = datagram_encode_shim,
    .decode_packet = datagram_decode_shim,
    .max_output_size = leafabi_datagram_max_output_size,
    .max_address_size = leafabi_datagram_max_address_size,
    .get_last_error = leafabi_datagram_last_error,
};

/* Set by leafabi_descriptor_configure once the descriptor is complete. */
static atomic_int CONFIGURED;

/* How long leaf_plugin_get_descriptor waits for the Go runtime to come up. A
 * runtime that has not started by then is not going to, and a descriptor with a
 * null name is what the host refuses, by name. */
#define CONFIGURE_TIMEOUT_MS 10000

static void sleep_a_millisecond(void) {
#if defined(_WIN32)
    Sleep(1);
#else
    struct timespec interval = {0, 1000000};
    nanosleep(&interval, NULL);
#endif
}

static PluginDescriptor DESCRIPTOR = {
    .size = sizeof(PluginDescriptor),
    .abi_major = LEAF_PLUGIN_ABI_MAJOR,
    .abi_minor = LEAF_PLUGIN_ABI_MINOR,
    .name = NULL,
    .version = NULL,
    .stream = NULL,
    .datagram = NULL,
    /* Unconditional, and set here rather than left to each plugin: every
     * library this SDK builds is -buildmode=c-shared and therefore carries the
     * Go runtime, whose threads outlive anything the host can hold the library
     * for. Without it the host unmaps the library when the last handler goes
     * and those threads fault on code that is no longer there -- at once on
     * Windows, where FreeLibrary really unmaps. The same reasoning as the
     * thread-pinning note at the top of this file, one step further on. */
    .flags = LEAF_PLUGIN_FLAG_EMBEDS_RUNTIME,
};

void leafabi_descriptor_configure(
    const char* name,
    const char* version,
    int has_stream,
    leaf_stream_connect_type_t connect_type,
    int has_datagram,
    leaf_datagram_transport_type_t transport_type) {
    DESCRIPTOR.name = name;
    DESCRIPTOR.version = version;
    if (has_stream) {
        STREAM_ENGINE.connect_type = connect_type;
        DESCRIPTOR.stream = &STREAM_ENGINE;
    } else {
        DESCRIPTOR.stream = NULL;
    }
    if (has_datagram) {
        DATAGRAM_ENGINE.transport_type = transport_type;
        DESCRIPTOR.datagram = &DATAGRAM_ENGINE;
    } else {
        DESCRIPTOR.datagram = NULL;
    }
    /* Released last, so a reader that sees it sees a finished descriptor. */
    atomic_store_explicit(&CONFIGURED, 1, memory_order_release);
}

void leafabi_host_log(
    leaf_host_log_fn fn,
    void* host_ctx,
    leaf_log_level_t level,
    const char* target,
    const uint8_t* message,
    size_t message_len) {
    if (fn != NULL) {
        fn(host_ctx, level, target, message, message_len);
    }
}

void leafabi_host_wake(leaf_host_wake_fn fn, void* host_ctx) {
    if (fn != NULL) {
        fn(host_ctx);
    }
}

LEAF_PLUGIN_EXPORT const PluginDescriptor* leaf_plugin_get_descriptor(void) {
    /* Safe to call concurrently, as the ABI requires, and pure after the first
     * call: everything it reports is written once, before the flag is set. */
    for (int waited = 0; waited < CONFIGURE_TIMEOUT_MS; waited++) {
        if (atomic_load_explicit(&CONFIGURED, memory_order_acquire)) {
            break;
        }
        sleep_a_millisecond();
    }
    return &DESCRIPTOR;
}
