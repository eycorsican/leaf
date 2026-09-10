/*
 * The C surface of the Go SDK: the entry points cgo exports from Go, and the
 * few helpers Go calls back into.
 *
 * A plugin never includes this. It exists so that descriptor.c can build the
 * static vtables the host reads, and so that every .go file in this package can
 * share one set of declarations -- a file carrying //export may only contribute
 * declarations to the preamble, never definitions.
 */

#ifndef LEAF_ABI_GO_H
#define LEAF_ABI_GO_H

#include <leaf_plugin_abi.h>

/* Exported from Go by export.go. The ABI passes several buffers as `const`,
 * which cgo cannot express in an exported signature, so descriptor.c wraps
 * these in shims that cast the constness away and never write through them. */
extern void* leafabi_stream_create(EngineCreateArgs* args);
extern void leafabi_stream_destroy(void* instance);
extern leaf_engine_status_t leafabi_stream_poll_state(
    void* instance,
    leaf_stream_state_flags_t* state_flags);
extern leaf_engine_status_t leafabi_stream_push(
    void* instance,
    leaf_stream_side_t side,
    uint8_t* input,
    size_t input_len,
    size_t* consumed);
extern leaf_engine_status_t leafabi_stream_pull(
    void* instance,
    leaf_stream_side_t side,
    uint8_t* output,
    size_t output_cap,
    size_t* produced);
extern leaf_engine_status_t leafabi_stream_close(
    void* instance,
    leaf_stream_close_flags_t close_flags);
extern leaf_engine_status_t leafabi_stream_last_error(
    void* instance,
    leaf_engine_status_t* code,
    uint8_t* output,
    size_t output_cap,
    size_t* written);
extern size_t leafabi_stream_output_size(void* instance, leaf_stream_side_t side);
extern size_t leafabi_stream_output_batch(void* instance, leaf_stream_side_t side);

extern void* leafabi_datagram_create(EngineCreateArgs* args);
extern void leafabi_datagram_destroy(void* instance);
extern leaf_engine_status_t leafabi_datagram_encode(
    void* instance,
    uint8_t* payload,
    size_t payload_len,
    PluginAddress* target,
    uint8_t* output,
    size_t output_cap,
    size_t* produced);
extern leaf_engine_status_t leafabi_datagram_decode(
    void* instance,
    uint8_t* input,
    size_t input_len,
    size_t* consumed,
    uint8_t* payload_out,
    size_t payload_cap,
    size_t* payload_len,
    PluginAddress* address_out);
extern size_t leafabi_datagram_max_output_size(
    void* instance,
    size_t input_len,
    leaf_datagram_direction_t direction);
extern size_t leafabi_datagram_max_address_size(
    void* instance,
    leaf_datagram_direction_t direction);
extern leaf_engine_status_t leafabi_datagram_last_error(
    void* instance,
    leaf_engine_status_t* code,
    uint8_t* output,
    size_t output_cap,
    size_t* written);

/* Called from Go, once, from the plugin's init. It fills the descriptor in and
 * releases leaf_plugin_get_descriptor, which waits for it.
 *
 * The direction matters. Go calling out to C costs nothing; C calling into Go
 * binds the calling thread to the Go runtime for good, and a thread bound that
 * way can never exit -- it parks forever in its own TLS destructor. The thread
 * that loads a plugin belongs to the host and may well be a short-lived one
 * from a blocking pool, so nothing here may drag it into Go.
 *
 * `name` and `version` must outlive the library, so Go hands over strings it
 * never frees. A NULL vtable is how a plugin says it has no engine of that
 * kind. */
void leafabi_descriptor_configure(
    const char* name,
    const char* version,
    int has_stream,
    leaf_stream_connect_type_t connect_type,
    int has_datagram,
    leaf_datagram_transport_type_t transport_type);

/* Calling a host callback through a Go function pointer variable is not
 * something cgo will do directly, and a NULL check belongs on this side of the
 * boundary anyway. */
void leafabi_host_log(
    leaf_host_log_fn fn,
    void* host_ctx,
    leaf_log_level_t level,
    const char* target,
    const uint8_t* message,
    size_t message_len);
void leafabi_host_wake(leaf_host_wake_fn fn, void* host_ctx);

#endif /* LEAF_ABI_GO_H */
