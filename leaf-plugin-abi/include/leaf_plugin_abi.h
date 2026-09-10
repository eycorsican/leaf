/*
 * The C ABI shared between the leaf plugin host and out-of-tree plugins.
 *
 * This header is the canonical C declaration of the ABI. The Rust mirror lives
 * in leaf-plugin-abi/src/lib.rs and the two are checked against each other by
 * leaf-plugin-abi/tests/header_parity.rs. Do not copy this file into a plugin
 * tree; include it instead, e.g. from cgo:
 *
 *   #cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
 *
 * The full contract -- object lifetimes, threading and the ban on blocking --
 * is documented on the Rust mirror. In short:
 *
 *   - The descriptor, the vtables it points to and its strings are static and
 *     live as long as the library is loaded.
 *   - EngineCreateArgs, and the HostCallbacks struct it points to, are valid
 *     only for the create_instance call; copy what you need.
 *   - The host_ctx and the log/wake function pointers copied out of
 *     HostCallbacks stay valid until destroy_instance returns, so no call to
 *     them may be in flight, or start, once it has.
 *   - Every other buffer is valid only for the call it was passed to, and
 *     output buffers belong to the host.
 *   - The host makes no two calls on one instance at once, but successive
 *     calls may come from different threads. log and wake are re-entrant and
 *     callable from any thread; the host never calls back into the plugin
 *     from them.
 *   - Engine calls run on the host's async executor: return promptly, never
 *     sleep, do I/O or wait on another thread. Use
 *     LEAF_STREAM_ENGINE_STATE_BLOCKED and wake instead. Only
 *     destroy_instance may block, and only briefly.
 *   - Never panic, abort or unwind across the boundary; return a status code.
 */

#ifndef LEAF_PLUGIN_ABI_H
#define LEAF_PLUGIN_ABI_H

#include <stdint.h>
#include <stddef.h>

/* A host loads a plugin only when the major versions match exactly; every
 * breaking change bumps LEAF_PLUGIN_ABI_MAJOR. Minor versions are additive and
 * never participate in the compatibility decision -- a peer discovers which
 * trailing fields exist from each struct's `size` field, not from this number. */
#define LEAF_PLUGIN_ABI_MAJOR 2
/* 1 added PluginDescriptor::flags. */
#define LEAF_PLUGIN_ABI_MINOR 1
/* Status codes. Every entry that returns leaf_engine_status_t returns OK or one
 * of the negative values, with detail left for get_last_error.
 *
 *   INVALID_ARGUMENT   -- a side, address kind or similar the engine does not
 *                         implement; the host treats it as fatal.
 *   BUFFER_TOO_SMALL   -- the output buffer was too small. The engine must have
 *                         consumed nothing, so the host can grow the buffer and
 *                         retry the same input; it does so a bounded number of
 *                         times before giving up on the engine.
 *   UNSUPPORTED        -- not implemented at all; retrying cannot help.
 *   PLUGIN_FAILURE     -- the engine failed for its own reasons. The host turns
 *                         it into an I/O error and tears the connection down. */
#define LEAF_ENGINE_STATUS_OK 0
#define LEAF_ENGINE_STATUS_INVALID_ARGUMENT -1
#define LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL -2
#define LEAF_ENGINE_STATUS_UNSUPPORTED -3
#define LEAF_ENGINE_STATUS_PLUGIN_FAILURE -4
/* Levels for leaf_host_log_fn. They mirror the host's own levels, so a message
 * logged above the level the host is configured for is dropped. */
#define LEAF_LOG_LEVEL_ERROR 1
#define LEAF_LOG_LEVEL_WARN 2
#define LEAF_LOG_LEVEL_INFO 3
#define LEAF_LOG_LEVEL_DEBUG 4
#define LEAF_LOG_LEVEL_TRACE 5
/* How to read PluginAddress.data: the four octets of an IPv4 address, the
 * sixteen octets of an IPv6 address, or a domain name as UTF-8 without a
 * trailing NUL, which the host rejects if empty. PluginAddress.port is a plain
 * uint16_t in host byte order for all three. */
#define LEAF_ADDRESS_KIND_IPV4 1
#define LEAF_ADDRESS_KIND_IPV6 2
#define LEAF_ADDRESS_KIND_DOMAIN 3
/* Which direction a datagram size hint is about, or is being performed:
 * ENCODE is encode_packet, DECODE is decode_packet. */
#define LEAF_DATAGRAM_DIRECTION_ENCODE 1
#define LEAF_DATAGRAM_DIRECTION_DECODE 2
/* What the host carries a datagram engine's frames over. RELIABLE puts it on
 * top of the stream transport the chain already established, and the engine
 * frames each datagram itself -- which is why decode_packet has `consumed`.
 * UNRELIABLE gets one whole frame per call in each direction. Either way the
 * outbound's host/port settings are required. */
#define LEAF_DATAGRAM_TRANSPORT_TYPE_RELIABLE 1
#define LEAF_DATAGRAM_TRANSPORT_TYPE_UNRELIABLE 2
/* What stream the host hands a stream engine. PROXY_TCP is a TCP connection to
 * the host/port in the outbound's settings, which must be configured; DIRECT is
 * a connection straight to the session's destination; NEXT is whatever the
 * previous outbound in the chain produced, as a TLS engine wants. DIRECT and
 * NEXT require that no host/port be configured. */
#define LEAF_STREAM_CONNECT_TYPE_PROXY_TCP 1
#define LEAF_STREAM_CONNECT_TYPE_DIRECT 2
#define LEAF_STREAM_CONNECT_TYPE_NEXT 3
/* The two sides of a stream engine: APP is the plaintext the proxy carries, NET
 * is the encoded bytes on the socket. */
#define LEAF_STREAM_SIDE_APP 1
#define LEAF_STREAM_SIDE_NET 2
/* State flags reported by poll_state.
 *
 *   WANT_APP_INPUT  -- room for more application input. Advisory; a short
 *                      `consumed` from push is the authoritative signal.
 *   WANT_NET_INPUT  -- waiting on bytes from the peer. This, not BLOCKED, is
 *                      what an engine reports while it waits for the other end.
 *   HAS_APP_OUTPUT  -- decoded bytes are ready to pull for the application. A
 *                      pull that then produces nothing is believed over the
 *                      flag.
 *   HAS_NET_OUTPUT  -- bytes are ready to pull for the socket. Set it during a
 *                      handshake too: the host keeps this side moving even
 *                      while the application is only reading.
 *   HANDSHAKING     -- informational; the handshake is not finished.
 *   ESTABLISHED     -- informational; application data is flowing.
 *   PEER_CLOSED     -- the peer closed. Once the engine has no application
 *                      output left, the host reports end of stream.
 *   FATAL           -- the engine is unusable and the host fails the
 *                      connection, whatever the call that reported it
 *                      returned. */
#define LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT (1U << 0)
#define LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT (1U << 1)
#define LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT (1U << 2)
#define LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT (1U << 3)
#define LEAF_STREAM_ENGINE_STATE_HANDSHAKING (1U << 4)
#define LEAF_STREAM_ENGINE_STATE_ESTABLISHED (1U << 5)
#define LEAF_STREAM_ENGINE_STATE_PEER_CLOSED (1U << 6)
#define LEAF_STREAM_ENGINE_STATE_FATAL (1U << 7)
/* The engine cannot make progress from anything the host can hand it right now
 * and will call leaf_host_wake_fn once that changes. An engine merely waiting
 * for the peer reports LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT instead. */
#define LEAF_STREAM_ENGINE_STATE_BLOCKED (1U << 8)
/* Passed to close: APP means the application has finished writing, so the
 * engine should emit whatever its protocol uses to say so; NET means the socket
 * reached end of file and nothing more will arrive from the peer. */
#define LEAF_STREAM_ENGINE_CLOSE_APP (1U << 0)
#define LEAF_STREAM_ENGINE_CLOSE_NET (1U << 1)

#if defined(_WIN32)
#define LEAF_PLUGIN_EXPORT __declspec(dllexport)
#else
#define LEAF_PLUGIN_EXPORT
#endif

typedef int32_t leaf_engine_status_t;
typedef uint32_t leaf_log_level_t;
typedef uint16_t leaf_address_kind_t;
typedef uint32_t leaf_datagram_direction_t;
typedef uint32_t leaf_datagram_transport_type_t;
typedef uint32_t leaf_stream_connect_type_t;
typedef uint32_t leaf_stream_side_t;
typedef uint32_t leaf_stream_state_flags_t;
typedef uint32_t leaf_stream_close_flags_t;
/* The get_last_error entry of both vtables writes the engine's own status code
 * through `code` and a UTF-8 message, without a trailing NUL, into `output`.
 * The host asks twice: once with a NULL `output` and an `output_cap` of 0, to
 * learn the length from `written`, and again with a buffer that size -- so the
 * message must survive being read twice. `instance` is NULL when
 * create_instance returned NULL and there is no instance to ask, so an engine
 * that wants to explain a failed creation must keep that message somewhere
 * reachable without one. A non-zero return means the engine has nothing to say
 * and the host falls back to the status code of the call that failed. */

typedef void (*leaf_host_log_fn)(
    void* host_ctx,
    leaf_log_level_t level,
    const char* target,
    const uint8_t* message,
    size_t message_len);
/* Called by an engine that reported LEAF_STREAM_ENGINE_STATE_BLOCKED once it
 * can make progress again. Callable from any thread at any time between
 * create_instance being entered and destroy_instance returning, including from
 * inside another engine call. The host never calls back into the plugin from
 * it, and a call made while the host is not waiting is harmless. */
typedef void (*leaf_host_wake_fn)(void* host_ctx);

typedef struct {
    size_t size;
    /* The host loads the plugin only if abi_major matches its own exactly;
     * abi_minor is informational. */
    uint32_t abi_major;
    uint32_t abi_minor;
    /* Name and version, for logs and diagnostics. */
    const char* name;
    const char* version;
    /* Either vtable may be NULL -- a UDP-only protocol has no stream engine to
     * export -- but a plugin that exports neither is rejected. One that exports
     * both makes an outbound carrying TCP through the stream engine and UDP
     * through the datagram one; one that exports a single engine makes an
     * outbound that only handles that kind of traffic. */
    const struct StreamEnginePlugin* stream;
    const struct DatagramEnginePlugin* datagram;
    /* Properties of the plugin as a library rather than of either engine; see
     * LEAF_PLUGIN_FLAG_* below. Added in minor 1: a plugin built against minor
     * 0 does not provide this field and the host reads it back as zero, which
     * is what a plugin with nothing to declare would have written anyway. Bits
     * the host does not know are ignored. */
    uint64_t flags;
} PluginDescriptor;

/* This plugin embeds a language runtime and must never be unmapped. A Go
 * c-shared build is the standard case: the threads such a runtime starts are
 * not something the host can hold a reference to, and they go on running code
 * in the library after everything the host does hold has gone. A host that
 * honours this keeps the library mapped for the life of the process. */
#define LEAF_PLUGIN_FLAG_EMBEDS_RUNTIME ((uint64_t)1 << 0)

typedef struct {
    size_t size;
    leaf_host_log_fn log;
    /* May be NULL, in which case an engine must not report
     * LEAF_STREAM_ENGINE_STATE_BLOCKED: there would be no way to un-block it. */
    leaf_host_wake_fn wake;
    void* host_ctx;
} HostCallbacks;

typedef struct {
    /* One of LEAF_ADDRESS_KIND_*, which says how to read `data`. `port` is in
     * host byte order. */
    leaf_address_kind_t kind;
    uint16_t port;
    const uint8_t* data;
    size_t data_len;
} PluginAddress;

typedef struct EngineCreateArgs {
    size_t size;
    /* The outbound's `args` setting, verbatim and NUL-terminated. Its shape is
     * the plugin's own business -- the host never looks inside. */
    const char* plugin_args;
    /* Where the session is ultimately headed, which is what a protocol engine
     * encodes into its header. Not the server the host connected to. */
    const PluginAddress* destination;
    /* Never NULL, and borrowed only for this call. */
    const HostCallbacks* host_callbacks;
    /* The host's own ABI version, so a plugin built against a newer minor
     * version can tell what the host will actually understand. */
    uint32_t host_abi_major;
    uint32_t host_abi_minor;
} EngineCreateArgs;

/* A stream engine instance is a byte-stream codec with two sides, APP and NET.
 * The host owns all the I/O and drives the instance in a loop: read poll_state,
 * push what it asks for, pull what it offers, repeat. The engine never touches
 * a socket and never blocks. Every entry below is required -- the host refuses
 * to load a plugin that leaves one NULL. */
typedef struct StreamEnginePlugin {
    size_t size;
    /* One of LEAF_STREAM_CONNECT_TYPE_*, read once at load time, so it is a
     * property of the plugin rather than of an instance. */
    leaf_stream_connect_type_t connect_type;
    /* Returns NULL on failure, leaving the reason for get_last_error, which the
     * host then calls with a NULL instance. */
    void* (*create_instance)(const EngineCreateArgs* args);
    /* Must not return until no log or wake call the plugin makes can still be
     * in flight. The one entry that may block, and only briefly. */
    void (*destroy_instance)(void* instance);
    /* Reports what the engine wants next as a bitmask of
     * LEAF_STREAM_ENGINE_STATE_*. Called between every other operation, so it
     * must be cheap and must not itself advance the protocol. */
    leaf_engine_status_t (*poll_state)(
        void* instance,
        leaf_stream_state_flags_t* state_flags);
    /* Takes input for one side and reports how much through `consumed`. A short
     * or zero `consumed` is backpressure, not failure: the host keeps the rest
     * and offers it again. `consumed` must never exceed input_len. */
    leaf_engine_status_t (*push)(
        void* instance,
        leaf_stream_side_t side,
        const uint8_t* input,
        size_t input_len,
        size_t* consumed);
    /* Writes output for one side and reports how much through `produced`. Zero
     * means nothing more is available right now, even if poll_state advertised
     * output; filling the buffer invites the host to call again. `produced`
     * must never exceed output_cap. */
    leaf_engine_status_t (*pull)(
        void* instance,
        leaf_stream_side_t side,
        uint8_t* output,
        size_t output_cap,
        size_t* produced);
    /* Tells the engine one or both sides are finished, as a bitmask of
     * LEAF_STREAM_ENGINE_CLOSE_*. The engine may still have output afterwards,
     * such as a close notify record, and the host still drains it. */
    leaf_engine_status_t (*close)(void* instance, leaf_stream_close_flags_t close_flags);
    leaf_engine_status_t (*get_last_error)(
        void* instance,
        leaf_engine_status_t* code,
        uint8_t* output,
        size_t output_cap,
        size_t* written);
    /* How big a buffer the engine wants for a pull on this side, and how many
     * pulls of that size the host should make in a row before going back to the
     * socket. Both are advisory and clamped by the host, so a wild hint costs
     * efficiency rather than memory. */
    size_t (*suggest_output_size)(void* instance, leaf_stream_side_t side);
    size_t (*suggest_output_batch)(void* instance, leaf_stream_side_t side);
} StreamEnginePlugin;

/* A datagram engine instance is a packet codec: one datagram and its address in,
 * wire bytes out, and back. As with the stream vtable the host owns the
 * transport, and every entry below is required for the plugin to load. */
typedef struct DatagramEnginePlugin {
    size_t size;
    /* One of LEAF_DATAGRAM_TRANSPORT_TYPE_*, read once at load time. */
    leaf_datagram_transport_type_t transport_type;
    /* Both behave as their stream vtable counterparts do. */
    void* (*create_instance)(const EngineCreateArgs* args);
    void (*destroy_instance)(void* instance);
    /* Encodes one datagram for `target`, reporting the length through
     * `produced`, which must never exceed output_cap. Returning
     * LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL makes the host grow the buffer and
     * retry the same datagram, so a conservative max_output_size costs an extra
     * call rather than the packet. */
    leaf_engine_status_t (*encode_packet)(
        void* instance,
        const uint8_t* payload,
        size_t payload_len,
        const PluginAddress* target,
        uint8_t* output,
        size_t output_cap,
        size_t* produced);
    /* Decodes at most one datagram out of `input`.
     *
     * Reliable transports carry framed datagrams over a byte stream, so a
     * single read can hand the engine a partial frame or several frames at
     * once. `consumed` is how the engine reports which of those happened:
     *
     *   consumed == 0 && payload_len == 0 -- incomplete frame; the host reads
     *     more bytes and calls again with the frame still at the front.
     *   consumed > 0 && payload_len == 0 -- a frame carrying no datagram, such
     *     as a keepalive, was consumed; the host drops it and calls again.
     *   consumed > 0 && payload_len > 0 -- one datagram was decoded.
     *
     * `consumed` must never exceed `input_len`. On
     * LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL the engine must consume nothing, so
     * the host can retry the same input with a larger output buffer.
     *
     * Unreliable transports get one whole frame per call and consume all of
     * it. */
    leaf_engine_status_t (*decode_packet)(
        void* instance,
        const uint8_t* input,
        size_t input_len,
        size_t* consumed,
        uint8_t* payload_out,
        size_t payload_cap,
        size_t* payload_len,
        PluginAddress* address_out);
    /* The buffer size the engine wants for an input of input_len bytes in that
     * direction, and the largest address it can write into the PluginAddress
     * buffer the host supplies to decode_packet. Both advisory and clamped; the
     * host grows the output buffer anyway on
     * LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL. */
    size_t (*max_output_size)(void* instance, size_t input_len, leaf_datagram_direction_t direction);
    size_t (*max_address_size)(void* instance, leaf_datagram_direction_t direction);
    leaf_engine_status_t (*get_last_error)(
        void* instance,
        leaf_engine_status_t* code,
        uint8_t* output,
        size_t output_cap,
        size_t* written);
} DatagramEnginePlugin;

/* The prefix every conforming peer must provide, frozen for the lifetime of
 * LEAF_PLUGIN_ABI_MAJOR. Appending a field must not change these. */
#define LEAF_REQUIRED_SIZE(type, last_field) \
    (offsetof(type, last_field) + sizeof(((type*)0)->last_field))

#define LEAF_PLUGIN_DESCRIPTOR_REQUIRED_SIZE \
    LEAF_REQUIRED_SIZE(PluginDescriptor, datagram)
#define LEAF_HOST_CALLBACKS_REQUIRED_SIZE \
    LEAF_REQUIRED_SIZE(HostCallbacks, host_ctx)
#define LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE \
    LEAF_REQUIRED_SIZE(EngineCreateArgs, host_abi_minor)
#define LEAF_STREAM_ENGINE_PLUGIN_REQUIRED_SIZE \
    LEAF_REQUIRED_SIZE(StreamEnginePlugin, suggest_output_batch)
#define LEAF_DATAGRAM_ENGINE_PLUGIN_REQUIRED_SIZE \
    LEAF_REQUIRED_SIZE(DatagramEnginePlugin, get_last_error)

LEAF_PLUGIN_EXPORT const PluginDescriptor* leaf_plugin_get_descriptor(void);

#endif /* LEAF_PLUGIN_ABI_H */
