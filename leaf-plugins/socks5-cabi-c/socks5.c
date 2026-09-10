/*
 * A SOCKS5 outbound plugin for the leaf C ABI, written in plain C11.
 *
 * It is the reference for what a plugin looks like in a language with no
 * runtime of its own: there are no threads, no allocator tricks and no
 * dependencies beyond libc. The engine is a state machine over the buffers the
 * host supplies, which is exactly the shape the ABI was designed for -- every
 * call returns immediately, so LEAF_STREAM_ENGINE_STATE_BLOCKED and the wake
 * callback are never needed.
 *
 * It exports one stream engine with LEAF_STREAM_CONNECT_TYPE_PROXY_TCP: the
 * host connects a TCP socket to the host and port in the outbound's settings,
 * both of which must be configured, and this engine performs the SOCKS5
 * handshake over it and then carries the session transparently.
 *
 * args is empty for a server that wants no authentication, or
 * `username:password` for one that wants a username and a password. The
 * password may contain colons; the username may not.
 *
 * Build:
 *
 *   cc -std=c11 -O2 -fPIC -shared -I../../leaf-plugin-abi/include \
 *      -o libsocks5_cabi_c.so socks5.c
 */

#include <leaf_plugin_abi.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLUGIN_NAME "leaf-socks5-cabi-c-plugin"
#define PLUGIN_VERSION "0.1.0"
#define LOG_TARGET "leaf.plugin.socks5.c"

/* SOCKS5 wire constants, from RFC 1928 and RFC 1929. */
#define SOCKS_VERSION 0x05
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_RESERVED 0x00
#define SOCKS_METHOD_NONE 0x00
#define SOCKS_METHOD_USERPASS 0x02
#define SOCKS_METHOD_UNACCEPTABLE 0xff
#define SOCKS_AUTH_VERSION 0x01
#define SOCKS_ATYP_IPV4 0x01
#define SOCKS_ATYP_DOMAIN 0x03
#define SOCKS_ATYP_IPV6 0x04

#define APP_OUTPUT_SIZE_HINT (16 * 1024)
#define NET_OUTPUT_SIZE_HINT (16 * 1024)
#define OUTPUT_BATCH_HINT 4
#define MAX_DOMAIN_LEN 255
/* The longest SOCKS5 address: type, length, domain, port. */
#define MAX_ADDRESS_LEN (1 + 1 + MAX_DOMAIN_LEN + 2)
/* A username and a password are each at most 255 bytes, each with a length
 * byte, after the version. */
#define MAX_AUTH_LEN (1 + 1 + 255 + 1 + 255)
#define MAX_MESSAGE_LEN 256

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif

/* ------------------------------------------------------------------ buffers */

/* A byte queue that grows at the back and is consumed from the front.
 *
 * `start` is what makes consuming the front cheap; the region before it is
 * reclaimed on the next append rather than on every read, so a stream that is
 * being drained as fast as it arrives never moves its bytes twice. */
typedef struct {
    uint8_t* data;
    size_t start;
    size_t end;
    size_t cap;
} buffer;

static void buffer_free(buffer* b) {
    free(b->data);
    b->data = NULL;
    b->start = b->end = b->cap = 0;
}

static size_t buffer_len(const buffer* b) { return b->end - b->start; }

static const uint8_t* buffer_head(const buffer* b) {
    return b->data == NULL ? NULL : b->data + b->start;
}

/* Makes room for `extra` more bytes, reclaiming what has been consumed first.
 * Returns 0 when the allocation fails. */
static int buffer_reserve(buffer* b, size_t extra) {
    if (b->cap - b->end >= extra) {
        return 1;
    }
    size_t len = buffer_len(b);
    if (b->start > 0) {
        memmove(b->data, b->data + b->start, len);
        b->start = 0;
        b->end = len;
        if (b->cap - b->end >= extra) {
            return 1;
        }
    }
    size_t wanted = len + extra;
    size_t cap = b->cap == 0 ? 1024 : b->cap;
    while (cap < wanted) {
        if (cap > SIZE_MAX / 2) {
            return 0;
        }
        cap *= 2;
    }
    uint8_t* data = (uint8_t*)realloc(b->data, cap);
    if (data == NULL) {
        return 0;
    }
    b->data = data;
    b->cap = cap;
    return 1;
}

static int buffer_append(buffer* b, const uint8_t* bytes, size_t len) {
    if (len == 0) {
        return 1;
    }
    if (!buffer_reserve(b, len)) {
        return 0;
    }
    memcpy(b->data + b->end, bytes, len);
    b->end += len;
    return 1;
}

static int buffer_append_byte(buffer* b, uint8_t byte) { return buffer_append(b, &byte, 1); }

static void buffer_consume(buffer* b, size_t len) {
    if (len >= buffer_len(b)) {
        b->start = b->end = 0;
        return;
    }
    b->start += len;
}

/* Copies at most `cap` bytes out of the front and drops them. */
static size_t buffer_take(buffer* b, uint8_t* out, size_t cap) {
    size_t len = buffer_len(b);
    size_t take = len < cap ? len : cap;
    if (take > 0) {
        memcpy(out, buffer_head(b), take);
        buffer_consume(b, take);
    }
    return take;
}

/* ------------------------------------------------------------------- engine */

typedef enum {
    /* Waiting for the server to choose an authentication method. */
    PHASE_METHOD = 0,
    /* Waiting for the result of a username and password exchange. */
    PHASE_AUTH,
    /* Waiting for the reply to the CONNECT request. */
    PHASE_REPLY,
    /* The session is carried transparently from here on. */
    PHASE_ESTABLISHED,
    /* Something went wrong and the connection has to fail. */
    PHASE_FATAL
} phase;

typedef struct {
    leaf_host_log_fn log;
    void* host_ctx;

    phase phase;

    buffer net_in;
    buffer net_out;
    buffer app_out;

    /* The CONNECT request, built once at creation and sent as soon as the
     * server has accepted an authentication method. */
    uint8_t request[3 + MAX_ADDRESS_LEN];
    size_t request_len;

    /* The username and password exchange, empty when none is configured. */
    uint8_t auth[MAX_AUTH_LEN];
    size_t auth_len;

    int app_closed;
    int net_closed;
    int peer_closed;

    leaf_engine_status_t last_code;
    char last_message[MAX_MESSAGE_LEN];
} socks5_engine;

/* Where a failure that happened before there was an instance is kept. The host
 * asks for it with a null instance, on the thread that made the failed call. */
static THREAD_LOCAL leaf_engine_status_t create_error_code;
static THREAD_LOCAL char create_error_message[MAX_MESSAGE_LEN];

static void set_create_error(leaf_engine_status_t code, const char* message) {
    create_error_code = code;
    snprintf(create_error_message, sizeof(create_error_message), "%s", message);
}

static void clear_create_error(void) {
    create_error_code = LEAF_ENGINE_STATUS_OK;
    create_error_message[0] = '\0';
}

static void engine_log(const socks5_engine* engine, leaf_log_level_t level, const char* message) {
    if (engine == NULL || engine->log == NULL) {
        return;
    }
    engine->log(
        engine->host_ctx, level, LOG_TARGET, (const uint8_t*)message, strlen(message));
}

static leaf_engine_status_t set_error(
    socks5_engine* engine,
    leaf_engine_status_t code,
    const char* message) {
    engine->last_code = code;
    snprintf(engine->last_message, sizeof(engine->last_message), "%s", message);
    return code;
}

static void clear_error(socks5_engine* engine) {
    if (engine->phase == PHASE_FATAL) {
        /* A fatal engine's reason has to outlive the poll_state calls the host
         * makes between operations: it is the only explanation the log will
         * ever get for why the connection failed. */
        return;
    }
    engine->last_code = LEAF_ENGINE_STATUS_OK;
    engine->last_message[0] = '\0';
}

/* Puts the engine beyond use. The host fails the connection as soon as it sees
 * LEAF_STREAM_ENGINE_STATE_FATAL, whatever the call that reported it returned,
 * so this is how a protocol error ends a session. */
static leaf_engine_status_t mark_fatal(socks5_engine* engine, const char* message) {
    engine->phase = PHASE_FATAL;
    engine_log(engine, LEAF_LOG_LEVEL_ERROR, message);
    return set_error(engine, LEAF_ENGINE_STATUS_PLUGIN_FAILURE, message);
}

/* ------------------------------------------------------------------ framing */

/* Appends the SOCKS5 form of `address`: the type byte, the address, then the
 * port in network order. Returns 0 for an address SOCKS5 cannot carry. */
static int encode_address(uint8_t* out, size_t cap, const PluginAddress* address, size_t* written) {
    if (address == NULL || out == NULL) {
        return 0;
    }
    size_t len = 0;
    switch (address->kind) {
        case LEAF_ADDRESS_KIND_IPV4:
            if (address->data_len != 4 || cap < 1 + 4 + 2) {
                return 0;
            }
            out[len++] = SOCKS_ATYP_IPV4;
            memcpy(out + len, address->data, 4);
            len += 4;
            break;
        case LEAF_ADDRESS_KIND_IPV6:
            if (address->data_len != 16 || cap < 1 + 16 + 2) {
                return 0;
            }
            out[len++] = SOCKS_ATYP_IPV6;
            memcpy(out + len, address->data, 16);
            len += 16;
            break;
        case LEAF_ADDRESS_KIND_DOMAIN:
            if (address->data_len == 0 || address->data_len > MAX_DOMAIN_LEN) {
                return 0;
            }
            if (cap < 1 + 1 + address->data_len + 2) {
                return 0;
            }
            out[len++] = SOCKS_ATYP_DOMAIN;
            out[len++] = (uint8_t)address->data_len;
            memcpy(out + len, address->data, address->data_len);
            len += address->data_len;
            break;
        default:
            return 0;
    }
    out[len++] = (uint8_t)(address->port >> 8);
    out[len++] = (uint8_t)(address->port & 0xff);
    *written = len;
    return 1;
}

/* How many bytes the address at the front of `input` occupies.
 *
 * Returns 0 when the address is not all there yet -- an ordinary outcome on a
 * byte stream -- and -1 when the type byte is one SOCKS5 does not define. */
static long address_length(const uint8_t* input, size_t len) {
    if (len < 1) {
        return 0;
    }
    switch (input[0]) {
        case SOCKS_ATYP_IPV4:
            return len < 1 + 4 + 2 ? 0 : 1 + 4 + 2;
        case SOCKS_ATYP_IPV6:
            return len < 1 + 16 + 2 ? 0 : 1 + 16 + 2;
        case SOCKS_ATYP_DOMAIN: {
            if (len < 2) {
                return 0;
            }
            size_t total = 1 + 1 + (size_t)input[1] + 2;
            return len < total ? 0 : (long)total;
        }
        default:
            return -1;
    }
}

/* The greeting: the version, then the methods this client is willing to use. */
static int build_greeting(buffer* out, int with_userpass) {
    if (!buffer_append_byte(out, SOCKS_VERSION)) {
        return 0;
    }
    if (!with_userpass) {
        return buffer_append_byte(out, 1) && buffer_append_byte(out, SOCKS_METHOD_NONE);
    }
    /* Both are offered so that one configuration works against a server that
     * wants credentials and one that does not. */
    return buffer_append_byte(out, 2) && buffer_append_byte(out, SOCKS_METHOD_NONE) &&
           buffer_append_byte(out, SOCKS_METHOD_USERPASS);
}

/* The RFC 1929 username and password exchange. */
static int build_auth(
    uint8_t* out,
    size_t cap,
    const char* username,
    const char* password,
    size_t* written) {
    size_t user_len = strlen(username);
    size_t pass_len = strlen(password);
    if (user_len > 255 || pass_len > 255) {
        return 0;
    }
    size_t len = 1 + 1 + user_len + 1 + pass_len;
    if (cap < len) {
        return 0;
    }
    size_t at = 0;
    out[at++] = SOCKS_AUTH_VERSION;
    out[at++] = (uint8_t)user_len;
    memcpy(out + at, username, user_len);
    at += user_len;
    out[at++] = (uint8_t)pass_len;
    memcpy(out + at, password, pass_len);
    at += pass_len;
    *written = at;
    return 1;
}

/* What a non-zero reply code means, so a failure names itself in the log. */
static const char* reply_message(uint8_t code) {
    switch (code) {
        case 0x01: return "socks5 server reported a general failure";
        case 0x02: return "socks5 server refused the connection by policy";
        case 0x03: return "socks5 server reported the network as unreachable";
        case 0x04: return "socks5 server reported the host as unreachable";
        case 0x05: return "socks5 server reported the connection as refused";
        case 0x06: return "socks5 server reported the TTL as expired";
        case 0x07: return "socks5 server does not support this command";
        case 0x08: return "socks5 server does not support this address type";
        default: return "socks5 server refused the request";
    }
}

/* ----------------------------------------------------------- the state machine */

/* Drives the handshake as far as the bytes in hand allow.
 *
 * Every branch either consumes a complete message and moves on, or returns
 * having consumed nothing so that the host can read more. */
static void advance(socks5_engine* engine) {
    for (;;) {
        const uint8_t* input = buffer_head(&engine->net_in);
        size_t len = buffer_len(&engine->net_in);

        switch (engine->phase) {
            case PHASE_METHOD: {
                if (len < 2) {
                    return;
                }
                if (input[0] != SOCKS_VERSION) {
                    mark_fatal(engine, "socks5 server replied with a different version");
                    return;
                }
                uint8_t method = input[1];
                buffer_consume(&engine->net_in, 2);
                if (method == SOCKS_METHOD_NONE) {
                    if (!buffer_append(&engine->net_out, engine->request, engine->request_len)) {
                        mark_fatal(engine, "out of memory queueing the socks5 request");
                        return;
                    }
                    engine->phase = PHASE_REPLY;
                    break;
                }
                if (method == SOCKS_METHOD_USERPASS) {
                    if (engine->auth_len == 0) {
                        mark_fatal(engine, "socks5 server asked for credentials that are not configured");
                        return;
                    }
                    if (!buffer_append(&engine->net_out, engine->auth, engine->auth_len)) {
                        mark_fatal(engine, "out of memory queueing the socks5 credentials");
                        return;
                    }
                    engine->phase = PHASE_AUTH;
                    break;
                }
                mark_fatal(
                    engine,
                    method == SOCKS_METHOD_UNACCEPTABLE
                        ? "socks5 server accepted none of the offered authentication methods"
                        : "socks5 server chose an authentication method that was not offered");
                return;
            }

            case PHASE_AUTH: {
                if (len < 2) {
                    return;
                }
                if (input[0] != SOCKS_AUTH_VERSION) {
                    mark_fatal(engine, "socks5 server replied with an unknown authentication version");
                    return;
                }
                uint8_t status = input[1];
                buffer_consume(&engine->net_in, 2);
                if (status != 0) {
                    mark_fatal(engine, "socks5 server rejected the credentials");
                    return;
                }
                if (!buffer_append(&engine->net_out, engine->request, engine->request_len)) {
                    mark_fatal(engine, "out of memory queueing the socks5 request");
                    return;
                }
                engine->phase = PHASE_REPLY;
                break;
            }

            case PHASE_REPLY: {
                /* Version, reply, reserved, then a bound address whose length
                 * depends on its own type byte. */
                if (len < 4) {
                    return;
                }
                if (input[0] != SOCKS_VERSION) {
                    mark_fatal(engine, "socks5 reply carried a different version");
                    return;
                }
                long address_len = address_length(input + 3, len - 3);
                if (address_len < 0) {
                    mark_fatal(engine, "socks5 reply carried an unknown address type");
                    return;
                }
                if (address_len == 0) {
                    return;
                }
                if (input[1] != 0) {
                    mark_fatal(engine, reply_message(input[1]));
                    return;
                }
                buffer_consume(&engine->net_in, 3 + (size_t)address_len);
                engine->phase = PHASE_ESTABLISHED;
                engine_log(engine, LEAF_LOG_LEVEL_DEBUG, "socks5 handshake completed");
                break;
            }

            case PHASE_ESTABLISHED: {
                /* Everything from here is the session itself. */
                if (len == 0) {
                    return;
                }
                if (!buffer_append(&engine->app_out, input, len)) {
                    mark_fatal(engine, "out of memory buffering decoded output");
                    return;
                }
                buffer_consume(&engine->net_in, len);
                return;
            }

            case PHASE_FATAL:
                return;
        }
    }
}

/* --------------------------------------------------------------- ABI: stream */

/* Splits `username:password`. A password may contain colons; a username may
 * not, since the first colon is the separator. */
static int parse_args(const char* args, socks5_engine* engine) {
    if (args == NULL || args[0] == '\0') {
        engine->auth_len = 0;
        return 1;
    }
    const char* separator = strchr(args, ':');
    if (separator == NULL) {
        return 0;
    }
    size_t user_len = (size_t)(separator - args);
    if (user_len == 0 || user_len > 255) {
        return 0;
    }
    char username[256];
    memcpy(username, args, user_len);
    username[user_len] = '\0';
    return build_auth(engine->auth, sizeof(engine->auth), username, separator + 1, &engine->auth_len);
}

static void* create_instance(const EngineCreateArgs* args) {
    if (args == NULL || args->size < LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE) {
        set_create_error(LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "engine create args are too small");
        return NULL;
    }

    socks5_engine* engine = (socks5_engine*)calloc(1, sizeof(socks5_engine));
    if (engine == NULL) {
        set_create_error(LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "out of memory creating the engine");
        return NULL;
    }
    if (args->host_callbacks != NULL &&
        args->host_callbacks->size >= LEAF_HOST_CALLBACKS_REQUIRED_SIZE) {
        engine->log = args->host_callbacks->log;
        engine->host_ctx = args->host_callbacks->host_ctx;
    }

    if (!parse_args(args->plugin_args, engine)) {
        free(engine);
        set_create_error(
            LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
            "socks5 plugin args must be empty or `username:password`");
        return NULL;
    }

    size_t address_len = 0;
    if (!encode_address(
            engine->request + 3, sizeof(engine->request) - 3, args->destination, &address_len)) {
        free(engine);
        set_create_error(
            LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "the session destination is not a socks5 address");
        return NULL;
    }
    engine->request[0] = SOCKS_VERSION;
    engine->request[1] = SOCKS_CMD_CONNECT;
    engine->request[2] = SOCKS_RESERVED;
    engine->request_len = 3 + address_len;

    /* The greeting is queued now rather than on the first write: the host
     * drains the network side while the application is only reading, so this is
     * what gets the handshake started either way. */
    if (!build_greeting(&engine->net_out, engine->auth_len > 0)) {
        buffer_free(&engine->net_out);
        free(engine);
        set_create_error(LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "out of memory queueing the greeting");
        return NULL;
    }

    clear_create_error();
    engine_log(engine, LEAF_LOG_LEVEL_INFO, "created socks5 stream engine");
    return engine;
}

static void destroy_instance(void* instance) {
    socks5_engine* engine = (socks5_engine*)instance;
    if (engine == NULL) {
        return;
    }
    buffer_free(&engine->net_in);
    buffer_free(&engine->net_out);
    buffer_free(&engine->app_out);
    free(engine);
}

static leaf_engine_status_t poll_state(void* instance, leaf_stream_state_flags_t* state_flags) {
    socks5_engine* engine = (socks5_engine*)instance;
    if (engine == NULL || state_flags == NULL) {
        return LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    }

    leaf_stream_state_flags_t flags = 0;
    if (engine->phase == PHASE_FATAL) {
        flags |= LEAF_STREAM_ENGINE_STATE_FATAL;
    }
    if (engine->phase == PHASE_ESTABLISHED) {
        flags |= LEAF_STREAM_ENGINE_STATE_ESTABLISHED;
        if (!engine->app_closed) {
            flags |= LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT;
        }
    } else if (engine->phase != PHASE_FATAL) {
        /* Application input is refused until the server has accepted the
         * request, so this side is deliberately not advertised: nothing may go
         * out ahead of the reply. */
        flags |= LEAF_STREAM_ENGINE_STATE_HANDSHAKING;
    }
    if (!engine->net_closed) {
        flags |= LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT;
    }
    if (buffer_len(&engine->net_out) > 0) {
        flags |= LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT;
    }
    if (buffer_len(&engine->app_out) > 0) {
        flags |= LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT;
    }
    if (engine->peer_closed) {
        flags |= LEAF_STREAM_ENGINE_STATE_PEER_CLOSED;
    }
    *state_flags = flags;
    clear_error(engine);
    return LEAF_ENGINE_STATUS_OK;
}

static leaf_engine_status_t push(
    void* instance,
    leaf_stream_side_t side,
    const uint8_t* input,
    size_t input_len,
    size_t* consumed) {
    socks5_engine* engine = (socks5_engine*)instance;
    if (engine == NULL || consumed == NULL) {
        return LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    }
    *consumed = 0;
    if (input_len > 0 && input == NULL) {
        return set_error(
            engine, LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "push was given no input buffer");
    }
    if (engine->phase == PHASE_FATAL) {
        return LEAF_ENGINE_STATUS_PLUGIN_FAILURE;
    }

    switch (side) {
        case LEAF_STREAM_SIDE_APP:
            if (engine->app_closed) {
                return set_error(
                    engine,
                    LEAF_ENGINE_STATUS_PLUGIN_FAILURE,
                    "push(app) after the application side was closed");
            }
            if (engine->phase != PHASE_ESTABLISHED) {
                /* Consuming nothing is the backpressure signal: the host keeps
                 * the bytes and offers them again once the handshake, which it
                 * can still drive from the network side, has finished. */
                return LEAF_ENGINE_STATUS_OK;
            }
            if (!buffer_append(&engine->net_out, input, input_len)) {
                return mark_fatal(engine, "out of memory buffering application input");
            }
            break;

        case LEAF_STREAM_SIDE_NET:
            if (engine->net_closed) {
                return set_error(
                    engine,
                    LEAF_ENGINE_STATUS_PLUGIN_FAILURE,
                    "push(net) after the network side was closed");
            }
            if (!buffer_append(&engine->net_in, input, input_len)) {
                return mark_fatal(engine, "out of memory buffering network input");
            }
            advance(engine);
            if (engine->phase == PHASE_FATAL) {
                *consumed = input_len;
                return LEAF_ENGINE_STATUS_PLUGIN_FAILURE;
            }
            break;

        default:
            return set_error(
                engine, LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "invalid stream side for push");
    }

    *consumed = input_len;
    clear_error(engine);
    return LEAF_ENGINE_STATUS_OK;
}

static leaf_engine_status_t pull(
    void* instance,
    leaf_stream_side_t side,
    uint8_t* output,
    size_t output_cap,
    size_t* produced) {
    socks5_engine* engine = (socks5_engine*)instance;
    if (engine == NULL || produced == NULL) {
        return LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    }
    *produced = 0;
    if (output_cap > 0 && output == NULL) {
        return set_error(
            engine, LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "pull was given no output buffer");
    }

    buffer* source = NULL;
    switch (side) {
        case LEAF_STREAM_SIDE_APP: source = &engine->app_out; break;
        case LEAF_STREAM_SIDE_NET: source = &engine->net_out; break;
        default:
            return set_error(
                engine, LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "invalid stream side for pull");
    }
    /* Output the peer already sent outlives a failure: the host is entitled to
     * drain what is there before the error takes the connection down. */
    if (buffer_len(source) == 0 && engine->phase == PHASE_FATAL) {
        return LEAF_ENGINE_STATUS_PLUGIN_FAILURE;
    }
    *produced = buffer_take(source, output, output_cap);
    clear_error(engine);
    return LEAF_ENGINE_STATUS_OK;
}

static leaf_engine_status_t close_engine(void* instance, leaf_stream_close_flags_t close_flags) {
    socks5_engine* engine = (socks5_engine*)instance;
    if (engine == NULL) {
        return LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    }
    if ((close_flags & LEAF_STREAM_ENGINE_CLOSE_APP) != 0) {
        engine->app_closed = 1;
    }
    if ((close_flags & LEAF_STREAM_ENGINE_CLOSE_NET) != 0) {
        engine->net_closed = 1;
        engine->peer_closed = 1;
        if (engine->phase != PHASE_ESTABLISHED && engine->phase != PHASE_FATAL) {
            /* A handshake the peer cut short is a failed connection, not an
             * empty one, and saying so is what puts a reason in the log. */
            return mark_fatal(engine, "socks5 server closed the connection during the handshake");
        }
    }
    clear_error(engine);
    return LEAF_ENGINE_STATUS_OK;
}

static leaf_engine_status_t get_last_error(
    void* instance,
    leaf_engine_status_t* code,
    uint8_t* output,
    size_t output_cap,
    size_t* written) {
    if (code == NULL || written == NULL) {
        return LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    }
    if (output_cap > 0 && output == NULL) {
        return LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    }

    const socks5_engine* engine = (const socks5_engine*)instance;
    const char* message = engine == NULL ? create_error_message : engine->last_message;
    *code = engine == NULL ? create_error_code : engine->last_code;

    size_t len = strlen(message);
    *written = len;
    if (output_cap > 0) {
        size_t take = len < output_cap ? len : output_cap;
        memcpy(output, message, take);
        *written = take;
    }
    return LEAF_ENGINE_STATUS_OK;
}

static size_t suggest_output_size(void* instance, leaf_stream_side_t side) {
    (void)instance;
    return side == LEAF_STREAM_SIDE_APP ? APP_OUTPUT_SIZE_HINT : NET_OUTPUT_SIZE_HINT;
}

static size_t suggest_output_batch(void* instance, leaf_stream_side_t side) {
    (void)instance;
    (void)side;
    return OUTPUT_BATCH_HINT;
}

/* ----------------------------------------------------------- ABI: descriptor */

static const StreamEnginePlugin LEAF_STREAM_ENGINE_PLUGIN = {
    .size = sizeof(StreamEnginePlugin),
    .connect_type = LEAF_STREAM_CONNECT_TYPE_PROXY_TCP,
    .create_instance = create_instance,
    .destroy_instance = destroy_instance,
    .poll_state = poll_state,
    .push = push,
    .pull = pull,
    .close = close_engine,
    .get_last_error = get_last_error,
    .suggest_output_size = suggest_output_size,
    .suggest_output_batch = suggest_output_batch,
};

static const PluginDescriptor LEAF_PLUGIN_DESCRIPTOR = {
    .size = sizeof(PluginDescriptor),
    .abi_major = LEAF_PLUGIN_ABI_MAJOR,
    .abi_minor = LEAF_PLUGIN_ABI_MINOR,
    .name = PLUGIN_NAME,
    .version = PLUGIN_VERSION,
    .stream = &LEAF_STREAM_ENGINE_PLUGIN,
    .datagram = NULL,
};

LEAF_PLUGIN_EXPORT const PluginDescriptor* leaf_plugin_get_descriptor(void) {
    return &LEAF_PLUGIN_DESCRIPTOR;
}
