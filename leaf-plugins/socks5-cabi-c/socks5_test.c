/*
 * Unit tests for the SOCKS5 C plugin.
 *
 * The engine is driven through its own vtable, the way the host drives it, with
 * the server's half of the conversation supplied byte by byte. That is what
 * these cover that an end-to-end test cannot: the handshake arriving in pieces,
 * every way a server can refuse, and the states the engine reports in between.
 *
 * Build and run:
 *
 *   cc -std=c11 -I../../leaf-plugin-abi/include -o socks5_test socks5_test.c
 *   ./socks5_test
 */

#include "socks5.c"

#include <assert.h>

static int failures;
static const char* current_case;

#define CHECK(condition, ...)                                       \
    do {                                                            \
        if (!(condition)) {                                         \
            failures++;                                             \
            fprintf(stderr, "%s: ", current_case);                  \
            fprintf(stderr, __VA_ARGS__);                           \
            fprintf(stderr, " (%s:%d)\n", __FILE__, __LINE__);      \
        }                                                           \
    } while (0)

/* --------------------------------------------------------------- the harness */

/* A stand-in for the host: it holds one engine and the two sides of the
 * conversation, and every call goes through the vtable rather than around it. */
typedef struct {
    void* instance;
    uint8_t wire[4096];   /* what the engine has written to the socket */
    size_t wire_len;
    uint8_t app[4096];    /* what the engine has decoded for the application */
    size_t app_len;
} driver;

static const StreamEnginePlugin* vtable(void) { return &LEAF_STREAM_ENGINE_PLUGIN; }

static size_t logged_messages;

static void count_log(
    void* host_ctx,
    leaf_log_level_t level,
    const char* target,
    const uint8_t* message,
    size_t message_len) {
    (void)host_ctx;
    (void)level;
    (void)message;
    (void)message_len;
    /* The target is a static string the host reads on every call, so a plugin
     * that built it per message would be caught here. */
    assert(target != NULL && strcmp(target, LOG_TARGET) == 0);
    logged_messages++;
}

static HostCallbacks test_callbacks(void) {
    HostCallbacks callbacks = {0};
    callbacks.size = sizeof(HostCallbacks);
    callbacks.log = count_log;
    callbacks.wake = NULL;
    callbacks.host_ctx = NULL;
    return callbacks;
}

/* Builds a destination the way the host does, with the address bytes borrowed
 * for the create call only. */
static PluginAddress ipv4_destination(const uint8_t octets[4], uint16_t port) {
    PluginAddress address = {0};
    address.kind = LEAF_ADDRESS_KIND_IPV4;
    address.port = port;
    address.data = octets;
    address.data_len = 4;
    return address;
}

static PluginAddress domain_destination(const char* name, uint16_t port) {
    PluginAddress address = {0};
    address.kind = LEAF_ADDRESS_KIND_DOMAIN;
    address.port = port;
    address.data = (const uint8_t*)name;
    address.data_len = strlen(name);
    return address;
}

static void* create(const char* args, const PluginAddress* destination) {
    HostCallbacks callbacks = test_callbacks();
    EngineCreateArgs create_args = {0};
    create_args.size = sizeof(EngineCreateArgs);
    create_args.plugin_args = args;
    create_args.destination = destination;
    create_args.host_callbacks = &callbacks;
    create_args.host_abi_major = LEAF_PLUGIN_ABI_MAJOR;
    create_args.host_abi_minor = LEAF_PLUGIN_ABI_MINOR;
    return vtable()->create_instance(&create_args);
}

static void driver_init(driver* d, const char* args, const PluginAddress* destination) {
    memset(d, 0, sizeof(*d));
    d->instance = create(args, destination);
    assert(d->instance != NULL);
}

static void driver_free(driver* d) {
    vtable()->destroy_instance(d->instance);
    d->instance = NULL;
}

static leaf_stream_state_flags_t driver_state(driver* d) {
    leaf_stream_state_flags_t flags = 0;
    leaf_engine_status_t rc = vtable()->poll_state(d->instance, &flags);
    CHECK(rc == LEAF_ENGINE_STATUS_OK, "poll_state returned %d", rc);
    return flags;
}

/* Drains whichever side the engine says has output, exactly as the host does. */
static void driver_drain(driver* d) {
    uint8_t out[1024];
    for (;;) {
        size_t produced = 0;
        leaf_stream_state_flags_t flags = driver_state(d);
        if ((flags & LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT) != 0) {
            if (vtable()->pull(d->instance, LEAF_STREAM_SIDE_NET, out, sizeof(out), &produced) !=
                    LEAF_ENGINE_STATUS_OK ||
                produced == 0) {
                return;
            }
            assert(d->wire_len + produced <= sizeof(d->wire));
            memcpy(d->wire + d->wire_len, out, produced);
            d->wire_len += produced;
            continue;
        }
        if ((flags & LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT) != 0) {
            if (vtable()->pull(d->instance, LEAF_STREAM_SIDE_APP, out, sizeof(out), &produced) !=
                    LEAF_ENGINE_STATUS_OK ||
                produced == 0) {
                return;
            }
            assert(d->app_len + produced <= sizeof(d->app));
            memcpy(d->app + d->app_len, out, produced);
            d->app_len += produced;
            continue;
        }
        return;
    }
}

/* Hands the engine bytes from the server and drains whatever they produced. */
static leaf_engine_status_t driver_from_server(driver* d, const uint8_t* bytes, size_t len) {
    size_t consumed = 0;
    leaf_engine_status_t rc =
        vtable()->push(d->instance, LEAF_STREAM_SIDE_NET, bytes, len, &consumed);
    if (rc == LEAF_ENGINE_STATUS_OK) {
        CHECK(consumed == len, "push(net) consumed %zu of %zu bytes", consumed, len);
        driver_drain(d);
    }
    return rc;
}

static size_t driver_from_app(driver* d, const uint8_t* bytes, size_t len) {
    size_t consumed = 0;
    leaf_engine_status_t rc =
        vtable()->push(d->instance, LEAF_STREAM_SIDE_APP, bytes, len, &consumed);
    CHECK(rc == LEAF_ENGINE_STATUS_OK, "push(app) returned %d", rc);
    driver_drain(d);
    return consumed;
}

/* Forgets what has been collected, so a later assertion is about what came
 * after this point rather than about everything so far. */
static void driver_reset_wire(driver* d) { d->wire_len = 0; }

static void expect_wire(driver* d, const uint8_t* want, size_t len, const char* what) {
    CHECK(d->wire_len == len, "%s: wrote %zu bytes, want %zu", what, d->wire_len, len);
    if (d->wire_len == len) {
        CHECK(memcmp(d->wire, want, len) == 0, "%s: wrote the wrong bytes", what);
    }
}

/* The no-authentication half of a server, up to the point the session opens. */
static void server_accepts_without_auth(driver* d) {
    static const uint8_t method[] = {0x05, 0x00};
    static const uint8_t reply[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    CHECK(driver_from_server(d, method, sizeof(method)) == LEAF_ENGINE_STATUS_OK,
          "the method selection was refused");
    CHECK(driver_from_server(d, reply, sizeof(reply)) == LEAF_ENGINE_STATUS_OK,
          "the reply was refused");
}

/* ----------------------------------------------------------------- the cases */

/* The greeting has to be queued at creation, not on the first write: the host
 * drains the network side while the application is only reading, and a proxy
 * whose peer speaks first would otherwise never start. */
static void test_greeting_is_ready_before_any_write(void) {
    current_case = "greeting is ready before any write";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "", &destination);

    leaf_stream_state_flags_t flags = driver_state(&d);
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT) != 0,
          "no network output was waiting");
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_HANDSHAKING) != 0, "the engine is not handshaking");
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT) != 0,
          "the engine is not waiting on the server");
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT) == 0,
          "the engine asked for application input mid handshake");

    driver_drain(&d);
    static const uint8_t want[] = {0x05, 0x01, 0x00};
    expect_wire(&d, want, sizeof(want), "greeting");
    driver_free(&d);
}

/* Credentials in args mean both methods are offered, so one configuration works
 * against a server that wants them and one that does not. */
static void test_greeting_offers_both_methods_with_credentials(void) {
    current_case = "greeting offers both methods with credentials";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "user:secret", &destination);
    driver_drain(&d);
    static const uint8_t want[] = {0x05, 0x02, 0x00, 0x02};
    expect_wire(&d, want, sizeof(want), "greeting");
    driver_free(&d);
}

/* The whole no-authentication exchange, and a session carried over it. */
static void test_no_auth_handshake_then_session(void) {
    current_case = "no auth handshake then session";
    const uint8_t octets[4] = {93, 184, 216, 34};
    PluginAddress destination = ipv4_destination(octets, 443);
    driver d;
    driver_init(&d, "", &destination);
    driver_drain(&d);
    driver_reset_wire(&d);

    /* Application data must not go out ahead of the reply. */
    CHECK(driver_from_app(&d, (const uint8_t*)"early", 5) == 0,
          "the engine took application input during the handshake");
    CHECK(d.wire_len == 0, "the engine wrote application bytes during the handshake");

    static const uint8_t method[] = {0x05, 0x00};
    CHECK(driver_from_server(&d, method, sizeof(method)) == LEAF_ENGINE_STATUS_OK,
          "the method selection was refused");
    static const uint8_t want_request[] = {0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xbb};
    expect_wire(&d, want_request, sizeof(want_request), "connect request");
    driver_reset_wire(&d);

    static const uint8_t reply[] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90};
    CHECK(driver_from_server(&d, reply, sizeof(reply)) == LEAF_ENGINE_STATUS_OK,
          "the reply was refused");

    leaf_stream_state_flags_t flags = driver_state(&d);
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_ESTABLISHED) != 0, "the engine is not established");
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT) != 0,
          "the engine is not asking for application input");
    CHECK(d.wire_len == 0, "the reply left bytes on the wire");

    /* From here the engine adds nothing in either direction. */
    CHECK(driver_from_app(&d, (const uint8_t*)"ping", 4) == 4, "the engine refused the write");
    expect_wire(&d, (const uint8_t*)"ping", 4, "application write");

    CHECK(driver_from_server(&d, (const uint8_t*)"pong", 4) == LEAF_ENGINE_STATUS_OK,
          "the response was refused");
    CHECK(d.app_len == 4 && memcmp(d.app, "pong", 4) == 0, "the response did not come back");
    driver_free(&d);
}

/* A domain destination travels as a name, which is a different branch of the
 * address encoder and the one a proxy is usually asked for. */
static void test_domain_destination_travels_as_a_name(void) {
    current_case = "domain destination travels as a name";
    PluginAddress destination = domain_destination("origin.e2e.invalid", 8080);
    driver d;
    driver_init(&d, "", &destination);
    driver_drain(&d);
    driver_reset_wire(&d);

    static const uint8_t method[] = {0x05, 0x00};
    driver_from_server(&d, method, sizeof(method));

    uint8_t want[64];
    size_t at = 0;
    want[at++] = 0x05;
    want[at++] = 0x01;
    want[at++] = 0x00;
    want[at++] = 0x03;
    want[at++] = (uint8_t)strlen("origin.e2e.invalid");
    memcpy(want + at, "origin.e2e.invalid", strlen("origin.e2e.invalid"));
    at += strlen("origin.e2e.invalid");
    want[at++] = 0x1f;
    want[at++] = 0x90;
    expect_wire(&d, want, at, "connect request");
    driver_free(&d);
}

/* A handshake that arrives a byte at a time is the ordinary case on a stream,
 * and the engine has to wait rather than misread a partial message. */
static void test_handshake_arriving_one_byte_at_a_time(void) {
    current_case = "handshake arriving one byte at a time";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "", &destination);
    driver_drain(&d);

    /* A reply whose bound address is a domain: its length is not known until
     * the length byte itself has arrived. */
    static const uint8_t conversation[] = {
        0x05, 0x00,                                     /* method selection */
        0x05, 0x00, 0x00, 0x03, 0x04, 'h', 'o', 's', 't', 0x00, 0x50 /* reply */
    };
    for (size_t i = 0; i < sizeof(conversation); i++) {
        leaf_engine_status_t rc = driver_from_server(&d, conversation + i, 1);
        CHECK(rc == LEAF_ENGINE_STATUS_OK, "byte %zu was refused", i);
        int established =
            (driver_state(&d) & LEAF_STREAM_ENGINE_STATE_ESTABLISHED) != 0;
        int last = i + 1 == sizeof(conversation);
        CHECK(established == last, "byte %zu: established = %d", i, established);
    }
    driver_free(&d);
}

/* Whatever the peer sent after the reply, in the same read, is session data. */
static void test_bytes_after_the_reply_are_session_data(void) {
    current_case = "bytes after the reply are session data";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "", &destination);
    driver_drain(&d);

    static const uint8_t method[] = {0x05, 0x00};
    driver_from_server(&d, method, sizeof(method));

    static const uint8_t reply_and_data[] = {
        0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 'g', 'r', 'e', 'e', 't'};
    CHECK(driver_from_server(&d, reply_and_data, sizeof(reply_and_data)) == LEAF_ENGINE_STATUS_OK,
          "the reply was refused");
    CHECK(d.app_len == 5 && memcmp(d.app, "greet", 5) == 0,
          "the trailing bytes did not reach the application");
    driver_free(&d);
}

/* The username and password exchange, and the request that follows it. */
static void test_username_password_exchange(void) {
    current_case = "username password exchange";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "leaf:hunter2", &destination);
    driver_drain(&d);
    driver_reset_wire(&d);

    static const uint8_t choose_userpass[] = {0x05, 0x02};
    CHECK(driver_from_server(&d, choose_userpass, sizeof(choose_userpass)) ==
              LEAF_ENGINE_STATUS_OK,
          "the method selection was refused");
    static const uint8_t want_auth[] = {
        0x01, 0x04, 'l', 'e', 'a', 'f', 0x07, 'h', 'u', 'n', 't', 'e', 'r', '2'};
    expect_wire(&d, want_auth, sizeof(want_auth), "credentials");
    driver_reset_wire(&d);

    static const uint8_t accepted[] = {0x01, 0x00};
    CHECK(driver_from_server(&d, accepted, sizeof(accepted)) == LEAF_ENGINE_STATUS_OK,
          "the credentials were refused");
    static const uint8_t want_request[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};
    expect_wire(&d, want_request, sizeof(want_request), "connect request");

    /* A password may contain colons; the first one is the separator. */
    driver_free(&d);
    driver_init(&d, "leaf:a:b", &destination);
    driver_drain(&d);
    driver_reset_wire(&d);
    driver_from_server(&d, choose_userpass, sizeof(choose_userpass));
    static const uint8_t want_colons[] = {0x01, 0x04, 'l', 'e', 'a', 'f', 0x03, 'a', ':', 'b'};
    expect_wire(&d, want_colons, sizeof(want_colons), "credentials with a colon");
    driver_free(&d);
}

/* Every way a server can end the handshake badly has to reach the host as a
 * fatal engine with a reason, not as a connection that hangs. */
static void test_a_refusing_server_is_fatal(void) {
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);

    struct {
        const char* name;
        const char* args;
        const uint8_t* bytes;
        size_t len;
    } cases[] = {
        {"no acceptable methods", "", (const uint8_t[]){0x05, 0xff}, 2},
        {"wrong version", "", (const uint8_t[]){0x04, 0x00}, 2},
        {"unoffered method", "", (const uint8_t[]){0x05, 0x03}, 2},
        {"credentials not configured", "", (const uint8_t[]){0x05, 0x02}, 2},
        {"credentials rejected", "u:p", (const uint8_t[]){0x05, 0x02, 0x01, 0x01}, 4},
        {"connection refused",
         "",
         (const uint8_t[]){0x05, 0x00, 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0},
         12},
        {"unknown reply address type",
         "",
         (const uint8_t[]){0x05, 0x00, 0x05, 0x00, 0x00, 0x7f, 0, 0, 0, 0},
         10},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        current_case = cases[i].name;
        driver d;
        driver_init(&d, cases[i].args, &destination);
        driver_drain(&d);
        driver_from_server(&d, cases[i].bytes, cases[i].len);

        leaf_stream_state_flags_t flags = 0;
        vtable()->poll_state(d.instance, &flags);
        CHECK((flags & LEAF_STREAM_ENGINE_STATE_FATAL) != 0, "the engine is not fatal");

        /* The host asks twice: once for the length, once with a buffer. */
        leaf_engine_status_t code = 0;
        size_t written = 0;
        CHECK(vtable()->get_last_error(d.instance, &code, NULL, 0, &written) ==
                  LEAF_ENGINE_STATUS_OK,
              "get_last_error failed");
        CHECK(code == LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "status = %d", code);
        CHECK(written > 0, "the engine had nothing to say about the failure");

        char message[MAX_MESSAGE_LEN];
        size_t again = 0;
        vtable()->get_last_error(d.instance, &code, (uint8_t*)message, written, &again);
        CHECK(again == written, "the message changed between the two reads: %zu then %zu",
              written, again);
        driver_free(&d);
    }
}

/* A peer that disappears mid handshake is a failed connection, not an empty
 * one, and the difference is what an operator reads in the log. */
static void test_a_peer_that_closes_mid_handshake_is_fatal(void) {
    current_case = "peer closes mid handshake";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "", &destination);
    driver_drain(&d);

    leaf_engine_status_t rc = vtable()->close(d.instance, LEAF_STREAM_ENGINE_CLOSE_NET);
    CHECK(rc == LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "close returned %d", rc);
    CHECK((driver_state(&d) & LEAF_STREAM_ENGINE_STATE_FATAL) != 0, "the engine is not fatal");
    driver_free(&d);

    /* The same close once the session is up is an ordinary end of stream. */
    current_case = "peer closes after the session opened";
    driver_init(&d, "", &destination);
    driver_drain(&d);
    server_accepts_without_auth(&d);
    CHECK(vtable()->close(d.instance, LEAF_STREAM_ENGINE_CLOSE_NET) == LEAF_ENGINE_STATUS_OK,
          "close was refused");
    leaf_stream_state_flags_t flags = driver_state(&d);
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_PEER_CLOSED) != 0, "the peer close was not reported");
    CHECK((flags & LEAF_STREAM_ENGINE_STATE_FATAL) == 0, "an ordinary close was called fatal");
    driver_free(&d);
}

/* Once the application has closed its side, a write to it is a host bug and
 * has to be refused rather than quietly encoded. */
static void test_writes_after_close_are_refused(void) {
    current_case = "writes after close are refused";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "", &destination);
    driver_drain(&d);
    server_accepts_without_auth(&d);

    CHECK(vtable()->close(d.instance, LEAF_STREAM_ENGINE_CLOSE_APP) == LEAF_ENGINE_STATUS_OK,
          "close was refused");
    size_t consumed = 0;
    leaf_engine_status_t rc =
        vtable()->push(d.instance, LEAF_STREAM_SIDE_APP, (const uint8_t*)"x", 1, &consumed);
    CHECK(rc == LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "push returned %d", rc);
    CHECK(consumed == 0, "push consumed %zu bytes after the close", consumed);
    driver_free(&d);
}

/* Arguments and destinations the plugin cannot use have to fail at creation,
 * where the host turns them into a message naming the outbound. */
static void test_creation_refuses_what_it_cannot_use(void) {
    current_case = "creation refuses what it cannot use";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress good = ipv4_destination(octets, 80);

    CHECK(create("nocolon", &good) == NULL, "a malformed args string was accepted");
    CHECK(create(":password", &good) == NULL, "an empty username was accepted");

    PluginAddress short_ipv4 = good;
    short_ipv4.data_len = 3;
    CHECK(create("", &short_ipv4) == NULL, "a three byte IPv4 address was accepted");

    PluginAddress unknown = good;
    unknown.kind = 0x7f;
    CHECK(create("", &unknown) == NULL, "an unknown address kind was accepted");

    PluginAddress empty_domain = domain_destination("", 80);
    CHECK(create("", &empty_domain) == NULL, "an empty domain was accepted");

    char too_long[MAX_DOMAIN_LEN + 2];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    PluginAddress long_domain = domain_destination(too_long, 80);
    CHECK(create("", &long_domain) == NULL, "an over-long domain was accepted");

    /* With no instance to ask, the host reads the reason from the thread the
     * failed call was made on. */
    leaf_engine_status_t code = 0;
    size_t written = 0;
    CHECK(vtable()->get_last_error(NULL, &code, NULL, 0, &written) == LEAF_ENGINE_STATUS_OK,
          "get_last_error failed with no instance");
    CHECK(code == LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "status = %d", code);
    CHECK(written > 0, "no reason was recorded for the failed creation");

    /* And a create that succeeds clears it again. */
    void* instance = create("", &good);
    CHECK(instance != NULL, "a valid configuration was refused");
    vtable()->get_last_error(NULL, &code, NULL, 0, &written);
    CHECK(written == 0, "a successful creation left a stale error behind");
    vtable()->destroy_instance(instance);
}

/* The entries the host calls without an instance, or with arguments the ABI
 * says cannot happen, still have to answer rather than reach into null. */
static void test_null_arguments_are_refused(void) {
    current_case = "null arguments are refused";
    const uint8_t octets[4] = {127, 0, 0, 1};
    PluginAddress destination = ipv4_destination(octets, 80);
    driver d;
    driver_init(&d, "", &destination);

    size_t size = 0;
    leaf_stream_state_flags_t flags = 0;
    CHECK(vtable()->poll_state(NULL, &flags) == LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
          "poll_state accepted a null instance");
    CHECK(vtable()->poll_state(d.instance, NULL) == LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
          "poll_state accepted a null output");
    CHECK(vtable()->push(d.instance, LEAF_STREAM_SIDE_APP, NULL, 4, &size) ==
              LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
          "push accepted a null input with a length");
    CHECK(vtable()->push(d.instance, 0x99, (const uint8_t*)"x", 1, &size) ==
              LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
          "push accepted an unknown side");
    CHECK(vtable()->pull(d.instance, 0x99, (uint8_t*)&size, 1, &size) ==
              LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
          "pull accepted an unknown side");
    CHECK(vtable()->close(NULL, 0) == LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
          "close accepted a null instance");
    /* destroy_instance(NULL) is explicitly allowed and must do nothing. */
    vtable()->destroy_instance(NULL);
    driver_free(&d);
}

/* The descriptor is what the host reads before anything else; a plugin that
 * gets it wrong never loads. */
static void test_descriptor_is_what_the_host_expects(void) {
    current_case = "descriptor is what the host expects";
    const PluginDescriptor* descriptor = leaf_plugin_get_descriptor();
    CHECK(descriptor != NULL, "no descriptor");
    CHECK(descriptor->size >= LEAF_PLUGIN_DESCRIPTOR_REQUIRED_SIZE, "descriptor is too small");
    CHECK(descriptor->abi_major == LEAF_PLUGIN_ABI_MAJOR, "wrong ABI major");
    CHECK(descriptor->name != NULL && descriptor->name[0] != '\0', "no name");
    CHECK(descriptor->version != NULL && descriptor->version[0] != '\0', "no version");
    CHECK(descriptor->datagram == NULL, "a datagram engine was published");
    CHECK(descriptor->stream != NULL, "no stream engine");
    CHECK(descriptor->stream->size >= LEAF_STREAM_ENGINE_PLUGIN_REQUIRED_SIZE,
          "the stream vtable is too small");
    CHECK(descriptor->stream->connect_type == LEAF_STREAM_CONNECT_TYPE_PROXY_TCP,
          "wrong connect type");
    /* Every entry is required: the host refuses a vtable with a hole in it. */
    CHECK(descriptor->stream->create_instance != NULL, "no create_instance");
    CHECK(descriptor->stream->destroy_instance != NULL, "no destroy_instance");
    CHECK(descriptor->stream->poll_state != NULL, "no poll_state");
    CHECK(descriptor->stream->push != NULL, "no push");
    CHECK(descriptor->stream->pull != NULL, "no pull");
    CHECK(descriptor->stream->close != NULL, "no close");
    CHECK(descriptor->stream->get_last_error != NULL, "no get_last_error");
    CHECK(descriptor->stream->suggest_output_size != NULL, "no suggest_output_size");
    CHECK(descriptor->stream->suggest_output_batch != NULL, "no suggest_output_batch");
    /* The same pointer every time: the host reads it once and keeps it. */
    CHECK(leaf_plugin_get_descriptor() == descriptor, "the descriptor moved");
}

/* The buffer under every queue: consuming the front must not lose the back, and
 * an append after a partial read must not corrupt what is left. */
static void test_buffer_survives_partial_reads(void) {
    current_case = "buffer survives partial reads";
    buffer b = {0};
    for (int round = 0; round < 4; round++) {
        CHECK(buffer_append(&b, (const uint8_t*)"0123456789", 10), "append failed");
        uint8_t out[4];
        size_t took = buffer_take(&b, out, sizeof(out));
        CHECK(took == 4, "took %zu bytes", took);
        CHECK(memcmp(out, "0123", 4) == 0, "took the wrong bytes");
        CHECK(buffer_append(&b, (const uint8_t*)"abcdef", 6), "append after a partial read failed");
        uint8_t rest[64];
        size_t drained = buffer_take(&b, rest, sizeof(rest));
        CHECK(drained == 12, "drained %zu bytes", drained);
        CHECK(memcmp(rest, "456789abcdef", 12) == 0, "the remainder came back altered");
        CHECK(buffer_len(&b) == 0, "the buffer is not empty");
    }
    /* One append far larger than the initial capacity, to grow it. */
    uint8_t big[8192];
    memset(big, 0x5a, sizeof(big));
    CHECK(buffer_append(&b, big, sizeof(big)), "large append failed");
    CHECK(buffer_len(&b) == sizeof(big), "large append lost bytes");
    buffer_free(&b);
    CHECK(buffer_len(&b) == 0, "freeing left bytes behind");
}

int main(void) {
    test_greeting_is_ready_before_any_write();
    test_greeting_offers_both_methods_with_credentials();
    test_no_auth_handshake_then_session();
    test_domain_destination_travels_as_a_name();
    test_handshake_arriving_one_byte_at_a_time();
    test_bytes_after_the_reply_are_session_data();
    test_username_password_exchange();
    test_a_refusing_server_is_fatal();
    test_a_peer_that_closes_mid_handshake_is_fatal();
    test_writes_after_close_are_refused();
    test_creation_refuses_what_it_cannot_use();
    test_null_arguments_are_refused();
    test_descriptor_is_what_the_host_expects();
    test_buffer_survives_partial_reads();

    if (logged_messages == 0) {
        fprintf(stderr, "the engine logged nothing at all\n");
        failures++;
    }
    if (failures > 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all socks5-cabi-c checks passed\n");
    return 0;
}
