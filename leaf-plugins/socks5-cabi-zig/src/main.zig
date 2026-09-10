//! A SOCKS5 outbound plugin for the leaf C ABI, written in Zig.
//!
//! It is the counterpart of the C plugin next door and does the same thing the
//! same way, on purpose: the two together are what says the ABI is a contract
//! rather than a Rust or a Go interface with a C-shaped hole in it. Like the C
//! one it has no runtime, no threads and no allocator of its own beyond libc's,
//! so every call returns immediately and
//! `LEAF_STREAM_ENGINE_STATE_BLOCKED` is never needed.
//!
//! It exports one stream engine with `LEAF_STREAM_CONNECT_TYPE_PROXY_TCP`: the
//! host connects a TCP socket to the host and port in the outbound's settings,
//! both of which must be configured, and this engine performs the SOCKS5
//! handshake over it and then carries the session transparently.
//!
//! `args` is empty for a server that wants no authentication, or
//! `username:password` for one that wants credentials. The password may contain
//! colons; the username may not.
//!
//! Build:
//!
//!     zig build -Doptimize=ReleaseSafe
//!
//! Test:
//!
//!     zig build test

const std = @import("std");

const c = @cImport({
    @cInclude("leaf_plugin_abi.h");
});

const plugin_name = "leaf-socks5-cabi-zig-plugin";
const plugin_version = "0.1.0";
const log_target = "leaf.plugin.socks5.zig";

/// SOCKS5 wire constants, from RFC 1928 and RFC 1929.
const socks_version: u8 = 0x05;
const cmd_connect: u8 = 0x01;
const reserved: u8 = 0x00;
const method_none: u8 = 0x00;
const method_userpass: u8 = 0x02;
const method_unacceptable: u8 = 0xff;
const auth_version: u8 = 0x01;
const atyp_ipv4: u8 = 0x01;
const atyp_domain: u8 = 0x03;
const atyp_ipv6: u8 = 0x04;

const app_output_size_hint: usize = 16 * 1024;
const net_output_size_hint: usize = 16 * 1024;
const output_batch_hint: usize = 4;

const max_domain_len = 255;
/// The longest SOCKS5 address: type, length, domain, port.
const max_address_len = 1 + 1 + max_domain_len + 2;
/// Version, then a username and a password of at most 255 bytes each, each with
/// a length byte.
const max_auth_len = 1 + 1 + 255 + 1 + 255;
const max_message_len = 256;

/// The prefix of a struct every conforming peer must provide, frozen for the
/// life of `LEAF_PLUGIN_ABI_MAJOR`. The header states this with `offsetof` in a
/// macro translate-c cannot follow, so it is restated here in Zig's own terms;
/// the ABI's header-parity test is what keeps the two honest.
fn requiredSize(comptime T: type, comptime last_field: []const u8) usize {
    return @offsetOf(T, last_field) + @sizeOf(@FieldType(T, last_field));
}

const create_args_required_size = requiredSize(c.EngineCreateArgs, "host_abi_minor");
const host_callbacks_required_size = requiredSize(c.HostCallbacks, "host_ctx");

/// libc's allocator, because the plugin is linked against libc anyway and the
/// host owns every buffer that matters. Nothing here allocates on a hot path
/// except the queues, which amortise.
const allocator = std.heap.c_allocator;

// ------------------------------------------------------------------ buffers

/// A byte queue that grows at the back and is consumed from the front.
///
/// `start` is what makes consuming the front cheap; the region before it is
/// reclaimed on the next append rather than on every read.
const Buffer = struct {
    bytes: std.ArrayList(u8) = .empty,
    start: usize = 0,

    fn deinit(self: *Buffer) void {
        self.bytes.deinit(allocator);
        self.* = .{};
    }

    fn items(self: *const Buffer) []const u8 {
        return self.bytes.items[self.start..];
    }

    fn len(self: *const Buffer) usize {
        return self.bytes.items.len - self.start;
    }

    fn append(self: *Buffer, data: []const u8) error{OutOfMemory}!void {
        if (data.len == 0) return;
        if (self.start > 0) {
            // Reclaimed here rather than on every read, so a queue that is
            // drained as fast as it fills never moves its bytes twice.
            const remaining = self.len();
            std.mem.copyForwards(u8, self.bytes.items[0..remaining], self.items());
            self.bytes.shrinkRetainingCapacity(remaining);
            self.start = 0;
        }
        try self.bytes.appendSlice(allocator, data);
    }

    fn consume(self: *Buffer, count: usize) void {
        if (count >= self.len()) {
            self.bytes.clearRetainingCapacity();
            self.start = 0;
            return;
        }
        self.start += count;
    }

    /// Copies at most `out.len` bytes out of the front and drops them.
    fn take(self: *Buffer, out: []u8) usize {
        const n = @min(self.len(), out.len);
        if (n > 0) {
            @memcpy(out[0..n], self.items()[0..n]);
            self.consume(n);
        }
        return n;
    }
};

// ------------------------------------------------------------------- engine

const Phase = enum {
    /// Waiting for the server to choose an authentication method.
    method,
    /// Waiting for the result of a username and password exchange.
    auth,
    /// Waiting for the reply to the CONNECT request.
    reply,
    /// The session is carried transparently from here on.
    established,
    /// Something went wrong and the connection has to fail.
    fatal,
};

const Engine = struct {
    log: c.leaf_host_log_fn = null,
    host_ctx: ?*anyopaque = null,

    phase: Phase = .method,

    net_in: Buffer = .{},
    net_out: Buffer = .{},
    app_out: Buffer = .{},

    /// The CONNECT request, built once at creation and sent as soon as the
    /// server has accepted an authentication method.
    request: [3 + max_address_len]u8 = undefined,
    request_len: usize = 0,

    /// The username and password exchange, empty when none is configured.
    auth: [max_auth_len]u8 = undefined,
    auth_len: usize = 0,

    app_closed: bool = false,
    net_closed: bool = false,
    peer_closed: bool = false,

    last_code: c.leaf_engine_status_t = c.LEAF_ENGINE_STATUS_OK,
    last_message: [max_message_len]u8 = undefined,
    last_message_len: usize = 0,

    fn deinit(self: *Engine) void {
        self.net_in.deinit();
        self.net_out.deinit();
        self.app_out.deinit();
    }

    fn emit(self: *const Engine, level: c.leaf_log_level_t, message: []const u8) void {
        const log = self.log orelse return;
        log(self.host_ctx, level, log_target.ptr, message.ptr, message.len);
    }

    fn setError(self: *Engine, code: c.leaf_engine_status_t, message: []const u8) c.leaf_engine_status_t {
        const n = @min(message.len, self.last_message.len);
        @memcpy(self.last_message[0..n], message[0..n]);
        self.last_message_len = n;
        self.last_code = code;
        return code;
    }

    fn clearError(self: *Engine) void {
        if (self.phase == .fatal) {
            // A fatal engine's reason has to outlive the poll_state calls the
            // host makes between operations: it is the only explanation the
            // log will ever get for why the connection failed.
            return;
        }
        self.last_code = c.LEAF_ENGINE_STATUS_OK;
        self.last_message_len = 0;
    }

    /// Puts the engine beyond use. The host fails the connection as soon as it
    /// sees `LEAF_STREAM_ENGINE_STATE_FATAL`, whatever the call that reported
    /// it returned, so this is how a protocol error ends a session.
    fn markFatal(self: *Engine, message: []const u8) c.leaf_engine_status_t {
        self.phase = .fatal;
        self.emit(c.LEAF_LOG_LEVEL_ERROR, message);
        return self.setError(c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE, message);
    }

    fn lastMessage(self: *const Engine) []const u8 {
        return self.last_message[0..self.last_message_len];
    }
};

/// Where a failure that happened before there was an instance is kept. The host
/// asks for it with a null instance, on the thread that made the failed call.
threadlocal var create_error_code: c.leaf_engine_status_t = c.LEAF_ENGINE_STATUS_OK;
threadlocal var create_error_buffer: [max_message_len]u8 = undefined;
threadlocal var create_error_len: usize = 0;

fn setCreateError(code: c.leaf_engine_status_t, message: []const u8) void {
    const n = @min(message.len, create_error_buffer.len);
    @memcpy(create_error_buffer[0..n], message[0..n]);
    create_error_len = n;
    create_error_code = code;
}

fn clearCreateError() void {
    create_error_code = c.LEAF_ENGINE_STATUS_OK;
    create_error_len = 0;
}

// ------------------------------------------------------------------ framing

const AddressError = error{ Incomplete, Unsupported };

/// Writes the SOCKS5 form of `address` -- the type byte, the address, then the
/// port in network order -- and reports its length.
fn encodeAddress(out: []u8, address: *const c.PluginAddress) AddressError!usize {
    const data: []const u8 = if (address.data) |ptr| ptr[0..address.data_len] else &.{};
    var at: usize = 0;
    switch (address.kind) {
        c.LEAF_ADDRESS_KIND_IPV4 => {
            if (data.len != 4 or out.len < 1 + 4 + 2) return error.Unsupported;
            out[at] = atyp_ipv4;
            at += 1;
            @memcpy(out[at..][0..4], data);
            at += 4;
        },
        c.LEAF_ADDRESS_KIND_IPV6 => {
            if (data.len != 16 or out.len < 1 + 16 + 2) return error.Unsupported;
            out[at] = atyp_ipv6;
            at += 1;
            @memcpy(out[at..][0..16], data);
            at += 16;
        },
        c.LEAF_ADDRESS_KIND_DOMAIN => {
            if (data.len == 0 or data.len > max_domain_len) return error.Unsupported;
            if (out.len < 1 + 1 + data.len + 2) return error.Unsupported;
            out[at] = atyp_domain;
            out[at + 1] = @intCast(data.len);
            at += 2;
            @memcpy(out[at..][0..data.len], data);
            at += data.len;
        },
        else => return error.Unsupported,
    }
    std.mem.writeInt(u16, out[at..][0..2], address.port, .big);
    return at + 2;
}

/// How many bytes the address at the front of `input` occupies.
///
/// `error.Incomplete` means it is not all there yet, which is the ordinary case
/// on a byte stream; `error.Unsupported` means a type SOCKS5 does not define.
fn addressLength(input: []const u8) AddressError!usize {
    if (input.len < 1) return error.Incomplete;
    const total: usize = switch (input[0]) {
        atyp_ipv4 => 1 + 4 + 2,
        atyp_ipv6 => 1 + 16 + 2,
        atyp_domain => blk: {
            if (input.len < 2) return error.Incomplete;
            break :blk 1 + 1 + @as(usize, input[1]) + 2;
        },
        else => return error.Unsupported,
    };
    if (input.len < total) return error.Incomplete;
    return total;
}

/// The greeting: the version, then the methods this client is willing to use.
fn encodeGreeting(out: []u8, with_userpass: bool) []const u8 {
    out[0] = socks_version;
    if (!with_userpass) {
        out[1] = 1;
        out[2] = method_none;
        return out[0..3];
    }
    // Both are offered so that one configuration works against a server that
    // wants credentials and one that does not.
    out[1] = 2;
    out[2] = method_none;
    out[3] = method_userpass;
    return out[0..4];
}

/// The RFC 1929 username and password exchange.
fn encodeAuth(out: []u8, username: []const u8, password: []const u8) error{Unsupported}!usize {
    if (username.len == 0 or username.len > 255 or password.len > 255) return error.Unsupported;
    if (out.len < 1 + 1 + username.len + 1 + password.len) return error.Unsupported;
    var at: usize = 0;
    out[at] = auth_version;
    out[at + 1] = @intCast(username.len);
    at += 2;
    @memcpy(out[at..][0..username.len], username);
    at += username.len;
    out[at] = @intCast(password.len);
    at += 1;
    @memcpy(out[at..][0..password.len], password);
    return at + password.len;
}

/// What a non-zero reply code means, so a failure names itself in the log.
fn replyMessage(code: u8) []const u8 {
    return switch (code) {
        0x01 => "socks5 server reported a general failure",
        0x02 => "socks5 server refused the connection by policy",
        0x03 => "socks5 server reported the network as unreachable",
        0x04 => "socks5 server reported the host as unreachable",
        0x05 => "socks5 server reported the connection as refused",
        0x06 => "socks5 server reported the TTL as expired",
        0x07 => "socks5 server does not support this command",
        0x08 => "socks5 server does not support this address type",
        else => "socks5 server refused the request",
    };
}

// ------------------------------------------------------------ state machine

/// Drives the handshake as far as the bytes in hand allow.
///
/// Every branch either consumes a complete message and moves on, or returns
/// having consumed nothing so that the host can read more.
fn advance(engine: *Engine) void {
    while (true) {
        const input = engine.net_in.items();
        switch (engine.phase) {
            .method => {
                if (input.len < 2) return;
                if (input[0] != socks_version) {
                    _ = engine.markFatal("socks5 server replied with a different version");
                    return;
                }
                const method = input[1];
                engine.net_in.consume(2);
                switch (method) {
                    method_none => {
                        engine.net_out.append(engine.request[0..engine.request_len]) catch {
                            _ = engine.markFatal("out of memory queueing the socks5 request");
                            return;
                        };
                        engine.phase = .reply;
                    },
                    method_userpass => {
                        if (engine.auth_len == 0) {
                            _ = engine.markFatal("socks5 server asked for credentials that are not configured");
                            return;
                        }
                        engine.net_out.append(engine.auth[0..engine.auth_len]) catch {
                            _ = engine.markFatal("out of memory queueing the socks5 credentials");
                            return;
                        };
                        engine.phase = .auth;
                    },
                    else => {
                        _ = engine.markFatal(if (method == method_unacceptable)
                            "socks5 server accepted none of the offered authentication methods"
                        else
                            "socks5 server chose an authentication method that was not offered");
                        return;
                    },
                }
            },

            .auth => {
                if (input.len < 2) return;
                if (input[0] != auth_version) {
                    _ = engine.markFatal("socks5 server replied with an unknown authentication version");
                    return;
                }
                const status = input[1];
                engine.net_in.consume(2);
                if (status != 0) {
                    _ = engine.markFatal("socks5 server rejected the credentials");
                    return;
                }
                engine.net_out.append(engine.request[0..engine.request_len]) catch {
                    _ = engine.markFatal("out of memory queueing the socks5 request");
                    return;
                };
                engine.phase = .reply;
            },

            .reply => {
                // Version, reply, reserved, then a bound address whose length
                // depends on its own type byte.
                if (input.len < 4) return;
                if (input[0] != socks_version) {
                    _ = engine.markFatal("socks5 reply carried a different version");
                    return;
                }
                const address_len = addressLength(input[3..]) catch |err| switch (err) {
                    error.Incomplete => return,
                    error.Unsupported => {
                        _ = engine.markFatal("socks5 reply carried an unknown address type");
                        return;
                    },
                };
                if (input[1] != 0) {
                    _ = engine.markFatal(replyMessage(input[1]));
                    return;
                }
                engine.net_in.consume(3 + address_len);
                engine.phase = .established;
                engine.emit(c.LEAF_LOG_LEVEL_DEBUG, "socks5 handshake completed");
            },

            .established => {
                // Everything from here is the session itself.
                if (input.len == 0) return;
                engine.app_out.append(input) catch {
                    _ = engine.markFatal("out of memory buffering decoded output");
                    return;
                };
                engine.net_in.consume(input.len);
                return;
            },

            .fatal => return,
        }
    }
}

/// Splits `username:password`. A password may contain colons; a username may
/// not, since the first colon is the separator.
fn parseArgs(engine: *Engine, args: []const u8) error{Unsupported}!void {
    if (args.len == 0) {
        engine.auth_len = 0;
        return;
    }
    const separator = std.mem.indexOfScalar(u8, args, ':') orelse return error.Unsupported;
    engine.auth_len = try encodeAuth(&engine.auth, args[0..separator], args[separator + 1 ..]);
}

// -------------------------------------------------------------- ABI: stream

fn createInstance(args: [*c]const c.EngineCreateArgs) callconv(.c) ?*anyopaque {
    if (args == null or args.*.size < create_args_required_size) {
        setCreateError(c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "engine create args are too small");
        return null;
    }

    const engine = allocator.create(Engine) catch {
        setCreateError(c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "out of memory creating the engine");
        return null;
    };
    engine.* = .{};

    if (args.*.host_callbacks) |callbacks| {
        if (callbacks.*.size >= host_callbacks_required_size) {
            engine.log = callbacks.*.log;
            engine.host_ctx = callbacks.*.host_ctx;
        }
    }

    const plugin_args: []const u8 = if (args.*.plugin_args) |raw|
        std.mem.span(raw)
    else
        &.{};
    parseArgs(engine, plugin_args) catch {
        allocator.destroy(engine);
        setCreateError(
            c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
            "socks5 plugin args must be empty or `username:password`",
        );
        return null;
    };

    const destination = args.*.destination orelse {
        allocator.destroy(engine);
        setCreateError(c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "the session has no destination");
        return null;
    };
    const address_len = encodeAddress(engine.request[3..], destination) catch {
        allocator.destroy(engine);
        setCreateError(
            c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
            "the session destination is not a socks5 address",
        );
        return null;
    };
    engine.request[0] = socks_version;
    engine.request[1] = cmd_connect;
    engine.request[2] = reserved;
    engine.request_len = 3 + address_len;

    // The greeting is queued now rather than on the first write: the host
    // drains the network side while the application is only reading, so this is
    // what gets the handshake started either way.
    var greeting: [4]u8 = undefined;
    engine.net_out.append(encodeGreeting(&greeting, engine.auth_len > 0)) catch {
        engine.deinit();
        allocator.destroy(engine);
        setCreateError(c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE, "out of memory queueing the greeting");
        return null;
    };

    clearCreateError();
    engine.emit(c.LEAF_LOG_LEVEL_INFO, "created socks5 stream engine");
    return engine;
}

fn destroyInstance(instance: ?*anyopaque) callconv(.c) void {
    const engine: *Engine = @ptrCast(@alignCast(instance orelse return));
    engine.deinit();
    allocator.destroy(engine);
}

fn pollState(instance: ?*anyopaque, state_flags: [*c]c.leaf_stream_state_flags_t) callconv(.c) c.leaf_engine_status_t {
    const engine: *Engine = @ptrCast(@alignCast(instance orelse return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT));
    if (state_flags == null) return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT;

    var flags: c.leaf_stream_state_flags_t = 0;
    switch (engine.phase) {
        .fatal => flags |= c.LEAF_STREAM_ENGINE_STATE_FATAL,
        .established => {
            flags |= c.LEAF_STREAM_ENGINE_STATE_ESTABLISHED;
            if (!engine.app_closed) flags |= c.LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT;
        },
        // Application input is refused until the server has accepted the
        // request, so that side is deliberately not advertised: nothing may go
        // out ahead of the reply.
        else => flags |= c.LEAF_STREAM_ENGINE_STATE_HANDSHAKING,
    }
    if (!engine.net_closed) flags |= c.LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT;
    if (engine.net_out.len() > 0) flags |= c.LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT;
    if (engine.app_out.len() > 0) flags |= c.LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT;
    if (engine.peer_closed) flags |= c.LEAF_STREAM_ENGINE_STATE_PEER_CLOSED;

    state_flags.* = flags;
    engine.clearError();
    return c.LEAF_ENGINE_STATUS_OK;
}

fn push(
    instance: ?*anyopaque,
    side: c.leaf_stream_side_t,
    input: [*c]const u8,
    input_len: usize,
    consumed: [*c]usize,
) callconv(.c) c.leaf_engine_status_t {
    const engine: *Engine = @ptrCast(@alignCast(instance orelse return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT));
    if (consumed == null) return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    consumed.* = 0;
    if (input_len > 0 and input == null) {
        return engine.setError(c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "push was given no input buffer");
    }
    if (engine.phase == .fatal) return c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE;

    const data: []const u8 = if (input_len > 0) input[0..input_len] else &.{};
    switch (side) {
        c.LEAF_STREAM_SIDE_APP => {
            if (engine.app_closed) {
                return engine.setError(
                    c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE,
                    "push(app) after the application side was closed",
                );
            }
            if (engine.phase != .established) {
                // Consuming nothing is the backpressure signal: the host keeps
                // the bytes and offers them again once the handshake, which it
                // can still drive from the network side, has finished.
                return c.LEAF_ENGINE_STATUS_OK;
            }
            engine.net_out.append(data) catch {
                return engine.markFatal("out of memory buffering application input");
            };
        },
        c.LEAF_STREAM_SIDE_NET => {
            if (engine.net_closed) {
                return engine.setError(
                    c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE,
                    "push(net) after the network side was closed",
                );
            }
            engine.net_in.append(data) catch {
                return engine.markFatal("out of memory buffering network input");
            };
            advance(engine);
            if (engine.phase == .fatal) {
                consumed.* = input_len;
                return c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE;
            }
        },
        else => return engine.setError(
            c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
            "invalid stream side for push",
        ),
    }

    consumed.* = input_len;
    engine.clearError();
    return c.LEAF_ENGINE_STATUS_OK;
}

fn pull(
    instance: ?*anyopaque,
    side: c.leaf_stream_side_t,
    output: [*c]u8,
    output_cap: usize,
    produced: [*c]usize,
) callconv(.c) c.leaf_engine_status_t {
    const engine: *Engine = @ptrCast(@alignCast(instance orelse return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT));
    if (produced == null) return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    produced.* = 0;
    if (output_cap > 0 and output == null) {
        return engine.setError(c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT, "pull was given no output buffer");
    }

    const source: *Buffer = switch (side) {
        c.LEAF_STREAM_SIDE_APP => &engine.app_out,
        c.LEAF_STREAM_SIDE_NET => &engine.net_out,
        else => return engine.setError(
            c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
            "invalid stream side for pull",
        ),
    };
    // Output the peer already sent outlives a failure: the host is entitled to
    // drain what is there before the error takes the connection down.
    if (source.len() == 0 and engine.phase == .fatal) {
        return c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE;
    }
    produced.* = if (output_cap > 0) source.take(output[0..output_cap]) else 0;
    engine.clearError();
    return c.LEAF_ENGINE_STATUS_OK;
}

fn closeEngine(instance: ?*anyopaque, close_flags: c.leaf_stream_close_flags_t) callconv(.c) c.leaf_engine_status_t {
    const engine: *Engine = @ptrCast(@alignCast(instance orelse return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT));
    if (close_flags & c.LEAF_STREAM_ENGINE_CLOSE_APP != 0) {
        engine.app_closed = true;
    }
    if (close_flags & c.LEAF_STREAM_ENGINE_CLOSE_NET != 0) {
        engine.net_closed = true;
        engine.peer_closed = true;
        if (engine.phase != .established and engine.phase != .fatal) {
            // A handshake the peer cut short is a failed connection, not an
            // empty one, and saying so is what puts a reason in the log.
            return engine.markFatal("socks5 server closed the connection during the handshake");
        }
    }
    engine.clearError();
    return c.LEAF_ENGINE_STATUS_OK;
}

fn getLastError(
    instance: ?*anyopaque,
    code: [*c]c.leaf_engine_status_t,
    output: [*c]u8,
    output_cap: usize,
    written: [*c]usize,
) callconv(.c) c.leaf_engine_status_t {
    if (code == null or written == null) return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT;
    if (output_cap > 0 and output == null) return c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT;

    var text: []const u8 = create_error_buffer[0..create_error_len];
    var status = create_error_code;
    if (instance) |raw| {
        const engine: *Engine = @ptrCast(@alignCast(raw));
        text = engine.lastMessage();
        status = engine.last_code;
    }

    code.* = status;
    written.* = text.len;
    if (output_cap > 0) {
        const n = @min(text.len, output_cap);
        @memcpy(output[0..n], text[0..n]);
        written.* = n;
    }
    return c.LEAF_ENGINE_STATUS_OK;
}

fn suggestOutputSize(instance: ?*anyopaque, side: c.leaf_stream_side_t) callconv(.c) usize {
    _ = instance;
    return if (side == c.LEAF_STREAM_SIDE_APP) app_output_size_hint else net_output_size_hint;
}

fn suggestOutputBatch(instance: ?*anyopaque, side: c.leaf_stream_side_t) callconv(.c) usize {
    _ = instance;
    _ = side;
    return output_batch_hint;
}

// ---------------------------------------------------------- ABI: descriptor

const stream_engine: c.StreamEnginePlugin = .{
    .size = @sizeOf(c.StreamEnginePlugin),
    .connect_type = c.LEAF_STREAM_CONNECT_TYPE_PROXY_TCP,
    .create_instance = createInstance,
    .destroy_instance = destroyInstance,
    .poll_state = pollState,
    .push = push,
    .pull = pull,
    .close = closeEngine,
    .get_last_error = getLastError,
    .suggest_output_size = suggestOutputSize,
    .suggest_output_batch = suggestOutputBatch,
};

const descriptor: c.PluginDescriptor = .{
    .size = @sizeOf(c.PluginDescriptor),
    .abi_major = c.LEAF_PLUGIN_ABI_MAJOR,
    .abi_minor = c.LEAF_PLUGIN_ABI_MINOR,
    .name = plugin_name,
    .version = plugin_version,
    .stream = &stream_engine,
    .datagram = null,
};

export fn leaf_plugin_get_descriptor() callconv(.c) *const c.PluginDescriptor {
    return &descriptor;
}

// ------------------------------------------------------------------- tests
//
// The engine is driven through its own vtable, the way the host drives it, with
// the server's half of the conversation supplied by hand. That is what these
// cover that an end-to-end test cannot: the handshake arriving in pieces, every
// way a server can refuse, and the states the engine reports in between.

const testing = std.testing;

var logged_messages: usize = 0;

fn countingLog(
    host_ctx: ?*anyopaque,
    level: c.leaf_log_level_t,
    target: [*c]const u8,
    message: [*c]const u8,
    message_len: usize,
) callconv(.c) void {
    _ = host_ctx;
    _ = level;
    _ = message;
    _ = message_len;
    // The target is a static string the host reads on every call, so a plugin
    // that built one per message would be caught here.
    std.debug.assert(std.mem.eql(u8, std.mem.span(target), log_target));
    logged_messages += 1;
}

fn ipv4Destination(octets: *const [4]u8, port: u16) c.PluginAddress {
    return .{
        .kind = c.LEAF_ADDRESS_KIND_IPV4,
        .port = port,
        .data = octets,
        .data_len = 4,
    };
}

fn domainDestination(name: []const u8, port: u16) c.PluginAddress {
    return .{
        .kind = c.LEAF_ADDRESS_KIND_DOMAIN,
        .port = port,
        .data = name.ptr,
        .data_len = name.len,
    };
}

fn createInstanceForTest(args: [*c]const u8, destination: *const c.PluginAddress) ?*anyopaque {
    var callbacks: c.HostCallbacks = .{
        .size = @sizeOf(c.HostCallbacks),
        .log = countingLog,
        .wake = null,
        .host_ctx = null,
    };
    const create_args: c.EngineCreateArgs = .{
        .size = @sizeOf(c.EngineCreateArgs),
        .plugin_args = args,
        .destination = destination,
        .host_callbacks = &callbacks,
        .host_abi_major = c.LEAF_PLUGIN_ABI_MAJOR,
        .host_abi_minor = c.LEAF_PLUGIN_ABI_MINOR,
    };
    return stream_engine.create_instance.?(&create_args);
}

/// A stand-in for the host: one engine, the two sides of the conversation, and
/// every call made through the vtable rather than around it.
const Driver = struct {
    instance: ?*anyopaque,
    wire: std.ArrayList(u8) = .empty,
    app: std.ArrayList(u8) = .empty,

    fn init(args: [*c]const u8, destination: *const c.PluginAddress) !Driver {
        const instance = createInstanceForTest(args, destination) orelse return error.CreateFailed;
        return .{ .instance = instance };
    }

    fn deinit(self: *Driver) void {
        stream_engine.destroy_instance.?(self.instance);
        self.wire.deinit(testing.allocator);
        self.app.deinit(testing.allocator);
    }

    fn state(self: *Driver) c.leaf_stream_state_flags_t {
        var flags: c.leaf_stream_state_flags_t = 0;
        std.debug.assert(stream_engine.poll_state.?(self.instance, &flags) == c.LEAF_ENGINE_STATUS_OK);
        return flags;
    }

    /// Drains whichever side the engine says has output, exactly as the host
    /// does.
    fn drain(self: *Driver) !void {
        var out: [1024]u8 = undefined;
        while (true) {
            const flags = self.state();
            var produced: usize = 0;
            if (flags & c.LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT != 0) {
                if (stream_engine.pull.?(self.instance, c.LEAF_STREAM_SIDE_NET, &out, out.len, &produced) !=
                    c.LEAF_ENGINE_STATUS_OK or produced == 0) return;
                try self.wire.appendSlice(testing.allocator, out[0..produced]);
                continue;
            }
            if (flags & c.LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT != 0) {
                if (stream_engine.pull.?(self.instance, c.LEAF_STREAM_SIDE_APP, &out, out.len, &produced) !=
                    c.LEAF_ENGINE_STATUS_OK or produced == 0) return;
                try self.app.appendSlice(testing.allocator, out[0..produced]);
                continue;
            }
            return;
        }
    }

    fn fromServer(self: *Driver, bytes: []const u8) !c.leaf_engine_status_t {
        var consumed: usize = 0;
        const status = stream_engine.push.?(
            self.instance,
            c.LEAF_STREAM_SIDE_NET,
            bytes.ptr,
            bytes.len,
            &consumed,
        );
        if (status == c.LEAF_ENGINE_STATUS_OK) {
            try testing.expectEqual(bytes.len, consumed);
            try self.drain();
        }
        return status;
    }

    fn fromApp(self: *Driver, bytes: []const u8) !usize {
        var consumed: usize = 0;
        const status = stream_engine.push.?(
            self.instance,
            c.LEAF_STREAM_SIDE_APP,
            bytes.ptr,
            bytes.len,
            &consumed,
        );
        try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, status);
        try self.drain();
        return consumed;
    }

    /// Forgets what has been collected, so a later assertion is about what came
    /// after this point rather than about everything so far.
    fn resetWire(self: *Driver) void {
        self.wire.clearRetainingCapacity();
    }

    fn acceptWithoutAuth(self: *Driver) !void {
        try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, try self.fromServer(&.{ 0x05, 0x00 }));
        try testing.expectEqual(
            c.LEAF_ENGINE_STATUS_OK,
            try self.fromServer(&.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }),
        );
    }
};

// The greeting has to be queued at creation, not on the first write: the host
// drains the network side while the application is only reading, and a proxy
// whose peer speaks first would otherwise never start.
test "the greeting is ready before any write" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();

    const flags = d.state();
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT != 0);
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_HANDSHAKING != 0);
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT != 0);
    // Nothing may go out ahead of the reply, so this side stays unadvertised.
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT == 0);

    try d.drain();
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x01, 0x00 }, d.wire.items);
}

// Credentials in args mean both methods are offered, so one configuration works
// against a server that wants them and one that does not.
test "the greeting offers both methods when credentials are configured" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("user:secret", &destination);
    defer d.deinit();

    try d.drain();
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x02, 0x00, 0x02 }, d.wire.items);
}

test "the whole no-auth handshake, then a session" {
    const octets = [4]u8{ 93, 184, 216, 34 };
    const destination = ipv4Destination(&octets, 443);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();
    d.resetWire();

    // Application data must not go out ahead of the reply.
    try testing.expectEqual(@as(usize, 0), try d.fromApp("early"));
    try testing.expectEqual(@as(usize, 0), d.wire.items.len);

    try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, try d.fromServer(&.{ 0x05, 0x00 }));
    try testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xbb },
        d.wire.items,
    );
    d.resetWire();

    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_OK,
        try d.fromServer(&.{ 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90 }),
    );
    const flags = d.state();
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_ESTABLISHED != 0);
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT != 0);
    try testing.expectEqual(@as(usize, 0), d.wire.items.len);

    // From here the engine adds nothing in either direction.
    try testing.expectEqual(@as(usize, 4), try d.fromApp("ping"));
    try testing.expectEqualSlices(u8, "ping", d.wire.items);
    try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, try d.fromServer("pong"));
    try testing.expectEqualSlices(u8, "pong", d.app.items);
}

// A domain destination travels as a name, which is a different branch of the
// address encoder and the one a proxy is usually asked for.
test "a domain destination travels as a name" {
    const name = "origin.e2e.invalid";
    const destination = domainDestination(name, 8080);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();
    d.resetWire();

    _ = try d.fromServer(&.{ 0x05, 0x00 });

    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(testing.allocator);
    try want.appendSlice(testing.allocator, &.{ 0x05, 0x01, 0x00, 0x03, name.len });
    try want.appendSlice(testing.allocator, name);
    try want.appendSlice(testing.allocator, &.{ 0x1f, 0x90 });
    try testing.expectEqualSlices(u8, want.items, d.wire.items);
}

// A handshake that arrives a byte at a time is the ordinary case on a stream,
// and the engine has to wait rather than misread a partial message.
test "a handshake arriving one byte at a time" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();

    // A reply whose bound address is a domain: its length is not known until
    // the length byte itself has arrived.
    const conversation = [_]u8{
        0x05, 0x00, // method selection
        0x05, 0x00, 0x00, 0x03, 0x04, 'h', 'o', 's', 't', 0x00, 0x50, // reply
    };
    for (conversation, 0..) |byte, index| {
        try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, try d.fromServer(&.{byte}));
        const established = d.state() & c.LEAF_STREAM_ENGINE_STATE_ESTABLISHED != 0;
        try testing.expectEqual(index + 1 == conversation.len, established);
    }
}

test "bytes after the reply are session data" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();

    _ = try d.fromServer(&.{ 0x05, 0x00 });
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_OK,
        try d.fromServer(&.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 'g', 'r', 'e', 'e', 't' }),
    );
    try testing.expectEqualSlices(u8, "greet", d.app.items);
}

test "the username and password exchange" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("leaf:hunter2", &destination);
    defer d.deinit();
    try d.drain();
    d.resetWire();

    try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, try d.fromServer(&.{ 0x05, 0x02 }));
    try testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x04, 'l', 'e', 'a', 'f', 0x07, 'h', 'u', 'n', 't', 'e', 'r', '2' },
        d.wire.items,
    );
    d.resetWire();

    try testing.expectEqual(c.LEAF_ENGINE_STATUS_OK, try d.fromServer(&.{ 0x01, 0x00 }));
    try testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 },
        d.wire.items,
    );

    // A password may contain colons; the first one is the separator.
    var colons = try Driver.init("leaf:a:b", &destination);
    defer colons.deinit();
    try colons.drain();
    colons.resetWire();
    _ = try colons.fromServer(&.{ 0x05, 0x02 });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x04, 'l', 'e', 'a', 'f', 0x03, 'a', ':', 'b' },
        colons.wire.items,
    );
}

// Every way a server can end the handshake badly has to reach the host as a
// fatal engine with a reason, not as a connection that hangs.
test "a refusing server is fatal, with a reason" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);

    const cases = [_]struct { args: [*c]const u8, bytes: []const u8 }{
        .{ .args = "", .bytes = &.{ 0x05, 0xff } },
        .{ .args = "", .bytes = &.{ 0x04, 0x00 } },
        .{ .args = "", .bytes = &.{ 0x05, 0x03 } },
        .{ .args = "", .bytes = &.{ 0x05, 0x02 } },
        .{ .args = "u:p", .bytes = &.{ 0x05, 0x02, 0x01, 0x01 } },
        .{ .args = "", .bytes = &.{ 0x05, 0x00, 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 } },
        .{ .args = "", .bytes = &.{ 0x05, 0x00, 0x05, 0x00, 0x00, 0x7f, 0, 0, 0, 0 } },
    };

    for (cases) |case| {
        var d = try Driver.init(case.args, &destination);
        defer d.deinit();
        try d.drain();
        _ = try d.fromServer(case.bytes);

        try testing.expect(d.state() & c.LEAF_STREAM_ENGINE_STATE_FATAL != 0);

        // The host asks twice: once for the length, once with a buffer.
        var code: c.leaf_engine_status_t = 0;
        var written: usize = 0;
        try testing.expectEqual(
            c.LEAF_ENGINE_STATUS_OK,
            stream_engine.get_last_error.?(d.instance, &code, null, 0, &written),
        );
        try testing.expectEqual(c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE, code);
        try testing.expect(written > 0);

        var message: [max_message_len]u8 = undefined;
        var again: usize = 0;
        _ = stream_engine.get_last_error.?(d.instance, &code, &message, written, &again);
        try testing.expectEqual(written, again);
    }
}

// A peer that disappears mid handshake is a failed connection, not an empty
// one, and the difference is what an operator reads in the log.
test "a peer that closes mid handshake is fatal" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();

    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE,
        stream_engine.close.?(d.instance, c.LEAF_STREAM_ENGINE_CLOSE_NET),
    );
    try testing.expect(d.state() & c.LEAF_STREAM_ENGINE_STATE_FATAL != 0);
}

test "the same close once the session is up is an ordinary end of stream" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();
    try d.acceptWithoutAuth();

    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_OK,
        stream_engine.close.?(d.instance, c.LEAF_STREAM_ENGINE_CLOSE_NET),
    );
    const flags = d.state();
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_PEER_CLOSED != 0);
    try testing.expect(flags & c.LEAF_STREAM_ENGINE_STATE_FATAL == 0);
}

// Once the application has closed its side, a write to it is a host bug and has
// to be refused rather than quietly encoded.
test "writes after the application close are refused" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();
    try d.drain();
    try d.acceptWithoutAuth();

    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_OK,
        stream_engine.close.?(d.instance, c.LEAF_STREAM_ENGINE_CLOSE_APP),
    );
    var consumed: usize = 0;
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_PLUGIN_FAILURE,
        stream_engine.push.?(d.instance, c.LEAF_STREAM_SIDE_APP, "x", 1, &consumed),
    );
    try testing.expectEqual(@as(usize, 0), consumed);
}

// Arguments and destinations the plugin cannot use have to fail at creation,
// where the host turns them into a message naming the outbound.
test "creation refuses what it cannot use" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const good = ipv4Destination(&octets, 80);

    try testing.expect(createInstanceForTest("nocolon", &good) == null);
    try testing.expect(createInstanceForTest(":password", &good) == null);

    var short_ipv4 = good;
    short_ipv4.data_len = 3;
    try testing.expect(createInstanceForTest("", &short_ipv4) == null);

    var unknown = good;
    unknown.kind = 0x7f;
    try testing.expect(createInstanceForTest("", &unknown) == null);

    const empty_domain = domainDestination("", 80);
    try testing.expect(createInstanceForTest("", &empty_domain) == null);

    const too_long = domainDestination("a" ** (max_domain_len + 1), 80);
    try testing.expect(createInstanceForTest("", &too_long) == null);

    // With no instance to ask, the host reads the reason from the thread the
    // failed call was made on.
    var code: c.leaf_engine_status_t = 0;
    var written: usize = 0;
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_OK,
        stream_engine.get_last_error.?(null, &code, null, 0, &written),
    );
    try testing.expectEqual(c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT, code);
    try testing.expect(written > 0);

    // And a create that succeeds clears it again.
    const instance = createInstanceForTest("", &good);
    try testing.expect(instance != null);
    _ = stream_engine.get_last_error.?(null, &code, null, 0, &written);
    try testing.expectEqual(@as(usize, 0), written);
    stream_engine.destroy_instance.?(instance);
}

// The entries the host calls without an instance, or with arguments the ABI
// says cannot happen, still have to answer rather than reach into null.
test "null arguments are refused" {
    const octets = [4]u8{ 127, 0, 0, 1 };
    const destination = ipv4Destination(&octets, 80);
    var d = try Driver.init("", &destination);
    defer d.deinit();

    var size: usize = 0;
    var flags: c.leaf_stream_state_flags_t = 0;
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
        stream_engine.poll_state.?(null, &flags),
    );
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
        stream_engine.poll_state.?(d.instance, null),
    );
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
        stream_engine.push.?(d.instance, c.LEAF_STREAM_SIDE_APP, null, 4, &size),
    );
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
        stream_engine.push.?(d.instance, 0x99, "x", 1, &size),
    );
    var scratch: [4]u8 = undefined;
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
        stream_engine.pull.?(d.instance, 0x99, &scratch, scratch.len, &size),
    );
    try testing.expectEqual(
        c.LEAF_ENGINE_STATUS_INVALID_ARGUMENT,
        stream_engine.close.?(null, 0),
    );
    // destroy_instance(null) is explicitly allowed and must do nothing.
    stream_engine.destroy_instance.?(null);
}

// The descriptor is what the host reads before anything else; a plugin that
// gets it wrong never loads.
test "the descriptor is what the host expects" {
    const d = leaf_plugin_get_descriptor();
    try testing.expect(d.size >= requiredSize(c.PluginDescriptor, "datagram"));
    try testing.expectEqual(@as(u32, c.LEAF_PLUGIN_ABI_MAJOR), d.abi_major);
    try testing.expect(d.name != null and d.name[0] != 0);
    try testing.expect(d.version != null and d.version[0] != 0);
    try testing.expect(d.datagram == null);
    try testing.expect(d.stream != null);
    try testing.expect(d.stream.*.size >= requiredSize(c.StreamEnginePlugin, "suggest_output_batch"));
    try testing.expectEqual(
        @as(u32, c.LEAF_STREAM_CONNECT_TYPE_PROXY_TCP),
        d.stream.*.connect_type,
    );
    // Every entry is required: the host refuses a vtable with a hole in it.
    inline for (@typeInfo(c.StreamEnginePlugin).@"struct".fields) |field| {
        if (@typeInfo(field.type) == .optional) {
            try testing.expect(@field(d.stream.*, field.name) != null);
        }
    }
    // The same pointer every time: the host reads it once and keeps it.
    try testing.expectEqual(d, leaf_plugin_get_descriptor());
}

// The buffer under every queue: consuming the front must not lose the back, and
// an append after a partial read must not corrupt what is left.
test "the buffer survives partial reads" {
    var b: Buffer = .{};
    defer b.deinit();

    for (0..4) |_| {
        try b.append("0123456789");
        var out: [4]u8 = undefined;
        try testing.expectEqual(@as(usize, 4), b.take(&out));
        try testing.expectEqualSlices(u8, "0123", &out);
        try b.append("abcdef");
        var rest: [64]u8 = undefined;
        try testing.expectEqual(@as(usize, 12), b.take(&rest));
        try testing.expectEqualSlices(u8, "456789abcdef", rest[0..12]);
        try testing.expectEqual(@as(usize, 0), b.len());
    }

    // One append far larger than the initial capacity, to grow it.
    const big = [_]u8{0x5a} ** 8192;
    try b.append(&big);
    try testing.expectEqual(big.len, b.len());
}

test "the engine logs through the host" {
    try testing.expect(logged_messages > 0);
}
