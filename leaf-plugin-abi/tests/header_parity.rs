//! Checks that `include/leaf_plugin_abi.h` and `src/lib.rs` describe the same
//! ABI. Without this the C and Rust declarations drift silently, which is
//! exactly the failure mode a shared ABI crate exists to prevent.

use std::collections::BTreeMap;
use std::mem::{offset_of, size_of};
use std::path::PathBuf;
use std::process::Command;

use leaf_plugin_abi::*;

const C_PROBE: &str = r#"
#include <stdio.h>
#include <stddef.h>
#include "leaf_plugin_abi.h"

#define P_SIZE(s) printf("size:%s=%zu\n", #s, sizeof(s))
#define P_OFF(s, f) printf("off:%s.%s=%zu\n", #s, #f, offsetof(s, f))
#define P_CONST(c) printf("const:%s=%lld\n", #c, (long long)(c))

int main(void) {
    P_SIZE(PluginDescriptor);
    P_OFF(PluginDescriptor, size);
    P_OFF(PluginDescriptor, abi_major);
    P_OFF(PluginDescriptor, abi_minor);
    P_OFF(PluginDescriptor, name);
    P_OFF(PluginDescriptor, version);
    P_OFF(PluginDescriptor, stream);
    P_OFF(PluginDescriptor, datagram);
    P_OFF(PluginDescriptor, flags);

    P_SIZE(HostCallbacks);
    P_OFF(HostCallbacks, size);
    P_OFF(HostCallbacks, log);
    P_OFF(HostCallbacks, wake);
    P_OFF(HostCallbacks, host_ctx);

    P_SIZE(PluginAddress);
    P_OFF(PluginAddress, kind);
    P_OFF(PluginAddress, port);
    P_OFF(PluginAddress, data);
    P_OFF(PluginAddress, data_len);

    P_SIZE(EngineCreateArgs);
    P_OFF(EngineCreateArgs, size);
    P_OFF(EngineCreateArgs, plugin_args);
    P_OFF(EngineCreateArgs, destination);
    P_OFF(EngineCreateArgs, host_callbacks);
    P_OFF(EngineCreateArgs, host_abi_major);
    P_OFF(EngineCreateArgs, host_abi_minor);

    P_SIZE(StreamEnginePlugin);
    P_OFF(StreamEnginePlugin, size);
    P_OFF(StreamEnginePlugin, connect_type);
    P_OFF(StreamEnginePlugin, create_instance);
    P_OFF(StreamEnginePlugin, destroy_instance);
    P_OFF(StreamEnginePlugin, poll_state);
    P_OFF(StreamEnginePlugin, push);
    P_OFF(StreamEnginePlugin, pull);
    P_OFF(StreamEnginePlugin, close);
    P_OFF(StreamEnginePlugin, get_last_error);
    P_OFF(StreamEnginePlugin, suggest_output_size);
    P_OFF(StreamEnginePlugin, suggest_output_batch);

    P_SIZE(DatagramEnginePlugin);
    P_OFF(DatagramEnginePlugin, size);
    P_OFF(DatagramEnginePlugin, transport_type);
    P_OFF(DatagramEnginePlugin, create_instance);
    P_OFF(DatagramEnginePlugin, destroy_instance);
    P_OFF(DatagramEnginePlugin, encode_packet);
    P_OFF(DatagramEnginePlugin, decode_packet);
    P_OFF(DatagramEnginePlugin, max_output_size);
    P_OFF(DatagramEnginePlugin, max_address_size);
    P_OFF(DatagramEnginePlugin, get_last_error);

    P_CONST(LEAF_PLUGIN_ABI_MAJOR);
    P_CONST(LEAF_PLUGIN_ABI_MINOR);
    P_CONST(LEAF_PLUGIN_DESCRIPTOR_REQUIRED_SIZE);
    P_CONST(LEAF_HOST_CALLBACKS_REQUIRED_SIZE);
    P_CONST(LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE);
    P_CONST(LEAF_STREAM_ENGINE_PLUGIN_REQUIRED_SIZE);
    P_CONST(LEAF_DATAGRAM_ENGINE_PLUGIN_REQUIRED_SIZE);
    P_CONST(LEAF_ENGINE_STATUS_OK);
    P_CONST(LEAF_ENGINE_STATUS_INVALID_ARGUMENT);
    P_CONST(LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL);
    P_CONST(LEAF_ENGINE_STATUS_UNSUPPORTED);
    P_CONST(LEAF_ENGINE_STATUS_PLUGIN_FAILURE);
    P_CONST(LEAF_LOG_LEVEL_ERROR);
    P_CONST(LEAF_LOG_LEVEL_WARN);
    P_CONST(LEAF_LOG_LEVEL_INFO);
    P_CONST(LEAF_LOG_LEVEL_DEBUG);
    P_CONST(LEAF_LOG_LEVEL_TRACE);
    P_CONST(LEAF_ADDRESS_KIND_IPV4);
    P_CONST(LEAF_ADDRESS_KIND_IPV6);
    P_CONST(LEAF_ADDRESS_KIND_DOMAIN);
    P_CONST(LEAF_DATAGRAM_DIRECTION_ENCODE);
    P_CONST(LEAF_DATAGRAM_DIRECTION_DECODE);
    P_CONST(LEAF_DATAGRAM_TRANSPORT_TYPE_RELIABLE);
    P_CONST(LEAF_DATAGRAM_TRANSPORT_TYPE_UNRELIABLE);
    P_CONST(LEAF_STREAM_CONNECT_TYPE_PROXY_TCP);
    P_CONST(LEAF_STREAM_CONNECT_TYPE_DIRECT);
    P_CONST(LEAF_STREAM_CONNECT_TYPE_NEXT);
    P_CONST(LEAF_STREAM_SIDE_APP);
    P_CONST(LEAF_STREAM_SIDE_NET);
    P_CONST(LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT);
    P_CONST(LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT);
    P_CONST(LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT);
    P_CONST(LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT);
    P_CONST(LEAF_STREAM_ENGINE_STATE_HANDSHAKING);
    P_CONST(LEAF_STREAM_ENGINE_STATE_ESTABLISHED);
    P_CONST(LEAF_STREAM_ENGINE_STATE_PEER_CLOSED);
    P_CONST(LEAF_STREAM_ENGINE_STATE_FATAL);
    P_CONST(LEAF_STREAM_ENGINE_STATE_BLOCKED);
    P_CONST(LEAF_STREAM_ENGINE_CLOSE_APP);
    P_CONST(LEAF_STREAM_ENGINE_CLOSE_NET);
    P_CONST(LEAF_PLUGIN_FLAG_EMBEDS_RUNTIME);
    return 0;
}
"#;

fn c_compiler() -> String {
    std::env::var("CC").unwrap_or_else(|_| "cc".to_string())
}

/// Compiles and runs the C probe, returning every `key=value` pair it printed.
fn c_layout() -> BTreeMap<String, i64> {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&tmp).expect("create tmp dir");
    let src = tmp.join("leaf_plugin_abi_probe.c");
    let bin = tmp.join("leaf_plugin_abi_probe");
    std::fs::write(&src, C_PROBE).expect("write probe source");

    let include = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include");
    let cc = c_compiler();
    let status = Command::new(&cc)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Werror")
        .arg("-I")
        .arg(&include)
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .status()
        .unwrap_or_else(|err| panic!("failed to run C compiler [{}]: {}", cc, err));
    assert!(status.success(), "C probe failed to compile with [{}]", cc);

    let output = Command::new(&bin).output().expect("run probe");
    assert!(output.status.success(), "C probe exited with failure");
    String::from_utf8(output.stdout)
        .expect("probe output is utf-8")
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.parse().expect("probe value")))
        .collect()
}

#[test]
fn c_header_matches_rust_definitions() {
    let c = c_layout();
    let mut rust: BTreeMap<String, i64> = BTreeMap::new();

    macro_rules! size {
        ($t:ty) => {
            rust.insert(format!("size:{}", stringify!($t)), size_of::<$t>() as i64);
        };
    }
    macro_rules! off {
        ($t:ty, $($f:ident),+ $(,)?) => {$(
            rust.insert(
                format!("off:{}.{}", stringify!($t), stringify!($f)),
                offset_of!($t, $f) as i64,
            );
        )+};
    }
    macro_rules! konst {
        ($($c:ident => $name:literal),+ $(,)?) => {$(
            rust.insert(format!("const:{}", $name), $c as i64);
        )+};
    }

    size!(PluginDescriptor);
    off!(
        PluginDescriptor,
        size,
        abi_major,
        abi_minor,
        name,
        version,
        stream,
        datagram,
        flags
    );
    size!(HostCallbacks);
    off!(HostCallbacks, size, log, wake, host_ctx);
    size!(PluginAddress);
    off!(PluginAddress, kind, port, data, data_len);
    size!(EngineCreateArgs);
    off!(
        EngineCreateArgs,
        size,
        plugin_args,
        destination,
        host_callbacks,
        host_abi_major,
        host_abi_minor,
    );
    size!(StreamEnginePlugin);
    off!(
        StreamEnginePlugin,
        size,
        connect_type,
        create_instance,
        destroy_instance,
        poll_state,
        push,
        pull,
        close,
        get_last_error,
        suggest_output_size,
        suggest_output_batch,
    );
    size!(DatagramEnginePlugin);
    off!(
        DatagramEnginePlugin,
        size,
        transport_type,
        create_instance,
        destroy_instance,
        encode_packet,
        decode_packet,
        max_output_size,
        max_address_size,
        get_last_error,
    );

    konst! {
        PLUGIN_ABI_MAJOR => "LEAF_PLUGIN_ABI_MAJOR",
        PLUGIN_ABI_MINOR => "LEAF_PLUGIN_ABI_MINOR",
        ENGINE_STATUS_OK => "LEAF_ENGINE_STATUS_OK",
        ENGINE_STATUS_INVALID_ARGUMENT => "LEAF_ENGINE_STATUS_INVALID_ARGUMENT",
        ENGINE_STATUS_BUFFER_TOO_SMALL => "LEAF_ENGINE_STATUS_BUFFER_TOO_SMALL",
        ENGINE_STATUS_UNSUPPORTED => "LEAF_ENGINE_STATUS_UNSUPPORTED",
        ENGINE_STATUS_PLUGIN_FAILURE => "LEAF_ENGINE_STATUS_PLUGIN_FAILURE",
        LOG_LEVEL_ERROR => "LEAF_LOG_LEVEL_ERROR",
        LOG_LEVEL_WARN => "LEAF_LOG_LEVEL_WARN",
        LOG_LEVEL_INFO => "LEAF_LOG_LEVEL_INFO",
        LOG_LEVEL_DEBUG => "LEAF_LOG_LEVEL_DEBUG",
        LOG_LEVEL_TRACE => "LEAF_LOG_LEVEL_TRACE",
        ADDRESS_KIND_IPV4 => "LEAF_ADDRESS_KIND_IPV4",
        ADDRESS_KIND_IPV6 => "LEAF_ADDRESS_KIND_IPV6",
        ADDRESS_KIND_DOMAIN => "LEAF_ADDRESS_KIND_DOMAIN",
        DATAGRAM_DIRECTION_ENCODE => "LEAF_DATAGRAM_DIRECTION_ENCODE",
        DATAGRAM_DIRECTION_DECODE => "LEAF_DATAGRAM_DIRECTION_DECODE",
        DATAGRAM_TRANSPORT_TYPE_RELIABLE => "LEAF_DATAGRAM_TRANSPORT_TYPE_RELIABLE",
        DATAGRAM_TRANSPORT_TYPE_UNRELIABLE => "LEAF_DATAGRAM_TRANSPORT_TYPE_UNRELIABLE",
        STREAM_CONNECT_TYPE_PROXY_TCP => "LEAF_STREAM_CONNECT_TYPE_PROXY_TCP",
        STREAM_CONNECT_TYPE_DIRECT => "LEAF_STREAM_CONNECT_TYPE_DIRECT",
        STREAM_CONNECT_TYPE_NEXT => "LEAF_STREAM_CONNECT_TYPE_NEXT",
        STREAM_SIDE_APP => "LEAF_STREAM_SIDE_APP",
        STREAM_SIDE_NET => "LEAF_STREAM_SIDE_NET",
        STREAM_ENGINE_STATE_WANT_APP_INPUT => "LEAF_STREAM_ENGINE_STATE_WANT_APP_INPUT",
        STREAM_ENGINE_STATE_WANT_NET_INPUT => "LEAF_STREAM_ENGINE_STATE_WANT_NET_INPUT",
        STREAM_ENGINE_STATE_HAS_APP_OUTPUT => "LEAF_STREAM_ENGINE_STATE_HAS_APP_OUTPUT",
        STREAM_ENGINE_STATE_HAS_NET_OUTPUT => "LEAF_STREAM_ENGINE_STATE_HAS_NET_OUTPUT",
        STREAM_ENGINE_STATE_HANDSHAKING => "LEAF_STREAM_ENGINE_STATE_HANDSHAKING",
        STREAM_ENGINE_STATE_ESTABLISHED => "LEAF_STREAM_ENGINE_STATE_ESTABLISHED",
        STREAM_ENGINE_STATE_PEER_CLOSED => "LEAF_STREAM_ENGINE_STATE_PEER_CLOSED",
        STREAM_ENGINE_STATE_FATAL => "LEAF_STREAM_ENGINE_STATE_FATAL",
        STREAM_ENGINE_STATE_BLOCKED => "LEAF_STREAM_ENGINE_STATE_BLOCKED",
        STREAM_ENGINE_CLOSE_APP => "LEAF_STREAM_ENGINE_CLOSE_APP",
        STREAM_ENGINE_CLOSE_NET => "LEAF_STREAM_ENGINE_CLOSE_NET",
        PLUGIN_FLAG_EMBEDS_RUNTIME => "LEAF_PLUGIN_FLAG_EMBEDS_RUNTIME",
    }

    for (name, required) in [
        (
            "LEAF_PLUGIN_DESCRIPTOR_REQUIRED_SIZE",
            PluginDescriptor::REQUIRED_SIZE,
        ),
        (
            "LEAF_HOST_CALLBACKS_REQUIRED_SIZE",
            HostCallbacks::REQUIRED_SIZE,
        ),
        (
            "LEAF_ENGINE_CREATE_ARGS_REQUIRED_SIZE",
            EngineCreateArgs::REQUIRED_SIZE,
        ),
        (
            "LEAF_STREAM_ENGINE_PLUGIN_REQUIRED_SIZE",
            StreamEnginePlugin::REQUIRED_SIZE,
        ),
        (
            "LEAF_DATAGRAM_ENGINE_PLUGIN_REQUIRED_SIZE",
            DatagramEnginePlugin::REQUIRED_SIZE,
        ),
    ] {
        rust.insert(format!("const:{name}"), required as i64);
    }

    let mut mismatches = Vec::new();
    for (key, rust_value) in &rust {
        match c.get(key) {
            Some(c_value) if c_value == rust_value => {}
            Some(c_value) => mismatches.push(format!("{key}: C={c_value} Rust={rust_value}")),
            None => mismatches.push(format!("{key}: missing from the C header probe")),
        }
    }
    for key in c.keys() {
        if !rust.contains_key(key) {
            mismatches.push(format!("{key}: missing from the Rust definitions"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "C header and Rust ABI definitions disagree:\n  {}",
        mismatches.join("\n  ")
    );
}
