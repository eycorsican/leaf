//! `PluginDescriptor::flags` was appended in minor 1, and the whole point of
//! appending rather than inserting is that a plugin built before it still
//! loads. These are the two things that has to mean.

use std::mem::{offset_of, size_of};

use leaf_plugin_abi::*;

/// A descriptor as a plugin built against minor 0 writes it: no `flags` field
/// at all, and a `size` that says so.
fn minor_zero_descriptor() -> PluginDescriptor {
    PluginDescriptor {
        size: PluginDescriptor::REQUIRED_SIZE,
        abi_major: PLUGIN_ABI_MAJOR,
        abi_minor: 0,
        name: c"old-plugin".as_ptr(),
        version: c"0.1.0".as_ptr(),
        stream: core::ptr::null(),
        datagram: core::ptr::null(),
        // Whatever this build happens to leave here is exactly what the host
        // must not read, because the plugin's `size` says it is not there.
        flags: PLUGIN_FLAG_EMBEDS_RUNTIME,
    }
}

/// The required prefix is frozen for the lifetime of the major version.
///
/// If someone moves `impl_abi_struct!` on to `flags`, this fails -- which is
/// the point. Doing so would refuse every plugin built against minor 0, whose
/// descriptor is smaller than the prefix would then demand.
#[test]
fn appending_flags_did_not_enlarge_the_required_prefix() {
    let frozen = offset_of!(PluginDescriptor, datagram) + size_of::<*const DatagramEnginePlugin>();
    assert_eq!(
        PluginDescriptor::REQUIRED_SIZE,
        frozen,
        "the required prefix must end at `datagram`, not at a field appended later"
    );
    assert!(
        size_of::<PluginDescriptor>() > PluginDescriptor::REQUIRED_SIZE,
        "this test is meaningless unless the struct has grown past the prefix"
    );
}

/// A plugin that predates the field reads back as one that did not set it,
/// rather than as whatever bytes happened to follow its descriptor.
#[test]
fn a_minor_zero_descriptor_reads_back_with_no_flags() {
    let descriptor = minor_zero_descriptor();
    // SAFETY: `descriptor` is a live `PluginDescriptor`, and `declared_size` is
    // the value in its own `size` field, which is at least `REQUIRED_SIZE`.
    let read = unsafe { read_struct_prefix(&descriptor as *const PluginDescriptor, descriptor.size) };
    assert_eq!(
        read.flags, 0,
        "a field the plugin's `size` excludes must read back zero, not the memory after it"
    );
    assert_eq!(read.abi_minor, 0);
    assert!(read.stream.is_null());
}

/// And a plugin that does set it is believed.
#[test]
fn a_full_descriptor_carries_its_flags_through() {
    let descriptor = PluginDescriptor {
        size: size_of::<PluginDescriptor>(),
        abi_minor: PLUGIN_ABI_MINOR,
        ..minor_zero_descriptor()
    };
    // SAFETY: as above.
    let read = unsafe { read_struct_prefix(&descriptor as *const PluginDescriptor, descriptor.size) };
    assert_eq!(read.flags & PLUGIN_FLAG_EMBEDS_RUNTIME, PLUGIN_FLAG_EMBEDS_RUNTIME);
}
