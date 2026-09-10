//! Standalone build for the SOCKS5 Zig plugin.
//!
//! `zig build` produces the shared library under `zig-out`, and `zig build
//! test` runs the unit tests in `src/main.zig`. leaf's own end-to-end harness
//! calls `zig build-lib` directly instead, because it needs to name the output
//! path; this file is here so the plugin can be built and tested on its own,
//! the way a third-party plugin would be.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        // libc for the allocator and for the C ABI header.
        .link_libc = true,
    });
    module.addIncludePath(b.path("../../leaf-plugin-abi/include"));

    const library = b.addLibrary(.{
        .name = "socks5_cabi_zig",
        .root_module = module,
        .linkage = .dynamic,
    });
    b.installArtifact(library);

    const unit_tests = b.addTest(.{ .root_module = module });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run the plugin's unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
