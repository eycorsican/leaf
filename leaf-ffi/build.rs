//! Compiles the C plugins this library is built with.
//!
//! A C plugin linked in rather than loaded is compiled with
//! `LEAF_PLUGIN_STATIC_NAME`, which renames its descriptor function to
//! `leaf_plugin_<name>_get_descriptor` and stops it being exported; see
//! `leaf_plugin_abi.h`. `src/lib.rs` declares that function and registers it.

fn main() {
    #[cfg(feature = "plugin-socks5-c")]
    compile_c_plugin("socks5_c", "../leaf-plugins/socks5-cabi-c/socks5.c");
}

#[cfg(feature = "plugin-socks5-c")]
fn compile_c_plugin(name: &str, source: &str) {
    println!("cargo:rerun-if-changed={}", source);
    println!("cargo:rerun-if-changed=../leaf-plugin-abi/include/leaf_plugin_abi.h");
    let mut build = cc::Build::new();
    build
        .file(source)
        .include("../leaf-plugin-abi/include")
        .define("LEAF_PLUGIN_STATIC_NAME", name)
        .warnings(true);
    // MSVC has no -std flag to give; everything else wants C11.
    if !build.get_compiler().is_like_msvc() {
        build.flag("-std=c11");
    }
    build.compile(&format!("leaf_plugin_{}", name));
}
