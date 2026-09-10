//! Records the target triple this harness was built for.
//!
//! The harness builds plugins itself at run time, and those builds have to land
//! where it will look for them. Cargo nests the profile under the triple when
//! it was given an explicit `--target` (a sanitizer or cross lane), and does
//! not otherwise, so the harness needs to know both the triple and which layout
//! it is looking at. Only cargo knows the triple, and only here.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=LEAF_E2E_TARGET={}",
        std::env::var("TARGET").expect("cargo sets TARGET for build scripts")
    );
}
