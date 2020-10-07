use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-Wno-everything")
        .layout_tests(false)
        .clang_arg(if arch == "aarch64" && os == "ios" {
            // https://github.com/rust-lang/rust-bindgen/issues/1211
            "--target=arm64-apple-ios"
        } else {
            ""
        })
        .clang_arg(if arch == "aarch64" && os == "ios" {
            // sdk path find by `xcrun --sdk iphoneos --show-sdk-path`
            let output = Command::new("xcrun")
                .arg("--sdk")
                .arg("iphoneos")
                .arg("--show-sdk-path")
                .output()
                .expect("failed to execute xcrun");
            let inc_path =
                Path::new(String::from_utf8_lossy(&output.stdout).trim()).join("usr/include");
            format!("-I{}", inc_path.to_str().expect("invalid include path"))
        } else {
            "".to_string()
        })
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
