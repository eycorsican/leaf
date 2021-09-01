use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn compile_lwip() {
    println!("cargo:rerun-if-changed=src/proxy/tun/netstack/lwip");
    cc::Build::new()
        .file("src/proxy/tun/netstack/lwip/core/init.c")
        .file("src/proxy/tun/netstack/lwip/core/def.c")
        // .file("src/proxy/tun/netstack/lwip/core/dns.c")
        .file("src/proxy/tun/netstack/lwip/core/inet_chksum.c")
        .file("src/proxy/tun/netstack/lwip/core/ip.c")
        .file("src/proxy/tun/netstack/lwip/core/mem.c")
        .file("src/proxy/tun/netstack/lwip/core/memp.c")
        .file("src/proxy/tun/netstack/lwip/core/netif.c")
        .file("src/proxy/tun/netstack/lwip/core/pbuf.c")
        .file("src/proxy/tun/netstack/lwip/core/raw.c")
        // .file("src/proxy/tun/netstack/lwip/core/stats.c")
        // .file("src/proxy/tun/netstack/lwip/core/sys.c")
        .file("src/proxy/tun/netstack/lwip/core/tcp.c")
        .file("src/proxy/tun/netstack/lwip/core/tcp_in.c")
        .file("src/proxy/tun/netstack/lwip/core/tcp_out.c")
        .file("src/proxy/tun/netstack/lwip/core/timeouts.c")
        .file("src/proxy/tun/netstack/lwip/core/udp.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv4/autoip.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv4/dhcp.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv4/etharp.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv4/icmp.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv4/igmp.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv4/ip4_frag.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv4/ip4.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv4/ip4_addr.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv6/dhcp6.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv6/ethip6.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv6/icmp6.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv6/inet6.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv6/ip6.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv6/ip6_addr.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv6/ip6_frag.c")
        // .file("src/proxy/tun/netstack/lwip/core/ipv6/mld6.c")
        .file("src/proxy/tun/netstack/lwip/core/ipv6/nd6.c")
        .file("src/proxy/tun/netstack/lwip/custom/sys_arch.c")
        .include("src/proxy/tun/netstack/lwip/custom")
        .include("src/proxy/tun/netstack/lwip/include")
        .warnings(false)
        .flag_if_supported("-Wno-everything")
        .compile("liblwip.a");
}

fn generate_lwip_bindings() {
    println!("cargo:rustc-link-lib=lwip");
    // println!("cargo:rerun-if-changed=src/proxy/tun/netstack/wrapper.h");
    println!("cargo:include=src/proxy/tun/netstack/lwip/include");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let bindings = bindgen::Builder::default()
        .header("src/proxy/tun/netstack/wrapper.h")
        .clang_arg("-I./src/proxy/tun/netstack/lwip/include")
        .clang_arg("-I./src/proxy/tun/netstack/lwip/custom")
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

    let mut out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    out_path = out_path.join("src/proxy/tun/netstack");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn generate_mobile_bindings() {
    println!("cargo:rerun-if-changed=src/mobile/wrapper.h");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let bindings = bindgen::Builder::default()
        .header("src/mobile/wrapper.h")
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
        .write_to_file(out_path.join("mobile_bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    if env::var("CARGO_FEATURE_INBOUND_TUN").is_ok() {
        let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        if os == "ios" || os == "android" || os == "linux" || os == "macos" {
            compile_lwip();
        }

        if env::var("BINDINGS_GEN").is_ok()
            && (os == "ios" || os == "android" || os == "linux" || os == "macos")
        {
            generate_lwip_bindings();
        }
    }

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if os == "ios" || os == "macos" || os == "android" {
        generate_mobile_bindings();
    }

    if env::var("PROTO_GEN").is_ok() {
        // println!("cargo:rerun-if-changed=src/config/internal/config.proto");
        protoc_rust::Codegen::new()
            .out_dir("src/config/internal")
            .inputs(&["src/config/internal/config.proto"])
            .customize(protoc_rust::Customize {
                expose_oneof: Some(true),
                expose_fields: Some(true),
                generate_accessors: Some(false),
                lite_runtime: Some(true),
                ..Default::default()
            })
            .run()
            .expect("protoc");

        // println!("cargo:rerun-if-changed=src/config/geosite.proto");
        protoc_rust::Codegen::new()
            .out_dir("src/config")
            .inputs(&["src/config/geosite.proto"])
            .customize(protoc_rust::Customize {
                expose_oneof: Some(true),
                expose_fields: Some(true),
                generate_accessors: Some(false),
                lite_runtime: Some(true),
                ..Default::default()
            })
            .run()
            .expect("protoc");

        protoc_rust::Codegen::new()
            .out_dir("src/app/outbound")
            .inputs(&["src/app/outbound/selector_cache.proto"])
            .customize(protoc_rust::Customize {
                expose_oneof: Some(true),
                expose_fields: Some(true),
                generate_accessors: Some(false),
                lite_runtime: Some(true),
                ..Default::default()
            })
            .run()
            .expect("protoc");
    }
}
