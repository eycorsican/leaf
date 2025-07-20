#!/usr/bin/env sh

set -ex

name=leaf
package=leaf-uniffi
manifest=android/Cargo.toml
mode=--release
targets=

if [ ! -z "$2" ]; then
	targets="$2"
else
	targets="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"
fi

for target in $targets; do
	rustup target add $target
done

if [ "$1" = "debug" ]; then
	mode=
fi

BASE=`dirname "$0"`
HOST_OS=`uname -s | tr "[:upper:]" "[:lower:]"`

# HOST_ARCH=`uname -m | tr "[:upper:]" "[:lower:]"`
HOST_ARCH=x86_64

export PATH="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin/":$PATH

android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin"
api=21

# See also: https://github.com/briansmith/ring/blob/main/mk/cargo.sh

for target in $targets; do
	case $target in
		'armv7-linux-androideabi')
			export CC_armv7_linux_androideabi="$android_tools/armv7a-linux-androideabi${api}-clang"
			export AR_armv7_linux_androideabi="$android_tools/llvm-ar"
			export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$android_tools/armv7a-linux-androideabi${api}-clang"
			;;
		'x86_64-linux-android')
			export CC_x86_64_linux_android="$android_tools/${target}${api}-clang"
			export AR_x86_64_linux_android="$android_tools/llvm-ar"
			export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			;;
		'aarch64-linux-android')
			export CC_aarch64_linux_android="$android_tools/${target}${api}-clang"
			export AR_aarch64_linux_android="$android_tools/llvm-ar"
			export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			;;
		'i686-linux-android')
			export CC_i686_linux_android="$android_tools/${target}${api}-clang"
			export AR_i686_linux_android="$android_tools/llvm-ar"
			export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			;;
		*)
			echo "Unknown target $target"
			;;
	esac
	cargo build -p $package --target $target $mode
done

# The output directory for JNI libs, conforming to the Android Studio project structure.
jni_libs_dir=$BASE/../jniLibs
# The output directory for the generated Kotlin binding code.
kotlin_out_dir=$BASE/../kotlin

# Clean up old artifacts and create directories.
rm -rf $jni_libs_dir
rm -rf $kotlin_out_dir
mkdir -p $kotlin_out_dir

# Copy the built libraries into the JNI directory structure.
for target in $targets; do
	abi=""
	case $target in
		'aarch64-linux-android')
			abi="arm64-v8a"
			;;
		'armv7-linux-androideabi')
			abi="armeabi-v7a"
			;;
		'x86_64-linux-android')
			abi="x86_64"
			;;
		'i686-linux-android')
			abi="x86"
			;;
		*)
			echo "Unknown target $target, skipping copy."
			continue
			;;
	esac

	target_dir="$jni_libs_dir/$abi"
	mkdir -p "$target_dir"

	src_path_segment="release"
	if [ "$mode" = "" ]; then
		src_path_segment="debug"
	fi

	cp "$BASE/../target/$target/$src_path_segment/libleafuniffi.so" "$target_dir/libleafuniffi.so"
done

# Build the library for the host system. This is required by uniffi-bindgen to
# generate the language bindings.
cargo build -p $package --lib $mode

# Determine the host library extension based on the OS.
host_lib_ext="so"
if [ "$HOST_OS" = "darwin" ]; then
    host_lib_ext="dylib"
elif [ "$HOST_OS" = "windows" ]; then
    host_lib_ext="dll"
fi

# Determine the source path for the host library.
src_path_segment="release"
if [ "$mode" = "" ]; then
    src_path_segment="debug"
fi
host_library_path="$BASE/../target/$src_path_segment/libleafuniffi.$host_lib_ext"

# Generate the Kotlin bindings.
cargo run -p $package --features=uniffi/cli --bin uniffi generate --library "$host_library_path" --language kotlin --out-dir "$kotlin_out_dir"

echo "Build finished."
echo "JNI libraries are in: $jni_libs_dir"
echo "Kotlin bindings are in: $kotlin_out_dir"
