#!/usr/bin/env sh

set -ex

name=leaf
package=leaf-ffi
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

if [ -z "${NDK_HOME}" ]; then
	echo "NDK_HOME is not set" >&2
	exit 1
fi

if [ ! -d "${NDK_HOME}" ]; then
	echo "NDK_HOME does not exist: ${NDK_HOME}" >&2
	exit 1
fi

if [ ! -d "${NDK_HOME}/toolchains/llvm/prebuilt/${HOST_OS}-${HOST_ARCH}/bin" ]; then
	HOST_ARCH=`uname -m | tr "[:upper:]" "[:lower:]"`
	if [ ! -d "${NDK_HOME}/toolchains/llvm/prebuilt/${HOST_OS}-${HOST_ARCH}/bin" ]; then
		echo "NDK toolchain not found under: ${NDK_HOME}/toolchains/llvm/prebuilt/${HOST_OS}-${HOST_ARCH}/bin" >&2
		exit 1
	fi
fi

export PATH="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin/":$PATH

android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin"
api=21

export ANDROID_NDK_ROOT="$NDK_HOME"
export ANDROID_NDK="$NDK_HOME"
export ANDROID_NDK_HOME="$NDK_HOME"
export CMAKE_GENERATOR=Ninja

# See also: https://github.com/briansmith/ring/blob/main/mk/cargo.sh

profile=release
if [ -z "$mode" ]; then
	profile=debug
fi

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

android_libs=$BASE/../target/leaf-android-libs

mkdir -p $android_libs
for target in $targets; do
	mv $BASE/../target/$target/$profile/libleaf.so $android_libs/libleaf-$target.so
done
cbindgen \
	--config $BASE/../$package/cbindgen.toml \
	$BASE/../$package/src/lib.rs > $android_libs/$name.h
