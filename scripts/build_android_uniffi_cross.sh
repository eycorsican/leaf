#!/usr/bin/env sh

set -ex

# Package name for uniffi bindings
package=leaf-uniffi
# Build mode, defaults to release
mode=--release
# Default targets
targets="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"

# Allow overriding targets from the command line
if [ ! -z "$2" ]; then
	targets="$2"
fi

# Allow switching to debug mode
if [ "$1" = "debug" ]; then
	mode=
fi

BASE=`dirname "$0"`
HOST_OS=`uname -s | tr "[:upper:]" "[:lower:]"`

# Check for cross installation
if ! command -v cross > /dev/null
then
    echo "cross is not installed. Please install it by running 'cargo install cross'"
    exit 1
fi

# Build for each Android target using cross
for target in $targets; do
	cross build -p $package --target $target $mode
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

	# cross places output in the same target directory structure
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
cargo run -p uniffi-bin --features=uniffi/cli --bin uniffi generate --library "$host_library_path" --language kotlin --out-dir "$kotlin_out_dir"

echo "Build finished using cross."
echo "JNI libraries are in: $jni_libs_dir"
echo "Kotlin bindings are in: $kotlin_out_dir"
