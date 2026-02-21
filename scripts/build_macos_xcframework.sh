#!/usr/bin/env sh

set -ex

# Source common functions
. $(dirname "$0")/apple_common.sh

setup_env "$1"
clean_dir
build_macos_libs
generate_header

# Create XCFramework for macOS only
rm -rf "$BASE_DIR/$name.xcframework"

xcodebuild -create-xcframework \
    -library "$BASE_DIR/macos/$lib" \
    -headers "$INCLUDE_DIR" \
    -output "$BASE_DIR/$name.xcframework"

ls -d "$BASE_DIR/$name.xcframework"
