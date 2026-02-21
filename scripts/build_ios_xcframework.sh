#!/usr/bin/env sh

set -ex

# Source common functions
. $(dirname "$0")/apple_common.sh

setup_env "$1"
clean_dir
build_ios_libs
generate_header

# Create XCFramework for iOS only
rm -rf "$BASE_DIR/$name.xcframework"

xcodebuild -create-xcframework \
    -library "$BASE_DIR/ios/$lib" \
    -headers "$INCLUDE_DIR" \
    -library "$BASE_DIR/ios-sim/$lib" \
    -headers "$INCLUDE_DIR" \
    -output "$BASE_DIR/$name.xcframework"

ls -d "$BASE_DIR/$name.xcframework"
