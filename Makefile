ios:
	cargo lipo -p leaf-ffi --release --targets aarch64-apple-ios --manifest-path leaf-ffi/Cargo.toml
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/universal/release/leaf.h

ios-dev:
	cargo lipo -p leaf-ffi --targets aarch64-apple-ios --manifest-path leaf-ffi/Cargo.toml
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/universal/debug/leaf.h

lib:
	cargo build -p leaf-ffi --release
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/release/leaf.h

local:
	cargo build -p leaf-bin --release

local-dev:
	cargo build -p leaf-bin

test:
	cargo test -p leaf

# Force a re-generation of protobuf files.
proto-gen:
	touch leaf/build.rs
	PROTO_GEN=1 cargo build -p leaf
