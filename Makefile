ios:
	cargo lipo -p leaf-mobile --release --targets aarch64-apple-ios --manifest-path leaf-mobile/Cargo.toml
	cbindgen leaf-mobile/src/lib.rs -l c > target/universal/release/leaf.h

ios-dev:
	cargo lipo -p leaf-mobile --targets aarch64-apple-ios --manifest-path leaf-mobile/Cargo.toml
	cbindgen leaf-mobile/src/lib.rs -l c > target/universal/debug/leaf.h

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
