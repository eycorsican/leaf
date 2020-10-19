ios:
	cargo lipo -p leaf-mobile --release --targets aarch64-apple-ios && cp target/universal/release/libleaf.a /tmp/ && cbindgen leaf-mobile/src/lib.rs -l c > /tmp/leaf.h

ios-dev:
	cargo lipo -p leaf-mobile --targets aarch64-apple-ios && cp target/universal/debug/libleaf.a /tmp/ && cbindgen leaf-mobile/src/lib.rs -l c > /tmp/leaf.h

local:
	cargo build -p leaf-bin --release

local-dev:
	cargo build -p leaf-bin

# Force a re-generation of protobuf files.
proto-gen:
	touch leaf/build.rs
	PROTO_GEN=1 cargo build -p leaf
