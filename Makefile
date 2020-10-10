aarch64-unknown-linux-gnu:
	docker build -t custom/cross:aarch64-unknown-linux-gnu - < docker/Dockerfile.aarch64-unknown-linux-gnu
	cross build --target aarch64-unknown-linux-gnu -p leaf-bin

x86_64-pc-windows-gnu:
	docker build -t custom/cross:x86_64-pc-windows-gnu - < docker/Dockerfile.x86_64-pc-windows-gnu
	cross build --target x86_64-pc-windows-gnu -p leaf-bin --release

ios:
	cargo lipo -p leaf-mobile --release --targets aarch64-apple-ios && cp target/universal/release/libleaf.a /tmp/ && cbindgen leaf-mobile/src/lib.rs -l c > /tmp/leaf.h

ios-dev:
	cargo lipo -p leaf-mobile --targets aarch64-apple-ios && cp target/universal/debug/libleaf.a /tmp/ && cbindgen leaf-mobile/src/lib.rs -l c > /tmp/leaf.h

local:
	cargo build -p leaf-bin --release

local-dev:
	cargo build -p leaf-bin
