.PHONY: local local-dev test proto-gen

local:
	cargo build -p leaf-bin --release

local-dev:
	cargo build -p leaf-bin

test:
	cargo test -p leaf -- --nocapture

proto-gen:
	./scripts/regenerate_proto_files.sh
