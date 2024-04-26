.PHONY: cli cli-dev test proto-gen

CFG_COMMIT_HASH := $(shell git rev-parse HEAD | cut -c 1-7)
export CFG_COMMIT_HASH := $(CFG_COMMIT_HASH)
CFG_COMMIT_DATE := $(shell git log --format="%ci" -n 1)
export CFG_COMMIT_DATE := $(CFG_COMMIT_DATE)

cli:
	cargo build -p leaf-cli --release

cli-dev:
	cargo build -p leaf-cli

test:
	cargo test -p leaf -- --nocapture

proto-gen:
	./scripts/regenerate_proto_files.sh
