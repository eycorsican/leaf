.PHONY: cli cli-dev test e2e soak interop plugin-test plugin-test-san proto-gen

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

# End-to-end plugin tests. Builds the plugins it needs on its own; pass
# arguments through, e.g. `make e2e E2E_ARGS="--tag go"`.
#
# The soak lane is left out: it is minutes per case and answers a question
# about the long run, which is `make soak` below. So is the interop lane, which
# builds other projects' servers from source: `make interop`.
e2e:
	cargo test -p leaf-e2e --test e2e -- --strict --no-tag soak --no-tag interop $(E2E_ARGS)

# The long lane: soaks and every cost meter, including the two that are too
# slow for a pull request. Each meter leaves its numbers in
# `target/<profile>/e2e-artifacts/<case>/meters.json`.
soak:
	cargo test -p leaf-e2e --test e2e -- --strict --tag soak --tag perf $(E2E_ARGS)

# The reference plugins against the servers people deploy: anytls-go, sing-box
# (stable and its testing branch), mihomo and the original shadow-tls, each
# built from source at the revision pinned in leaf-e2e/src/fixtures.rs. The
# first run clones and builds them under target/e2e-upstream/, which takes a
# few minutes and needs the network, Go, and rustup (shadow-tls pins a nightly
# toolchain of its own). A machine that has the binaries already can name them
# instead: LEAF_E2E_UPSTREAM_SING_BOX=/path/to/sing-box, and so on.
interop:
	cargo test -p leaf-e2e --test e2e -- --strict --tag interop $(E2E_ARGS)

# Everything plugin-related that is not an end-to-end run: the host's own tests
# for the loader and the wrappers, and each plugin's unit tests, one language at
# a time. These cover what an end-to-end run cannot reach: a descriptor that
# lies about its size, a handshake arriving a byte at a time, every way a server
# can refuse, and the buffer bookkeeping under all of it.
CC ?= cc
ABI_INCLUDE := leaf-plugin-abi/include

plugin-test:
	cargo test -p leaf --features plugin --lib
	cargo test -p leaf-plugin-abi
	cargo test -p tls-cabi-rs -p shadowsocks-cabi-rs
	cd leaf-plugins/leaf-abi-go && go test -race ./...
	cd leaf-plugins/tls-cabi-go && go test ./...
	cd leaf-plugins/trojan-cabi-go && go test ./...
	cd leaf-plugins/anytls-cabi-go && go test -race ./...
	cd leaf-plugins/shadowtls-cabi-go && go test -race ./...
	mkdir -p target
	$(CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fstack-protector-strong \
		-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -I$(ABI_INCLUDE) \
		-o target/socks5_cabi_c_test leaf-plugins/socks5-cabi-c/socks5_test.c
	./target/socks5_cabi_c_test
	cd leaf-plugins/socks5-cabi-zig && zig build test

# The C plugin's own tests under the sanitizers. Kept separate from
# `plugin-test` because not every toolchain ships the runtimes, and this is the
# lane that answers the question `-Wall` cannot: what the parser does with a
# server that lies about its lengths.
plugin-test-san:
	mkdir -p target
	$(CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
		-fno-omit-frame-pointer -I$(ABI_INCLUDE) \
		-o target/socks5_cabi_c_test_san leaf-plugins/socks5-cabi-c/socks5_test.c
	./target/socks5_cabi_c_test_san

proto-gen:
	./scripts/regenerate_proto_files.sh
