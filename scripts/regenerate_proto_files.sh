#!/usr/bin/env sh

set -x

touch leaf/build.rs
PROTO_GEN=1 cargo build -p leaf
