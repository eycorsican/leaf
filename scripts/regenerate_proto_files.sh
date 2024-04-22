#!/usr/bin/env sh

set -ex

touch leaf/build.rs
PROTO_GEN=1 cargo build -p leaf
