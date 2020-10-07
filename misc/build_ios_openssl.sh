#!/bin/sh

export CC=clang
export CROSS_TOP=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer
export CROSS_SDK=iPhoneOS.sdk
export PATH="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"

git clone --depth 1 --branch OpenSSL_1_1_1g https://github.com/openssl/openssl.git && cd openssl
./Configure ios64-cross no-shared no-dso no-hw no-engine --prefix=/tmp/openssl-ios64
ncores=`sysctl -n hw.ncpu`
make -j $ncores && make install
