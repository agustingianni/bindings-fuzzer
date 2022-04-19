#!/usr/bin/env bash

set -euo pipefail

LLVM_DIR="$(brew --prefix llvm)/bin"
PATH="${LLVM_DIR}:${PATH}"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
INSTALL_DIR="${SCRIPT_DIR}/../../../sources/installation/ruby-libfuzzer"
export PKG_CONFIG_PATH="${INSTALL_DIR}/lib/pkgconfig"

RUBY_LIB_DIR=$(pkg-config --variable=libdir ruby-3.2)
RUBY_LIBRARIES=$(pkg-config --variable=LIBRUBYARG_STATIC ruby-3.2)
RUBY_INCLUDES=$(pkg-config --cflags ruby-3.2)

# Compile our fuzzer.
clang++ abstract-fuzzer.cpp ruby-fuzzer.cpp -o ruby-fuzzer \
    -std=c++20 -g -O0 -fno-omit-frame-pointer -fno-common \
    -fsanitize=address,fuzzer \
    -Wall \
    -L${RUBY_LIB_DIR} \
    ${RUBY_INCLUDES} \
    ${RUBY_LIBRARIES}
