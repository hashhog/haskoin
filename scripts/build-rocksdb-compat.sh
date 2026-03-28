#!/usr/bin/env bash
# Build the rocksdb_compat shim library for haskoin
#
# RocksDB 9.x removed the rocksdb_filterpolicy_create() function that
# rocksdb-haskell expects. This script builds a small shared library
# that provides the missing symbol by delegating to rocksdb_filterpolicy_create_bloom.
#
# Prerequisites: sudo apt install -y librocksdb-dev
# Output: installs librocksdb_compat.so to /usr/local/lib

set -euo pipefail

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/rocksdb_compat.c" << 'SHIM'
#include <rocksdb/c.h>
#include <stdlib.h>

/*
 * Compatibility shim for RocksDB 9.x
 *
 * rocksdb_filterpolicy_create() was removed in RocksDB 9.x.
 * The rocksdb-haskell binding still references it, so we provide a stub
 * that returns a standard bloom filter policy instead.
 */
rocksdb_filterpolicy_t* rocksdb_filterpolicy_create(
    void* state,
    void (*destructor)(void*),
    char* (*create_filter)(void*, const char* const* key_array,
                           const size_t* key_length_array, int num_keys,
                           size_t* filter_length),
    unsigned char (*key_may_match)(void*, const char* key, size_t length,
                                   const char* filter, size_t filter_length),
    void (*delete_filter)(void*, const char* filter, size_t filter_length),
    const char* (*name)(void*))
{
    (void)state; (void)destructor; (void)create_filter;
    (void)key_may_match; (void)delete_filter; (void)name;
    return rocksdb_filterpolicy_create_bloom(10);
}
SHIM

echo "Building librocksdb_compat.so..."
cd "$TMPDIR"
gcc -shared -fPIC -O2 -o librocksdb_compat.so rocksdb_compat.c -lrocksdb

echo "Installing to /usr/local/lib..."
sudo cp librocksdb_compat.so /usr/local/lib/
sudo ldconfig

echo "Done. librocksdb_compat.so installed to /usr/local/lib"
