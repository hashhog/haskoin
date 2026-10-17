# Building haskoin

## Toolchain

- GHC 9.6 (tested with 9.6.7). `haskoin.cabal` accepts `base >= 4.14`, but 9.6 is the
  version the test suites are run with.
- cabal-install 3.14 (tested with 3.14.2.0).

[GHCup](https://www.haskell.org/ghcup/) installs both:

```bash
ghcup install ghc 9.6.7 && ghcup set ghc 9.6.7
ghcup install cabal 3.14.2.0 && ghcup set cabal 3.14.2.0
```

## System libraries

The library links against `minisketch`, `stdc++`, `rocksdb_compat`, `rocksdb`, `secp256k1`
and `libzmq.so.5` (see `extra-libraries` in `haskoin.cabal`). On Debian 13:

```bash
sudo apt-get install -y build-essential autoconf automake libtool pkg-config git curl \
  librocksdb-dev libsecp256k1-dev libzmq5 zlib1g-dev libgmp-dev
```

Only the `libzmq5` runtime library is needed, not the ZeroMQ headers: `cbits/zmq_stubs.c`
declares the few functions it uses itself.

### minisketch

Not packaged by Debian. Build it from source and install it to `/usr/local`:

```bash
git clone --depth 1 https://github.com/sipa/minisketch.git
cd minisketch && ./autogen.sh && ./configure && make -j"$(nproc)"
sudo make install && sudo ldconfig
cd ..
```

### rocksdb_compat

RocksDB 9 removed `rocksdb_filterpolicy_create`, which the Haskell RocksDB binding still
calls. `scripts/build-rocksdb-compat.sh` compiles a one-function shim that forwards it to the
bloom-filter constructor and installs `librocksdb_compat.so` to `/usr/local/lib`:

```bash
sudo bash scripts/build-rocksdb-compat.sh
```

If you install minisketch or the shim somewhere other than `/usr/local/lib`, pass that
directory to cabal with `--extra-lib-dirs` and add it to `LD_LIBRARY_PATH` when you run the
node.

## Building

```bash
cabal update
cabal build exe:haskoin
cabal list-bin haskoin
```

`cabal list-bin` prints the path of the built binary. A first build downloads and compiles
about 150 Haskell dependencies and takes a while; later builds only recompile haskoin.

`cabal build` with no target builds the library and every executable below. The test suites
are built by `cabal test` (see [status.md](status.md)).

| Component | What it is |
|---|---|
| `exe:haskoin` | The node |
| `exe:verifyscript-shim`, `exe:bip341-shim` | Small stdin/stdout wrappers around the script interpreter and the BIP-341 sighash, for differential testing against other implementations |
| `exe:txospender-proof` | Exercises the `txospenderindex` connect/disconnect/reorg paths against a temporary RocksDB |
| `exe:db-breakdown` | Offline: bytes and entry count per key prefix in a stopped node's database (`tools-measure/`) |
| `exe:reconcile-repair` | Offline, dry-run by default: repairs a best-block pointer that is ahead of the applied UTXO set (`tools-measure/`) |
| `bench:haskoin-bench` | criterion benchmarks (`bench/Bench.hs`) |

The node is linked with `-threaded -rtsopts` and defaults to `+RTS -N4 -I0`. You can override
GHC runtime options at start-up, for example `./haskoin +RTS -N -A64m -RTS -n Mainnet node`.

## Reproducible builds

There is no reproducible-build recipe yet. GHC output depends on the compiler version and on
the dependency versions cabal resolves, so pin both (`cabal freeze`) if you need two builds to
match.
