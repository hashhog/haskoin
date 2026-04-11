# Stage 1: Build
FROM haskell:9.8-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    librocksdb-dev pkg-config libsecp256k1-dev zlib1g-dev \
    build-essential autoconf automake libtool git && \
    rm -rf /var/lib/apt/lists/*

# Build and install minisketch from source
RUN git clone --depth 1 https://github.com/sipa/minisketch.git /tmp/minisketch && \
    cd /tmp/minisketch && \
    ./autogen.sh && ./configure && make -j$(nproc) && make install && \
    ldconfig && rm -rf /tmp/minisketch

COPY scripts/build-rocksdb-compat.sh /tmp/build-rocksdb-compat.sh
COPY cbits/ /tmp/cbits/
RUN bash /tmp/build-rocksdb-compat.sh

COPY . .
RUN cabal update && cabal build all
RUN cabal install --install-method=copy --installdir=/build/bin

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/bin/haskoin /usr/local/bin/haskoin
COPY --from=builder /usr/local/lib/libminisketch* /usr/local/lib/
COPY --from=builder /usr/local/lib/librocksdb_compat* /usr/local/lib/
RUN ldconfig
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["haskoin"]
CMD ["-d", "/data", "-n", "Mainnet", "node"]
