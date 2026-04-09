# Stage 1: Build
FROM haskell:9.6-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    librocksdb-dev pkg-config libsecp256k1-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*
COPY . .
RUN cabal update && cabal build all
RUN cabal install --install-method=copy --installdir=/build/bin

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/bin/haskoin /usr/local/bin/haskoin
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["haskoin"]
CMD ["-d", "/data", "-n", "Mainnet", "node"]
