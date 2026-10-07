# ============================================================
# Multi-stage build for the C++ Reverse Proxy
# ============================================================

# ── Stage 1: Build ────────────────────────────────────────────
FROM debian:bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake make git libcurl4-openssl-dev libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt main.cpp ./

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --parallel $(nproc)

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/zt_proxy /usr/local/bin/zt_proxy

EXPOSE 8000
ENTRYPOINT ["zt_proxy"]
