FROM alpine:3.20 AS builder

# Install build essentials
RUN apk add --no-cache sqlite-dev sqlite-static xz curl

# Install Zig 0.13.0
RUN curl -L https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz | tar xJ -C /opt && \
    ln -s /opt/zig-linux-x86_64-0.13.0/zig /usr/local/bin/zig

# Download sqlite amalgamation
RUN curl -L https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip -o /tmp/sqlite.zip && \
    cd /tmp && unzip sqlite.zip && \
    mkdir -p /opt/sqlite3 && \
    cp sqlite-amalgamation-3450100/sqlite3.c sqlite-amalgamation-3450100/sqlite3.h /opt/sqlite3/

WORKDIR /src
COPY . .

# Build with native musl target for static binary
# Use the modified build.zig that compiles sqlite3 from source
RUN zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl 2>&1

# Verify it's static
RUN apk add --no-cache file && file zig-out/bin/wasmexec-zig && ldd zig-out/bin/wasmexec-zig 2>&1 || true

FROM scratch
COPY --from=builder /src/zig-out/bin/wasmexec-zig /wasmexec-zig
EXPOSE 8000
ENTRYPOINT ["/wasmexec-zig"]
