FROM scratch
COPY wasmexec-zig /wasmexec-zig
EXPOSE 8000
ENTRYPOINT ["/wasmexec-zig"]
