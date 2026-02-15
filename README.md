# wasmexec-zig

HTTP server for content-addressable blob storage and WebAssembly execution.
Built with Zig, SQLite, and wasm3.

## API

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/blobs` | Upload a blob. Returns `{"hash":"<sha256>"}` (201). |
| `GET` | `/blobs/:hash` | Retrieve a blob by its SHA-256 hash. |
| `POST` | `/execute/:hash` | Execute a wasm blob. Request body = input, response body = output. |

Blobs are content-addressable and immutable.

## Wasm Contract

Modules must export:
- `memory` — the module's linear memory
- `run(input_ptr: i32, input_len: i32) -> i32` — entry point

The host writes input bytes at offset `0x10000`, then calls `run(0x10000, input_len)`.

`run` returns a pointer to the output, formatted as:
```
[output_len: u32 LE][output_bytes...]
```

No WASI. No imported functions. Pure computation.

## Build & Run

```bash
zig build
./zig-out/bin/wasmexec-zig   # listens on :8000
```

Requires `libsqlite3-dev` on the system. wasm3 is vendored.

## Test

```bash
# Start server, then:
bash test/test.sh
```
