const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
    @cInclude("wasm3.h");
    @cInclude("m3_env.h");
});
const log = std.log.scoped(.server);
const http = std.http;
const net = std.net;
const mem = std.mem;

// ── Constants ────────────────────────────────────────────────────────

const PORT: u16 = 8000;
const WASM_INPUT_OFF: u32 = 0x10000;
const WASM_STACK_SIZE: u32 = 256 * 1024;
const MAX_BODY: usize = 10 * 1024 * 1024; // 10MB

// ── Blob Store (SQLite) ──────────────────────────────────────────────

const BlobStore = struct {
    db: *c.sqlite3,

    fn init(path: [*:0]const u8) !BlobStore {
        var db_ptr: ?*c.sqlite3 = null;
        if (c.sqlite3_open(path, &db_ptr) != c.SQLITE_OK) {
            return error.SqliteOpen;
        }
        const db = db_ptr.?;
        var err_msg: [*c]u8 = null;
        const sql = "CREATE TABLE IF NOT EXISTS blobs (hash TEXT PRIMARY KEY, data BLOB NOT NULL)";
        if (c.sqlite3_exec(db, sql, null, null, &err_msg) != c.SQLITE_OK) {
            if (err_msg) |msg| {
                log.err("sqlite exec: {s}", .{msg});
                c.sqlite3_free(msg);
            }
            return error.SqliteExec;
        }
        return BlobStore{ .db = db };
    }

    fn deinit(self: *BlobStore) void {
        _ = c.sqlite3_close(self.db);
    }

    fn put(self: *BlobStore, data: []const u8) !HashHex {
        const hash = sha256(data);
        const hex = hexEncode(hash);

        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "INSERT OR IGNORE INTO blobs (hash, data) VALUES (?, ?)";
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK)
            return error.SqlitePrepare;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt.?, 1, &hex, hex.len, c.SQLITE_STATIC);
        _ = c.sqlite3_bind_blob(stmt.?, 2, data.ptr, @intCast(data.len), c.SQLITE_STATIC);

        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE)
            return error.SqliteStep;

        return hex;
    }

    fn get(self: *BlobStore, hex: []const u8) !?[]const u8 {
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "SELECT data FROM blobs WHERE hash = ?";
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK)
            return error.SqlitePrepare;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt.?, 1, hex.ptr, @intCast(hex.len), c.SQLITE_STATIC);

        if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW)
            return null;

        const blob_ptr = c.sqlite3_column_blob(stmt.?, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 0));
        if (blob_ptr == null) return null;

        const out = try alloc.alloc(u8, blob_len);
        @memcpy(out, @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len]);
        return out;
    }
};

// ── SHA-256 ──────────────────────────────────────────────────────────

const HashHex = [64]u8;

fn sha256(data: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(data);
    return h.finalResult();
}

fn hexEncode(bytes: [32]u8) HashHex {
    const hex_chars = "0123456789abcdef";
    var out: HashHex = undefined;
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return out;
}

// ── Wasm execution (wasm3) ───────────────────────────────────────────

fn executeWasm(wasm_bytes: []const u8, input: []const u8) ![]const u8 {
    const env = c.m3_NewEnvironment() orelse return error.WasmEnvCreate;
    defer c.m3_FreeEnvironment(env);

    const runtime = c.m3_NewRuntime(env, WASM_STACK_SIZE, null) orelse return error.WasmRuntimeCreate;
    defer c.m3_FreeRuntime(runtime);

    var module: c.IM3Module = null;
    var result = c.m3_ParseModule(env, &module, wasm_bytes.ptr, @intCast(wasm_bytes.len));
    if (result != null) {
        log.err("wasm3 parse: {s}", .{result});
        return error.WasmParse;
    }

    result = c.m3_LoadModule(runtime, module);
    if (result != null) {
        log.err("wasm3 load: {s}", .{result});
        return error.WasmLoad;
    }

    var func: c.IM3Function = null;
    result = c.m3_FindFunction(&func, runtime, "run");
    if (result != null) {
        log.err("wasm3 find 'run': {s}", .{result});
        return error.WasmFindFunc;
    }

    // Get memory and write input at WASM_INPUT_OFF
    var mem_size: u32 = 0;
    const mem_ptr = c.m3_GetMemory(runtime, &mem_size, 0);
    if (mem_ptr == null) return error.WasmNoMemory;

    if (WASM_INPUT_OFF + input.len > mem_size) {
        return error.WasmMemoryTooSmall;
    }

    const wasm_mem: [*]u8 = @ptrCast(mem_ptr);
    @memcpy(wasm_mem[WASM_INPUT_OFF .. WASM_INPUT_OFF + input.len], input);

    // Call run(input_ptr, input_len)
    const input_ptr_val: u32 = WASM_INPUT_OFF;
    const input_len_val: u32 = @intCast(input.len);
    const args = [_]?*const anyopaque{
        @ptrCast(&input_ptr_val),
        @ptrCast(&input_len_val),
    };
    result = c.m3_Call(func, 2, @constCast(@ptrCast(&args)));
    if (result != null) {
        log.err("wasm3 call: {s}", .{result});
        return error.WasmCall;
    }

    // Get return value (pointer to output)
    var ret_val: u32 = 0;
    var rets = [_]?*anyopaque{@ptrCast(&ret_val)};
    result = c.m3_GetResults(func, 1, @ptrCast(&rets));
    if (result != null) {
        log.err("wasm3 get results: {s}", .{result});
        return error.WasmGetResults;
    }

    // Re-fetch memory (may have grown)
    var mem_size2: u32 = 0;
    const mem_ptr2 = c.m3_GetMemory(runtime, &mem_size2, 0);
    if (mem_ptr2 == null) return error.WasmNoMemory;

    const mem2: [*]const u8 = @ptrCast(mem_ptr2);

    if (ret_val + 4 > mem_size2) return error.WasmOutputOOB;

    const out_len = std.mem.readInt(u32, mem2[ret_val..][0..4], .little);
    const out_start = ret_val + 4;

    if (out_start + out_len > mem_size2) return error.WasmOutputOOB;

    // Copy output
    const output = try alloc.alloc(u8, out_len);
    @memcpy(output, mem2[out_start .. out_start + out_len]);
    return output;
}

// ── HTTP Helpers ─────────────────────────────────────────────────────

const alloc = std.heap.c_allocator;

fn readRequestBody(request: *http.Server.Request) ![]const u8 {
    const reader = try request.reader();
    return try reader.readAllAlloc(alloc, MAX_BODY);
}

// ── Route Handlers ───────────────────────────────────────────────────

var store: BlobStore = undefined;

fn handlePutBlob(request: *http.Server.Request) !void {
    const body = try readRequestBody(request);
    defer alloc.free(body);

    const hex = store.put(body) catch {
        try request.respond("Store error\n", .{ .status = .internal_server_error });
        return;
    };

    var buf: [128]u8 = undefined;
    const json = std.fmt.bufPrint(&buf, "{{\"hash\":\"{s}\"}}", .{hex}) catch unreachable;

    try request.respond(json, .{ .status = .created });
}

fn handleGetBlob(request: *http.Server.Request) !void {
    const target = request.head.target;
    const hash = target["/blobs/".len..];
    if (hash.len != 64) {
        try request.respond("Invalid hash\n", .{ .status = .bad_request });
        return;
    }

    const data = store.get(hash) catch {
        try request.respond("Store error\n", .{ .status = .internal_server_error });
        return;
    };

    if (data) |d| {
        defer alloc.free(d);
        try request.respond(d, .{
            .status = .ok,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/octet-stream" },
            },
        });
    } else {
        try request.respond("Not Found\n", .{ .status = .not_found });
    }
}

fn handleExecute(request: *http.Server.Request) !void {
    const target = request.head.target;
    const hash = target["/execute/".len..];
    if (hash.len != 64) {
        try request.respond("Invalid hash\n", .{ .status = .bad_request });
        return;
    }

    const wasm_bytes = store.get(hash) catch {
        try request.respond("Store error\n", .{ .status = .internal_server_error });
        return;
    };

    if (wasm_bytes == null) {
        try request.respond("Not Found\n", .{ .status = .not_found });
        return;
    }
    defer alloc.free(wasm_bytes.?);

    const input = try readRequestBody(request);
    defer alloc.free(input);

    const output = executeWasm(wasm_bytes.?, input) catch |err| {
        log.err("wasm exec failed: {}", .{err});
        try request.respond("Execution error\n", .{ .status = .internal_server_error });
        return;
    };
    defer alloc.free(output);

    try request.respond(output, .{ .status = .ok });
}

fn handleRequest(request: *http.Server.Request) !void {
    const target = request.head.target;
    const method = request.head.method;

    if (method == .PUT and mem.eql(u8, target, "/blobs")) {
        return handlePutBlob(request);
    }

    if (method == .GET and mem.startsWith(u8, target, "/blobs/")) {
        return handleGetBlob(request);
    }

    if (method == .POST and mem.startsWith(u8, target, "/execute/")) {
        return handleExecute(request);
    }

    try request.respond("Not Found\n", .{ .status = .not_found });
}

pub fn main() !void {
    store = try BlobStore.init("blobs.db");
    defer store.deinit();

    const addr = net.Address.parseIp("0.0.0.0", PORT) catch unreachable;
    var tcp_server = try addr.listen(.{ .reuse_address = true });
    defer tcp_server.deinit();

    log.info("listening on port {d}", .{PORT});

    while (true) {
        const conn = try tcp_server.accept();
        var buf: [8192]u8 = undefined;
        var server = http.Server.init(conn, &buf);

        while (server.state == .ready) {
            var request = server.receiveHead() catch |err| {
                if (err == error.HttpConnectionClosing) break;
                log.err("receive head: {}", .{err});
                break;
            };

            handleRequest(&request) catch |err| {
                log.err("request handling failed: {}", .{err});
                break;
            };
        }
    }
}
