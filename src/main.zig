const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
    @cInclude("wasm3.h");
    @cInclude("m3_env.h");
    @cInclude("microhttpd.h");
});
const log = std.log.scoped(.server);
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

    var mem_size: u32 = 0;
    const mem_ptr = c.m3_GetMemory(runtime, &mem_size, 0);
    if (mem_ptr == null) return error.WasmNoMemory;

    if (WASM_INPUT_OFF + input.len > mem_size) {
        return error.WasmMemoryTooSmall;
    }

    const wasm_mem: [*]u8 = @ptrCast(mem_ptr);
    @memcpy(wasm_mem[WASM_INPUT_OFF .. WASM_INPUT_OFF + input.len], input);

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

    var ret_val: u32 = 0;
    var rets = [_]?*anyopaque{@ptrCast(&ret_val)};
    result = c.m3_GetResults(func, 1, @ptrCast(&rets));
    if (result != null) {
        log.err("wasm3 get results: {s}", .{result});
        return error.WasmGetResults;
    }

    var mem_size2: u32 = 0;
    const mem_ptr2 = c.m3_GetMemory(runtime, &mem_size2, 0);
    if (mem_ptr2 == null) return error.WasmNoMemory;

    const mem2: [*]const u8 = @ptrCast(mem_ptr2);

    if (ret_val + 4 > mem_size2) return error.WasmOutputOOB;

    const out_len = std.mem.readInt(u32, mem2[ret_val..][0..4], .little);
    const out_start = ret_val + 4;

    if (out_start + out_len > mem_size2) return error.WasmOutputOOB;

    const output = try alloc.alloc(u8, out_len);
    @memcpy(output, mem2[out_start .. out_start + out_len]);
    return output;
}

// ── Upload buffer (per-connection) ───────────────────────────────────

const UploadBuf = struct {
    data: ?[*]u8 = null,
    len: usize = 0,
    cap: usize = 0,

    fn append(self: *UploadBuf, chunk: [*]const u8, size: usize) !void {
        if (self.len + size > self.cap) {
            var newcap: usize = if (self.cap == 0) 4096 else self.cap;
            while (newcap < self.len + size) newcap *= 2;
            if (newcap > MAX_BODY) return error.BodyTooLarge;
            const new_data = alloc.alloc(u8, newcap) catch return error.OutOfMemory;
            if (self.data) |old| {
                @memcpy(new_data[0..self.len], old[0..self.len]);
                alloc.free(old[0..self.cap]);
            }
            self.data = new_data.ptr;
            self.cap = newcap;
        }
        @memcpy(self.data.?[self.len .. self.len + size], chunk[0..size]);
        self.len += size;
    }

    fn slice(self: *const UploadBuf) []const u8 {
        if (self.data) |d| return d[0..self.len];
        return &[_]u8{};
    }

    fn deinit(self: *UploadBuf) void {
        if (self.data) |d| {
            alloc.free(d[0..self.cap]);
        }
        alloc.destroy(self);
    }
};

// ── HTTP handler (libmicrohttpd) ─────────────────────────────────────

const alloc = std.heap.c_allocator;

var store: BlobStore = undefined;

fn respondText(conn: *c.MHD_Connection, code: c_uint, text: [*]const u8, len: usize) c_uint {
    const resp = c.MHD_create_response_from_buffer(
        len,
        @constCast(@ptrCast(text)),
        c.MHD_RESPMEM_MUST_COPY,
    ) orelse return c.MHD_NO;
    _ = c.MHD_add_response_header(resp, "Content-Type", "text/plain");
    const ret = c.MHD_queue_response(conn, code, resp);
    c.MHD_destroy_response(resp);
    return ret;
}

fn respondOwned(conn: *c.MHD_Connection, code: c_uint, data: []const u8, content_type: [*:0]const u8) c_uint {
    const resp = c.MHD_create_response_from_buffer(
        data.len,
        @constCast(@ptrCast(data.ptr)),
        c.MHD_RESPMEM_MUST_COPY,
    ) orelse return c.MHD_NO;
    _ = c.MHD_add_response_header(resp, "Content-Type", content_type);
    const ret = c.MHD_queue_response(conn, code, resp);
    c.MHD_destroy_response(resp);
    return ret;
}

fn handleRequest(
    _: ?*anyopaque,
    connection: ?*c.MHD_Connection,
    url_c: [*c]const u8,
    method_c: [*c]const u8,
    _: [*c]const u8, // version
    upload_data: [*c]const u8,
    upload_data_size: [*c]usize,
    con_cls: [*c]?*anyopaque,
) callconv(.C) c_uint {
    const conn = connection orelse return c.MHD_NO;
    const url = mem.span(@as([*:0]const u8, @ptrCast(url_c)));
    const method = mem.span(@as([*:0]const u8, @ptrCast(method_c)));
    // First call: allocate upload buffer
    if (con_cls.* == null) {
        const ubuf = alloc.create(UploadBuf) catch return c.MHD_NO;
        ubuf.* = .{};
        con_cls.* = @ptrCast(ubuf);
        return c.MHD_YES;
    }

    const ubuf: *UploadBuf = @ptrCast(@alignCast(con_cls.*));

    // Accumulate upload data
    if (upload_data_size.* > 0) {
        ubuf.append(upload_data, upload_data_size.*) catch
            return respondText(conn, 500, "upload error\n", 14);
        upload_data_size.* = 0;
        return c.MHD_YES;
    }

    // All data received — route
    const body = ubuf.slice();

    // PUT /blobs
    if (mem.eql(u8, method, "PUT") and mem.eql(u8, url, "/blobs")) {
        const hex = store.put(body) catch
            return respondText(conn, 500, "store error\n", 13);
        var json_buf: [128]u8 = undefined;
        const json = std.fmt.bufPrint(&json_buf, "{{\"hash\":\"{s}\"}}", .{hex}) catch unreachable;
        return respondOwned(conn, 201, json, "application/json");
    }

    // GET /blobs/:hash
    if (mem.eql(u8, method, "GET") and mem.startsWith(u8, url, "/blobs/")) {
        const hash = url["/blobs/".len..];
        if (hash.len != 64)
            return respondText(conn, 400, "invalid hash\n", 14);

        const data = store.get(hash) catch
            return respondText(conn, 500, "store error\n", 13);

        if (data) |d| {
            defer alloc.free(d);
            return respondOwned(conn, 200, d, "application/octet-stream");
        } else {
            return respondText(conn, 404, "not found\n", 10);
        }
    }

    // POST /execute/:hash
    if (mem.eql(u8, method, "POST") and mem.startsWith(u8, url, "/execute/")) {
        const hash = url["/execute/".len..];
        if (hash.len != 64)
            return respondText(conn, 400, "invalid hash\n", 14);

        const wasm_bytes = store.get(hash) catch
            return respondText(conn, 500, "store error\n", 13);

        if (wasm_bytes == null)
            return respondText(conn, 404, "not found\n", 10);
        defer alloc.free(wasm_bytes.?);

        const output = executeWasm(wasm_bytes.?, body) catch |err| {
            log.err("wasm exec failed: {}", .{err});
            return respondText(conn, 500, "execution error\n", 17);
        };
        defer alloc.free(output);

        return respondOwned(conn, 200, output, "application/octet-stream");
    }

    return respondText(conn, 404, "not found\n", 10);
}

fn requestCompleted(
    _: ?*anyopaque,
    _: ?*c.MHD_Connection,
    con_cls: [*c]?*anyopaque,
    _: c.MHD_RequestTerminationCode,
) callconv(.C) void {
    if (con_cls.*) |ptr| {
        const ubuf: *UploadBuf = @ptrCast(@alignCast(ptr));
        ubuf.deinit();
        con_cls.* = null;
    }
}

pub fn main() !void {
    store = try BlobStore.init("blobs.db");
    defer store.deinit();

    const daemon = c.MHD_start_daemon(
        c.MHD_USE_INTERNAL_POLLING_THREAD,
        PORT,
        null,
        null,
        handleRequest,
        null,
        @as(c_uint, c.MHD_OPTION_NOTIFY_COMPLETED),
        requestCompleted,
        @as(?*anyopaque, null),
        @as(c_uint, c.MHD_OPTION_END),
    ) orelse {
        log.err("failed to start MHD daemon on port {d}", .{PORT});
        return error.MhdStartFailed;
    };

    log.info("listening on port {d}", .{PORT});

    // Block forever (MHD runs in its own thread)
    while (true) {
        std.time.sleep(std.time.ns_per_s);
    }

    c.MHD_stop_daemon(daemon);
}
