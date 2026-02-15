const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- wasm3 static library (C sources) ---
    const wasm3_sources = [_][]const u8{
        "wasm3/m3_bind.c",
        "wasm3/m3_code.c",
        "wasm3/m3_compile.c",
        "wasm3/m3_core.c",
        "wasm3/m3_env.c",
        "wasm3/m3_exec.c",
        "wasm3/m3_function.c",
        "wasm3/m3_info.c",
        "wasm3/m3_module.c",
        "wasm3/m3_parse.c",
        "wasm3/m3_api_libc.c",
        "wasm3/m3_api_meta_wasi.c",
        "wasm3/m3_api_tracer.c",
        "wasm3/m3_api_uvwasi.c",
        "wasm3/m3_api_wasi.c",
    };

    const wasm3 = b.addStaticLibrary(.{
        .name = "wasm3",
        .target = target,
        .optimize = optimize,
    });
    wasm3.addCSourceFiles(.{
        .files = &wasm3_sources,
        .flags = &.{ "-std=c11", "-O2", "-Wno-unused-function", "-Wno-sign-compare" },
    });
    wasm3.addIncludePath(b.path("wasm3"));
    wasm3.linkLibC();

    // --- main executable ---
    const exe = b.addExecutable(.{
        .name = "wasmexec-zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.addIncludePath(b.path("wasm3"));
    exe.linkLibrary(wasm3);
    exe.linkSystemLibrary("sqlite3");
    exe.linkLibC();

    b.installArtifact(exe);

    // --- run step ---
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the server");
    run_step.dependOn(&run_cmd.step);
}
