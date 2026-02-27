const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Library module (importable by other projects) ─────────────────────────
    const voidnote_mod = b.addModule("voidnote", .{
        .root_source_file = b.path("voidnote.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = voidnote_mod;

    // ── Tests ─────────────────────────────────────────────────────────────────
    const test_mod = b.createModule(.{
        .root_source_file = b.path("voidnote.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link system libraries that the RNG needs
    if (target.result.os.tag == .windows) {
        test_mod.linkSystemLibrary("bcrypt", .{});
    }

    const tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // ── Example binary ────────────────────────────────────────────────────────
    const example_mod = b.createModule(.{
        .root_source_file = b.path("example.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "voidnote", .module = b.createModule(.{
                .root_source_file = b.path("voidnote.zig"),
                .target = target,
                .optimize = optimize,
            }) },
        },
    });

    if (target.result.os.tag == .windows) {
        example_mod.linkSystemLibrary("bcrypt", .{});
    }

    const example = b.addExecutable(.{
        .name = "voidnote-example",
        .root_module = example_mod,
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    if (b.args) |args| run_example.addArgs(args);
    const run_step = b.step("run", "Run the example");
    run_step.dependOn(&run_example.step);
}
