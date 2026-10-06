const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const nostr = b.dependency("nostr", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "puck",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nostr", .module = nostr.module("nostr") },
            },
        }),
    });

    exe.root_module.strip = optimize == std.builtin.OptimizeMode.ReleaseSmall or optimize == std.builtin.OptimizeMode.ReleaseFast;
    exe.root_module.link_libc = true;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (comptime @hasDecl(std.Build.Step.Run, "addPassthruArgs")) run_cmd.addPassthruArgs() else if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run the NWC server").dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nostr", .module = nostr.module("nostr") },
            },
        }),
    });
    unit_tests.root_module.link_libc = true;

    const run_unit_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run unit tests").dependOn(&run_unit_tests.step);
}
