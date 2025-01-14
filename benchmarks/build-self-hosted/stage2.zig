const std = @import("std");
const bench = @import("root");

const Context = struct {
    zig_exe: []const u8,
    build_file_path: []const u8,
};

const output_dir = "stage2";

pub fn setup(gpa: std.mem.Allocator, options: *bench.Options) !Context {
    options.useChildProcess();

    try std.fs.cwd().deleteTree(output_dir);

    return Context{
        .zig_exe = options.zig_exe,
        .build_file_path = try std.fs.path.join(gpa, &.{ options.zig_src_root, "build.zig" }),
    };
}

pub fn run(gpa: std.mem.Allocator, context: Context) !void {
    return bench.exec(gpa, &[_][]const u8{
        context.zig_exe, "build",
        "--build-file",  context.build_file_path,
        "-p",            output_dir,
        "-fno-stage1",   "-Dskip-install-lib-files",
    }, .{});
}
