const std = @import("std");
const fs = std.fs;
const json = std.json;
const assert = std.debug.assert;

const Record = struct {
    timestamp: u64,
    benchmark_name: []const u8,
    commit_hash: [20]u8,
    commit_timestamp: u64,
    zig_version: []const u8,
    error_message: []const u8 = &[0]u8{},
    samples_taken: u64 = 0,
    wall_time_median: u64 = 0,
    wall_time_mean: u64 = 0,
    wall_time_min: u64 = 0,
    wall_time_max: u64 = 0,
    utime_median: u64 = 0,
    utime_mean: u64 = 0,
    utime_min: u64 = 0,
    utime_max: u64 = 0,
    stime_median: u64 = 0,
    stime_mean: u64 = 0,
    stime_min: u64 = 0,
    stime_max: u64 = 0,
    cpu_cycles_median: u64 = 0,
    cpu_cycles_mean: u64 = 0,
    cpu_cycles_min: u64 = 0,
    cpu_cycles_max: u64 = 0,
    instructions_median: u64 = 0,
    instructions_mean: u64 = 0,
    instructions_min: u64 = 0,
    instructions_max: u64 = 0,
    cache_references_median: u64 = 0,
    cache_references_mean: u64 = 0,
    cache_references_min: u64 = 0,
    cache_references_max: u64 = 0,
    cache_misses_median: u64 = 0,
    cache_misses_mean: u64 = 0,
    cache_misses_min: u64 = 0,
    cache_misses_max: u64 = 0,
    branch_misses_median: u64 = 0,
    branch_misses_mean: u64 = 0,
    branch_misses_min: u64 = 0,
    branch_misses_max: u64 = 0,
    maxrss: u64 = 0,

    const Key = struct {
        commit_hash: [20]u8,
        benchmark_name: []const u8,

        fn eql(self: Key, other: Key) bool {
            return std.mem.eql(u8, &self.commit_hash, &other.commit_hash) and
                std.mem.eql(u8, self.benchmark_name, other.benchmark_name);
        }
    };
};

fn jsonToRecord(
    arena: std.mem.Allocator,
    /// main object
    mo: json.Value,
    timestamp: u64,
    benchmark_name: []const u8,
    commit_hash: [20]u8,
    zig_version: []const u8,
    commit_timestamp: u64,
) !Record {
    // Example success output of benchmark program:
    // {"samples_taken":3,"wall_time":{"median":131511898884,"mean":131511898884,"min":131511898884,"max":131511898884},"utime":{"median":131507380000,"mean":131507380000,"min":131507380000,"max":131507380000},"stime":{"median":885000,"mean":885000,"min":885000,"max":885000},"cpu_cycles":{"median":506087170166,"mean":506087170166,"min":506087170166,"max":506087170166},"instructions":{"median":1013354628954,"mean":1013354628954,"min":1013354628954,"max":1013354628954},"cache_references":{"median":22131539,"mean":22131539,"min":22131539,"max":22131539},"cache_misses":{"median":4523975,"mean":4523975,"min":4523975,"max":4523975},"branch_misses":{"median":885333330,"mean":885333330,"min":885333330,"max":885333330},"maxrss":341004}
    //
    // Example failure output of the benchmark program:
    // FileNotFound
    var record: Record = .{
        .timestamp = timestamp,
        .benchmark_name = try arena.dupe(u8, benchmark_name),
        .commit_hash = commit_hash,
        .commit_timestamp = commit_timestamp,
        .zig_version = zig_version,
    };
    if (mo == .string) {
        record.error_message = try arena.dupe(u8, mo.string);
    } else {
        record.samples_taken = @intCast(mo.object.get("samples_taken").?.integer);
        record.wall_time_median = @intCast(mo.object.get("wall_time").?.object.get("median").?.integer);
        record.wall_time_mean = @intCast(mo.object.get("wall_time").?.object.get("mean").?.integer);
        record.wall_time_min = @intCast(mo.object.get("wall_time").?.object.get("min").?.integer);
        record.wall_time_max = @intCast(mo.object.get("wall_time").?.object.get("max").?.integer);
        record.utime_median = @intCast(mo.object.get("utime").?.object.get("median").?.integer);
        record.utime_mean = @intCast(mo.object.get("utime").?.object.get("mean").?.integer);
        record.utime_min = @intCast(mo.object.get("utime").?.object.get("min").?.integer);
        record.utime_max = @intCast(mo.object.get("utime").?.object.get("max").?.integer);
        record.stime_median = @intCast(mo.object.get("stime").?.object.get("median").?.integer);
        record.stime_mean = @intCast(mo.object.get("stime").?.object.get("mean").?.integer);
        record.stime_min = @intCast(mo.object.get("stime").?.object.get("min").?.integer);
        record.stime_max = @intCast(mo.object.get("stime").?.object.get("max").?.integer);
        record.cpu_cycles_median = @intCast(mo.object.get("cpu_cycles").?.object.get("median").?.integer);
        record.cpu_cycles_mean = @intCast(mo.object.get("cpu_cycles").?.object.get("mean").?.integer);
        record.cpu_cycles_min = @intCast(mo.object.get("cpu_cycles").?.object.get("min").?.integer);
        record.cpu_cycles_max = @intCast(mo.object.get("cpu_cycles").?.object.get("max").?.integer);
        record.instructions_median = @intCast(mo.object.get("instructions").?.object.get("median").?.integer);
        record.instructions_mean = @intCast(mo.object.get("instructions").?.object.get("mean").?.integer);
        record.instructions_min = @intCast(mo.object.get("instructions").?.object.get("min").?.integer);
        record.instructions_max = @intCast(mo.object.get("instructions").?.object.get("max").?.integer);
        record.cache_references_median = @intCast(mo.object.get("cache_references").?.object.get("median").?.integer);
        record.cache_references_mean = @intCast(mo.object.get("cache_references").?.object.get("mean").?.integer);
        record.cache_references_min = @intCast(mo.object.get("cache_references").?.object.get("min").?.integer);
        record.cache_references_max = @intCast(mo.object.get("cache_references").?.object.get("max").?.integer);
        record.cache_misses_median = @intCast(mo.object.get("cache_misses").?.object.get("median").?.integer);
        record.cache_misses_mean = @intCast(mo.object.get("cache_misses").?.object.get("mean").?.integer);
        record.cache_misses_min = @intCast(mo.object.get("cache_misses").?.object.get("min").?.integer);
        record.cache_misses_max = @intCast(mo.object.get("cache_misses").?.object.get("max").?.integer);
        record.branch_misses_median = @intCast(mo.object.get("branch_misses").?.object.get("median").?.integer);
        record.branch_misses_mean = @intCast(mo.object.get("branch_misses").?.object.get("mean").?.integer);
        record.branch_misses_min = @intCast(mo.object.get("branch_misses").?.object.get("min").?.integer);
        record.branch_misses_max = @intCast(mo.object.get("branch_misses").?.object.get("max").?.integer);
        record.maxrss = @intCast(mo.object.get("maxrss").?.integer);
    }

    return record;
}

const comma = ",";
const CommitTable = std.HashMap(
    Record.Key,
    usize,
    CommitTableContext,
    std.hash_map.default_max_load_percentage,
);

const CommitTableContext = struct {
    pub const Key = Record.Key;

    pub fn eql(ctx: @This(), a: Key, b: Key) bool {
        _ = ctx;
        return a.eql(b);
    }

    pub fn hash(ctx: @This(), key: Key) u64 {
        _ = ctx;
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHashStrat(&hasher, key, .Deep);
        return hasher.final();
    }
};

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);
    const records_csv_path = args[1];
    const zig_exe = args[2];
    const commit = try parseCommit(args[3]);
    const commit_timestamp = try parseTimestamp(args[4]);

    const zig_version_raw = try execCapture(arena, &[_][]const u8{ zig_exe, "version" }, .{});
    const zig_version = std.mem.trim(u8, zig_version_raw, " \r\n\t");
    std.debug.print("Detected zig version {s}...\n", .{zig_version});

    // Load CSV into memory
    std.debug.print("Loading CSV data...\n", .{});
    var records = std.ArrayList(Record).init(gpa);
    defer records.deinit();
    var commit_table = CommitTable.init(gpa);
    defer commit_table.deinit();

    {
        const csv_text = try fs.cwd().readFileAlloc(gpa, records_csv_path, 2 * 1024 * 1024 * 1024);
        defer gpa.free(csv_text);

        var field_indexes: [@typeInfo(Record).Struct.fields.len]usize = undefined;
        var seen_fields = [1]bool{false} ** field_indexes.len;
        var line_it = std.mem.split(u8, csv_text, "\n");
        {
            const first_line = line_it.next() orelse {
                std.debug.print("empty CSV file", .{});
                std.process.exit(1);
            };
            var csv_index: usize = 0;
            var it = std.mem.split(u8, first_line, comma);
            while (it.next()) |field_name| : (csv_index += 1) {
                if (csv_index >= field_indexes.len) {
                    std.debug.print("extra CSV field: {s}\n", .{field_name});
                    std.process.exit(1);
                }
                const field_index = fieldIndex(Record, field_name) orelse {
                    std.debug.print("bad CSV field name: {s}\n", .{field_name});
                    std.process.exit(1);
                };
                //std.debug.print("found field '{}' = {}\n", .{ field_name, field_index });
                field_indexes[csv_index] = field_index;
                seen_fields[field_index] = true;
            }
            inline for (@typeInfo(Record).Struct.fields, 0..) |field, i| {
                if (!seen_fields[i]) {
                    std.debug.print("missing CSV field: {s}", .{field.name});
                    std.process.exit(1);
                }
            }
        }

        var line_index: usize = 1;
        while (line_it.next()) |line| : (line_index += 1) {
            if (std.mem.eql(u8, line, "")) continue; // Skip blank lines.
            var it = std.mem.split(u8, line, comma);
            var csv_index: usize = 0;
            const record_index = records.items.len;
            const record = try records.addOne();
            while (it.next()) |field| : (csv_index += 1) {
                if (csv_index >= field_indexes.len) {
                    std.debug.print("extra CSV field on line {d}\n", .{line_index + 1});
                    std.process.exit(1);
                }
                setRecordField(arena, record, field, field_indexes[csv_index]);
            }
            if (csv_index != field_indexes.len) {
                std.debug.print("CSV line {d} missing a field\n", .{line_index + 1});
                std.process.exit(1);
            }
            const key: Record.Key = .{
                .commit_hash = record.commit_hash,
                .benchmark_name = record.benchmark_name,
            };
            if (try commit_table.fetchPut(key, record_index)) |existing| {
                //const existing_record = records.items[existing.value];
                _ = commit_table.putAssumeCapacity(key, existing.value);
                records.shrinkRetainingCapacity(records.items.len - 1);
            }
        }
    }

    const manifest_text = try fs.cwd().readFileAlloc(gpa, "benchmarks/manifest.json", 3 * 1024 * 1024);
    const manifest_tree = try json.parseFromSlice(json.Value, gpa, manifest_text, .{});
    // TODO uncertain if this is needed, wasn't here before
    defer manifest_tree.deinit();

    runBenchmarks(gpa, arena, &records, &commit_table, manifest_tree.value, zig_exe, commit, zig_version, commit_timestamp) catch |err| {
        std.debug.print("error running benchmarks: {s}\n", .{@errorName(err)});
    };

    // Save CSV
    std.debug.print("Updating {s}...\n", .{records_csv_path});
    {
        const baf = try std.io.BufferedAtomicFile.create(gpa, fs.cwd(), records_csv_path, .{});
        defer baf.destroy();

        const out = baf.writer();
        inline for (@typeInfo(Record).Struct.fields, 0..) |field, i| {
            if (i != 0) {
                try out.writeAll(comma);
            }
            try out.writeAll(field.name);
        }
        try out.writeAll("\n");
        for (records.items) |record| {
            try writeCSVRecord(out, record);
            try out.writeAll("\n");
        }

        try baf.finish();
    }
}

fn fieldIndex(comptime T: type, name: []const u8) ?usize {
    inline for (@typeInfo(T).Struct.fields, 0..) |field, i| {
        if (std.mem.eql(u8, field.name, name))
            return i;
    }
    return null;
}

fn setRecordField(arena: std.mem.Allocator, record: *Record, data: []const u8, index: usize) void {
    inline for (@typeInfo(Record).Struct.fields, 0..) |field, i| {
        if (i == index) {
            setRecordFieldT(arena, field.type, &@field(record, field.name), data);
            return;
        }
    }
    unreachable;
}

fn setRecordFieldT(arena: std.mem.Allocator, comptime T: type, ptr: *T, data: []const u8) void {
    if (@typeInfo(T) == .Enum) {
        ptr.* = std.meta.stringToEnum(T, data) orelse {
            std.debug.print("bad enum value: {d}\n", .{data});
            std.process.exit(1);
        };
        return;
    }
    switch (T) {
        u64 => {
            ptr.* = std.fmt.parseInt(u64, data, 10) catch |err| {
                std.debug.print("bad u64 value '{d}': {s}\n", .{ data, @errorName(err) });
                std.process.exit(1);
            };
        },
        []const u8 => {
            ptr.* = arena.dupe(u8, data) catch @panic("out of memory");
        },
        [20]u8 => {
            ptr.* = parseCommit(data) catch |err| {
                std.debug.print("wrong format for commit hash: '{d}': {s}", .{ data, @errorName(err) });
                std.process.exit(1);
            };
        },
        else => @compileError("no deserialization for " ++ @typeName(T)),
    }
}

fn writeCSVRecord(out: anytype, record: Record) !void {
    inline for (@typeInfo(Record).Struct.fields, 0..) |field, i| {
        if (i != 0) {
            try out.writeAll(comma);
        }
        try writeCSVRecordField(out, @field(record, field.name));
    }
}

fn writeCSVRecordField(out: anytype, field: anytype) !void {
    const T = @TypeOf(field);
    if (@typeInfo(T) == .Enum) {
        return out.writeAll(@tagName(field));
    }
    switch (T) {
        u64 => return out.print("{}", .{field}),
        []const u8 => return out.writeAll(field),
        [20]u8 => return out.print("{}", .{std.fmt.fmtSliceHexLower(&field)}),
        else => @compileError("unsupported writeCSVRecordField type: " ++ @typeName(T)),
    }
}

fn parseCommit(text: []const u8) ![20]u8 {
    var result: [20]u8 = undefined;
    if (text.len != 40) {
        return error.WrongSHALength;
    }
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        const byte = std.fmt.parseInt(u8, text[i * 2 ..][0..2], 16) catch {
            return error.BadSHACharacter;
        };
        result[i] = byte;
    }
    return result;
}

fn parseTimestamp(text: []const u8) !u64 {
    return std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n\r\t"), 10) catch |err| {
        std.debug.print("bad timestamp format: '{s}': {s}\n", .{ text, @errorName(err) });
        return error.BadTimestampFormat;
    };
}

fn runBenchmarks(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    records: *std.ArrayList(Record),
    commit_table: *CommitTable,
    manifest: json.Value,
    zig_exe: []const u8,
    commit: [20]u8,
    zig_version: []const u8,
    commit_timestamp: u64,
) !void {
    try records.ensureUnusedCapacity(manifest.object.count() * 2);

    const timestamp = @as(u64, @intCast(std.time.timestamp()));

    // cd benchmarks/self-hosted-parser
    // zig build-exe --main-pkg-path ../.. --pkg-begin app main.zig --pkg-end ../../bench.zig --enable-cache
    // ./../../zig-cache/path/to/bench zig
    var benchmarks_it = manifest.object.iterator();
    while (benchmarks_it.next()) |entry| {
        const benchmark_name = entry.key_ptr.*;
        const dir_name = entry.value_ptr.object.get("dir").?.string;
        const main_basename = entry.value_ptr.object.get("mainPath").?.string;

        const bench_cwd = try fs.path.join(gpa, &[_][]const u8{ "benchmarks", dir_name });
        defer gpa.free(bench_cwd);

        const full_main_path = try fs.path.join(gpa, &[_][]const u8{ bench_cwd, main_basename });
        defer gpa.free(full_main_path);
        const abs_main_path = try fs.realpathAlloc(gpa, full_main_path);
        defer gpa.free(abs_main_path);

        std.debug.print(
            "Running '{s}' for {}...\n",
            .{ benchmark_name, std.fmt.fmtSliceHexLower(&commit) },
        );

        // Compile first to ensure that it doesn't affect the rusage stats
        var compile_argv = std.ArrayList([]const u8).init(gpa);
        defer compile_argv.deinit();
        try appendBenchBuildArgs(&compile_argv, zig_exe, abs_main_path, "../../bench.zig");

        const compile_stdout = try execCapture(gpa, compile_argv.items, .{ .cwd = bench_cwd });
        defer gpa.free(compile_stdout);

        // Because we compiled with --enable-cache, the path to the cache directory was printed
        // to stdout. We can append `./` to the front and `bench` to the end to execute it
        const trimmed_output = std.mem.trimRight(u8, compile_stdout, "\r\n");
        const main_exe = try std.fs.path.join(gpa, &.{ ".", trimmed_output, "bench" });
        defer gpa.free(main_exe);
        var main_argv = &[_][]const u8{ main_exe, zig_exe };

        const main_stdout = try execCapture(gpa, main_argv, .{ .cwd = bench_cwd });
        defer gpa.free(main_stdout);

        var main_json = json.parseFromSlice(json.Value, gpa, main_stdout, .{}) catch |err| {
            std.debug.print("bad json: {s}\n{s}\n", .{ @errorName(err), main_stdout });
            return error.InvalidBenchJSON;
        };
        defer main_json.deinit();

        const record = try jsonToRecord(
            arena,
            main_json.value,
            timestamp,
            benchmark_name,
            commit,
            zig_version,
            commit_timestamp,
        );

        const key: Record.Key = .{
            .commit_hash = record.commit_hash,
            .benchmark_name = record.benchmark_name,
        };
        const main_gop = try commit_table.getOrPut(key);
        if (main_gop.found_existing) {
            records.items[main_gop.value_ptr.*] = record;
        } else {
            main_gop.value_ptr.* = records.items.len;
            records.appendAssumeCapacity(record);
        }
    }
}

fn appendBenchBuildArgs(
    list: *std.ArrayList([]const u8),
    zig_exe: []const u8,
    main_path: []const u8,
    bench_zig: []const u8,
) !void {
    try list.ensureUnusedCapacity(20);
    list.appendSliceAssumeCapacity(&[_][]const u8{
        zig_exe,           "build-exe",
        "--main-pkg-path", "../..",
        "--pkg-begin",     "app",
        main_path,         "--pkg-end",
        "-O",              "ReleaseFast",
        "--enable-cache",  bench_zig,
    });
}

fn exec(
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    options: struct { cwd: ?[]const u8 = null },
) !void {
    const child = try std.ChildProcess.init(argv, gpa);
    defer child.deinit();

    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.cwd = options.cwd;

    const term = try child.spawnAndWait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                return error.ChildProcessBadExitCode;
            }
        },
        else => {
            return error.ChildProcessCrashed;
        },
    }
}

fn execCapture(
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    options: struct { cwd: ?[]const u8 = null },
) ![]u8 {
    //std.debug.print("exec argv[0]={} cwd={}\n", .{argv[0], options.cwd});
    var child = std.ChildProcess.init(argv, gpa);

    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;
    child.cwd = options.cwd;

    //std.debug.print("cwd={}\n", .{child.cwd});
    //for (argv) |arg| {
    //    std.debug.print("{} ", .{arg});
    //}
    //std.debug.print("\n", .{});

    try child.spawn();

    const stdout_in = child.stdout.?.reader();

    const stdout = try stdout_in.readAllAlloc(gpa, 9999);
    errdefer gpa.free(stdout);

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                return error.ChildProcessBadExitCode;
            }
        },
        else => {
            return error.ChildProcessCrashed;
        },
    }

    return stdout;
}
