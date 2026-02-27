//! VoidNote Zig SDK — example usage
//! Run: zig build run -- read <url-or-token>
//!      zig build run -- create "your secret message" <api-key>
//!      zig build run -- stream <api-key>

const std = @import("std");
const voidnote = @import("voidnote");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try std.io.getStdErr().writeAll(
            \\Usage:
            \\  voidnote-example read <url-or-token>
            \\  voidnote-example create <message> <api-key>
            \\  voidnote-example stream <api-key>
            \\
        );
        std.process.exit(1);
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "read")) {
        if (args.len < 3) {
            std.debug.print("error: read requires <url-or-token>\n", .{});
            std.process.exit(1);
        }
        const result = voidnote.read(allocator, args[2]) catch |err| {
            std.debug.print("error: {}\n", .{err});
            std.process.exit(1);
        };
        defer result.deinit(allocator);

        std.debug.print("content:    {s}\n", .{result.content});
        if (result.title) |t| std.debug.print("title:      {s}\n", .{t});
        std.debug.print("views:      {d}/{d}\n", .{ result.view_count, result.max_views });
        std.debug.print("destroyed:  {}\n", .{result.destroyed});
    } else if (std.mem.eql(u8, cmd, "create")) {
        if (args.len < 4) {
            std.debug.print("error: create requires <message> <api-key>\n", .{});
            std.process.exit(1);
        }
        const result = voidnote.create(allocator, args[2], .{ .api_key = args[3] }) catch |err| {
            std.debug.print("error: {}\n", .{err});
            std.process.exit(1);
        };
        defer result.deinit(allocator);

        std.debug.print("url:        {s}\n", .{result.url});
        std.debug.print("expires_at: {s}\n", .{result.expires_at});
    } else if (std.mem.eql(u8, cmd, "stream")) {
        if (args.len < 3) {
            std.debug.print("error: stream requires <api-key>\n", .{});
            std.process.exit(1);
        }
        var stream = voidnote.createStream(allocator, .{ .api_key = args[2] }) catch |err| {
            std.debug.print("error: {}\n", .{err});
            std.process.exit(1);
        };
        defer stream.deinit();

        std.debug.print("stream url: {s}\n", .{stream.url});
        std.debug.print("share the URL above, then writing messages...\n", .{});

        try stream.write("Hello from Zig! Message 1");
        try stream.write("Message 2 — post-quantum encrypted");
        try stream.close();
        std.debug.print("stream closed.\n", .{});
    } else {
        std.debug.print("unknown command: {s}\n", .{cmd});
        std.process.exit(1);
    }
}
