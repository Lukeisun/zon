const std = @import("std");
const net = std.net;
const posix = std.posix;
const print = std.debug.print;

pub fn main() !void {
    const socket = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    const addr = net.Address{ .in = try net.Ip4Address.resolveIp("127.0.0.1", 8080) };
    // ty stdlib
    const opt_bytes = &std.mem.toBytes(@as(c_int, 1));
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, opt_bytes);
    posix.bind(socket, &addr.any, addr.getOsSockLen()) catch |err| {
        std.log.err("{s}\n", .{@errorName(err)});
        posix.close(socket);
        std.process.exit(1);
    };
    try posix.listen(socket, 128);
    const new_fd = try posix.accept(socket, null, null, 0);
    var buf: [128]u8 = undefined;
    const size = try posix.recv(new_fd, &buf, 128);
    print("{s}\n", .{buf[0..size]});
    posix.close(socket);
}
