const std = @import("std");
const net = std.net;
const posix = std.posix;
const print = std.debug.print;
const assert = std.debug.assert;
const io_t = std.os.linux.IoUring;
const UserData = std.os.linux.IORING_OP;
pub fn fmt_data(op: UserData) u64 {
    const d: u8 = @intFromEnum(op);
    const ret: u64 = @as(u64, d) << 56;
    return ret;
}
pub fn get_op(data: u64) UserData {
    const op: u8 = @truncate(data >> 56);
    return @enumFromInt(op);
}

pub fn main() !void {
    const socket = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(socket);
    const addr = try net.Address.resolveIp("127.0.0.1", 8080);
    var client_addr = try net.Address.resolveIp("127.0.0.1", 8080);
    var client_size = client_addr.getOsSockLen();

    // ty stdlib
    const opt_bytes = &std.mem.toBytes(@as(c_int, 1));
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, opt_bytes);
    posix.bind(socket, &addr.any, addr.getOsSockLen()) catch |err| {
        std.log.err("{s}\n", .{@errorName(err)});
        posix.close(socket);
        std.process.exit(1);
    };

    var io = try io_t.init(32, 0);
    defer io.deinit();
    try posix.listen(socket, 128);
    const buf_size = 128;
    const buf_count = 10;
    var buffers: [buf_count][buf_size]u8 = undefined;
    _ = try io.provide_buffers(fmt_data(UserData.PROVIDE_BUFFERS), @as([*]u8, @ptrCast(&buffers)), buf_size, buf_count, 0, 0);
    _ = try io.accept(fmt_data(UserData.ACCEPT), socket, &client_addr.any, &client_size, 0);
    _ = try io.submit();
    const recv_buf = io_t.RecvBuffer{
        .buffer_selection = .{
            .group_id = 0,
            .len = buf_size,
        },
    };

    // user_data
    // ................................................................
    // ^^^^^^^^                                        ^^^^^^^^^^^^^^^^
    // Last byte is opcode                                            |> FD for recv
    while (true) {
        while (io.cq_ready() > 0) {
            const cqe = try io.copy_cqe();
            switch (cqe.err()) {
                .SUCCESS => {},
                .NOBUFS => {
                    buffers = undefined;
                    _ = try io.provide_buffers(fmt_data(UserData.PROVIDE_BUFFERS), @as([*]u8, @ptrCast(&buffers)), buf_size, buf_count, 0, 0);
                    // Just replay the event
                    if (get_op(cqe.user_data) == .RECV) {
                        const fd: u16 = @truncate(cqe.user_data);
                        recv(&io, cqe.user_data, fd, recv_buf, 0);
                    }
                    _ = try io.submit_and_wait(2);
                    continue;
                },
                else => unreachable,
            }
            print("{s}\n", .{@tagName(get_op(cqe.user_data))});
            const op: UserData = get_op(cqe.user_data);
            switch (op) {
                .ACCEPT => {
                    const maybe_new_fd = cqe.res;
                    if (maybe_new_fd < 0) std.debug.panic("Invalid fd", .{});
                    // result of accept is FD
                    const new_fd: u16 = @intCast(cqe.res);
                    const user_data: u64 = fmt_data(UserData.RECV) | new_fd;
                    std.log.info("{any} {d}\n", .{ client_addr, new_fd });
                    recv(&io, user_data, new_fd, recv_buf, 0);
                    _ = try io.accept(fmt_data(UserData.ACCEPT), socket, &client_addr.any, &client_size, 0);
                },
                .RECV => {
                    const buf_id = try cqe.buffer_id();
                    // process
                    const buf = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
                    //send back
                    print("{s}\n", .{buffers[buf_id]});
                    const fd: u16 = @truncate(cqe.user_data);
                    _ = try io.send(fmt_data(UserData.SEND), fd, buf, 0);
                },
                .PROVIDE_BUFFERS => {},
                .SEND => {},
                else => unreachable,
            }
        }
        _ = try io.submit();
    }
}
fn recv(iou: *io_t, data: u64, fd: i32, recv_buf: io_t.RecvBuffer, flags: u8) void {
    _ = iou.recv(data, fd, recv_buf, flags) catch unreachable;
}
