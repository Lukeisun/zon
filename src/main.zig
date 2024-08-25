const std = @import("std");
const net = std.net;
const posix = std.posix;
const print = std.debug.print;
const assert = std.debug.assert;
const io_t = std.os.linux.IoUring;
const UserData = std.os.linux.IORING_OP;
const Allocator = std.mem.Allocator;
pub fn fmt_data(op: UserData) u64 {
    const d: u8 = @intFromEnum(op);
    const ret: u64 = @as(u64, d) << 56;
    return ret;
}
pub fn get_op(data: u64) UserData {
    const op: u8 = @truncate(data >> 56);
    return @enumFromInt(op);
}
pub const Request = struct {
    request_line: []const u8,
    header_lines: [][]const u8,
    body: [][]const u8,
    allocator: Allocator,
    pub fn parse(allocator: Allocator, request: []const u8) Request {
        var s = std.mem.splitSequence(u8, request, "\r\n");
        const request_line = s.next().?;
        var header_lines = std.ArrayList([]const u8).init(allocator);
        while (s.next()) |str| {
            // break header
            if (std.mem.eql(u8, str, "")) break;
            header_lines.append(str) catch unreachable;
        }
        var body = std.ArrayList([]const u8).init(allocator);
        while (s.next()) |str| {
            if (std.mem.eql(u8, str, "")) break;
            body.append(str) catch unreachable;
        }
        const header_slice = header_lines.toOwnedSlice() catch unreachable;
        const body_slice = body.toOwnedSlice() catch unreachable;
        return .{ .request_line = request_line, .header_lines = header_slice, .body = body_slice, .allocator = allocator };
    }
    pub fn destroy(self: *Request) void {
        self.allocator.free(self.header_lines);
        self.allocator.free(self.body);
    }
    pub fn show(self: Request) void {
        print("Req Line: {s}\n", .{self.request_line});
        print("Headers: \n", .{});
        for (self.header_lines) |line| {
            print("\t {s}\n", .{line});
        }
        print("Body: \n", .{});
        for (self.body) |line| {
            print("\t {s}\n", .{line});
        }
    }
};
pub const Server = struct {
    const buf_size = 128;
    const buf_count = 10;
    const recv_buf = io_t.RecvBuffer{
        .buffer_selection = .{
            .group_id = 0,
            .len = buf_size,
        },
    };
    const socket_t = std.os.linux.socket_t;
    allocator: Allocator,
    buffers: [buf_count][buf_size]u8 = undefined,
    socket: std.os.linux.socket_t,
    addr: net.Address,
    uring: io_t,

    pub fn init(allocator: Allocator, socket: socket_t, ip_str: []const u8, port: u16) !Server {
        const addr = try net.Address.resolveIp(ip_str, port);
        const opt_bytes = &std.mem.toBytes(@as(c_int, 1));
        try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, opt_bytes);
        const uring = try io_t.init(32, 0);
        posix.bind(socket, &addr.any, addr.getOsSockLen()) catch |err| {
            std.log.err("{s}\n", .{@errorName(err)});
            posix.close(socket);
            std.process.exit(1);
        };
        try posix.listen(socket, 128);
        return .{ .addr = addr, .uring = uring, .socket = socket, .allocator = allocator };
    }
    pub fn start(self: *Server) !void {
        // dumy addr
        var client_addr = try net.Address.resolveIp("127.0.0.1", 8080);
        var client_size = client_addr.getOsSockLen();
        _ = try self.uring.provide_buffers(fmt_data(UserData.PROVIDE_BUFFERS), @as([*]u8, @ptrCast(&self.buffers)), buf_size, buf_count, 0, 0);
        _ = try self.uring.accept(fmt_data(UserData.ACCEPT), self.socket, &client_addr.any, &client_size, 0);
        _ = try self.uring.submit();
        while (true) {
            while (self.uring.cq_ready() > 0) {
                const cqe = try self.uring.copy_cqe();
                switch (cqe.err()) {
                    .SUCCESS => {},
                    .NOBUFS => {
                        self.buffers = undefined;
                        _ = try self.uring.provide_buffers(fmt_data(UserData.PROVIDE_BUFFERS), @as([*]u8, @ptrCast(&self.buffers)), buf_size, buf_count, 0, 0);
                        // Just replay the event
                        if (get_op(cqe.user_data) == .RECV) {
                            const fd: u16 = @truncate(cqe.user_data);
                            recv(&self.uring, cqe.user_data, fd, recv_buf, 0);
                        }
                        _ = try self.uring.submit_and_wait(2);
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
                        recv(&self.uring, user_data, new_fd, recv_buf, 0);
                        _ = try self.uring.accept(fmt_data(UserData.ACCEPT), self.socket, &client_addr.any, &client_size, 0);
                    },
                    .RECV => {
                        const buf_id = try cqe.buffer_id();
                        // process
                        const request_raw = self.buffers[buf_id];
                        var x = Request.parse(self.allocator, &request_raw);
                        defer x.destroy();
                        x.show();
                        const buf = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
                        //send back
                        print("{s}\n", .{request_raw});
                        const fd: u16 = @truncate(cqe.user_data);
                        _ = try self.uring.send(fmt_data(UserData.SEND), fd, buf, 0);
                    },
                    .PROVIDE_BUFFERS => {},
                    .SEND => {},
                    else => unreachable,
                }
            }
            _ = try self.uring.submit();
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const socket = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    var server = try Server.init(allocator, socket, "127.0.0.1", 8080);
    server.start() catch unreachable;
    // user_data
    // ................................................................
    // ^^^^^^^^                                        ^^^^^^^^^^^^^^^^
    // Last byte is opcode                                            |> FD for recv
}
fn recv(iou: *io_t, data: u64, fd: i32, recv_buf: io_t.RecvBuffer, flags: u8) void {
    _ = iou.recv(data, fd, recv_buf, flags) catch unreachable;
}
