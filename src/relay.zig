const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const ws = nostr.ws;
const utils = nostr.utils;

const log = std.log.scoped(.relay);

pub const RelayError = error{
    ConnectionFailed,
    SendFailed,
    InvalidMessage,
    Closed,
};

pub const Message = union(enum) {
    event: struct {
        subscription_id: []const u8,
        event_json: []const u8,
    },
    ok: struct {
        event_id: []const u8,
        success: bool,
        message: []const u8,
    },
    eose: []const u8,
    notice: []const u8,
    closed: struct {
        subscription_id: []const u8,
        message: []const u8,
    },
    unknown,
};

pub const Relay = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    client: ws.Client,

    pub fn connect(allocator: std.mem.Allocator, url: []const u8) !Relay {
        const client = ws.Client.connect(allocator, url) catch |err| {
            log.err("WebSocket connection failed: {}", .{err});
            return RelayError.ConnectionFailed;
        };
        enableKeepalive(client.tcp_stream.socket.handle);

        return .{
            .allocator = allocator,
            .url = url,
            .client = client,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.client.close();
    }

    pub fn socket(self: *const Relay) std.posix.fd_t {
        return self.client.tcp_stream.socket.handle;
    }

    pub fn send(self: *Relay, data: []const u8) !void {
        self.client.sendText(data) catch return RelayError.SendFailed;
    }

    pub fn receive(self: *Relay) !Message {
        const msg = self.client.recvMessage() catch |err| {
            log.warn("Receive failed: {}", .{err});
            return RelayError.Closed;
        };
        defer msg.deinit();
        return parseMessage(msg.payload, self.allocator);
    }

    pub fn freeMessage(self: *Relay, message: *Message) void {
        freeMessageWith(self.allocator, message);
    }

    pub fn publish(self: *Relay, event_json: []const u8) !void {
        var buf: [65536]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[\"EVENT\",{s}]", .{event_json}) catch return RelayError.SendFailed;
        try self.send(msg);
    }

    pub fn subscribe(self: *Relay, sub_id: []const u8, filter_json: []const u8) !void {
        var buf: [4096]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[\"REQ\",\"{s}\",{s}]", .{ sub_id, filter_json }) catch return RelayError.SendFailed;
        try self.send(msg);
    }

    pub fn close(self: *Relay, sub_id: []const u8) !void {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[\"CLOSE\",\"{s}\"]", .{sub_id}) catch return RelayError.SendFailed;
        try self.send(msg);
    }
};

/// A relay that vanishes without closing the connection (host down, NAT
/// timeout) would otherwise leave the blocking read waiting forever. Kernel
/// keepalive probes, plus a cap on unacknowledged writes, turn that into a read
/// error after about 90 seconds, which drops into the reconnect loop.
// Detects a dead peer, not a live relay that stops sending; an application
// level ping (REQ answered by EOSE) would cover that too.
fn enableKeepalive(fd: std.posix.fd_t) void {
    const set = struct {
        fn opt(sock: std.posix.fd_t, level: i32, name: u32, value: c_int) void {
            std.posix.setsockopt(sock, level, name, std.mem.asBytes(&value)) catch |err| {
                log.warn("setsockopt {d}/{d} failed: {}", .{ level, name, err });
            };
        }
    }.opt;
    set(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, 1);
    if (builtin.os.tag == .linux) {
        const tcp = std.posix.IPPROTO.TCP;
        set(fd, tcp, std.posix.TCP.KEEPIDLE, 60);
        set(fd, tcp, std.posix.TCP.KEEPINTVL, 10);
        set(fd, tcp, std.posix.TCP.KEEPCNT, 3);
        set(fd, tcp, std.posix.TCP.USER_TIMEOUT, 90_000);
    }
}

fn freeMessageWith(allocator: std.mem.Allocator, message: *Message) void {
    switch (message.*) {
        .event => |e| {
            allocator.free(e.subscription_id);
            allocator.free(e.event_json);
        },
        .ok => |o| {
            allocator.free(o.event_id);
            allocator.free(o.message);
        },
        .eose => |s| allocator.free(s),
        .notice => |s| allocator.free(s),
        .closed => |c| {
            allocator.free(c.subscription_id);
            allocator.free(c.message);
        },
        .unknown => {},
    }
}

fn stringElement(data: []const u8, index: usize) ?[]const u8 {
    const elem = utils.findArrayElement(data, index) orelse return null;
    const trimmed = std.mem.trim(u8, elem, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '"' or trimmed[trimmed.len - 1] != '"') return null;
    return trimmed[1 .. trimmed.len - 1];
}

fn parseMessage(data: []const u8, allocator: std.mem.Allocator) !Message {
    const trimmed = std.mem.trim(u8, data, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '[') return .unknown;
    const msg_type = stringElement(trimmed, 0) orelse return .unknown;

    if (std.mem.eql(u8, msg_type, "EVENT")) {
        const sub_id = stringElement(trimmed, 1) orelse return .unknown;
        const raw_event = utils.findArrayElement(trimmed, 2) orelse return .unknown;
        const event_json = std.mem.trim(u8, raw_event, " \t\r\n");
        if (event_json.len == 0 or event_json[0] != '{') return .unknown;
        if (utils.skipJsonValue(event_json, 0) != event_json.len) return .unknown;

        const sub_id_copy = try allocator.dupe(u8, sub_id);
        errdefer allocator.free(sub_id_copy);
        return .{ .event = .{
            .subscription_id = sub_id_copy,
            .event_json = try allocator.dupe(u8, event_json),
        } };
    }

    if (std.mem.eql(u8, msg_type, "OK")) {
        const event_id = stringElement(trimmed, 1) orelse return .unknown;
        const success_raw = utils.findArrayElement(trimmed, 2) orelse return .unknown;
        const message = stringElement(trimmed, 3) orelse "";

        const event_id_copy = try allocator.dupe(u8, event_id);
        errdefer allocator.free(event_id_copy);
        return .{ .ok = .{
            .event_id = event_id_copy,
            .success = std.mem.eql(u8, std.mem.trim(u8, success_raw, " \t\r\n"), "true"),
            .message = try allocator.dupe(u8, message),
        } };
    }

    if (std.mem.eql(u8, msg_type, "EOSE")) {
        return .{ .eose = try allocator.dupe(u8, stringElement(trimmed, 1) orelse return .unknown) };
    }

    if (std.mem.eql(u8, msg_type, "NOTICE")) {
        return .{ .notice = try allocator.dupe(u8, stringElement(trimmed, 1) orelse return .unknown) };
    }

    if (std.mem.eql(u8, msg_type, "CLOSED")) {
        const sub_id = stringElement(trimmed, 1) orelse return .unknown;
        const message = stringElement(trimmed, 2) orelse "";

        const sub_id_copy = try allocator.dupe(u8, sub_id);
        errdefer allocator.free(sub_id_copy);
        return .{ .closed = .{
            .subscription_id = sub_id_copy,
            .message = try allocator.dupe(u8, message),
        } };
    }

    return .unknown;
}

test "parse EVENT keeps braces inside strings" {
    const allocator = std.testing.allocator;
    const data =
        \\["EVENT","nwc",{"id":"x","tags":[["t","}{"]],"content":"a}b"}]
    ;
    var msg = try parseMessage(data, allocator);
    defer freeMessageWith(allocator, &msg);
    try std.testing.expectEqualStrings("nwc", msg.event.subscription_id);
    try std.testing.expectEqualStrings(
        \\{"id":"x","tags":[["t","}{"]],"content":"a}b"}
    , msg.event.event_json);
}

test "parse OK, EOSE, NOTICE and CLOSED" {
    const allocator = std.testing.allocator;

    var ok = try parseMessage("[\"OK\",\"abc\",false,\"blocked: no\"]", allocator);
    defer freeMessageWith(allocator, &ok);
    try std.testing.expect(!ok.ok.success);
    try std.testing.expectEqualStrings("blocked: no", ok.ok.message);

    var eose = try parseMessage("[\"EOSE\",\"nwc\"]", allocator);
    defer freeMessageWith(allocator, &eose);
    try std.testing.expectEqualStrings("nwc", eose.eose);

    var notice = try parseMessage("[\"NOTICE\",\"hi\"]", allocator);
    defer freeMessageWith(allocator, &notice);
    try std.testing.expectEqualStrings("hi", notice.notice);

    var closed = try parseMessage("[\"CLOSED\",\"nwc\",\"error: x\"]", allocator);
    defer freeMessageWith(allocator, &closed);
    try std.testing.expectEqualStrings("error: x", closed.closed.message);
}

test "malformed EVENT is unknown" {
    const allocator = std.testing.allocator;
    var msg = try parseMessage("[\"EVENT\",\"nwc\",{\"id\":\"x\"", allocator);
    defer freeMessageWith(allocator, &msg);
    try std.testing.expect(msg == .unknown);
}
