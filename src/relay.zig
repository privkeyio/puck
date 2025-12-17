const std = @import("std");
const nostr = @import("nostr");
const ws = nostr.ws;

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
        var client = ws.Client.connect(allocator, url) catch |err| {
            log.err("WebSocket connection failed: {}", .{err});
            return RelayError.ConnectionFailed;
        };
        errdefer client.close();

        return .{
            .allocator = allocator,
            .url = url,
            .client = client,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.client.close();
    }

    pub fn send(self: *Relay, data: []const u8) !void {
        self.client.sendText(data) catch return RelayError.SendFailed;
    }

    pub fn receive(self: *Relay) !?Message {
        const msg = self.client.recvMessage() catch |err| {
            if (err == error.EndOfStream or err == error.ConnectionResetByPeer) {
                return RelayError.Closed;
            }
            return null;
        };

        const result = parseMessage(msg.payload, self.allocator) catch |err| {
            msg.deinit();
            return err;
        };
        msg.deinit();
        return result;
    }

    pub fn freeMessage(self: *Relay, message: *Message) void {
        switch (message.*) {
            .event => |e| {
                self.allocator.free(e.subscription_id);
                self.allocator.free(e.event_json);
            },
            .ok => |o| {
                self.allocator.free(o.event_id);
                self.allocator.free(o.message);
            },
            .eose => |s| self.allocator.free(s),
            .notice => |s| self.allocator.free(s),
            .closed => |c| {
                self.allocator.free(c.subscription_id);
                self.allocator.free(c.message);
            },
            .unknown => {},
        }
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

fn parseMessage(data: []const u8, allocator: std.mem.Allocator) !Message {
    if (data.len < 5) return .unknown;
    if (data[0] != '[') return .unknown;

    const type_start = std.mem.indexOf(u8, data, "\"") orelse return .unknown;
    const type_end = std.mem.indexOfPos(u8, data, type_start + 1, "\"") orelse return .unknown;
    const msg_type = data[type_start + 1 .. type_end];

    if (std.mem.eql(u8, msg_type, "EVENT")) {
        var pos = type_end + 1;
        while (pos < data.len and (data[pos] == ',' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
        const sub_start = pos;
        while (pos < data.len and data[pos] != '"') : (pos += 1) {}
        const sub_id = data[sub_start..pos];

        pos += 1;
        while (pos < data.len and (data[pos] == ',' or data[pos] == ' ')) : (pos += 1) {}

        if (pos < data.len and data[pos] == '{') {
            var depth: usize = 0;
            const event_start = pos;
            while (pos < data.len) : (pos += 1) {
                if (data[pos] == '{') depth += 1;
                if (data[pos] == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        const sub_id_copy = try allocator.dupe(u8, sub_id);
                        errdefer allocator.free(sub_id_copy);
                        const event_json_copy = try allocator.dupe(u8, data[event_start .. pos + 1]);
                        return .{ .event = .{
                            .subscription_id = sub_id_copy,
                            .event_json = event_json_copy,
                        } };
                    }
                }
            }
        }
        return .unknown;
    }

    if (std.mem.eql(u8, msg_type, "OK")) {
        var pos = type_end + 1;
        while (pos < data.len and (data[pos] == ',' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
        const id_start = pos;
        while (pos < data.len and data[pos] != '"') : (pos += 1) {}
        const event_id = data[id_start..pos];

        while (pos < data.len and data[pos] != 't' and data[pos] != 'f') : (pos += 1) {}
        const success = pos < data.len and data[pos] == 't';

        var message: []const u8 = "";
        if (std.mem.lastIndexOf(u8, data, "\"")) |last_quote| {
            if (lastIndexOfBefore(data, '"', last_quote)) |second_last| {
                message = data[second_last + 1 .. last_quote];
            }
        }

        const event_id_copy = try allocator.dupe(u8, event_id);
        errdefer allocator.free(event_id_copy);
        const message_copy = try allocator.dupe(u8, message);
        return .{ .ok = .{
            .event_id = event_id_copy,
            .success = success,
            .message = message_copy,
        } };
    }

    if (std.mem.eql(u8, msg_type, "EOSE")) {
        var pos = type_end + 1;
        while (pos < data.len and (data[pos] == ',' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
        const sub_start = pos;
        while (pos < data.len and data[pos] != '"') : (pos += 1) {}
        return .{ .eose = try allocator.dupe(u8, data[sub_start..pos]) };
    }

    if (std.mem.eql(u8, msg_type, "NOTICE")) {
        if (std.mem.lastIndexOf(u8, data, "\"")) |last_quote| {
            if (lastIndexOfBefore(data, '"', last_quote)) |second_last| {
                return .{ .notice = try allocator.dupe(u8, data[second_last + 1 .. last_quote]) };
            }
        }
        return .unknown;
    }

    if (std.mem.eql(u8, msg_type, "CLOSED")) {
        var pos = type_end + 1;
        while (pos < data.len and (data[pos] == ',' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
        const sub_start = pos;
        while (pos < data.len and data[pos] != '"') : (pos += 1) {}
        const sub_id = data[sub_start..pos];

        var message: []const u8 = "";
        if (std.mem.lastIndexOf(u8, data, "\"")) |last_quote| {
            if (lastIndexOfBefore(data, '"', last_quote)) |second_last| {
                message = data[second_last + 1 .. last_quote];
            }
        }

        const sub_id_copy = try allocator.dupe(u8, sub_id);
        errdefer allocator.free(sub_id_copy);
        const message_copy = try allocator.dupe(u8, message);
        return .{ .closed = .{
            .subscription_id = sub_id_copy,
            .message = message_copy,
        } };
    }

    return .unknown;
}

fn lastIndexOfBefore(data: []const u8, needle: u8, before: usize) ?usize {
    if (before == 0) return null;
    var i = before - 1;
    while (true) {
        if (data[i] == needle) return i;
        if (i == 0) return null;
        i -= 1;
    }
}
