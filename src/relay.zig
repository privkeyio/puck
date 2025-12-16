const std = @import("std");
const websocket = @import("websocket");

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
    client: websocket.Client,
    recv_buf: []u8,
    ca_bundle: ?std.crypto.Certificate.Bundle,

    pub fn connect(allocator: std.mem.Allocator, url: []const u8) !Relay {
        const parsed = parseWsUrl(url) orelse {
            log.err("Invalid WebSocket URL: {s}", .{url});
            return RelayError.ConnectionFailed;
        };

        var ca_bundle: ?std.crypto.Certificate.Bundle = null;
        if (parsed.tls) {
            ca_bundle = std.crypto.Certificate.Bundle{};
            ca_bundle.?.rescan(allocator) catch |err| {
                log.err("Failed to scan CA certificates: {}", .{err});
                return RelayError.ConnectionFailed;
            };
        }
        errdefer if (ca_bundle) |*b| b.deinit(allocator);

        var client = websocket.Client.init(allocator, .{
            .tls = parsed.tls,
            .host = parsed.host,
            .port = parsed.port,
            .ca_bundle = ca_bundle,
        }) catch |err| {
            log.err("WebSocket init failed: {}", .{err});
            return RelayError.ConnectionFailed;
        };
        errdefer client.deinit();

        var host_header_buf: [256]u8 = undefined;
        const host_header = std.fmt.bufPrint(&host_header_buf, "Host: {s}\r\n", .{parsed.host}) catch {
            log.err("Host too long", .{});
            return RelayError.ConnectionFailed;
        };

        client.handshake(parsed.path, .{
            .headers = host_header,
        }) catch |err| {
            log.err("WebSocket handshake failed: {}", .{err});
            return RelayError.ConnectionFailed;
        };

        const recv_buf = allocator.alloc(u8, 65536) catch return RelayError.ConnectionFailed;

        return .{
            .allocator = allocator,
            .url = url,
            .client = client,
            .recv_buf = recv_buf,
            .ca_bundle = ca_bundle,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.allocator.free(self.recv_buf);
        self.client.deinit();
        if (self.ca_bundle) |*b| b.deinit(self.allocator);
    }

    pub fn send(self: *Relay, data: []const u8) !void {
        if (data.len > self.recv_buf.len) return RelayError.SendFailed;
        @memcpy(self.recv_buf[0..data.len], data);
        self.client.writeText(self.recv_buf[0..data.len]) catch return RelayError.SendFailed;
    }

    pub fn receive(self: *Relay) !?Message {
        const msg = self.client.read() catch |err| {
            if (err == error.EndOfStream or err == error.ConnectionResetByPeer) {
                return RelayError.Closed;
            }
            return null;
        };

        if (msg) |m| {
            defer self.client.done(m);
            if (m.type == .text or m.type == .binary) {
                return parseMessage(m.data);
            }
        }
        return null;
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

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    tls: bool,
};

fn parseWsUrl(url: []const u8) ?ParsedUrl {
    var remaining = url;
    var tls = false;

    if (std.mem.startsWith(u8, remaining, "wss://")) {
        tls = true;
        remaining = remaining[6..];
    } else if (std.mem.startsWith(u8, remaining, "ws://")) {
        remaining = remaining[5..];
    } else {
        return null;
    }

    const path_start = std.mem.indexOf(u8, remaining, "/") orelse remaining.len;
    const host_port = remaining[0..path_start];
    const path = if (path_start < remaining.len) remaining[path_start..] else "/";

    var port: u16 = if (tls) 443 else 80;
    var host = host_port;

    if (std.mem.indexOf(u8, host_port, ":")) |colon| {
        host = host_port[0..colon];
        port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null;
    }

    return .{
        .host = host,
        .port = port,
        .path = path,
        .tls = tls,
    };
}

fn parseMessage(data: []const u8) Message {
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
                        return .{ .event = .{
                            .subscription_id = sub_id,
                            .event_json = data[event_start .. pos + 1],
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

        return .{ .ok = .{
            .event_id = event_id,
            .success = success,
            .message = message,
        } };
    }

    if (std.mem.eql(u8, msg_type, "EOSE")) {
        var pos = type_end + 1;
        while (pos < data.len and (data[pos] == ',' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
        const sub_start = pos;
        while (pos < data.len and data[pos] != '"') : (pos += 1) {}
        return .{ .eose = data[sub_start..pos] };
    }

    if (std.mem.eql(u8, msg_type, "NOTICE")) {
        if (std.mem.lastIndexOf(u8, data, "\"")) |last_quote| {
            if (lastIndexOfBefore(data, '"', last_quote)) |second_last| {
                return .{ .notice = data[second_last + 1 .. last_quote] };
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

        return .{ .closed = .{
            .subscription_id = sub_id,
            .message = message,
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
