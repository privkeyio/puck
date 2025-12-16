const std = @import("std");
const nostr = @import("nostr");

pub const Config = struct {
    privkey: [32]u8,
    pubkey: [32]u8,
    relay: []const u8,
    lnbits_host: []const u8,
    lnbits_admin_key: []const u8,

    _allocated: std.ArrayListUnmanaged([]const u8),
    _allocator: std.mem.Allocator,

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
        var config = Config{
            .privkey = undefined,
            .pubkey = undefined,
            .relay = "",
            .lnbits_host = "",
            .lnbits_admin_key = "",
            ._allocated = .{},
            ._allocator = allocator,
        };

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        var section: []const u8 = "";
        var lines = std.mem.splitScalar(u8, content, '\n');
        var has_privkey = false;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                section = trimmed[1 .. trimmed.len - 1];
                continue;
            }

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            if (std.mem.eql(u8, section, "nostr")) {
                if (std.mem.eql(u8, key, "privkey")) {
                    config.privkey = try parsePrivkey(allocator, value);
                    try nostr.crypto.getPublicKey(&config.privkey, &config.pubkey);
                    has_privkey = true;
                } else if (std.mem.eql(u8, key, "relay")) {
                    config.relay = try config.allocString(value);
                }
            } else if (std.mem.eql(u8, section, "lnbits")) {
                if (std.mem.eql(u8, key, "host")) {
                    config.lnbits_host = try config.allocString(value);
                } else if (std.mem.eql(u8, key, "admin_key")) {
                    config.lnbits_admin_key = try config.allocString(value);
                }
            }
        }

        if (!has_privkey) return error.MissingPrivkey;
        if (config.relay.len == 0) return error.MissingRelay;
        if (config.lnbits_host.len == 0) return error.MissingLnbitsHost;
        if (config.lnbits_admin_key.len == 0) return error.MissingLnbitsKey;

        return config;
    }

    fn parsePrivkey(allocator: std.mem.Allocator, value: []const u8) ![32]u8 {
        if (std.mem.startsWith(u8, value, "nsec1")) {
            const decoded = nostr.bech32.decodeNostr(allocator, value) catch return error.InvalidPrivkey;
            switch (decoded) {
                .seckey => |sk| return sk,
                else => return error.InvalidPrivkey,
            }
        } else if (value.len == 64) {
            var key: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, value) catch return error.InvalidPrivkey;
            return key;
        }
        return error.InvalidPrivkey;
    }

    fn allocString(self: *Config, value: []const u8) ![]const u8 {
        const copy = try self._allocator.dupe(u8, value);
        try self._allocated.append(self._allocator, copy);
        return copy;
    }

    pub fn deinit(self: *Config) void {
        for (self._allocated.items) |s| {
            self._allocator.free(s);
        }
        self._allocated.deinit(self._allocator);
    }
};
