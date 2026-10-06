const std = @import("std");
const nostr = @import("nostr");

pub const Config = struct {
    privkey: [32]u8,
    pubkey: [32]u8,
    relay: []const u8,
    client_pubkeys: std.ArrayListUnmanaged([32]u8),
    lnbits_host: []const u8,
    lnbits_admin_key: []const u8,

    _allocated: std.ArrayListUnmanaged([]u8),
    _allocator: std.mem.Allocator,

    pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Config {
        const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        defer {
            std.crypto.secureZero(u8, content);
            allocator.free(content);
        }
        return parse(allocator, content);
    }

    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Config {
        var config = Config{
            .privkey = undefined,
            .pubkey = undefined,
            .relay = "",
            .client_pubkeys = .empty,
            .lnbits_host = "",
            .lnbits_admin_key = "",
            ._allocated = .empty,
            ._allocator = allocator,
        };
        errdefer config.deinit();

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
            const value = unquote(std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t"));

            if (std.mem.eql(u8, section, "nostr")) {
                if (std.mem.eql(u8, key, "privkey")) {
                    config.privkey = try parsePrivkey(allocator, value);
                    try nostr.crypto.getPublicKey(&config.privkey, &config.pubkey);
                    has_privkey = true;
                } else if (std.mem.eql(u8, key, "relay")) {
                    config.relay = try config.allocString(value);
                } else if (std.mem.eql(u8, key, "client_pubkeys")) {
                    try config.addClientPubkeys(allocator, value);
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
        if (config.client_pubkeys.items.len == 0) return error.MissingClientPubkeys;
        if (config.lnbits_host.len == 0) return error.MissingLnbitsHost;
        if (config.lnbits_admin_key.len == 0) return error.MissingLnbitsKey;

        return config;
    }

    pub fn isAuthorized(self: *const Config, pubkey: *const [32]u8) bool {
        for (self.client_pubkeys.items) |*pk| {
            if (std.mem.eql(u8, pk, pubkey)) return true;
        }
        return false;
    }

    fn unquote(value: []const u8) []const u8 {
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            return value[1 .. value.len - 1];
        }
        return value;
    }

    fn addClientPubkeys(self: *Config, allocator: std.mem.Allocator, value: []const u8) !void {
        var list = value;
        if (list.len >= 2 and list[0] == '[' and list[list.len - 1] == ']') {
            list = list[1 .. list.len - 1];
        }
        var items = std.mem.splitScalar(u8, list, ',');
        while (items.next()) |item| {
            const entry = unquote(std.mem.trim(u8, item, " \t"));
            if (entry.len == 0) continue;
            const pk = try parsePubkey(allocator, entry);
            if (!self.isAuthorized(&pk)) try self.client_pubkeys.append(self._allocator, pk);
        }
    }

    fn parsePrivkey(allocator: std.mem.Allocator, value: []const u8) ![32]u8 {
        if (std.mem.startsWith(u8, value, "nsec1")) {
            const decoded = nostr.bech32.decodeNostr(allocator, value) catch return error.InvalidPrivkey;
            switch (decoded) {
                .seckey => |sk| return sk,
                else => {
                    decoded.deinit(allocator);
                    return error.InvalidPrivkey;
                },
            }
        } else if (value.len == 64) {
            var key: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &key);
            _ = std.fmt.hexToBytes(&key, value) catch return error.InvalidPrivkey;
            return key;
        }
        return error.InvalidPrivkey;
    }

    fn parsePubkey(allocator: std.mem.Allocator, value: []const u8) ![32]u8 {
        if (std.mem.startsWith(u8, value, "npub1")) {
            const decoded = nostr.bech32.decodeNostr(allocator, value) catch return error.InvalidClientPubkey;
            switch (decoded) {
                .pubkey => |pk| return pk,
                else => {
                    decoded.deinit(allocator);
                    return error.InvalidClientPubkey;
                },
            }
        } else if (value.len == 64) {
            var key: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, value) catch return error.InvalidClientPubkey;
            return key;
        }
        return error.InvalidClientPubkey;
    }

    fn allocString(self: *Config, value: []const u8) ![]const u8 {
        const copy = try self._allocator.dupe(u8, value);
        errdefer self._allocator.free(copy);
        try self._allocated.append(self._allocator, copy);
        return copy;
    }

    pub fn deinit(self: *Config) void {
        for (self._allocated.items) |s| {
            std.crypto.secureZero(u8, s);
            self._allocator.free(s);
        }
        self._allocated.deinit(self._allocator);
        self.client_pubkeys.deinit(self._allocator);
        std.crypto.secureZero(u8, &self.privkey);
    }
};

const test_privkey = "0000000000000000000000000000000000000000000000000000000000000001";
const test_client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

test "parse full config with client pubkey list" {
    try nostr.init();
    defer nostr.cleanup();

    const content =
        \\[nostr]
        \\privkey = "
    ++ test_privkey ++
        \\"
        \\relay = "ws://127.0.0.1:7777"
        \\client_pubkeys = ["
    ++ test_client ++
        \\", "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"]
        \\
        \\[lnbits]
        \\host = "http://127.0.0.1:5000"
        \\admin_key = "abc"
    ;
    var config = try Config.parse(std.testing.allocator, content);
    defer config.deinit();

    try std.testing.expectEqualStrings("ws://127.0.0.1:7777", config.relay);
    var want_privkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_privkey, test_privkey);
    try std.testing.expectEqualSlices(u8, &want_privkey, &config.privkey);
    try std.testing.expectEqual(@as(usize, 2), config.client_pubkeys.items.len);

    var client: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client, test_client);
    try std.testing.expect(config.isAuthorized(&client));
    const stranger: [32]u8 = @splat(1);
    try std.testing.expect(!config.isAuthorized(&stranger));
}

test "config without client pubkeys is rejected" {
    try nostr.init();
    defer nostr.cleanup();

    const content =
        \\[nostr]
        \\privkey = "
    ++ test_privkey ++
        \\"
        \\relay = "ws://127.0.0.1:7777"
        \\[lnbits]
        \\host = "http://127.0.0.1:5000"
        \\admin_key = "abc"
    ;
    try std.testing.expectError(error.MissingClientPubkeys, Config.parse(std.testing.allocator, content));
}

test "invalid client pubkey is rejected" {
    try nostr.init();
    defer nostr.cleanup();

    const content =
        \\[nostr]
        \\privkey = "
    ++ test_privkey ++
        \\"
        \\relay = "ws://127.0.0.1:7777"
        \\client_pubkeys = "not-a-key"
        \\[lnbits]
        \\host = "http://127.0.0.1:5000"
        \\admin_key = "abc"
    ;
    try std.testing.expectError(error.InvalidClientPubkey, Config.parse(std.testing.allocator, content));
}
