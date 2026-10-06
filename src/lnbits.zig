const std = @import("std");

const log = std.log.scoped(.lnbits);

pub const LnbitsError = error{
    RequestFailed,
    InvalidResponse,
    InvoiceNotFound,
    InvalidAmount,
};

/// Deadline for every LNbits call other than paying.
pub const request_timeout_s = 10;
/// LNbits itself answers a payment that is still in flight as pending after
/// `LNBITS_FUNDING_SOURCE_PAY_INVOICE_WAIT_SECONDS` (5 s by default).
pub const pay_timeout_s = 30;
/// Delays before each lookup of a payment whose outcome the pay call left open.
pub const lookup_backoff_s = [_]i64{ 0, 1, 2, 4, 8 };
/// Larger responses are treated as unreadable; memos and route hints fit easily.
pub const max_response_len = 64 * 1024;

pub const WalletInfo = struct {
    name: []const u8,
    balance: u64,
};

pub const Invoice = struct {
    payment_hash: []const u8,
    payment_request: []const u8,
};

pub const PaymentState = enum { paid, failed, pending };

pub const PaymentDetails = struct {
    state: PaymentState,
    /// Only set when it hashes to the payment hash.
    preimage: ?[32]u8 = null,
    /// Negative for outgoing payments.
    amount_msat: ?i64 = null,
    fee_msat: ?u64 = null,
    memo: ?[]const u8 = null,
    bolt11: ?[]const u8 = null,
};

pub const Paid = struct {
    preimage: ?[32]u8,
    fee_msat: ?u64,
};

pub const PayOutcome = union(enum) {
    paid: Paid,
    /// LNbits definitively reports the payment as not made; carries its reason.
    failed: []const u8,
    /// Still in flight, or LNbits could not be asked: it may yet complete.
    unknown,
};

/// What the pay call alone says, before any lookup.
pub const PostOutcome = union(enum) {
    paid: Paid,
    failed: []const u8,
    ambiguous,
};

pub const HttpResponse = struct {
    status: u16,
    body: []const u8,
};

pub const SendError = error{
    /// No connection was made, so LNbits never saw the request.
    NotSent,
    /// The request may have reached LNbits but no complete response came back.
    NoResponse,
    Timeout,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    admin_key: []const u8,
    http_client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, host: []const u8, admin_key: []const u8) Client {
        return .{
            .allocator = allocator,
            .io = io,
            .host = host,
            .admin_key = admin_key,
            .http_client = .{ .allocator = allocator, .io = io, .read_buffer_size = 16 * 1024 },
        };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
    }

    pub fn getWallet(self: *Client, arena: std.mem.Allocator) !WalletInfo {
        const response = try self.expectOk(arena, .GET, "/api/v1/wallet", null);
        const name = extractJsonString(response, "name") orelse "LNbits Wallet";
        const balance_msat = extractJsonInt(response, "balance") orelse 0;
        return .{
            .name = name,
            .balance = std.math.cast(u64, balance_msat) orelse return LnbitsError.InvalidResponse,
        };
    }

    pub fn createInvoice(self: *Client, arena: std.mem.Allocator, amount_msat: u64, memo: ?[]const u8) !Invoice {
        if (amount_msat == 0 or amount_msat % 1000 != 0) return LnbitsError.InvalidAmount;
        const amount_sats = amount_msat / 1000;
        const body = if (memo) |m|
            try std.fmt.allocPrint(arena, "{{\"out\":false,\"amount\":{d},\"memo\":\"{s}\"}}", .{ amount_sats, m })
        else
            try std.fmt.allocPrint(arena, "{{\"out\":false,\"amount\":{d}}}", .{amount_sats});

        const response = try self.expectOk(arena, .POST, "/api/v1/payments", body);
        return .{
            .payment_hash = extractJsonString(response, "payment_hash") orelse return LnbitsError.InvalidResponse,
            .payment_request = extractJsonString(response, "payment_request") orelse return LnbitsError.InvalidResponse,
        };
    }

    /// Pays `bolt11`, whose payment hash the caller decoded, and never reports
    /// failure unless LNbits says the payment did not happen: every other
    /// outcome is resolved by looking the payment up by hash.
    pub fn payInvoice(self: *Client, arena: std.mem.Allocator, bolt11: []const u8, payment_hash: *const [32]u8) !PayOutcome {
        const hash_hex = std.fmt.bytesToHex(payment_hash, .lower);
        const body = try std.fmt.allocPrint(arena, "{{\"out\":true,\"bolt11\":\"{s}\"}}", .{bolt11});

        const post: PostOutcome = if (self.send(arena, .POST, "/api/v1/payments", body, pay_timeout_s)) |response|
            classifyPayResponse(arena, response, payment_hash)
        else |err| switch (err) {
            error.NotSent => {
                log.warn("payment {s}: LNbits unreachable, not attempted", .{&hash_hex});
                return .{ .failed = "LNbits unreachable, payment not attempted" };
            },
            error.NoResponse, error.Timeout => blk: {
                log.warn("payment {s}: no response from LNbits ({t})", .{ &hash_hex, err });
                break :blk .ambiguous;
            },
        };

        switch (post) {
            .paid => |paid| return .{ .paid = paid },
            .failed => |reason| {
                // A rejection can follow a completed payment (LNbits bookkeeping
                // after the payment), or race an earlier attempt still in flight.
                const details = self.lookupOutgoing(arena, &hash_hex) orelse return .{ .failed = reason };
                return switch (details.state) {
                    .paid => .{ .paid = .{ .preimage = details.preimage, .fee_msat = details.fee_msat } },
                    .failed => .{ .failed = reason },
                    .pending => .unknown,
                };
            },
            .ambiguous => {
                for (lookup_backoff_s) |delay| {
                    if (delay > 0) std.Io.sleep(self.io, .fromSeconds(delay), .awake) catch {};
                    const details = self.lookupOutgoing(arena, &hash_hex) orelse continue;
                    switch (details.state) {
                        .paid => return .{ .paid = .{ .preimage = details.preimage, .fee_msat = details.fee_msat } },
                        .failed => return .{ .failed = "LNbits reported the payment as failed" },
                        .pending => {},
                    }
                }
                log.warn("payment {s}: outcome still unknown after lookups", .{&hash_hex});
                return .unknown;
            },
        }
    }

    /// The wallet's outgoing payment for `hash_hex`, or null if LNbits has none
    /// or could not be asked.
    fn lookupOutgoing(self: *Client, arena: std.mem.Allocator, hash_hex: *const [64]u8) ?PaymentDetails {
        const details = self.lookupPayment(arena, hash_hex) catch |err| {
            log.warn("payment {s}: lookup failed: {t}", .{ hash_hex, err });
            return null;
        };
        if (details.amount_msat) |amount| if (amount > 0) return null;
        log.info("payment {s}: lookup state {t}", .{ hash_hex, details.state });
        return details;
    }

    pub fn lookupPayment(self: *Client, arena: std.mem.Allocator, payment_hash: []const u8) !PaymentDetails {
        if (!isPaymentHash(payment_hash)) return LnbitsError.InvoiceNotFound;
        var hash: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&hash, payment_hash) catch return LnbitsError.InvoiceNotFound;
        const path = try std.fmt.allocPrint(arena, "/api/v1/payments/{s}", .{payment_hash});

        const response = self.send(arena, .GET, path, null, request_timeout_s) catch return LnbitsError.RequestFailed;
        if (response.status == 404) return LnbitsError.InvoiceNotFound;
        if (response.status != 200) return LnbitsError.RequestFailed;
        return parsePaymentDetails(arena, response.body, &hash) orelse LnbitsError.InvalidResponse;
    }

    fn expectOk(self: *Client, arena: std.mem.Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8) ![]const u8 {
        const response = self.send(arena, method, path, body, request_timeout_s) catch return LnbitsError.RequestFailed;
        if (response.status != 200 and response.status != 201) return LnbitsError.RequestFailed;
        return response.body;
    }

    const Race = union(enum) {
        response: SendError!HttpResponse,
        deadline: std.Io.Cancelable!void,
    };

    /// Runs one request against a deadline. std.http.Client has no timeout, so
    /// the request runs as a concurrent task that is canceled, interrupting any
    /// blocked connect, write or read, when the deadline task finishes first.
    fn send(self: *Client, arena: std.mem.Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8, timeout_s: i64) SendError!HttpResponse {
        var buf: [2]Race = undefined;
        var race = std.Io.Select(Race).init(self.io, &buf);
        race.concurrent(.deadline, std.Io.sleep, .{ self.io, .fromSeconds(timeout_s), .awake }) catch return error.NotSent;
        race.concurrent(.response, sendNow, .{ self, arena, method, path, body }) catch {
            race.cancelDiscard();
            return error.NotSent;
        };

        var result: ?(SendError!HttpResponse) = null;
        var timed_out = false;
        var next: ?Race = race.await() catch race.cancel();
        while (next) |done| : (next = race.cancel()) switch (done) {
            .response => |r| result = r,
            .deadline => |d| if (d) |_| {
                if (result == null) timed_out = true;
            } else |_| {},
        };

        const r = result orelse return error.Timeout;
        if (r) |response| return response else |err| {
            return if (timed_out and err == error.NoResponse) error.Timeout else err;
        }
    }

    fn sendNow(self: *Client, arena: std.mem.Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8) SendError!HttpResponse {
        const uri_str = std.fmt.allocPrint(arena, "{s}{s}", .{ self.host, path }) catch return error.NotSent;
        const uri = std.Uri.parse(uri_str) catch return error.NotSent;

        var req = self.http_client.request(method, uri, .{
            .headers = .{ .accept_encoding = .omit, .content_type = .{ .override = "application/json" } },
            .extra_headers = &.{
                .{ .name = "X-Api-Key", .value = self.admin_key },
            },
            .redirect_behavior = .unhandled,
            .keep_alive = false,
        }) catch return error.NotSent;
        defer req.deinit();
        // Never return a connection to the pool, even after a failed send.
        if (req.connection) |connection| connection.closing = true;

        if (body) |b| {
            req.transfer_encoding = .{ .content_length = b.len };
            req.sendBodyComplete(@constCast(b)) catch return error.NoResponse;
        } else {
            req.sendBodiless() catch return error.NoResponse;
        }

        var response = req.receiveHead(&.{}) catch return error.NoResponse;
        const status: u16 = @intFromEnum(response.head.status);

        var transfer_buf: [4096]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        const data = reader.allocRemaining(arena, .limited(max_response_len)) catch |err| {
            log.warn("{s}: unreadable response body (HTTP {d}): {t}", .{ path, status, err });
            return error.NoResponse;
        };
        return .{ .status = status, .body = data };
    }
};

/// Classifies LNbits' answer to `POST /api/v1/payments` with `out: true`.
/// Only a 201 with status "success", a `PaymentError` with status "failed"
/// (HTTP 520), or a 4xx with a JSON `detail` (request rejected before any
/// payment) are definitive; anything else needs a lookup.
pub fn classifyPayResponse(arena: std.mem.Allocator, response: HttpResponse, payment_hash: *const [32]u8) PostOutcome {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, response.body, .{}) catch return .ambiguous;
    const obj = switch (root) {
        .object => |o| o,
        else => return .ambiguous,
    };
    const status = stringField(obj, "status");
    const detail = stringField(obj, "detail");

    if (response.status == 200 or response.status == 201) {
        if (stringField(obj, "payment_hash")) |h| {
            const want = std.fmt.bytesToHex(payment_hash, .lower);
            if (!std.ascii.eqlIgnoreCase(h, &want)) return .ambiguous;
        }
        const s = status orelse return .ambiguous;
        if (std.mem.eql(u8, s, "success")) return .{ .paid = .{
            .preimage = verifiedPreimage(stringField(obj, "preimage"), payment_hash),
            .fee_msat = feeMsat(obj.get("fee")),
        } };
        if (std.mem.eql(u8, s, "failed")) return .{ .failed = "LNbits reported the payment as failed" };
        return .ambiguous;
    }

    if (status) |s| {
        if (std.mem.eql(u8, s, "failed")) return .{ .failed = detail orelse "LNbits reported the payment as failed" };
        return .ambiguous;
    }

    if (response.status >= 400 and response.status < 500 and obj.get("detail") != null) {
        return .{ .failed = detail orelse "LNbits rejected the payment request" };
    }
    return .ambiguous;
}

/// Parses `GET /api/v1/payments/{hash}`: `paid` is authoritative, otherwise a
/// status of "failed" (top level or in `details`) is a failure and anything
/// else is still pending.
pub fn parsePaymentDetails(arena: std.mem.Allocator, body: []const u8, payment_hash: *const [32]u8) ?PaymentDetails {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return null;
    const obj = switch (root) {
        .object => |o| o,
        else => return null,
    };
    const details: ?std.json.ObjectMap = if (obj.get("details")) |d| switch (d) {
        .object => |o| o,
        else => null,
    } else null;

    const paid = if (obj.get("paid")) |p| switch (p) {
        .bool => |b| b,
        else => return null,
    } else return null;

    const failed = blk: {
        if (stringField(obj, "status")) |s| break :blk std.mem.eql(u8, s, "failed");
        if (details) |d| if (stringField(d, "status")) |s| break :blk std.mem.eql(u8, s, "failed");
        break :blk false;
    };

    var result: PaymentDetails = .{ .state = if (paid) .paid else if (failed) .failed else .pending };
    if (paid) result.preimage = verifiedPreimage(stringField(obj, "preimage"), payment_hash);
    if (details) |d| {
        if (d.get("amount")) |a| if (a == .integer) {
            result.amount_msat = a.integer;
        };
        if (paid) result.fee_msat = feeMsat(d.get("fee"));
        result.memo = stringField(d, "memo");
        result.bolt11 = stringField(d, "bolt11");
    }
    return result;
}

fn stringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn feeMsat(value: ?std.json.Value) ?u64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |i| if (i == 0) null else @abs(i),
        else => null,
    };
}

fn verifiedPreimage(hex: ?[]const u8, payment_hash: *const [32]u8) ?[32]u8 {
    const h = hex orelse return null;
    if (h.len != 64) return null;
    var preimage: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&preimage, h) catch return null;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&preimage, &digest, .{});
    if (!std.mem.eql(u8, &digest, payment_hash)) return null;
    return preimage;
}

pub fn isPaymentHash(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;

    var pos = key_pos + search.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}

    if (pos >= json.len) return null;

    if (json[pos] == '"') {
        const start = pos + 1;
        var end = start;
        while (end < json.len and json[end] != '"') : (end += 1) {
            if (json[end] == '\\' and end + 1 < json.len) end += 1;
        }
        return json[start..end];
    }

    return null;
}

fn extractJsonInt(json: []const u8, key: []const u8) ?i64 {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;

    var pos = key_pos + search.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}

    if (pos >= json.len) return null;

    var end = pos;
    if (json[end] == '-') end += 1;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') : (end += 1) {}

    if (end == pos) return null;
    return std.fmt.parseInt(i64, json[pos..end], 10) catch null;
}

test "payment hash validation" {
    var hash: [64]u8 = @splat('a');
    try std.testing.expect(isPaymentHash(&hash));
    try std.testing.expect(!isPaymentHash(hash[0..63]));
    try std.testing.expect(!isPaymentHash("../wallet"));
    hash[62] = '/';
    try std.testing.expect(!isPaymentHash(&hash));
}

test "createInvoice rejects amounts that are not whole sats" {
    var client = Client.init(std.testing.allocator, std.testing.io, "http://127.0.0.1:1", "key");
    defer client.deinit();
    try std.testing.expectError(LnbitsError.InvalidAmount, client.createInvoice(std.testing.allocator, 0, null));
    try std.testing.expectError(LnbitsError.InvalidAmount, client.createInvoice(std.testing.allocator, 1500, null));
}

const TestPayment = struct {
    preimage: [32]u8 = @splat(0x42),
    hash: [32]u8 = undefined,
    preimage_hex: [64]u8 = undefined,
    hash_hex: [64]u8 = undefined,

    fn init() TestPayment {
        var p: TestPayment = .{};
        std.crypto.hash.sha2.Sha256.hash(&p.preimage, &p.hash, .{});
        p.preimage_hex = std.fmt.bytesToHex(&p.preimage, .lower);
        p.hash_hex = std.fmt.bytesToHex(&p.hash, .lower);
        return p;
    }
};

fn classifyBody(arena: std.mem.Allocator, status: u16, comptime fmt: []const u8, p: *const TestPayment) !PostOutcome {
    const body = try std.fmt.allocPrint(arena, fmt, .{ .hash = &p.hash_hex, .preimage = &p.preimage_hex });
    return classifyPayResponse(arena, .{ .status = status, .body = body }, &p.hash);
}

test "classifyPayResponse separates definitive outcomes from ambiguous ones" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = TestPayment.init();

    const paid = try classifyBody(arena, 201,
        \\{{"payment_hash":"{[hash]s}","status":"success","preimage":"{[preimage]s}","fee":-2000,"memo":"x"}}
    , &p);
    try std.testing.expectEqualSlices(u8, &p.preimage, &paid.paid.preimage.?);
    try std.testing.expectEqual(@as(?u64, 2000), paid.paid.fee_msat);

    const wrong_preimage = try classifyBody(arena, 201,
        \\{{"payment_hash":"{[hash]s}","status":"success","preimage":"{[hash]s}","memo":"{[preimage]s}"}}
    , &p);
    try std.testing.expectEqual(@as(?[32]u8, null), wrong_preimage.paid.preimage);

    const insufficient = classifyPayResponse(arena, .{ .status = 520, .body = "{\"detail\":\"Insufficient balance.\",\"status\":\"failed\"}" }, &p.hash);
    try std.testing.expectEqualStrings("Insufficient balance.", insufficient.failed);

    const bad_request = classifyPayResponse(arena, .{ .status = 400, .body = "{\"detail\":\"Missing BOLT11 invoice\"}" }, &p.hash);
    try std.testing.expectEqualStrings("Missing BOLT11 invoice", bad_request.failed);

    const validation = classifyPayResponse(arena, .{ .status = 400, .body = "{\"detail\":[{\"loc\":[\"body\",\"bolt11\"]}]}" }, &p.hash);
    try std.testing.expect(validation == .failed);

    const failed_201 = try classifyBody(arena, 201,
        \\{{"payment_hash":"{[hash]s}","status":"failed","preimage":"{[preimage]s}"}}
    , &p);
    try std.testing.expect(failed_201 == .failed);

    const ambiguous = [_]struct { status: u16, body: []const u8 }{
        .{ .status = 201, .body = "{\"status\":\"pending\"}" },
        .{ .status = 201, .body = "{\"payment_hash\":\"00\",\"status\":\"success\"}" },
        .{ .status = 201, .body = "{\"payment_hash\":\"x\",\"checking_id\":\"y\"}" },
        .{ .status = 520, .body = "{\"detail\":\"Payment is still pending.\",\"status\":\"pending\"}" },
        .{ .status = 520, .body = "{\"detail\":\"Payment already paid.\",\"status\":\"success\"}" },
        .{ .status = 500, .body = "{\"detail\":\"Unexpected error! ID: 1\"}" },
        .{ .status = 502, .body = "<html>Bad Gateway</html>" },
        .{ .status = 404, .body = "<html>Not Found</html>" },
        .{ .status = 201, .body = "{\"status\":\"succ" },
        .{ .status = 201, .body = "" },
    };
    for (ambiguous) |case| {
        const outcome = classifyPayResponse(arena, .{ .status = case.status, .body = case.body }, &p.hash);
        std.testing.expect(outcome == .ambiguous) catch |err| {
            std.debug.print("expected ambiguous for {d} {s}\n", .{ case.status, case.body });
            return err;
        };
    }
}

test "parsePaymentDetails reads LNbits payment lookups" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = TestPayment.init();

    const paid_body = try std.fmt.allocPrint(arena,
        \\{{"paid":true,"preimage":"{s}","details":{{"amount":-1000,"fee":-3000,"status":"success","memo":"m","bolt11":"lnbc"}}}}
    , .{&p.preimage_hex});
    const paid = parsePaymentDetails(arena, paid_body, &p.hash).?;
    try std.testing.expectEqual(PaymentState.paid, paid.state);
    try std.testing.expectEqualSlices(u8, &p.preimage, &paid.preimage.?);
    try std.testing.expectEqual(@as(?i64, -1000), paid.amount_msat);
    try std.testing.expectEqual(@as(?u64, 3000), paid.fee_msat);
    try std.testing.expectEqualStrings("m", paid.memo.?);

    const failed = parsePaymentDetails(arena, "{\"paid\":false,\"status\":\"failed\",\"details\":{\"amount\":-1000,\"fee\":-10}}", &p.hash).?;
    try std.testing.expectEqual(PaymentState.failed, failed.state);
    try std.testing.expectEqual(@as(?u64, null), failed.fee_msat);

    const pending = parsePaymentDetails(arena, "{\"paid\":false,\"status\":\"pending\",\"preimage\":null}", &p.hash).?;
    try std.testing.expectEqual(PaymentState.pending, pending.state);

    const no_status = parsePaymentDetails(arena, "{\"paid\":false}", &p.hash).?;
    try std.testing.expectEqual(PaymentState.pending, no_status.state);

    try std.testing.expect(parsePaymentDetails(arena, "{\"detail\":\"Payment does not exist.\"}", &p.hash) == null);
    try std.testing.expect(parsePaymentDetails(arena, "[]", &p.hash) == null);
}
