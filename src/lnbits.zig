const std = @import("std");

pub const LnbitsError = error{
    RequestFailed,
    InvalidResponse,
    PaymentFailed,
    InvoiceNotFound,
    InsufficientBalance,
};

pub const WalletInfo = struct {
    name: []const u8,
    balance: u64,
};

pub const Invoice = struct {
    payment_hash: []const u8,
    payment_request: []const u8,
    checking_id: []const u8,
};

pub const PaymentResult = struct {
    payment_hash: []const u8,
    checking_id: []const u8,
};

pub const PaymentDetails = struct {
    pending: bool,
    amount: i64,
    fee: i64,
    memo: []const u8,
    preimage: []const u8,
    payment_hash: []const u8,
    bolt11: []const u8,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    admin_key: []const u8,
    http_client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, admin_key: []const u8) Client {
        return .{
            .allocator = allocator,
            .host = host,
            .admin_key = admin_key,
            .http_client = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.connection_pool.deinit();
    }

    pub fn getWallet(self: *Client) !WalletInfo {
        var response_buf: [4096]u8 = undefined;
        const response = try self.request(.GET, "/api/v1/wallet", null, &response_buf);

        const name = extractJsonString(response, "name") orelse "LNbits Wallet";
        const balance_msat = extractJsonInt(response, "balance") orelse 0;

        return .{
            .name = name,
            .balance = @intCast(balance_msat),
        };
    }

    pub fn createInvoice(self: *Client, amount_msat: u64, memo: ?[]const u8) !Invoice {
        var body_buf: [512]u8 = undefined;
        const amount_sats = amount_msat / 1000;
        const body = if (memo) |m|
            std.fmt.bufPrint(&body_buf, "{{\"out\":false,\"amount\":{d},\"memo\":\"{s}\"}}", .{ amount_sats, m }) catch return LnbitsError.RequestFailed
        else
            std.fmt.bufPrint(&body_buf, "{{\"out\":false,\"amount\":{d}}}", .{amount_sats}) catch return LnbitsError.RequestFailed;

        var response_buf: [8192]u8 = undefined;
        const response = try self.request(.POST, "/api/v1/payments", body, &response_buf);

        return .{
            .payment_hash = extractJsonString(response, "payment_hash") orelse return LnbitsError.InvalidResponse,
            .payment_request = extractJsonString(response, "payment_request") orelse return LnbitsError.InvalidResponse,
            .checking_id = extractJsonString(response, "checking_id") orelse "",
        };
    }

    pub fn payInvoice(self: *Client, bolt11: []const u8) !PaymentResult {
        var body_buf: [2048]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"out\":true,\"bolt11\":\"{s}\"}}", .{bolt11}) catch return LnbitsError.RequestFailed;

        var response_buf: [4096]u8 = undefined;
        const response = try self.request(.POST, "/api/v1/payments", body, &response_buf);

        if (std.mem.indexOf(u8, response, "\"error\"") != null) {
            return LnbitsError.PaymentFailed;
        }

        return .{
            .payment_hash = extractJsonString(response, "payment_hash") orelse return LnbitsError.InvalidResponse,
            .checking_id = extractJsonString(response, "checking_id") orelse "",
        };
    }

    pub fn lookupPayment(self: *Client, payment_hash: []const u8) !PaymentDetails {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/api/v1/payments/{s}", .{payment_hash}) catch return LnbitsError.RequestFailed;

        var response_buf: [8192]u8 = undefined;
        const response = try self.request(.GET, path, null, &response_buf);

        if (std.mem.indexOf(u8, response, "\"detail\"") != null) {
            return LnbitsError.InvoiceNotFound;
        }

        const pending_str = extractJsonString(response, "pending");
        const pending = if (pending_str) |p| std.mem.eql(u8, p, "true") else extractJsonBool(response, "pending") orelse true;

        return .{
            .pending = pending,
            .amount = extractJsonInt(response, "amount") orelse 0,
            .fee = extractJsonInt(response, "fee") orelse 0,
            .memo = extractJsonString(response, "memo") orelse "",
            .preimage = extractJsonString(response, "preimage") orelse "",
            .payment_hash = extractJsonString(response, "payment_hash") orelse payment_hash,
            .bolt11 = extractJsonString(response, "bolt11") orelse "",
        };
    }

    fn request(self: *Client, method: std.http.Method, path: []const u8, body: ?[]const u8, response_buf: []u8) ![]const u8 {
        var uri_buf: [512]u8 = undefined;
        const uri_str = std.fmt.bufPrint(&uri_buf, "{s}{s}", .{ self.host, path }) catch return LnbitsError.RequestFailed;

        const uri = std.Uri.parse(uri_str) catch return LnbitsError.RequestFailed;

        var req = self.http_client.request(method, uri, .{
            .extra_headers = &.{
                .{ .name = "X-Api-Key", .value = self.admin_key },
                .{ .name = "Content-Type", .value = "application/json" },
            },
        }) catch return LnbitsError.RequestFailed;
        defer req.deinit();

        if (body) |b| {
            req.transfer_encoding = .{ .content_length = b.len };
            req.sendBodyComplete(@constCast(b)) catch return LnbitsError.RequestFailed;
        } else {
            req.sendBodiless() catch return LnbitsError.RequestFailed;
        }

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch return LnbitsError.RequestFailed;

        if (response.head.status != .ok and response.head.status != .created) {
            return LnbitsError.RequestFailed;
        }

        var body_reader = response.reader(response_buf);
        const len = body_reader.readSliceShort(response_buf) catch return LnbitsError.RequestFailed;
        return response_buf[0..len];
    }
};

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

fn extractJsonBool(json: []const u8, key: []const u8) ?bool {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;

    var pos = key_pos + search.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}

    if (pos + 4 <= json.len and std.mem.eql(u8, json[pos..][0..4], "true")) return true;
    if (pos + 5 <= json.len and std.mem.eql(u8, json[pos..][0..5], "false")) return false;
    return null;
}
