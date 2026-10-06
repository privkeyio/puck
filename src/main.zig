const std = @import("std");
const nostr = @import("nostr");
const Config = @import("config.zig").Config;
const LnbitsClient = @import("lnbits.zig").Client;
const bolt11 = @import("bolt11.zig");
const Relay = @import("relay.zig").Relay;

const nwc = nostr.nwc;
const utils = nostr.utils;

const supported_methods = [_]nwc.Method{
    .get_balance,
    .get_info,
    .make_invoice,
    .pay_invoice,
    .lookup_invoice,
};

/// Requests older than this are ignored, and request ids are remembered for at
/// least this long, so a captured request cannot be replayed to run twice.
const max_request_age_s: i64 = 600;

/// The replay cache does not survive a restart, so requests created more than
/// this long before the process started are ignored.
const start_skew_s: i64 = 60;

var g_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var g_relay_fd: std.atomic.Value(std.posix.fd_t) = std.atomic.Value(std.posix.fd_t).init(-1);

fn signalHandler(_: std.posix.SIG) callconv(std.builtin.CallingConvention.c) void {
    g_shutdown.store(true, .release);
    const fd = g_relay_fd.load(.acquire);
    if (fd >= 0) _ = std.c.shutdown(fd, std.posix.SHUT.RD);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const config_path = if (args.len > 1) args[1] else "puck.toml";

    try nostr.init();
    defer nostr.cleanup();

    var config = Config.load(allocator, io, config_path) catch |err| {
        std.log.err("Failed to load config from {s}: {}", .{ config_path, err });
        return err;
    };
    defer config.deinit();

    std.log.info("Puck NWC Server starting", .{});
    var pubkey_hex: [64]u8 = undefined;
    nostr.hex.encode(&config.pubkey, &pubkey_hex);
    std.log.info("Pubkey: {s}", .{&pubkey_hex});
    var url_buf: [512]u8 = undefined;
    std.log.info("Relay: {s}", .{redactUserinfo(config.relay, &url_buf)});
    std.log.info("LNbits: {s}", .{redactUserinfo(config.lnbits_host, &url_buf)});
    std.log.info("Authorized client pubkeys: {d}", .{config.client_pubkeys.items.len});

    const sa = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    const ignore_sa = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &ignore_sa, null);

    var lnbits = LnbitsClient.init(allocator, io, config.lnbits_host, config.lnbits_admin_key);
    defer lnbits.deinit();

    var guard: ReplayGuard = .{ .not_before = nostr.io.timestamp() - start_skew_s };
    defer guard.deinit(allocator);

    while (!g_shutdown.load(.acquire)) {
        runEventLoop(allocator, &config, &lnbits, &guard) catch |err| {
            std.log.err("Event loop error: {}", .{err});
        };

        if (!g_shutdown.load(.acquire)) {
            std.log.info("Reconnecting in 5 seconds...", .{});
            std.Io.sleep(io, .{ .nanoseconds = 5 * std.time.ns_per_s }, .awake) catch {};
        }
    }

    std.log.info("Shutdown complete", .{});
}

/// `url` with any userinfo (`user:password@`) replaced, for logging.
fn redactUserinfo(url: []const u8, buf: []u8) []const u8 {
    const authority_start = (std.mem.indexOf(u8, url, "://") orelse return url) + 3;
    const authority_end = std.mem.indexOfAnyPos(u8, url, authority_start, "/?#") orelse url.len;
    const at = std.mem.lastIndexOfScalar(u8, url[authority_start..authority_end], '@') orelse return url;
    return std.fmt.bufPrint(buf, "{s}***@{s}", .{ url[0..authority_start], url[authority_start + at + 1 ..] }) catch "<redacted>";
}

fn runEventLoop(allocator: std.mem.Allocator, config: *Config, lnbits: *LnbitsClient, guard: *ReplayGuard) !void {
    std.log.info("Connecting to relay...", .{});
    var relay = try Relay.connect(allocator, config.relay);
    g_relay_fd.store(relay.socket(), .release);
    defer {
        g_relay_fd.store(-1, .release);
        relay.deinit();
    }
    std.log.info("Connected to relay", .{});

    try publishInfoEvent(config, &relay);

    var filter_buf: [4096]u8 = undefined;
    const filter = try buildRequestFilter(config, @max(nostr.io.timestamp() - max_request_age_s, guard.not_before), &filter_buf);

    try relay.subscribe("nwc", filter);
    std.log.info("Subscribed to NWC requests", .{});

    while (!g_shutdown.load(.acquire)) {
        var message = try relay.receive();
        defer relay.freeMessage(&message);
        switch (message) {
            .event => |e| {
                handleEvent(allocator, config, lnbits, &relay, guard, e.event_json) catch |err| {
                    std.log.err("Failed to handle event: {}", .{err});
                };
            },
            .eose => std.log.debug("EOSE received", .{}),
            .notice => |n| std.log.warn("Notice: {s}", .{n}),
            .ok => |o| {
                if (!o.success) {
                    std.log.warn("Event rejected: {s}", .{o.message});
                }
            },
            .closed => |c| {
                std.log.warn("Subscription closed: {s}", .{c.message});
                return error.SubscriptionClosed;
            },
            .unknown => {},
        }
    }
}

fn buildRequestFilter(config: *const Config, since: i64, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    var hex_buf: [64]u8 = undefined;
    nostr.hex.encode(&config.pubkey, &hex_buf);
    try w.print("{{\"kinds\":[{d}],\"#p\":[\"{s}\"],\"authors\":[", .{ nwc.Kind.request, &hex_buf });
    for (config.client_pubkeys.items, 0..) |*pk, i| {
        if (i > 0) try w.writeByte(',');
        nostr.hex.encode(pk, &hex_buf);
        try w.print("\"{s}\"", .{&hex_buf});
    }
    try w.print("],\"since\":{d}}}", .{since});
    return w.buffered();
}

fn publishInfoEvent(config: *Config, relay: *Relay) !void {
    var content_buf: [256]u8 = undefined;
    var content_pos: usize = 0;
    for (supported_methods, 0..) |method, i| {
        if (i > 0) {
            content_buf[content_pos] = ' ';
            content_pos += 1;
        }
        const method_str = method.toString();
        @memcpy(content_buf[content_pos .. content_pos + method_str.len], method_str);
        content_pos += method_str.len;
    }
    const content = content_buf[0..content_pos];

    var keypair = nostr.Keypair{
        .secret_key = config.privkey,
        .public_key = config.pubkey,
    };
    defer std.crypto.secureZero(u8, &keypair.secret_key);

    const tags = [_][]const []const u8{
        &[_][]const u8{ "encryption", nwc.Encryption.nip44_v2.toString() },
    };

    var builder = nostr.EventBuilder{};
    _ = builder.setKind(nwc.Kind.info).setContent(content).setTags(&tags);
    try builder.sign(&keypair);

    var event_buf: [4096]u8 = undefined;
    const event_json = try builder.serialize(&event_buf);

    try relay.publish(event_json);
    std.log.info("Published info event (kind {d})", .{nwc.Kind.info});
}

const RequestError = error{
    WrongKind,
    NotAddressedToUs,
    Unauthorized,
    InvalidSignature,
    Expired,
    Stale,
    BeforeStart,
};

/// Checks run before a request is decrypted: it must be a kind 23194 event
/// addressed to this wallet service, authored by a configured client key,
/// correctly signed, unexpired (NIP-47 `expiration` tag), recent, and not
/// created before `not_before` (shortly before this process started).
fn checkRequest(config: *const Config, event: *const nostr.Event, now: i64, not_before: i64) RequestError!void {
    if (event.kind() != nwc.Kind.request) return error.WrongKind;
    if (!config.isAuthorized(event.pubkey())) return error.Unauthorized;

    var tags = utils.TagIterator.init(event.raw_json, "tags") orelse return error.NotAddressedToUs;
    var addressed = false;
    var expired = false;
    while (tags.next()) |tag| {
        if (std.mem.eql(u8, tag.name, "p")) {
            var pk: [32]u8 = undefined;
            if (tag.value.len == 64) {
                if (std.fmt.hexToBytes(&pk, tag.value)) |_| {
                    if (std.mem.eql(u8, &pk, &config.pubkey)) addressed = true;
                } else |_| {}
            }
        } else if (std.mem.eql(u8, tag.name, "expiration")) {
            const at = std.fmt.parseInt(i64, tag.value, 10) catch {
                expired = true;
                continue;
            };
            if (now > at) expired = true;
        }
    }
    if (tags.malformed or !addressed) return error.NotAddressedToUs;

    event.validate() catch return error.InvalidSignature;

    if (expired) return error.Expired;
    if (event.createdAt() < now - max_request_age_s) return error.Stale;
    if (event.createdAt() < not_before) return error.BeforeStart;
}

/// NIP-47: a request without an `encryption` tag uses NIP-04.
fn requestEncryption(event: *const nostr.Event) error{UnsupportedEncryption}!nwc.Encryption {
    var tags = utils.TagIterator.init(event.raw_json, "tags") orelse return .nip04;
    var found: ?nwc.Encryption = null;
    while (tags.next()) |tag| {
        if (!std.mem.eql(u8, tag.name, "encryption")) continue;
        if (found != null) return error.UnsupportedEncryption;
        found = nwc.Encryption.fromString(tag.value) orelse return error.UnsupportedEncryption;
    }
    return found orelse .nip04;
}

/// Remembers the ids of accepted requests until they are older than
/// `max_request_age_s` and would be rejected as stale anyway.
// Linear scan; only authorized, signed requests are recorded, so it stays small.
const ReplayGuard = struct {
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    /// Process start minus `start_skew_s`; earlier requests may predate the cache.
    not_before: i64,

    const Entry = struct { id: [32]u8, created_at: i64 };

    fn firstSeen(self: *ReplayGuard, allocator: std.mem.Allocator, id: *const [32]u8, created_at: i64, now: i64) !bool {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].created_at < now - max_request_age_s) {
                _ = self.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.id, id)) return false;
        }
        try self.entries.append(allocator, .{ .id = id.*, .created_at = created_at });
        return true;
    }

    fn deinit(self: *ReplayGuard, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }
};

fn handleEvent(allocator: std.mem.Allocator, config: *Config, lnbits: *LnbitsClient, relay: *Relay, guard: *ReplayGuard, event_json: []const u8) !void {
    var event = try nostr.Event.parseWithAllocator(event_json, allocator);
    defer event.deinit();

    var id_hex: [64]u8 = undefined;
    nostr.hex.encode(&event.id_bytes, &id_hex);

    const now = nostr.io.timestamp();
    checkRequest(config, &event, now, guard.not_before) catch |err| {
        std.log.warn("Ignoring request {s}: {}", .{ &id_hex, err });
        return;
    };
    if (!try guard.firstSeen(allocator, &event.id_bytes, event.createdAt(), now)) {
        std.log.warn("Ignoring replayed request {s}", .{&id_hex});
        return;
    }

    const sender_pubkey = event.pubkey();
    var event_buf: [32768]u8 = undefined;

    const encryption = requestEncryption(&event) catch {
        std.log.warn("Request {s}: unsupported encryption", .{&id_hex});
        // The method is unreadable, so result_type stays empty; the reply uses
        // the only scheme the info event advertises.
        const response_event = try buildResponseEvent(allocator, config, sender_pubkey, &event.id_bytes, unsupported_encryption_response, .nip44_v2, &event_buf);
        try relay.publish(response_event);
        return;
    };

    const decrypted = decrypt(allocator, config, sender_pubkey, event.content(), encryption) catch |err| {
        std.log.err("Decryption failed: {}", .{err});
        return;
    };
    defer {
        std.crypto.secureZero(u8, decrypted);
        allocator.free(decrypted);
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var response_buf: [16384]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buf);
    const response_json = switch (encryption) {
        .nip04 => blk: {
            const method = nwc.Method.fromString(utils.extractJsonString(decrypted, "method") orelse return) orelse return;
            const response = nwc.Response{
                .result_type = method,
                .err = .{ .code = .unsupported_encryption, .message = "Use nip44_v2 encryption" },
            };
            break :blk try response.serialize(&response_buf);
        },
        .nip44_v2 => if (nwc.Request.parseJson(decrypted)) |request| blk: {
            std.log.info("Received {s} request", .{request.method.toString()});
            break :blk try handleRequest(arena.allocator(), request, utils.findJsonValue(decrypted, "params") orelse "{}", lnbits, &response_buf);
        } else serializeInvalidRequest(decrypted, &response_buf) orelse {
            std.log.err("Failed to parse NWC request", .{});
            return;
        },
    };

    const response_event = try buildResponseEvent(allocator, config, sender_pubkey, &event.id_bytes, response_json, encryption, &event_buf);
    try relay.publish(response_event);
    std.log.debug("Published response", .{});
}

const unsupported_encryption_response = "{\"result_type\":\"\",\"error\":{\"code\":\"UNSUPPORTED_ENCRYPTION\",\"message\":\"Use nip44_v2 encryption\"},\"result\":null}";

fn decrypt(allocator: std.mem.Allocator, config: *const Config, sender: *const [32]u8, content: []const u8, encryption: nwc.Encryption) ![]u8 {
    return switch (encryption) {
        .nip44_v2 => nostr.crypto.nip44Decrypt(&config.privkey, sender, content, allocator),
        .nip04 => nostr.nip04.decrypt(&config.privkey, sender, content, allocator),
    };
}

/// Response for a request whose method is unknown or whose params are invalid.
fn serializeInvalidRequest(decrypted: []const u8, buf: []u8) ?[]const u8 {
    const method_str = utils.extractJsonString(decrypted, "method") orelse return null;
    if (nwc.Method.fromString(method_str)) |method| {
        const response = nwc.Response{
            .result_type = method,
            .err = .{ .code = .other, .message = "Invalid request parameters" },
        };
        return response.serialize(buf) catch null;
    }
    // method_str is raw JSON string content, so it is safe to place back between quotes.
    return std.fmt.bufPrint(buf, "{{\"result_type\":\"{s}\",\"error\":{{\"code\":\"NOT_IMPLEMENTED\",\"message\":\"Method not supported\"}},\"result\":null}}", .{method_str}) catch null;
}

/// Amount in msat encoded in a BOLT-11 invoice's human-readable part, or null
/// if the invoice has no amount.
fn bolt11AmountMsat(invoice: []const u8) error{InvalidInvoice}!?u64 {
    const sep = std.mem.lastIndexOfScalar(u8, invoice, '1') orelse return error.InvalidInvoice;
    const hrp = invoice[0..sep];
    if (hrp.len < 3 or !std.ascii.eqlIgnoreCase(hrp[0..2], "ln")) return error.InvalidInvoice;

    var pos: usize = 2;
    while (pos < hrp.len and std.ascii.isAlphabetic(hrp[pos])) : (pos += 1) {}
    if (pos == 2) return error.InvalidInvoice;

    const amount = hrp[pos..];
    if (amount.len == 0) return null;

    const last = std.ascii.toLower(amount[amount.len - 1]);
    const digits = if (std.ascii.isDigit(last)) amount else amount[0 .. amount.len - 1];
    if (digits.len == 0 or digits[0] == '0') return error.InvalidInvoice;
    for (digits) |c| if (!std.ascii.isDigit(c)) return error.InvalidInvoice;
    const n = std.fmt.parseInt(u64, digits, 10) catch return error.InvalidInvoice;

    const msat_per_unit: u64 = switch (last) {
        '0'...'9' => 100_000_000_000,
        'm' => 100_000_000,
        'u' => 100_000,
        'n' => 100,
        'p' => {
            if (n % 10 != 0) return error.InvalidInvoice;
            return n / 10;
        },
        else => return error.InvalidInvoice,
    };
    return std.math.mul(u64, n, msat_per_unit) catch error.InvalidInvoice;
}

fn isAlphanumeric(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isAlphanumeric(c)) return false;
    return true;
}

/// Rejects a pay_invoice request whose amount could be read differently by the
/// client and by the wallet: a malformed `amount`, an amount that differs from
/// the invoice's, or an amountless invoice (LNbits is never sent `amount`).
fn checkPayInvoice(params_json: []const u8, params: nwc.Request.PayInvoice) ?nwc.Response.Error {
    if (!isAlphanumeric(params.invoice)) return .{ .code = .other, .message = "Invalid invoice" };

    if (utils.findJsonFieldStart(params_json, "amount")) |start| {
        if (params.amount == null and !std.mem.startsWith(u8, params_json[start..], "null")) {
            return .{ .code = .other, .message = "Invalid amount" };
        }
    }

    const invoice_amount = (bolt11AmountMsat(params.invoice) catch return .{ .code = .other, .message = "Invalid invoice" }) orelse
        return .{ .code = .not_implemented, .message = "Amountless invoices are not supported" };

    if (params.amount) |requested| {
        if (requested != invoice_amount) return .{ .code = .other, .message = "Amount does not match invoice" };
    }
    return null;
}

/// Response to a pay_invoice whose outcome LNbits could not confirm. Not
/// PAYMENT_FAILED: the payment may still complete, so a blind retry could pay twice.
const payment_unknown_message = "Payment status unknown, it may still complete; check lookup_invoice before retrying";

fn handleRequest(arena: std.mem.Allocator, request: nwc.Request, params_json: []const u8, lnbits: *LnbitsClient, buf: []u8) ![]u8 {
    var response: nwc.Response = .{ .result_type = request.method };
    var preimage_hex: [64]u8 = undefined;

    switch (request.params) {
        .get_balance => {
            const wallet = lnbits.getWallet(arena) catch {
                response.err = .{ .code = .internal, .message = "Failed to get balance" };
                return response.serialize(buf);
            };
            response.result = .{ .get_balance = .{ .balance = wallet.balance } };
        },
        .get_info => {
            const wallet = lnbits.getWallet(arena) catch {
                response.err = .{ .code = .internal, .message = "Failed to get wallet info" };
                return response.serialize(buf);
            };
            response.result = .{ .get_info = .{
                .alias = wallet.name,
                .network = "mainnet",
                .methods = &supported_methods,
            } };
        },
        .make_invoice => |params| {
            if (params.amount == 0 or params.amount % 1000 != 0) {
                response.err = .{ .code = .other, .message = "Amount must be a positive whole number of sats" };
                return response.serialize(buf);
            }
            const invoice = lnbits.createInvoice(arena, params.amount, params.description) catch {
                response.err = .{ .code = .internal, .message = "Failed to create invoice" };
                return response.serialize(buf);
            };
            response.result = .{ .make_invoice = .{
                .tx_type = .incoming,
                .state = .pending,
                .invoice = invoice.payment_request,
                .payment_hash = invoice.payment_hash,
                .amount = params.amount,
                .description = params.description,
                .created_at = nostr.io.timestamp(),
            } };
        },
        .pay_invoice => |params| {
            if (checkPayInvoice(params_json, params)) |err| {
                response.err = err;
                return response.serialize(buf);
            }

            const payment_hash = bolt11.paymentHash(params.invoice) catch {
                response.err = .{ .code = .other, .message = "Invalid invoice" };
                return response.serialize(buf);
            };

            switch (try lnbits.payInvoice(arena, params.invoice, &payment_hash)) {
                .paid => |paid| {
                    const preimage: []const u8 = if (paid.preimage) |p| blk: {
                        preimage_hex = std.fmt.bytesToHex(&p, .lower);
                        break :blk &preimage_hex;
                    } else blk: {
                        std.log.warn("Payment succeeded but LNbits returned no matching preimage", .{});
                        break :blk "";
                    };
                    response.result = .{ .pay_invoice = .{
                        .preimage = preimage,
                        .fees_paid = paid.fee_msat,
                    } };
                },
                .failed => |reason| response.err = .{
                    .code = .payment_failed,
                    .message = try std.fmt.allocPrint(arena, "Payment failed: {s}", .{reason}),
                },
                .unknown => response.err = .{ .code = .internal, .message = payment_unknown_message },
            }
        },
        .lookup_invoice => |params| {
            const hash = params.payment_hash orelse {
                response.err = .{ .code = .not_found, .message = "payment_hash required" };
                return response.serialize(buf);
            };

            const details = lnbits.lookupPayment(arena, hash) catch {
                response.err = .{ .code = .not_found, .message = "Invoice not found" };
                return response.serialize(buf);
            };

            const incoming = if (details.amount_msat) |a| a > 0 else false;
            response.result = .{
                .lookup_invoice = .{
                    .tx_type = if (incoming) .incoming else .outgoing,
                    .state = switch (details.state) {
                        .paid => .settled,
                        .failed => if (incoming) .expired else .failed,
                        .pending => .pending,
                    },
                    // libnostr-z writes the invoice unescaped.
                    .invoice = if (details.bolt11) |b| if (isAlphanumeric(b)) b else null else null,
                    .payment_hash = hash,
                    .preimage = if (details.preimage) |p| try arena.dupe(u8, &std.fmt.bytesToHex(&p, .lower)) else null,
                    .amount = if (details.amount_msat) |a| if (a != 0) @abs(a) else null else null,
                    .fees_paid = details.fee_msat,
                    .description = if (details.memo) |m| if (m.len > 0) m else null else null,
                },
            };
        },
        else => {
            response.err = .{ .code = .not_implemented, .message = "Method not supported" };
        },
    }

    return response.serialize(buf);
}

/// Signs a kind 23195 response encrypted to the requester with the scheme the
/// request used, tagged with the requester (`p`) and the request id (`e`).
fn buildResponseEvent(
    allocator: std.mem.Allocator,
    config: *const Config,
    recipient_pubkey: *const [32]u8,
    request_id: *const [32]u8,
    response_json: []const u8,
    encryption: nwc.Encryption,
    out: []u8,
) ![]u8 {
    const encrypted = switch (encryption) {
        .nip44_v2 => try nostr.crypto.nip44Encrypt(&config.privkey, recipient_pubkey, response_json, allocator),
        .nip04 => try nostr.nip04.encrypt(&config.privkey, recipient_pubkey, response_json, allocator),
    };
    defer allocator.free(encrypted);

    var keypair = nostr.Keypair{
        .secret_key = config.privkey,
        .public_key = config.pubkey,
    };
    defer std.crypto.secureZero(u8, &keypair.secret_key);

    var p_tag_hex: [64]u8 = undefined;
    nostr.hex.encode(recipient_pubkey, &p_tag_hex);

    var e_tag_hex: [64]u8 = undefined;
    nostr.hex.encode(request_id, &e_tag_hex);

    const tags = [_][]const []const u8{
        &[_][]const u8{ "p", &p_tag_hex },
        &[_][]const u8{ "e", &e_tag_hex },
    };

    var builder = nostr.EventBuilder{};
    _ = builder.setKind(nwc.Kind.response).setContent(encrypted).setTags(&tags);
    try builder.sign(&keypair);

    return builder.serialize(out);
}

test {
    _ = @import("bolt11.zig");
    _ = @import("config.zig");
    _ = @import("lnbits.zig");
    _ = @import("relay.zig");
}

const testing = std.testing;

const TestKeys = struct {
    wallet: nostr.Keypair,
    client: nostr.Keypair,
    stranger: nostr.Keypair,
    config: Config,

    fn init() !TestKeys {
        try nostr.init();
        var keys: TestKeys = .{
            .wallet = nostr.Keypair.generate(),
            .client = nostr.Keypair.generate(),
            .stranger = nostr.Keypair.generate(),
            .config = undefined,
        };
        keys.config = .{
            .privkey = keys.wallet.secret_key,
            .pubkey = keys.wallet.public_key,
            .relay = "ws://127.0.0.1:1",
            .client_pubkeys = .empty,
            .lnbits_host = "http://127.0.0.1:1",
            .lnbits_admin_key = "key",
            ._allocated = .empty,
            ._allocator = testing.allocator,
        };
        try keys.config.client_pubkeys.append(testing.allocator, keys.client.public_key);
        return keys;
    }

    fn deinit(self: *TestKeys) void {
        self.config.deinit();
        nostr.cleanup();
    }
};

const SignedEvent = struct {
    buf: [8192]u8 = undefined,
    json: []const u8 = "",
};

fn signRequest(out: *SignedEvent, author: *const nostr.Keypair, tags: []const []const []const u8, created_at: i64, content: []const u8) !void {
    var builder = nostr.EventBuilder{};
    _ = builder.setKind(nwc.Kind.request).setContent(content).setTags(tags).setCreatedAt(created_at);
    try builder.sign(author);
    out.json = try builder.serialize(&out.buf);
}

fn hexOf(key: *const [32]u8) [64]u8 {
    var out: [64]u8 = undefined;
    nostr.hex.encode(key, &out);
    return out;
}

test "checkRequest accepts a signed request from an authorized client" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const now = nostr.io.timestamp();
    const wallet_hex = hexOf(&keys.wallet.public_key);
    const tags = [_][]const []const u8{&.{ "p", &wallet_hex }};
    var signed: SignedEvent = .{};
    try signRequest(&signed, &keys.client, &tags, now, "x");

    var event = try nostr.Event.parseWithAllocator(signed.json, testing.allocator);
    defer event.deinit();
    try checkRequest(&keys.config, &event, now, 0);
}

test "checkRequest rejects an unauthorized author" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const now = nostr.io.timestamp();
    const wallet_hex = hexOf(&keys.wallet.public_key);
    const tags = [_][]const []const u8{&.{ "p", &wallet_hex }};
    var signed: SignedEvent = .{};
    try signRequest(&signed, &keys.stranger, &tags, now, "x");

    var event = try nostr.Event.parseWithAllocator(signed.json, testing.allocator);
    defer event.deinit();
    try testing.expectError(error.Unauthorized, checkRequest(&keys.config, &event, now, 0));
}

test "checkRequest rejects a forged signature" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const now = nostr.io.timestamp();
    const wallet_hex = hexOf(&keys.wallet.public_key);
    const tags = [_][]const []const u8{&.{ "p", &wallet_hex }};
    var signed: SignedEvent = .{};
    try signRequest(&signed, &keys.client, &tags, now, "x");

    // Same content and author, different created_at: id and sig no longer match.
    const original = try testing.allocator.dupe(u8, signed.json);
    defer testing.allocator.free(original);
    var created_buf: [20]u8 = undefined;
    const created = try std.fmt.bufPrint(&created_buf, "{d}", .{now});
    var bumped_buf: [20]u8 = undefined;
    const bumped = try std.fmt.bufPrint(&bumped_buf, "{d}", .{now - 1});
    const tampered = try std.mem.replaceOwned(u8, testing.allocator, original, created, bumped);
    defer testing.allocator.free(tampered);

    var event = try nostr.Event.parseWithAllocator(tampered, testing.allocator);
    defer event.deinit();
    try testing.expectError(error.InvalidSignature, checkRequest(&keys.config, &event, now, 0));
}

test "checkRequest rejects requests not addressed to this wallet" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const now = nostr.io.timestamp();
    const other_hex = hexOf(&keys.stranger.public_key);
    const tags = [_][]const []const u8{&.{ "p", &other_hex }};
    var signed: SignedEvent = .{};
    try signRequest(&signed, &keys.client, &tags, now, "x");

    var event = try nostr.Event.parseWithAllocator(signed.json, testing.allocator);
    defer event.deinit();
    try testing.expectError(error.NotAddressedToUs, checkRequest(&keys.config, &event, now, 0));
}

test "checkRequest rejects expired, malformed-expiration and stale requests" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const now = nostr.io.timestamp();
    const wallet_hex = hexOf(&keys.wallet.public_key);

    var past_buf: [20]u8 = undefined;
    const past = try std.fmt.bufPrint(&past_buf, "{d}", .{now - 1});
    const expired_tags = [_][]const []const u8{ &.{ "p", &wallet_hex }, &.{ "expiration", past } };
    var expired: SignedEvent = .{};
    try signRequest(&expired, &keys.client, &expired_tags, now, "x");
    var expired_event = try nostr.Event.parseWithAllocator(expired.json, testing.allocator);
    defer expired_event.deinit();
    try testing.expectError(error.Expired, checkRequest(&keys.config, &expired_event, now, 0));

    const bad_tags = [_][]const []const u8{ &.{ "p", &wallet_hex }, &.{ "expiration", "soon" } };
    var bad: SignedEvent = .{};
    try signRequest(&bad, &keys.client, &bad_tags, now, "x");
    var bad_event = try nostr.Event.parseWithAllocator(bad.json, testing.allocator);
    defer bad_event.deinit();
    try testing.expectError(error.Expired, checkRequest(&keys.config, &bad_event, now, 0));

    var future_buf: [20]u8 = undefined;
    const future = try std.fmt.bufPrint(&future_buf, "{d}", .{now + 60});
    const live_tags = [_][]const []const u8{ &.{ "p", &wallet_hex }, &.{ "expiration", future } };
    var stale: SignedEvent = .{};
    try signRequest(&stale, &keys.client, &live_tags, now - max_request_age_s - 1, "x");
    var stale_event = try nostr.Event.parseWithAllocator(stale.json, testing.allocator);
    defer stale_event.deinit();
    try testing.expectError(error.Stale, checkRequest(&keys.config, &stale_event, now, 0));

    var live: SignedEvent = .{};
    try signRequest(&live, &keys.client, &live_tags, now, "x");
    var live_event = try nostr.Event.parseWithAllocator(live.json, testing.allocator);
    defer live_event.deinit();
    try checkRequest(&keys.config, &live_event, now, 0);
}

test "checkRequest rejects requests created before the process started" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const now = nostr.io.timestamp();
    const not_before = now - start_skew_s;
    const wallet_hex = hexOf(&keys.wallet.public_key);
    const tags = [_][]const []const u8{&.{ "p", &wallet_hex }};

    var old: SignedEvent = .{};
    try signRequest(&old, &keys.client, &tags, not_before - 1, "x");
    var old_event = try nostr.Event.parseWithAllocator(old.json, testing.allocator);
    defer old_event.deinit();
    try testing.expectError(error.BeforeStart, checkRequest(&keys.config, &old_event, now, not_before));
    try checkRequest(&keys.config, &old_event, now, not_before - 1);

    var fresh: SignedEvent = .{};
    try signRequest(&fresh, &keys.client, &tags, not_before, "x");
    var fresh_event = try nostr.Event.parseWithAllocator(fresh.json, testing.allocator);
    defer fresh_event.deinit();
    try checkRequest(&keys.config, &fresh_event, now, not_before);
}

test "redactUserinfo hides credentials in URLs" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("https://***@lnbits.example/api", redactUserinfo("https://user:pass@lnbits.example/api", &buf));
    try testing.expectEqualStrings("http://***@127.0.0.1:5000", redactUserinfo("http://a@b@127.0.0.1:5000", &buf));
    try testing.expectEqualStrings("http://127.0.0.1:5000/x?y=a@b", redactUserinfo("http://127.0.0.1:5000/x?y=a@b", &buf));
    try testing.expectEqualStrings("lnbits.local", redactUserinfo("lnbits.local", &buf));
}

test "requestEncryption follows the NIP-47 encryption tag" {
    var keys = try TestKeys.init();
    defer keys.deinit();
    const now = nostr.io.timestamp();

    const cases = [_]struct { tags: []const []const []const u8, want: ?nwc.Encryption }{
        .{ .tags = &.{&.{ "encryption", "nip44_v2" }}, .want = .nip44_v2 },
        .{ .tags = &.{&.{ "encryption", "nip04" }}, .want = .nip04 },
        .{ .tags = &.{}, .want = .nip04 },
        .{ .tags = &.{&.{ "encryption", "nip99" }}, .want = null },
        .{ .tags = &.{ &.{ "encryption", "nip44_v2" }, &.{ "encryption", "nip04" } }, .want = null },
    };
    for (cases) |case| {
        var signed: SignedEvent = .{};
        try signRequest(&signed, &keys.client, case.tags, now, "x");
        var event = try nostr.Event.parseWithAllocator(signed.json, testing.allocator);
        defer event.deinit();
        if (case.want) |want| {
            try testing.expectEqual(want, try requestEncryption(&event));
        } else {
            try testing.expectError(error.UnsupportedEncryption, requestEncryption(&event));
        }
    }
}

test "ReplayGuard rejects a repeated id and forgets expired ones" {
    var guard: ReplayGuard = .{ .not_before = 0 };
    defer guard.deinit(testing.allocator);

    const id: [32]u8 = @splat(7);
    const other: [32]u8 = @splat(8);
    try testing.expect(try guard.firstSeen(testing.allocator, &id, 1000, 1000));
    try testing.expect(!try guard.firstSeen(testing.allocator, &id, 1000, 1000 + max_request_age_s));
    try testing.expect(try guard.firstSeen(testing.allocator, &other, 1000, 1000));
    try testing.expect(try guard.firstSeen(testing.allocator, &id, 1000, 1001 + max_request_age_s));
}

test "bolt11AmountMsat reads the human-readable amount" {
    try testing.expectEqual(@as(?u64, 250_000_000), try bolt11AmountMsat("lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq"));
    try testing.expectEqual(@as(?u64, 5_000), try bolt11AmountMsat("lnbc50n1pdummy"));
    try testing.expectEqual(@as(?u64, 1), try bolt11AmountMsat("lnbcrt10p1pdummy"));
    try testing.expectEqual(@as(?u64, 200_000_000_000), try bolt11AmountMsat("LNTB21PDUMMY"));
    try testing.expectEqual(@as(?u64, null), try bolt11AmountMsat("lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq"));
    try testing.expectError(error.InvalidInvoice, bolt11AmountMsat("lnbc15p1pdummy"));
    try testing.expectError(error.InvalidInvoice, bolt11AmountMsat("lnbc025u1pdummy"));
    try testing.expectError(error.InvalidInvoice, bolt11AmountMsat("lnbc25x1pdummy"));
    try testing.expectError(error.InvalidInvoice, bolt11AmountMsat("bc25u1pdummy"));
    try testing.expectError(error.InvalidInvoice, bolt11AmountMsat("lnbc99999999999999999991pdummy"));
}

test "checkPayInvoice rejects confusable amounts" {
    const invoice = "lnbc50n1pdummy";
    const ok = nwc.Request.parseJson("{\"method\":\"pay_invoice\",\"params\":{\"invoice\":\"lnbc50n1pdummy\"}}").?;
    try testing.expect(checkPayInvoice("{\"invoice\":\"lnbc50n1pdummy\"}", ok.params.pay_invoice) == null);

    const matching = "{\"invoice\":\"lnbc50n1pdummy\",\"amount\":5000}";
    try testing.expect(checkPayInvoice(matching, .{ .invoice = invoice, .amount = 5000 }) == null);

    const mismatched = "{\"invoice\":\"lnbc50n1pdummy\",\"amount\":6000}";
    try testing.expectEqualStrings("Amount does not match invoice", checkPayInvoice(mismatched, .{ .invoice = invoice, .amount = 6000 }).?.message);

    const req = nwc.Request.parseJson("{\"method\":\"pay_invoice\",\"params\":{\"invoice\":\"lnbc50n1pdummy\",\"amount\":\"5000\"}}").?;
    try testing.expectEqual(@as(?u64, null), req.params.pay_invoice.amount);
    try testing.expectEqualStrings("Invalid amount", checkPayInvoice("{\"invoice\":\"lnbc50n1pdummy\",\"amount\":\"5000\"}", req.params.pay_invoice).?.message);

    try testing.expectEqual(nwc.ErrorCode.not_implemented, checkPayInvoice("{\"invoice\":\"lnbc1pdummy\",\"amount\":5000}", .{ .invoice = "lnbc1pdummy", .amount = 5000 }).?.code);
    try testing.expectEqualStrings("Invalid invoice", checkPayInvoice("{}", .{ .invoice = "lnbc50n1p\\\"x" }).?.message);
}

test "serializeInvalidRequest answers unknown methods and bad params" {
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(
        "{\"result_type\":\"sign_message\",\"error\":{\"code\":\"NOT_IMPLEMENTED\",\"message\":\"Method not supported\"},\"result\":null}",
        serializeInvalidRequest("{\"method\":\"sign_message\",\"params\":{}}", &buf).?,
    );

    try testing.expect(nwc.Request.parseJson("{\"method\":\"pay_invoice\",\"params\":{}}") == null);
    const bad = serializeInvalidRequest("{\"method\":\"pay_invoice\",\"params\":{}}", &buf).?;
    const parsed = nwc.Response.parseJson(bad).?;
    try testing.expectEqual(nwc.Method.pay_invoice, parsed.result_type);
    try testing.expectEqual(nwc.ErrorCode.other, parsed.err.?.code);

    try testing.expect(serializeInvalidRequest("{\"params\":{}}", &buf) == null);
}

test "buildResponseEvent encrypts to the requester and tags p and e" {
    var keys = try TestKeys.init();
    defer keys.deinit();

    const request_id: [32]u8 = @splat(0xab);
    const response_json = "{\"result_type\":\"get_balance\",\"error\":null,\"result\":{\"balance\":1000}}";

    for ([_]nwc.Encryption{ .nip44_v2, .nip04 }) |encryption| {
        var out: [16384]u8 = undefined;
        const json = try buildResponseEvent(testing.allocator, &keys.config, &keys.client.public_key, &request_id, response_json, encryption, &out);

        var event = try nostr.Event.parseWithAllocator(json, testing.allocator);
        defer event.deinit();
        try event.validate();
        try testing.expectEqual(nwc.Kind.response, event.kind());
        try testing.expectEqualSlices(u8, &keys.wallet.public_key, event.pubkey());

        var tags = utils.TagIterator.init(event.raw_json, "tags").?;
        const p = tags.next().?;
        try testing.expectEqualStrings("p", p.name);
        try testing.expectEqualStrings(&hexOf(&keys.client.public_key), p.value);
        const e = tags.next().?;
        try testing.expectEqualStrings("e", e.name);
        try testing.expectEqualStrings(&hexOf(&request_id), e.value);

        const plain = switch (encryption) {
            .nip44_v2 => try nostr.crypto.nip44Decrypt(&keys.client.secret_key, &keys.wallet.public_key, event.content(), testing.allocator),
            .nip04 => try nostr.nip04.decrypt(&keys.client.secret_key, &keys.wallet.public_key, event.content(), testing.allocator),
        };
        defer testing.allocator.free(plain);
        try testing.expectEqualStrings(response_json, plain);
    }
}

test "handleRequest rejects invalid make_invoice amounts without calling LNbits" {
    var lnbits = LnbitsClient.init(testing.allocator, testing.io, "http://127.0.0.1:1", "key");
    defer lnbits.deinit();

    var buf: [1024]u8 = undefined;
    for ([_]u64{ 0, 1500, 999 }) |amount| {
        const request = nwc.Request{ .method = .make_invoice, .params = .{ .make_invoice = .{ .amount = amount } } };
        const json = try handleRequest(testing.allocator, request, "{}", &lnbits, &buf);
        const parsed = nwc.Response.parseJson(json).?;
        try testing.expectEqual(nwc.ErrorCode.other, parsed.err.?.code);
    }

    const pay = nwc.Request{ .method = .pay_invoice, .params = .{ .pay_invoice = .{ .invoice = "lnbc50n1pdummy", .amount = 1 } } };
    const pay_json = try handleRequest(testing.allocator, pay, "{\"invoice\":\"lnbc50n1pdummy\",\"amount\":1}", &lnbits, &buf);
    try testing.expectEqualStrings("Amount does not match invoice", nwc.Response.parseJson(pay_json).?.err.?.message);

    const bad_checksum = nwc.Request{ .method = .pay_invoice, .params = .{ .pay_invoice = .{ .invoice = "lnbc50n1pdummy" } } };
    const bad_json = try handleRequest(testing.allocator, bad_checksum, "{\"invoice\":\"lnbc50n1pdummy\"}", &lnbits, &buf);
    try testing.expectEqualStrings("Invalid invoice", nwc.Response.parseJson(bad_json).?.err.?.message);
}
