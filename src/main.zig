const std = @import("std");
const nostr = @import("nostr");
const Config = @import("config.zig").Config;
const LnbitsClient = @import("lnbits.zig").Client;
const Relay = @import("relay.zig").Relay;
const RelayMessage = @import("relay.zig").Message;

const supported_methods = [_]nostr.nwc.Method{
    .get_balance,
    .get_info,
    .make_invoice,
    .pay_invoice,
    .lookup_invoice,
};

var g_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn signalHandler(_: c_int) callconv(std.builtin.CallingConvention.c) void {
    g_shutdown.store(true, .release);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config_path = if (args.len > 1) args[1] else "puck.toml";

    var config = Config.load(allocator, config_path) catch |err| {
        std.log.err("Failed to load config from {s}: {}", .{ config_path, err });
        return err;
    };
    defer config.deinit();

    try nostr.init();
    defer nostr.cleanup();

    std.log.info("Puck NWC Server starting", .{});
    var pubkey_hex: [64]u8 = undefined;
    nostr.hex.encode(&config.pubkey, &pubkey_hex);
    std.log.info("Pubkey: {s}", .{&pubkey_hex});
    std.log.info("Relay: {s}", .{config.relay});
    std.log.info("LNbits: {s}", .{config.lnbits_host});

    const sa = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    var lnbits = LnbitsClient.init(allocator, config.lnbits_host, config.lnbits_admin_key);
    defer lnbits.deinit();

    while (!g_shutdown.load(.acquire)) {
        runEventLoop(allocator, &config, &lnbits) catch |err| {
            std.log.err("Event loop error: {}", .{err});
        };

        if (!g_shutdown.load(.acquire)) {
            std.log.info("Reconnecting in 5 seconds...", .{});
            std.Thread.sleep(5 * std.time.ns_per_s);
        }
    }

    std.log.info("Shutdown complete", .{});
}

fn runEventLoop(allocator: std.mem.Allocator, config: *Config, lnbits: *LnbitsClient) !void {
    std.log.info("Connecting to relay...", .{});
    var relay = try Relay.connect(allocator, config.relay);
    defer relay.deinit();
    std.log.info("Connected to relay", .{});

    try publishInfoEvent(allocator, config, &relay);

    var filter_buf: [256]u8 = undefined;
    var pubkey_hex: [64]u8 = undefined;
    nostr.hex.encode(&config.pubkey, &pubkey_hex);
    const filter = std.fmt.bufPrint(&filter_buf, "{{\"kinds\":[{d}],\"#p\":[\"{s}\"]}}", .{ nostr.nwc.Kind.request, &pubkey_hex }) catch return error.BufferTooSmall;

    try relay.subscribe("nwc", filter);
    std.log.info("Subscribed to NWC requests", .{});

    while (!g_shutdown.load(.acquire)) {
        const msg = relay.receive() catch |err| {
            if (err == error.Closed) return err;
            continue;
        };

        if (msg) |m| {
            switch (m) {
                .event => |e| {
                    handleEvent(allocator, config, lnbits, &relay, e.event_json) catch |err| {
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
                .closed => |c| std.log.warn("Subscription closed: {s}", .{c.message}),
                .unknown => {},
            }
        }
    }
}

fn publishInfoEvent(allocator: std.mem.Allocator, config: *Config, relay: *Relay) !void {
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

    const tags = [_][]const []const u8{
        &[_][]const u8{ "encryption", "nip44_v2" },
    };

    var builder = nostr.EventBuilder{};
    _ = builder.setKind(nostr.nwc.Kind.info).setContent(content).setTags(&tags);
    try builder.sign(&keypair);

    var event_buf: [4096]u8 = undefined;
    const event_json = try builder.serialize(&event_buf);

    try relay.publish(event_json);
    std.log.info("Published info event (kind {d})", .{nostr.nwc.Kind.info});

    _ = allocator;
}

fn handleEvent(allocator: std.mem.Allocator, config: *Config, lnbits: *LnbitsClient, relay: *Relay, event_json: []const u8) !void {
    var event = try nostr.Event.parseWithAllocator(event_json, allocator);
    defer event.deinit();

    if (event.kind() != nostr.nwc.Kind.request) return;

    const encrypted_content = event.content();
    if (encrypted_content.len == 0) return;

    const sender_pubkey = event.pubkey();

    const decrypted = nostr.crypto.nip44Decrypt(&config.privkey, sender_pubkey, encrypted_content, allocator) catch |err| {
        std.log.err("Decryption failed: {}", .{err});
        return;
    };
    defer allocator.free(decrypted);

    const request = nostr.nwc.Request.parseJson(decrypted) orelse {
        std.log.err("Failed to parse NWC request", .{});
        return;
    };

    std.log.info("Received {s} request", .{request.method.toString()});

    var response_buf: [4096]u8 = undefined;
    const response_json = try handleRequest(request, lnbits, &response_buf);

    try publishResponse(allocator, config, relay, sender_pubkey, &event.id_bytes, response_json);
}

fn handleRequest(request: nostr.nwc.Request, lnbits: *LnbitsClient, buf: []u8) ![]u8 {
    var response: nostr.nwc.Response = .{ .result_type = request.method };

    switch (request.params) {
        .get_balance => {
            const wallet = lnbits.getWallet() catch {
                response.err = .{ .code = .internal, .message = "Failed to get balance" };
                return response.serialize(buf);
            };
            response.result = .{ .get_balance = .{ .balance = wallet.balance } };
        },
        .get_info => {
            const wallet = lnbits.getWallet() catch {
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
            const invoice = lnbits.createInvoice(params.amount, params.description) catch {
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
                .created_at = std.time.timestamp(),
            } };
        },
        .pay_invoice => |params| {
            const result = lnbits.payInvoice(params.invoice) catch {
                response.err = .{ .code = .payment_failed, .message = "Payment failed" };
                return response.serialize(buf);
            };

            const details = lnbits.lookupPayment(result.payment_hash) catch {
                response.result = .{ .pay_invoice = .{
                    .preimage = "",
                    .fees_paid = null,
                } };
                return response.serialize(buf);
            };

            response.result = .{ .pay_invoice = .{
                .preimage = details.preimage,
                .fees_paid = if (details.fee > 0) @intCast(details.fee) else null,
            } };
        },
        .lookup_invoice => |params| {
            const hash = params.payment_hash orelse {
                response.err = .{ .code = .not_found, .message = "payment_hash required" };
                return response.serialize(buf);
            };

            const details = lnbits.lookupPayment(hash) catch {
                response.err = .{ .code = .not_found, .message = "Invoice not found" };
                return response.serialize(buf);
            };

            const state: nostr.nwc.TransactionState = if (details.pending) .pending else .settled;
            response.result = .{ .lookup_invoice = .{
                .tx_type = if (details.amount > 0) .incoming else .outgoing,
                .state = state,
                .invoice = if (details.bolt11.len > 0) details.bolt11 else null,
                .payment_hash = details.payment_hash,
                .preimage = if (details.preimage.len > 0) details.preimage else null,
                .amount = if (details.amount > 0) @intCast(details.amount) else null,
                .fees_paid = if (details.fee > 0) @intCast(details.fee) else null,
                .description = if (details.memo.len > 0) details.memo else null,
            } };
        },
        else => {
            response.err = .{ .code = .not_implemented, .message = "Method not supported" };
        },
    }

    return response.serialize(buf);
}

fn publishResponse(allocator: std.mem.Allocator, config: *Config, relay: *Relay, recipient_pubkey: *const [32]u8, request_id: *const [32]u8, response_json: []const u8) !void {
    const encrypted = try nostr.crypto.nip44Encrypt(&config.privkey, recipient_pubkey, response_json, allocator);
    defer allocator.free(encrypted);

    var keypair = nostr.Keypair{
        .secret_key = config.privkey,
        .public_key = config.pubkey,
    };

    var p_tag_hex: [64]u8 = undefined;
    nostr.hex.encode(recipient_pubkey, &p_tag_hex);

    var e_tag_hex: [64]u8 = undefined;
    nostr.hex.encode(request_id, &e_tag_hex);

    const tags = [_][]const []const u8{
        &[_][]const u8{ "p", &p_tag_hex },
        &[_][]const u8{ "e", &e_tag_hex },
    };

    var builder = nostr.EventBuilder{};
    _ = builder.setKind(nostr.nwc.Kind.response).setContent(encrypted).setTags(&tags);
    try builder.sign(&keypair);

    var event_buf: [65536]u8 = undefined;
    const event_json = try builder.serialize(&event_buf);

    try relay.publish(event_json);
    std.log.debug("Published response", .{});
}

test "config parsing" {
    _ = @import("config.zig");
}

test "lnbits client" {
    _ = @import("lnbits.zig");
}

test "relay connection" {
    _ = @import("relay.zig");
}
