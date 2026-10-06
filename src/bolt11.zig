const std = @import("std");

pub const Error = error{InvalidInvoice};

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const timestamp_len = 7;
const signature_len = 104;
const checksum_len = 6;
const hash_field_len = 52;
const tag_payment_hash = 1;

fn charValue(c: u8) ?u5 {
    const lower = std.ascii.toLower(c);
    return for (charset, 0..) |ch, i| {
        if (ch == lower) break @intCast(i);
    } else null;
}

fn polymodStep(chk: u32, value: u5) u32 {
    const gen = [_]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    const top = chk >> 25;
    var next = ((chk & 0x1ffffff) << 5) ^ value;
    inline for (0..5) |i| {
        if ((top >> i) & 1 == 1) next ^= gen[i];
    }
    return next;
}

/// Payment hash of a BOLT 11 invoice: the first `p` field with the required
/// length of 52 groups. Verifies the bech32 checksum (without the 90 character
/// limit, which BOLT 11 lifts) but not the signature.
pub fn paymentHash(invoice: []const u8) Error![32]u8 {
    var has_lower = false;
    var has_upper = false;
    for (invoice) |c| {
        if (c < 33 or c > 126) return error.InvalidInvoice;
        if (std.ascii.isLower(c)) has_lower = true;
        if (std.ascii.isUpper(c)) has_upper = true;
    }
    if (has_lower and has_upper) return error.InvalidInvoice;

    const sep = std.mem.lastIndexOfScalar(u8, invoice, '1') orelse return error.InvalidInvoice;
    const hrp = invoice[0..sep];
    const data = invoice[sep + 1 ..];
    if (hrp.len < 3 or !std.ascii.eqlIgnoreCase(hrp[0..2], "ln")) return error.InvalidInvoice;
    if (data.len < timestamp_len + signature_len + checksum_len) return error.InvalidInvoice;

    var chk: u32 = 1;
    for (hrp) |c| chk = polymodStep(chk, @truncate(std.ascii.toLower(c) >> 5));
    chk = polymodStep(chk, 0);
    for (hrp) |c| chk = polymodStep(chk, @truncate(std.ascii.toLower(c) & 31));
    for (data) |c| chk = polymodStep(chk, charValue(c) orelse return error.InvalidInvoice);
    if (chk != 1) return error.InvalidInvoice;

    const fields = data[timestamp_len .. data.len - checksum_len - signature_len];
    var pos: usize = 0;
    while (pos < fields.len) {
        if (fields.len - pos < 3) return error.InvalidInvoice;
        const tag = charValue(fields[pos]).?;
        const len = @as(usize, charValue(fields[pos + 1]).?) * 32 + charValue(fields[pos + 2]).?;
        pos += 3;
        if (fields.len - pos < len) return error.InvalidInvoice;
        if (tag == tag_payment_hash and len == hash_field_len) {
            return decodeHash(fields[pos..][0..hash_field_len]);
        }
        pos += len;
    }
    return error.InvalidInvoice;
}

fn decodeHash(groups: *const [hash_field_len]u8) [32]u8 {
    var out: [32]u8 = undefined;
    var acc: u32 = 0;
    var bits: u5 = 0;
    var i: usize = 0;
    for (groups) |c| {
        acc = (acc << 5) | charValue(c).?;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (i < out.len) out[i] = @truncate(acc >> bits);
            i += 1;
        }
        acc &= (@as(u32, 1) << bits) - 1;
    }
    return out;
}

const testing = std.testing;

fn expectHash(want_hex: []const u8, invoice: []const u8) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try testing.expectEqualSlices(u8, &want, &try paymentHash(invoice));
}

const sequential_hash = "0001020304050607080900010203040506070809000102030405060708090102";

test "paymentHash reads BOLT 11 test vectors" {
    try expectHash(sequential_hash, "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql");
    try expectHash(sequential_hash, "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8");
    try expectHash("462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f", "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz");
    try expectHash(sequential_hash, "LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3SGPZ3UAPA");
}

test "paymentHash reads an invoice with an unsigned payload" {
    try expectHash("72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793", "lnbc10n1pj48ugqpp5wtxkappzcsrlkmgfs6g0zyct0hkhashh7hsaxz7e65slq9fkx7fsdqdwp6kx6eqv5ex2sp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg3hk8m");
}

test "paymentHash skips p fields with the wrong length" {
    try expectHash(sequential_hash, "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x");
}

test "paymentHash rejects malformed invoices" {
    const bad = [_][]const u8{
        // BOLT 11: Bech32 checksum is invalid.
        "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt",
        // BOLT 11: Malformed bech32 string (no 1).
        "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny",
        // BOLT 11: Malformed bech32 string (mixed case).
        "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny",
        // BOLT 11: String is too short.
        "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh",
        // Checksum-valid invoice without a `p` field.
        "lnbc10n1pj48ugqdqdwp6kx6eqv5ex2sp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlf93rv",
        "lnbc50n1pdummy",
        "",
    };
    for (bad) |invoice| try testing.expectError(error.InvalidInvoice, paymentHash(invoice));
}
