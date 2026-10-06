# Puck

Nostr Wallet Connect (NIP-47) server in Zig with LNbits backend.

## Features

- `get_balance` - Check wallet balance
- `get_info` - Wallet info
- `make_invoice` - Create invoices
- `pay_invoice` - Pay bolt11 invoices
- `lookup_invoice` - Check payment status

## Quick Start

1. Create `puck.toml`:

```toml
[nostr]
# nsec or hex; the config parser does not accept trailing comments
privkey = "nsec1..."
relay = "wss://relay.example.com"
client_pubkeys = ["<CLIENT_PUBKEY>"]

[lnbits]
host = "http://127.0.0.1:5000"
admin_key = "your_lnbits_admin_key"
```

2. Build and run:

```sh
zig build
./zig-out/bin/puck
```

## Connect a Wallet

Generate a connection string:

```
nostr+walletconnect://<PUBKEY>?relay=<RELAY>&secret=<CLIENT_SECRET>
```

- `PUBKEY` - Puck's pubkey (shown on startup)
- `RELAY` - Your relay URL
- `CLIENT_SECRET` - Random 32-byte hex secret for this connection

Add the public key of `CLIENT_SECRET` (hex or npub, for example from `nak key public <CLIENT_SECRET>`) to `client_pubkeys`, one entry per connection, and restart Puck. Requests from any other key are ignored. Puck does not store the secret.

Requests must use NIP-44 (`["encryption", "nip44_v2"]`); NIP-04 requests get an `UNSUPPORTED_ENCRYPTION` error, and requests with any other `encryption` tag get an `UNSUPPORTED_ENCRYPTION` error encrypted with NIP-44 and an empty `result_type`. Requests older than 10 minutes, past their `expiration` tag, or already seen are ignored. The record of seen requests is kept in memory only, so requests created more than 60 seconds before Puck started are ignored as well and get no reply; the client must send a new request.

## Payment Outcomes

`pay_invoice` reports `PAYMENT_FAILED` only when LNbits says the payment failed or was never attempted (for example insufficient balance, an invalid invoice, or LNbits unreachable). When the outcome is unclear (a timeout, a dropped connection, a 5xx or unreadable response, or a payment LNbits still lists as pending), Puck looks the payment up by the invoice's payment hash for about 15 seconds. It then replies with the preimage if the payment went through, `PAYMENT_FAILED` if LNbits marked it failed, and otherwise an `INTERNAL` error whose message says the status is unknown. Treat that error as "may still complete": check `lookup_invoice` before paying again.

Every LNbits call has a deadline: 30 seconds for paying, 10 seconds for everything else. Puck handles one request at a time, so a payment whose outcome stays unclear holds up other requests for up to about 95 seconds in the worst case. The relay connection uses TCP keepalive; on Linux a relay that disappears without closing the connection is detected within about 90 seconds and Puck reconnects.

Use with Alby, Amethyst, Damus, or any NWC-compatible app.

## Requirements

- Zig 0.16.0 or 0.17.0
- OpenSSL 3 development libraries (`libssl-dev` on Debian/Ubuntu, `openssl@3` on macOS)
- LNbits instance with funded wallet
