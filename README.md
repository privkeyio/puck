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

Requests must use NIP-44 (`["encryption", "nip44_v2"]`); NIP-04 requests get an `UNSUPPORTED_ENCRYPTION` error. Requests older than 10 minutes, past their `expiration` tag, or already seen are ignored.

Use with Alby, Amethyst, Damus, or any NWC-compatible app.

## Requirements

- Zig 0.16.0 or 0.17.0
- OpenSSL 3 development libraries (`libssl-dev` on Debian/Ubuntu, `openssl@3` on macOS)
- LNbits instance with funded wallet
