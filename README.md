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
privkey = "nsec1..."  # or hex
relay = "wss://relay.example.com"

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
- `CLIENT_SECRET` - Random 32-byte hex (client generates this)

Use with Alby, Amethyst, Damus, or any NWC-compatible app.

## Requirements

- Zig 0.15+
- LNbits instance with funded wallet
