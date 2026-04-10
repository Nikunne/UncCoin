# UncCoin

UncCoin is a toy proof-of-work cryptocurrency written in Python, with the mining loop moved into C for speed.

GitHub repository:

- https://github.com/Fleli/UncCoin

## What It Has

- signed transactions
- balances and nonces
- fixed mining rewards and miner fees
- proof of work
- P2P transaction and block relay
- chain sync on connect
- orphan block handling
- canonical-chain persistence
- interactive node CLI

## Docs

- [GettingStarted.md](/Users/frederikedvardsen/Desktop/unccoin/GettingStarted.md)
  First local setup, wallet creation, native build, and running nodes.
- [Tailscale.md](/Users/frederikedvardsen/Desktop/unccoin/Tailscale.md)
  Running UncCoin across multiple devices over Tailscale.

## Interactive Node Commands

```text
peers
known-peers
discover
sync
localself
add-peer <host:port>
tx <receiver> <amount> <fee>
msg <wallet> <content>
messages
mine [description]
automine [description]
stop
blockchain
balance [address]
balances
send <host:port> <json>
clear
quit
<raw json>
```

## Local Convenience Commands

These are mainly for local testing on one machine.

```bash
make wallet name=alice
make show-wallet name=alice
make 9000
make 9001
make 9002
```
