# UncCoin Over Tailscale

This guide assumes you have already gone through [GettingStarted.md](/Users/frederikedvardsen/Desktop/unccoin/GettingStarted.md) and want to move from one-machine testing to multiple devices.

Tailscale is the simplest way to run UncCoin across multiple devices without exposing nodes directly to the public internet.

## Why Tailscale

Tailscale gives each device a private network address, so UncCoin nodes can talk to each other over normal TCP without:

- router port forwarding
- public IP setup
- exposing the node directly to the internet

## 1. Install Tailscale

Each participant installs Tailscale on their own device and joins the same tailnet.

Official docs:

- https://tailscale.com/docs/install
- https://tailscale.com/docs/install/start

## 2. Verify Tailscale Connectivity

On each device, confirm that Tailscale is running and find the device's Tailscale IP.

You can usually check with:

```bash
tailscale ip -4
```

Then test reachability to another device:

```bash
tailscale ping <peer-tailscale-ip>
```

If that works, the devices can most likely reach each other for UncCoin too.

## 3. Build Native Proof of Work

Do this once per device:

```bash
./scripts/build_native_pow.sh
```

You can force a rebuild with:

```bash
./scripts/build_native_pow.sh --force
```

## 4. Create a Wallet

Each person should create their own wallet:

```bash
python3 -m wallet.cli create --name <wallet-name>
```

To inspect it:

```bash
python3 -m wallet.cli show --name <wallet-name>
```

## 5. Start a Node

Important: for cross-device networking, do not bind only to `127.0.0.1`.
Use `--host 0.0.0.0` so the node listens on the machine's network interfaces.

Example first node:

```bash
python3 -m node.cli --host 0.0.0.0 --wallet-name <wallet-name> --port 9000
```

Example second node connecting to the first over Tailscale:

```bash
./scripts/run.sh <wallet-name> 9001 <peer-tailscale-ip>:9000
```

Example third node:

```bash
./scripts/run.sh <wallet-name> 9002 <peer-tailscale-ip>:9000
```

The script also works for the first node:

```bash
./scripts/run.sh <wallet-name> 9000
```

## 6. Use the Node CLI

Once connected, useful interactive commands include:

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
clear
quit
```

## Notes

- The current node sync is good enough for a small toy network, but still simple.
- Canonical blockchain state is persisted per wallet address.
- Native proof of work currently builds for macOS.
- Tailscale is used only for networking; it is not a Python dependency.
