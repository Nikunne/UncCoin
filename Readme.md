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
alias <wallet-id> <alias>
autosend <wallet-id>
autosend off
mute
unmute
tx <receiver> <amount> <fee>
msg <wallet> <content>
messages
mine [description]
automine [description]
stop
blockchain
balance [address]
balances
balances >100
balances <50
txtbalances <relative-path>
txtblockchain <relative-path>
send <host:port> <json>
clear
quit
<raw json>
```

Commands that take wallet ids such as `tx`, `msg`, `balance`, and `alias` accept either a raw wallet address or a locally stored alias.

## Local Convenience Commands

These are mainly for local testing on one machine.

```bash
make wallet name=alice
make show-wallet name=alice
make 9000
make 9001
make 9002
```

## Mining Tuning

Mining can be tuned with environment variables:

- `UNCCOIN_MINING_CPU_WORKERS`
  Override the number of CPU workers used for proof of work.
- `UNCCOIN_GPU_BATCH_SIZE`
  Override the GPU batch size. On macOS this tunes the Metal backend; on Linux/WSL it tunes the OpenCL backend.
- `UNCCOIN_MINING_PROGRESS_INTERVAL`
  Control how often mining progress is printed. Larger values reduce terminal overhead.
- `UNCCOIN_DISABLE_MINING_AUTOTUNE`
  Disable the local mining worker auto-tuner.
- `UNCCOIN_DISABLE_OPENCL_GPU`
  Force Linux/WSL mining to stay on CPU even if an OpenCL runtime is available.

When `UNCCOIN_MINING_CPU_WORKERS` is not set, UncCoin benchmarks a few local worker counts once and
caches the fastest result in `state/mining_tuning.json`. This only affects local mining execution.

## WSL GPU Mining

On macOS, GPU mining uses Metal. On Linux and WSL, UncCoin uses OpenCL when an OpenCL GPU runtime is available.

For Ubuntu-based WSL installs, the usual minimum is:

```bash
sudo apt install ocl-icd-libopencl1 clinfo
clinfo
```

If `clinfo` can see your GPU from inside WSL, `mine` and `automine` will use it automatically.
