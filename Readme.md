# UncCoin

## Interactive Node Commands

```text
peers
known-peers
discover
tx <receiver> <amount> <fee>
mine [description]
automine [description]
stop
blockchain
balance [address]
send <host:port> <json>
clear
quit
<raw json>
```

## Commands

```bash
make wallet NAME=alice
make show-wallet NAME=alice
make 9000
make 9001
make 9002
```

## Direct CLI

```bash
python3 -m wallet.cli create --name alice
python3 -m wallet.cli show --name alice
python3 -m node.cli --port 9000 --wallet-name alice
python3 -m node.cli --port 9001 --peer 127.0.0.1:9000 --wallet-name bob
python3 -m node.cli --port 9002 --peer 127.0.0.1:9000 --wallet-name charlie
```
