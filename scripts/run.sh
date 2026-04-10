#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <wallet-name> <port> [peer-host:peer-port ...]"
  exit 1
fi

WALLET_NAME="$1"
PORT="$2"
shift 2

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARGS=(python3 -m node.cli --host 0.0.0.0 --wallet-name "$WALLET_NAME" --port "$PORT")

for PEER in "$@"; do
  ARGS+=(--peer "$PEER")
done

exec "${ARGS[@]}"
