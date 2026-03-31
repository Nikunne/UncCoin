import json
from pathlib import Path
from typing import Callable

from core.block import Block
from core.blockchain import Blockchain
from core.transaction import Transaction


BLOCKCHAINS_DIR = Path("blockchains")


def ensure_blockchains_dir() -> Path:
    BLOCKCHAINS_DIR.mkdir(exist_ok=True)
    return BLOCKCHAINS_DIR


def blockchain_state_path(wallet_address: str) -> Path:
    return ensure_blockchains_dir() / f"{wallet_address}.json"


def save_blockchain_state(wallet_address: str, blockchain: Blockchain) -> Path:
    path = blockchain_state_path(wallet_address)
    state = {
        "wallet_address": wallet_address,
        "difficulty_bits": blockchain.difficulty_bits,
        "blocks": [block.to_dict() for block in blockchain.blocks],
        "pending_transactions": [
            transaction.to_dict()
            for transaction in blockchain.pending_transactions
        ],
    }
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return path


def load_blockchain_state(
    wallet_address: str,
    hash_function: Callable[[Block], str],
) -> Blockchain | None:
    path = blockchain_state_path(wallet_address)
    if not path.exists():
        return None

    state = json.loads(path.read_text(encoding="utf-8"))
    blockchain = Blockchain(
        difficulty_bits=int(state["difficulty_bits"]),
        hash_function=hash_function,
    )

    for block_data in state.get("blocks", []):
        block = Block.from_dict(block_data, hash_function=hash_function)
        if not blockchain.add_block(block):
            raise ValueError(f"Persisted block {block.block_hash[:12]} is invalid.")

    for transaction_data in state.get("pending_transactions", []):
        blockchain.add_transaction(Transaction.from_dict(transaction_data))

    return blockchain
