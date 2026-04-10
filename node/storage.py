import json
from pathlib import Path
from typing import Callable

from config import DEFAULT_DIFFICULTY_GROWTH_FACTOR
from config import DEFAULT_DIFFICULTY_GROWTH_BITS
from config import DEFAULT_DIFFICULTY_GROWTH_START_HEIGHT
from core.block import Block
from core.blockchain import Blockchain
from core.transaction import Transaction
from state_paths import ensure_state_dir


BLOCKCHAINS_DIR = ensure_state_dir() / "blockchains"


def ensure_blockchains_dir() -> Path:
    ensure_state_dir()
    BLOCKCHAINS_DIR.mkdir(exist_ok=True)
    return BLOCKCHAINS_DIR


def blockchain_state_path(wallet_address: str) -> Path:
    return ensure_blockchains_dir() / f"{wallet_address}.json"


def save_blockchain_state(wallet_address: str, blockchain: Blockchain) -> Path:
    path = blockchain_state_path(wallet_address)
    state = {
        "wallet_address": wallet_address,
        "difficulty_bits": blockchain.difficulty_bits,
        "genesis_difficulty_bits": blockchain.genesis_difficulty_bits,
        "difficulty_growth_factor": blockchain.difficulty_growth_factor,
        "difficulty_growth_start_height": blockchain.difficulty_growth_start_height,
        "difficulty_growth_bits": blockchain.difficulty_growth_bits,
        "difficulty_schedule_activation_height": blockchain.difficulty_schedule_activation_height,
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
    activation_height = state.get("difficulty_schedule_activation_height")
    genesis_difficulty_bits = state.get("genesis_difficulty_bits")
    growth_factor = state.get("difficulty_growth_factor")
    growth_start_height = state.get("difficulty_growth_start_height")
    growth_bits = state.get("difficulty_growth_bits")
    blockchain = Blockchain(
        difficulty_bits=int(state["difficulty_bits"]),
        hash_function=hash_function,
        genesis_difficulty_bits=(
            int(genesis_difficulty_bits)
            if genesis_difficulty_bits is not None
            else int(state["difficulty_bits"])
        ),
        difficulty_growth_factor=(
            int(growth_factor)
            if growth_factor is not None
            else DEFAULT_DIFFICULTY_GROWTH_FACTOR
        ),
        difficulty_growth_start_height=(
            int(growth_start_height)
            if growth_start_height is not None
            else DEFAULT_DIFFICULTY_GROWTH_START_HEIGHT
        ),
        difficulty_growth_bits=(
            int(growth_bits)
            if growth_bits is not None
            else DEFAULT_DIFFICULTY_GROWTH_BITS
        ),
        difficulty_schedule_activation_height=(
            int(activation_height)
            if activation_height is not None
            else 2**63 - 1
        ),
    )

    for block_data in state.get("blocks", []):
        block = Block.from_dict(block_data, hash_function=hash_function)
        if not blockchain.add_block(block):
            raise ValueError(f"Persisted block {block.block_hash[:12]} is invalid.")

    for transaction_data in state.get("pending_transactions", []):
        blockchain.add_transaction(Transaction.from_dict(transaction_data))

    if activation_height is None:
        blockchain.difficulty_schedule_activation_height = (
            blockchain._get_canonical_state().height + 1
        )

    return blockchain
