from dataclasses import dataclass, field
from typing import Callable

from core.native_pow import mine_pow as native_mine_pow
from core.serialization import serialize_block_prefix
from core.transaction import Transaction


@dataclass
class Block:
    block_id: int
    transactions: list[Transaction]
    hash_function: Callable[["Block"], str]
    description: str
    previous_hash: str
    nonce: int = 0
    block_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.block_hash = self.hash_function(self)

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "transactions": [transaction.to_dict() for transaction in self.transactions],
            "description": self.description,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(
        cls,
        block_data: dict,
        hash_function: Callable[["Block"], str],
    ) -> "Block":
        block = cls(
            block_id=int(block_data["block_id"]),
            transactions=[
                Transaction.from_dict(transaction_data)
                for transaction_data in block_data["transactions"]
            ],
            hash_function=hash_function,
            description=block_data["description"],
            previous_hash=block_data["previous_hash"],
            nonce=int(block_data.get("nonce", 0)),
        )
        block.block_hash = block_data.get("block_hash", block.block_hash)
        return block


def has_leading_zero_bits(block_hash: str, difficulty_bits: int) -> bool:
    binary_hash = bin(int(block_hash, 16))[2:].zfill(len(block_hash) * 4)
    return binary_hash.startswith("0" * difficulty_bits)


def hash_to_binary(block_hash: str) -> str:
    return bin(int(block_hash, 16))[2:].zfill(len(block_hash) * 4)


def short_binary_hash(block_hash: str, difficulty_bits: int) -> str:
    preview_length = difficulty_bits + 16
    return f"{hash_to_binary(block_hash)[:preview_length]}..."


def proof_of_work(
    block: Block,
    difficulty_bits: int,
    progress_callback: Callable[[int], None] | None = None,
    progress_interval: int = 10_000,
) -> str:
    if (
        block.hash_function.__module__ != "core.hashing"
        or block.hash_function.__name__ != "sha256_block_hash"
    ):
        raise ValueError("Native proof-of-work only supports core.hashing.sha256_block_hash.")

    prefix = serialize_block_prefix(block)
    native_progress_interval = progress_interval if progress_callback is not None else 0
    nonce, block_hash = native_mine_pow(
        prefix,
        difficulty_bits,
        block.nonce,
        native_progress_interval,
    )
    block.nonce = nonce
    block.block_hash = block_hash

    return block.block_hash


def verify_block(block: Block, difficulty_bits: int) -> bool:
    expected_hash = block.hash_function(block)
    return (
        block.block_hash == expected_hash
        and has_leading_zero_bits(block.block_hash, difficulty_bits)
    )
