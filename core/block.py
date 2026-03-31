from dataclasses import dataclass, field
from typing import Callable

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


def has_leading_zero_bits(block_hash: str, difficulty_bits: int) -> bool:
    binary_hash = bin(int(block_hash, 16))[2:].zfill(len(block_hash) * 4)
    return binary_hash.startswith("0" * difficulty_bits)


def hash_to_binary(block_hash: str) -> str:
    return bin(int(block_hash, 16))[2:].zfill(len(block_hash) * 4)


def short_binary_hash(block_hash: str, difficulty_bits: int) -> str:
    preview_length = difficulty_bits + 16
    return f"{hash_to_binary(block_hash)[:preview_length]}..."


def proof_of_work(block: Block, difficulty_bits: int) -> str:
    while not has_leading_zero_bits(block.block_hash, difficulty_bits):
        block.nonce += 1
        block.block_hash = block.hash_function(block)

    return block.block_hash


def verify_block(block: Block, difficulty_bits: int) -> bool:
    expected_hash = block.hash_function(block)
    return (
        block.block_hash == expected_hash
        and has_leading_zero_bits(block.block_hash, difficulty_bits)
    )
