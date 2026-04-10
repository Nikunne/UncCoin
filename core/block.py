import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from core.native_pow import gpu_available as native_gpu_available
from core.native_pow import mine_pow as native_mine_pow
from core.native_pow import mine_pow_gpu as native_mine_pow_gpu
from core.native_pow import request_pow_cancel
from core.native_pow import reset_pow_cancel
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


class ProofOfWorkCancelled(Exception):
    pass


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
    reset_pow_cancel()
    worker_count = max(1, os.cpu_count() or 1)
    gpu_enabled = native_gpu_available()
    total_partitions = worker_count + (1 if gpu_enabled else 0)

    def mine_gpu() -> tuple[int, str, bool]:
        return native_mine_pow_gpu(
            prefix,
            difficulty_bits,
            block.nonce + worker_count,
            0,
            nonce_step=total_partitions,
        )

    def mine_range(worker_index: int) -> tuple[int, str, bool]:
        worker_progress_interval = 0
        if native_progress_interval > 0 and worker_index == 0:
            worker_progress_interval = native_progress_interval * total_partitions
        return native_mine_pow(
            prefix,
            difficulty_bits,
            block.nonce + worker_index,
            worker_progress_interval,
            total_partitions,
        )

    winner: tuple[int, str] | None = None
    cancelled_workers = 0
    gpu_failed = False

    with ThreadPoolExecutor(max_workers=worker_count + (1 if gpu_enabled else 0)) as executor:
        future_labels = {
            executor.submit(mine_range, worker_index): "cpu"
            for worker_index in range(worker_count)
        }
        if gpu_enabled:
            future_labels[executor.submit(mine_gpu)] = "gpu"

        try:
            for future in as_completed(future_labels):
                try:
                    nonce, block_hash, cancelled = future.result()
                except RuntimeError:
                    if future_labels[future] == "gpu":
                        gpu_failed = True
                        continue
                    raise
                if cancelled:
                    cancelled_workers += 1
                    continue

                winner = (nonce, block_hash)
                request_pow_cancel()
                break
        finally:
            request_pow_cancel()
            for future, label in future_labels.items():
                try:
                    future.result()
                except RuntimeError:
                    if label != "gpu":
                        raise

    expected_cancelled = worker_count + (0 if gpu_failed or not gpu_enabled else 1)
    if winner is None or cancelled_workers == expected_cancelled:
        raise ProofOfWorkCancelled("Proof of work was cancelled.")

    block.nonce, block.block_hash = winner

    return block.block_hash


def verify_block(block: Block, difficulty_bits: int) -> bool:
    return get_block_verification_error(block, difficulty_bits) is None


def get_block_verification_error(block: Block, difficulty_bits: int) -> str | None:
    expected_hash = block.hash_function(block)
    if block.block_hash != expected_hash:
        return "block hash does not match block contents"
    if not has_leading_zero_bits(block.block_hash, difficulty_bits):
        return (
            f"block hash does not satisfy proof-of-work difficulty "
            f"{difficulty_bits}"
        )
    return None
