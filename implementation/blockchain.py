from dataclasses import dataclass, field
from typing import Callable

from implementation.block import Block, proof_of_work, verify_block
from implementation.transaction import Transaction
from implementation.utils.chain import get_previous_hash
from implementation.utils.mining import (
    create_mining_reward_transaction,
    is_mining_reward_transaction,
    validate_mining_reward_transaction,
)


@dataclass
class Blockchain:
    difficulty_bits: int
    hash_function: Callable[[Block], str]
    blocks: list[Block] = field(default_factory=list)
    pending_transactions: list[Transaction] = field(default_factory=list)

    def add_transaction(self, transaction: Transaction) -> None:
        if is_mining_reward_transaction(transaction):
            raise ValueError("Mining reward transactions can only be created by the blockchain.")

        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address: str, description: str) -> Block:
        reward_transaction = create_mining_reward_transaction(miner_address)
        block_transactions = [reward_transaction, *self.pending_transactions]

        block = Block(
            block_id=len(self.blocks),
            transactions=block_transactions,
            hash_function=self.hash_function,
            description=description,
            previous_hash=get_previous_hash(self.blocks),
        )
        proof_of_work(block, self.difficulty_bits)

        if not self.add_block(block):
            raise ValueError("Mined block failed validation.")

        self.pending_transactions.clear()
        return block

    def add_block(self, block: Block) -> bool:
        expected_previous_hash = get_previous_hash(self.blocks)

        if block.previous_hash != expected_previous_hash:
            return False

        if not validate_mining_reward_transaction(block):
            return False

        if not verify_block(block, self.difficulty_bits):
            return False

        self.blocks.append(block)
        return True

    def verify_chain(self) -> bool:
        for index, block in enumerate(self.blocks):
            expected_previous_hash = get_previous_hash(self.blocks[:index])

            if block.previous_hash != expected_previous_hash:
                return False

            if not validate_mining_reward_transaction(block):
                return False

            if not verify_block(block, self.difficulty_bits):
                return False

        return True
