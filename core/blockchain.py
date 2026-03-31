from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable

from core.block import Block, proof_of_work, verify_block
from core.transaction import Transaction
from core.utils.chain import get_previous_hash
from core.utils.constants import MAX_TRANSACTIONS_PER_BLOCK
from core.utils.mining import (
    create_mining_reward_transaction,
    is_mining_reward_transaction,
    validate_mining_reward_transaction,
)
from wallet.wallet import Wallet


@dataclass
class Blockchain:
    difficulty_bits: int
    hash_function: Callable[[Block], str]
    blocks: list[Block] = field(default_factory=list)
    pending_transactions: list[Transaction] = field(default_factory=list)

    def get_balance(self, address: str) -> Decimal:
        balances = self._calculate_balances(self.blocks)
        return balances.get(address, Decimal("0.0"))

    def get_available_balance(self, address: str) -> Decimal:
        balances = self._calculate_balances(self.blocks)

        for transaction in self.pending_transactions:
            if not self._apply_transaction_to_balances(transaction, balances):
                return Decimal("0.0")

        return balances.get(address, Decimal("0.0"))

    def add_transaction(self, transaction: Transaction) -> None:
        if is_mining_reward_transaction(transaction):
            raise ValueError("Mining reward transactions can only be created by the blockchain.")

        if not self._validate_transaction_authenticity(transaction):
            raise ValueError("Transaction has invalid signature or sender identity.")

        balances = self._calculate_balances(self.blocks)
        for pending_transaction in self.pending_transactions:
            if not self._apply_transaction_to_balances(pending_transaction, balances):
                raise ValueError("Existing pending transactions are invalid.")

        if not self._apply_transaction_to_balances(transaction, balances):
            raise ValueError("Transaction is invalid or sender has insufficient funds.")

        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address: str, description: str) -> Block:
        selected_transactions = sorted(
            self.pending_transactions,
            key=lambda transaction: transaction.fee,
            reverse=True,
        )[: MAX_TRANSACTIONS_PER_BLOCK - 1]
        total_fees = sum(
            (transaction.fee for transaction in selected_transactions),
            start=Decimal("0.0"),
        )
        reward_transaction = create_mining_reward_transaction(miner_address, total_fees=total_fees)
        block_transactions = [reward_transaction, *selected_transactions]

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

        mined_transaction_ids = {id(transaction) for transaction in selected_transactions}
        self.pending_transactions = [
            transaction
            for transaction in self.pending_transactions
            if id(transaction) not in mined_transaction_ids
        ]
        return block

    def add_block(self, block: Block) -> bool:
        expected_previous_hash = get_previous_hash(self.blocks)

        if block.previous_hash != expected_previous_hash:
            return False

        if len(block.transactions) > MAX_TRANSACTIONS_PER_BLOCK:
            return False

        if not validate_mining_reward_transaction(block):
            return False

        balances = self._calculate_balances(self.blocks)
        if not self._validate_block_transactions(block, balances):
            return False

        if not verify_block(block, self.difficulty_bits):
            return False

        self.blocks.append(block)
        return True

    def verify_chain(self) -> bool:
        balances: dict[str, Decimal] = {}

        for index, block in enumerate(self.blocks):
            expected_previous_hash = get_previous_hash(self.blocks[:index])

            if block.previous_hash != expected_previous_hash:
                return False

            if len(block.transactions) > MAX_TRANSACTIONS_PER_BLOCK:
                return False

            if not validate_mining_reward_transaction(block):
                return False

            if not self._validate_block_transactions(block, balances):
                return False

            if not verify_block(block, self.difficulty_bits):
                return False

        return True

    def _calculate_balances(self, blocks: list[Block]) -> dict[str, Decimal]:
        balances: dict[str, Decimal] = {}

        for block in blocks:
            if not self._validate_block_transactions(block, balances):
                raise ValueError("Blockchain contains invalid transactions.")

        return balances

    def _validate_block_transactions(
        self,
        block: Block,
        balances: dict[str, Decimal],
    ) -> bool:
        for transaction in block.transactions:
            if not self._apply_transaction_to_balances(transaction, balances):
                return False

        return True

    def _apply_transaction_to_balances(
        self,
        transaction: Transaction,
        balances: dict[str, Decimal],
    ) -> bool:
        if not self._validate_transaction_authenticity(transaction):
            return False

        if (
            not transaction.receiver
            or transaction.amount <= Decimal("0.0")
            or transaction.fee < Decimal("0.0")
        ):
            return False

        if is_mining_reward_transaction(transaction):
            balances[transaction.receiver] = (
                balances.get(transaction.receiver, Decimal("0.0")) + transaction.amount
            )
            return True

        if not transaction.sender:
            return False

        sender_balance = balances.get(transaction.sender, Decimal("0.0"))
        total_cost = transaction.amount + transaction.fee
        if sender_balance < total_cost:
            return False

        balances[transaction.sender] = sender_balance - total_cost
        balances[transaction.receiver] = (
            balances.get(transaction.receiver, Decimal("0.0")) + transaction.amount
        )
        return True

    def _validate_transaction_authenticity(self, transaction: Transaction) -> bool:
        if is_mining_reward_transaction(transaction):
            return transaction.sender_public_key is None and transaction.signature is None

        if transaction.sender_public_key is None or transaction.signature is None:
            return False

        sender_address = Wallet.address_from_public_key(transaction.sender_public_key)
        if transaction.sender != sender_address:
            return False

        return Wallet.verify_signature_with_public_key(
            message=transaction.signing_payload(),
            signature=transaction.signature,
            public_key=transaction.sender_public_key,
        )
