from datetime import datetime
from decimal import Decimal

from core.block import Block
from core.transaction import Transaction
from core.utils.constants import MINING_REWARD_AMOUNT, MINING_REWARD_SENDER


def create_mining_reward_transaction(
    miner_address: str,
    total_fees: Decimal = Decimal("0.0"),
) -> Transaction:
    return Transaction(
        sender=MINING_REWARD_SENDER,
        receiver=miner_address,
        amount=MINING_REWARD_AMOUNT + total_fees,
        fee=Decimal("0.0"),
        timestamp=datetime.now(),
    )


def is_mining_reward_transaction(transaction: Transaction) -> bool:
    return transaction.sender == MINING_REWARD_SENDER


def validate_mining_reward_transaction(block: Block) -> bool:
    reward_transactions = [
        transaction
        for transaction in block.transactions
        if is_mining_reward_transaction(transaction)
    ]

    if block.block_id == 0:
        return len(reward_transactions) == 0

    if len(reward_transactions) != 1:
        return False

    reward_transaction = reward_transactions[0]
    expected_reward_amount = MINING_REWARD_AMOUNT + sum(
        (
            transaction.fee
            for transaction in block.transactions
            if not is_mining_reward_transaction(transaction)
        ),
        start=Decimal("0.0"),
    )
    return (
        block.transactions[0] == reward_transaction
        and reward_transaction.amount == expected_reward_amount
        and reward_transaction.fee == Decimal("0.0")
        and bool(reward_transaction.receiver)
    )
