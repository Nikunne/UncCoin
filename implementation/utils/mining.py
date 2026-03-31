from datetime import datetime

from implementation.block import Block
from implementation.transaction import Transaction
from implementation.utils.constants import MINING_REWARD_AMOUNT, MINING_REWARD_SENDER


def create_mining_reward_transaction(miner_address: str) -> Transaction:
    return Transaction(
        sender=MINING_REWARD_SENDER,
        receiver=miner_address,
        amount=MINING_REWARD_AMOUNT,
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
    return (
        block.transactions[0] == reward_transaction
        and reward_transaction.amount == MINING_REWARD_AMOUNT
        and bool(reward_transaction.receiver)
    )
