import hashlib

from core.block import Block
from core.transaction import Transaction


def serialize_public_key(public_key: tuple[int, int] | None) -> str:
    if public_key is None:
        return ""
    return f"{public_key[0]}:{public_key[1]}"


def serialize_transaction(transaction: Transaction) -> str:
    return (
        f"{transaction.sender}|{transaction.receiver}|"
        f"{transaction.amount}|{transaction.fee}|{transaction.timestamp.isoformat()}|"
        f"{transaction.nonce}|"
        f"{serialize_public_key(transaction.sender_public_key)}|{transaction.signature or ''}"
    )


def sha256_transaction_hash(transaction: Transaction) -> str:
    return hashlib.sha256(
        serialize_transaction(transaction).encode("utf-8")
    ).hexdigest()


def serialize_block(block: Block) -> str:
    transaction_data = "".join(
        serialize_transaction(transaction)
        for transaction in block.transactions
    )
    return (
        f"{block.block_id}|{transaction_data}|{block.description}|"
        f"{block.previous_hash}|{block.nonce}"
    )


def sha256_block_hash(block: Block) -> str:
    return hashlib.sha256(serialize_block(block).encode("utf-8")).hexdigest()
