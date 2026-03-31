import hashlib

from implementation.block import Block


def serialize_block(block: Block) -> str:
    transaction_data = "".join(
        f"{transaction.sender}:{transaction.receiver}:{transaction.amount}:{transaction.timestamp.isoformat()}"
        for transaction in block.transactions
    )
    return (
        f"{block.block_id}|{transaction_data}|{block.description}|"
        f"{block.previous_hash}|{block.nonce}"
    )


def sha256_block_hash(block: Block) -> str:
    return hashlib.sha256(serialize_block(block).encode("utf-8")).hexdigest()
