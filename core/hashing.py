import hashlib

from core.block import Block
from core.serialization import serialize_block
from core.serialization import serialize_transaction
from core.transaction import Transaction


def sha256_transaction_hash(transaction: Transaction) -> str:
    return hashlib.sha256(
        serialize_transaction(transaction).encode("utf-8")
    ).hexdigest()


def sha256_block_hash(block: Block) -> str:
    return hashlib.sha256(serialize_block(block).encode("utf-8")).hexdigest()
