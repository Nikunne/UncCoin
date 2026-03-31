from decimal import Decimal
from datetime import datetime

from core.block import Block, proof_of_work
from core.blockchain import Blockchain
from core.hashing import sha256_block_hash
from core.transaction import Transaction
from core.utils.constants import GENESIS_PREVIOUS_HASH


def main() -> None:
    difficulty_bits = 1
    blockchain = Blockchain(
        difficulty_bits=difficulty_bits,
        hash_function=sha256_block_hash,
    )

    genesis_block = Block(
        block_id=0,
        transactions=[],
        hash_function=sha256_block_hash,
        description="Genesis block",
        previous_hash=GENESIS_PREVIOUS_HASH,
    )
    proof_of_work(genesis_block, difficulty_bits)
    blockchain.add_block(genesis_block)

    reward_block = blockchain.mine_pending_transactions(
        miner_address="Alice",
        description="Initial mining reward"
    )

    blockchain.add_transaction(
        Transaction(
            sender="Alice",
            receiver="Bob",
            amount=Decimal("9.5"),
            fee=Decimal("0.5"),
            timestamp=datetime.now(),
        )
    )
    blockchain.add_transaction(
        Transaction(
            sender="Bob",
            receiver="Charlie",
            amount=Decimal("3.5"),
            fee=Decimal("0.1"),
            timestamp=datetime.now(),
        )
    )

    mined_block = blockchain.mine_pending_transactions(
        miner_address="Alice",
        description="User transactions"
    )

    print("Reward block:", reward_block.block_id)
    print("Mined block:", mined_block.block_id)
    print("Mining reward transaction:", mined_block.transactions[0])
    print("Mined transaction fees:", [transaction.fee for transaction in mined_block.transactions[1:]])
    print("Pending transactions after mining:", len(blockchain.pending_transactions))
    print("Alice balance:", blockchain.get_balance("Alice"))
    print("Bob balance:", blockchain.get_balance("Bob"))
    print("Charlie balance:", blockchain.get_balance("Charlie"))
    print("Blockchain valid before tampering:", blockchain.verify_chain())

    mined_block.transactions[0].amount = Decimal("999.0")

    print("Blockchain valid after tampering:", blockchain.verify_chain())


if __name__ == "__main__":
    main()
