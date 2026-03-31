from datetime import datetime

from implementation.block import Block, proof_of_work
from implementation.blockchain import Blockchain
from implementation.hashing import sha256_block_hash
from implementation.transaction import Transaction
from implementation.utils.constants import GENESIS_PREVIOUS_HASH


def main() -> None:
    difficulty_bits = 8
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

    blockchain.add_transaction(
        Transaction(
            sender="Alice",
            receiver="Bob",
            amount=10.0,
            timestamp=datetime.now(),
        )
    )
    blockchain.add_transaction(
        Transaction(
            sender="Bob",
            receiver="Charlie",
            amount=3.5,
            timestamp=datetime.now(),
        )
    )

    mined_block = blockchain.mine_pending_transactions(
        miner_address="Miner01",
        description="User transactions"
    )

    print("Mined block:", mined_block.block_id)
    print("Mining reward transaction:", mined_block.transactions[0])
    print("Pending transactions after mining:", len(blockchain.pending_transactions))
    print("Blockchain valid before tampering:", blockchain.verify_chain())

    mined_block.transactions[0].amount = 999.0

    print("Blockchain valid after tampering:", blockchain.verify_chain())


if __name__ == "__main__":
    main()
