from decimal import Decimal
from datetime import datetime

from core.block import Block, proof_of_work
from core.blockchain import Blockchain
from core.hashing import sha256_block_hash
from core.transaction import Transaction
from core.utils.constants import GENESIS_PREVIOUS_HASH
from wallet import create_wallet


def create_signed_transaction(
    blockchain: Blockchain,
    sender_wallet,
    receiver_address: str,
    amount: Decimal,
    fee: Decimal,
) -> Transaction:
    transaction = Transaction(
        sender=sender_wallet.address,
        receiver=receiver_address,
        amount=amount,
        fee=fee,
        timestamp=datetime.now(),
        nonce=blockchain.get_next_nonce(sender_wallet.address),
        sender_public_key=sender_wallet.public_key,
    )
    transaction.signature = sender_wallet.sign_message(transaction.signing_payload())
    return transaction


def main() -> None:
    difficulty_bits = 1
    alice_wallet = create_wallet(name="alice")
    bob_wallet = create_wallet(name="bob")
    charlie_wallet = create_wallet(name="charlie")

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
        miner_address=alice_wallet.address,
        description="Initial mining reward"
    )

    blockchain.add_transaction(
        create_signed_transaction(
            blockchain=blockchain,
            sender_wallet=alice_wallet,
            receiver_address=bob_wallet.address,
            amount=Decimal("9.5"),
            fee=Decimal("0.5"),
        )
    )
    blockchain.add_transaction(
        create_signed_transaction(
            blockchain=blockchain,
            sender_wallet=bob_wallet,
            receiver_address=charlie_wallet.address,
            amount=Decimal("3.5"),
            fee=Decimal("0.1"),
        )
    )

    mined_block = blockchain.mine_pending_transactions(
        miner_address=alice_wallet.address,
        description="User transactions"
    )

    print("Reward block:", reward_block.block_id)
    print("Mined block:", mined_block.block_id)
    print("Mining reward transaction:", mined_block.transactions[0])
    print("Mined transaction fees:", [transaction.fee for transaction in mined_block.transactions[1:]])
    print("Pending transactions after mining:", len(blockchain.pending_transactions))
    print("Alice balance:", blockchain.get_balance(alice_wallet.address))
    print("Bob balance:", blockchain.get_balance(bob_wallet.address))
    print("Charlie balance:", blockchain.get_balance(charlie_wallet.address))
    print("Blockchain valid before tampering:", blockchain.verify_chain())

    mined_block.transactions[0].amount = Decimal("999.0")

    print("Blockchain valid after tampering:", blockchain.verify_chain())


if __name__ == "__main__":
    main()
