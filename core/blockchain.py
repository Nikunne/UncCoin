from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable

from core.block import Block, proof_of_work, verify_block
from core.hashing import sha256_transaction_hash
from core.transaction import Transaction
from core.utils.constants import GENESIS_PREVIOUS_HASH, MAX_TRANSACTIONS_PER_BLOCK
from core.utils.mining import (
    create_mining_reward_transaction,
    is_mining_reward_transaction,
    validate_mining_reward_transaction,
)
from wallet.wallet import Wallet


@dataclass
class ChainState:
    balances: dict[str, Decimal] = field(default_factory=dict)
    nonces: dict[str, int] = field(default_factory=dict)
    height: int = -1

    def copy(self) -> "ChainState":
        return ChainState(
            balances=self.balances.copy(),
            nonces=self.nonces.copy(),
            height=self.height,
        )


@dataclass
class Blockchain:
    difficulty_bits: int
    hash_function: Callable[[Block], str]
    blocks_by_hash: dict[str, Block] = field(default_factory=dict)
    children_by_hash: dict[str, list[str]] = field(default_factory=dict)
    block_states: dict[str, ChainState] = field(default_factory=dict)
    pending_transactions: list[Transaction] = field(default_factory=list)
    main_tip_hash: str | None = None

    @property
    def blocks(self) -> list[Block]:
        return self.get_chain()

    def get_chain(self, tip_hash: str | None = None) -> list[Block]:
        chain: list[Block] = []
        current_hash = self.main_tip_hash if tip_hash is None else tip_hash

        while current_hash is not None:
            block = self.blocks_by_hash.get(current_hash)
            if block is None:
                break

            chain.append(block)
            if block.previous_hash == GENESIS_PREVIOUS_HASH:
                break

            current_hash = block.previous_hash

        chain.reverse()
        return chain

    def get_balance(self, address: str) -> Decimal:
        return self._get_canonical_state().balances.get(address, Decimal("0.0"))

    def get_available_balance(self, address: str) -> Decimal:
        state = self._get_canonical_state().copy()

        for transaction in self.pending_transactions:
            if not self._apply_transaction_to_state(transaction, state):
                return Decimal("0.0")

        return state.balances.get(address, Decimal("0.0"))

    def get_next_nonce(self, address: str) -> int:
        state = self._get_canonical_state().copy()

        for transaction in self.pending_transactions:
            if not self._apply_transaction_to_state(transaction, state):
                raise ValueError("Existing pending transactions are invalid.")

        return state.nonces.get(address, 0)

    def add_transaction(self, transaction: Transaction) -> None:
        if is_mining_reward_transaction(transaction):
            raise ValueError("Mining reward transactions can only be created by the blockchain.")

        if not self._validate_transaction_authenticity(transaction):
            raise ValueError("Transaction has invalid signature or sender identity.")

        state = self._get_canonical_state().copy()
        for pending_transaction in self.pending_transactions:
            if not self._apply_transaction_to_state(pending_transaction, state):
                raise ValueError("Existing pending transactions are invalid.")

        expected_nonce = state.nonces.get(transaction.sender, 0)
        if transaction.nonce != expected_nonce:
            raise ValueError("Transaction has invalid nonce.")

        if not self._apply_transaction_to_state(transaction, state):
            raise ValueError("Transaction is invalid or sender has insufficient funds.")

        self.pending_transactions.append(transaction)

    def mine_pending_transactions(
        self,
        miner_address: str,
        description: str,
        progress_callback: Callable[[int], None] | None = None,
    ) -> Block:
        if self.main_tip_hash is None:
            raise ValueError("Genesis block must be created before mining.")

        selected_transactions = self._select_transactions_for_block()
        total_fees = sum(
            (transaction.fee for transaction in selected_transactions),
            start=Decimal("0.0"),
        )
        reward_transaction = create_mining_reward_transaction(
            miner_address,
            total_fees=total_fees,
        )
        block_transactions = [reward_transaction, *selected_transactions]

        block = Block(
            block_id=self._get_canonical_state().height + 1,
            transactions=block_transactions,
            hash_function=self.hash_function,
            description=description,
            previous_hash=self.main_tip_hash,
        )
        proof_of_work(
            block,
            self.difficulty_bits,
            progress_callback=progress_callback,
        )

        if not self.add_block(block):
            raise ValueError("Mined block failed validation.")

        return block

    def add_block(self, block: Block) -> bool:
        return self.add_block_with_status(block) == "accepted"

    def add_block_with_status(self, block: Block) -> str:
        block_hash = block.block_hash
        if block_hash in self.blocks_by_hash:
            return "duplicate"

        if (
            block.previous_hash != GENESIS_PREVIOUS_HASH
            and block.previous_hash not in self.block_states
        ):
            return "missing_parent"

        parent_state = self._get_parent_state_for_block(block)
        if parent_state is None:
            return "invalid"

        child_state = self._build_child_state(block, parent_state)
        if child_state is None:
            return "invalid"

        previous_head = self.main_tip_hash
        self.blocks_by_hash[block_hash] = block
        self.block_states[block_hash] = child_state
        self.children_by_hash.setdefault(block_hash, [])
        if block.previous_hash != GENESIS_PREVIOUS_HASH:
            self.children_by_hash.setdefault(block.previous_hash, []).append(block_hash)

        if self._should_update_main_tip(block_hash):
            self.main_tip_hash = block_hash

        self._reconcile_pending_transactions(previous_head)
        return "accepted"

    def verify_chain(self) -> bool:
        temp_states: dict[str, ChainState] = {}
        temp_children: dict[str, list[str]] = {
            block_hash: []
            for block_hash in self.blocks_by_hash
        }

        def compute_state(block_hash: str) -> ChainState | None:
            if block_hash in temp_states:
                return temp_states[block_hash]

            block = self.blocks_by_hash[block_hash]
            if block.previous_hash == GENESIS_PREVIOUS_HASH:
                parent_state = self._get_parent_state_for_block(block, states=temp_states)
                if parent_state is None:
                    return None
            else:
                if block.previous_hash not in self.blocks_by_hash:
                    return None
                parent_state = compute_state(block.previous_hash)
                if parent_state is None:
                    return None

            child_state = self._build_child_state(block, parent_state)
            if child_state is None:
                return None

            temp_states[block_hash] = child_state
            return child_state

        genesis_blocks = 0
        for block_hash, block in self.blocks_by_hash.items():
            if block.previous_hash == GENESIS_PREVIOUS_HASH:
                genesis_blocks += 1
            else:
                temp_children.setdefault(block.previous_hash, []).append(block_hash)

            if compute_state(block_hash) is None:
                return False

        if genesis_blocks > 1:
            return False

        previous_head = self.main_tip_hash
        self.block_states = temp_states
        self.children_by_hash = temp_children
        self.main_tip_hash = self._select_best_tip(temp_states, temp_children)
        self._reconcile_pending_transactions(previous_head)
        return True

    def _build_child_state(
        self,
        block: Block,
        parent_state: ChainState,
    ) -> ChainState | None:
        if len(block.transactions) > MAX_TRANSACTIONS_PER_BLOCK:
            return None

        if not validate_mining_reward_transaction(block):
            return None

        if not verify_block(block, self.difficulty_bits):
            return None

        state = parent_state.copy()
        state.height = block.block_id

        for transaction in block.transactions:
            if not self._apply_transaction_to_state(transaction, state):
                return None

        return state

    def _get_parent_state_for_block(
        self,
        block: Block,
        states: dict[str, ChainState] | None = None,
    ) -> ChainState | None:
        block_states = self.block_states if states is None else states

        if block.previous_hash == GENESIS_PREVIOUS_HASH:
            if block.block_id != 0:
                return None
            if any(
                existing_block.previous_hash == GENESIS_PREVIOUS_HASH
                and existing_hash != block.block_hash
                for existing_hash, existing_block in self.blocks_by_hash.items()
            ):
                return None
            return ChainState()

        parent_state = block_states.get(block.previous_hash)
        if parent_state is None:
            return None

        if block.block_id != parent_state.height + 1:
            return None

        return parent_state

    def _get_canonical_state(self) -> ChainState:
        if self.main_tip_hash is None:
            return ChainState()
        return self.block_states[self.main_tip_hash]

    def _should_update_main_tip(self, block_hash: str) -> bool:
        if self.main_tip_hash is None:
            return True

        new_height = self.block_states[block_hash].height
        current_height = self.block_states[self.main_tip_hash].height
        return new_height > current_height

    def _select_best_tip(
        self,
        states: dict[str, ChainState],
        children: dict[str, list[str]],
    ) -> str | None:
        if not states:
            return None

        tip_hashes = [
            block_hash
            for block_hash in states
            if not children.get(block_hash)
        ]

        if not tip_hashes:
            return None

        max_height = max(states[block_hash].height for block_hash in tip_hashes)
        candidates = [
            block_hash
            for block_hash in tip_hashes
            if states[block_hash].height == max_height
        ]

        if self.main_tip_hash in candidates:
            return self.main_tip_hash

        return sorted(candidates)[0]

    def _select_transactions_for_block(self) -> list[Transaction]:
        remaining_transactions = sorted(
            self.pending_transactions,
            key=lambda transaction: transaction.fee,
            reverse=True,
        )
        state = self._get_canonical_state().copy()
        selected_transactions: list[Transaction] = []

        while remaining_transactions and len(selected_transactions) < MAX_TRANSACTIONS_PER_BLOCK - 1:
            progress = False
            next_round: list[Transaction] = []

            for transaction in remaining_transactions:
                if len(selected_transactions) >= MAX_TRANSACTIONS_PER_BLOCK - 1:
                    next_round.append(transaction)
                    continue

                test_state = state.copy()
                if self._apply_transaction_to_state(transaction, test_state):
                    state = test_state
                    selected_transactions.append(transaction)
                    progress = True
                else:
                    next_round.append(transaction)

            if not progress:
                break

            remaining_transactions = next_round

        return selected_transactions

    def _reconcile_pending_transactions(self, previous_head: str | None) -> None:
        previous_transactions = self._collect_transactions(previous_head)
        current_transactions = self._collect_transactions(self.main_tip_hash)
        current_transaction_ids = {
            sha256_transaction_hash(transaction)
            for transaction in current_transactions
        }

        resurrected_transactions = [
            transaction
            for transaction in previous_transactions
            if not is_mining_reward_transaction(transaction)
            and sha256_transaction_hash(transaction) not in current_transaction_ids
        ]

        candidate_transactions = [*resurrected_transactions, *self.pending_transactions]
        state = self._get_canonical_state().copy()
        seen_transaction_ids: set[str] = set()
        valid_pending_transactions: list[Transaction] = []

        for transaction in candidate_transactions:
            transaction_id = sha256_transaction_hash(transaction)
            if transaction_id in seen_transaction_ids or transaction_id in current_transaction_ids:
                continue

            test_state = state.copy()
            if self._apply_transaction_to_state(transaction, test_state):
                state = test_state
                valid_pending_transactions.append(transaction)
                seen_transaction_ids.add(transaction_id)

        self.pending_transactions = valid_pending_transactions

    def _collect_transactions(self, tip_hash: str | None) -> list[Transaction]:
        if tip_hash is None:
            return []

        transactions: list[Transaction] = []
        for block in self.get_chain(tip_hash):
            transactions.extend(block.transactions)
        return transactions

    def _apply_transaction_to_state(
        self,
        transaction: Transaction,
        state: ChainState,
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
            state.balances[transaction.receiver] = (
                state.balances.get(transaction.receiver, Decimal("0.0")) + transaction.amount
            )
            return True

        if not transaction.sender:
            return False

        expected_nonce = state.nonces.get(transaction.sender, 0)
        if transaction.nonce != expected_nonce:
            return False

        sender_balance = state.balances.get(transaction.sender, Decimal("0.0"))
        total_cost = transaction.amount + transaction.fee
        if sender_balance < total_cost:
            return False

        state.nonces[transaction.sender] = expected_nonce + 1
        state.balances[transaction.sender] = sender_balance - total_cost
        state.balances[transaction.receiver] = (
            state.balances.get(transaction.receiver, Decimal("0.0")) + transaction.amount
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
