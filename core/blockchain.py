from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable

from core.block import Block, get_block_verification_error, proof_of_work
from core.hashing import sha256_transaction_hash
from core.transaction import Transaction
from core.utils.constants import GENESIS_PREVIOUS_HASH, MAX_TRANSACTIONS_PER_BLOCK
from core.utils.mining import (
    create_mining_reward_transaction,
    get_mining_reward_validation_error,
    is_mining_reward_transaction,
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


@dataclass(frozen=True)
class BlockAcceptanceResult:
    status: str
    reason: str | None = None


@dataclass
class Blockchain:
    difficulty_bits: int
    hash_function: Callable[[Block], str]
    genesis_difficulty_bits: int | None = None
    difficulty_growth_factor: int = 10
    difficulty_growth_start_height: int = 100
    difficulty_growth_bits: int = 1
    difficulty_schedule_activation_height: int = 0
    blocks_by_hash: dict[str, Block] = field(default_factory=dict)
    children_by_hash: dict[str, list[str]] = field(default_factory=dict)
    block_states: dict[str, ChainState] = field(default_factory=dict)
    pending_transactions: list[Transaction] = field(default_factory=list)
    main_tip_hash: str | None = None

    @property
    def blocks(self) -> list[Block]:
        return self.get_chain()

    def get_difficulty_bits_for_height(self, block_height: int) -> int:
        if block_height < 0:
            raise ValueError("block_height must be non-negative.")
        if self.genesis_difficulty_bits is not None and self.genesis_difficulty_bits < 0:
            raise ValueError("genesis_difficulty_bits must be non-negative.")
        if self.difficulty_growth_factor < 2:
            raise ValueError("difficulty_growth_factor must be at least 2.")
        if self.difficulty_growth_start_height < 1:
            raise ValueError("difficulty_growth_start_height must be at least 1.")
        if self.difficulty_growth_bits < 1:
            raise ValueError("difficulty_growth_bits must be at least 1.")

        if block_height == 0:
            return (
                self.genesis_difficulty_bits
                if self.genesis_difficulty_bits is not None
                else self.difficulty_bits
            )

        if block_height < self.difficulty_schedule_activation_height:
            return self.difficulty_bits

        if block_height < self.difficulty_growth_start_height:
            return self.difficulty_bits

        growth_steps = 0
        threshold = self.difficulty_growth_start_height
        while block_height >= threshold:
            growth_steps += 1
            threshold *= self.difficulty_growth_factor

        return self.difficulty_bits + (growth_steps * self.difficulty_growth_bits)

    def get_next_block_difficulty_bits(self) -> int:
        return self.get_difficulty_bits_for_height(self._get_canonical_state().height + 1)

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
            if self._apply_transaction_to_state_error(transaction, state) is not None:
                return Decimal("0.0")

        return state.balances.get(address, Decimal("0.0"))

    def get_next_nonce(self, address: str) -> int:
        state = self._get_canonical_state().copy()

        for transaction in self.pending_transactions:
            if self._apply_transaction_to_state_error(transaction, state) is not None:
                raise ValueError("Existing pending transactions are invalid.")

        return state.nonces.get(address, 0)

    def add_transaction(self, transaction: Transaction) -> None:
        if is_mining_reward_transaction(transaction):
            raise ValueError("Mining reward transactions can only be created by the blockchain.")

        state = self._get_canonical_state().copy()
        for index, pending_transaction in enumerate(self.pending_transactions):
            pending_error = self._apply_transaction_to_state_error(pending_transaction, state)
            if pending_error is not None:
                raise ValueError(
                    f"Existing pending transaction {index} is invalid: "
                    f"{pending_error}"
                )

        transaction_error = self._apply_transaction_to_state_error(transaction, state)
        if transaction_error is not None:
            raise ValueError(transaction_error)

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
            self.get_difficulty_bits_for_height(block.block_id),
            progress_callback=progress_callback,
        )

        add_result = self.add_block_result(block)
        if add_result.status != "accepted":
            raise ValueError(
                "Mined block failed validation: "
                f"{add_result.reason or add_result.status}"
            )

        return block

    def add_block(self, block: Block) -> bool:
        return self.add_block_result(block).status == "accepted"

    def add_block_with_status(self, block: Block) -> str:
        return self.add_block_result(block).status

    def add_block_result(self, block: Block) -> BlockAcceptanceResult:
        block_hash = block.block_hash
        if block_hash in self.blocks_by_hash:
            return BlockAcceptanceResult("duplicate", "block already exists")

        if (
            block.previous_hash != GENESIS_PREVIOUS_HASH
            and block.previous_hash not in self.block_states
        ):
            return BlockAcceptanceResult(
                "missing_parent",
                f"missing parent block {block.previous_hash[:12]}",
            )

        parent_state, parent_error = self._get_parent_state_for_block(block)
        if parent_state is None:
            return BlockAcceptanceResult("invalid", parent_error)

        child_state, child_error = self._build_child_state(block, parent_state)
        if child_state is None:
            return BlockAcceptanceResult("invalid", child_error)

        previous_head = self.main_tip_hash
        self.blocks_by_hash[block_hash] = block
        self.block_states[block_hash] = child_state
        self.children_by_hash.setdefault(block_hash, [])
        if block.previous_hash != GENESIS_PREVIOUS_HASH:
            self.children_by_hash.setdefault(block.previous_hash, []).append(block_hash)

        if self._should_update_main_tip(block_hash):
            self.main_tip_hash = block_hash

        self._reconcile_pending_transactions(previous_head)
        return BlockAcceptanceResult("accepted")

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
                parent_state, _ = self._get_parent_state_for_block(block, states=temp_states)
                if parent_state is None:
                    return None
            else:
                if block.previous_hash not in self.blocks_by_hash:
                    return None
                parent_state = compute_state(block.previous_hash)
                if parent_state is None:
                    return None

            child_state, _ = self._build_child_state(block, parent_state)
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
    ) -> tuple[ChainState | None, str | None]:
        if len(block.transactions) > MAX_TRANSACTIONS_PER_BLOCK:
            return (
                None,
                f"block has {len(block.transactions)} transactions, "
                f"max is {MAX_TRANSACTIONS_PER_BLOCK}",
            )

        mining_reward_error = get_mining_reward_validation_error(block)
        if mining_reward_error is not None:
            return None, mining_reward_error

        block_verification_error = get_block_verification_error(
            block,
            self.get_difficulty_bits_for_height(block.block_id),
        )
        if block_verification_error is not None:
            return None, block_verification_error

        state = parent_state.copy()
        state.height = block.block_id

        for index, transaction in enumerate(block.transactions):
            transaction_error = self._apply_transaction_to_state_error(transaction, state)
            if transaction_error is not None:
                transaction_id = sha256_transaction_hash(transaction)[:12]
                return (
                    None,
                    f"transaction {index} ({transaction_id}) is invalid: "
                    f"{transaction_error}",
                )

        return state, None

    def _get_parent_state_for_block(
        self,
        block: Block,
        states: dict[str, ChainState] | None = None,
    ) -> tuple[ChainState | None, str | None]:
        block_states = self.block_states if states is None else states

        if block.previous_hash == GENESIS_PREVIOUS_HASH:
            if block.block_id != 0:
                return (
                    None,
                    f"genesis block must have block_id 0, got {block.block_id}",
                )
            if any(
                existing_block.previous_hash == GENESIS_PREVIOUS_HASH
                and existing_hash != block.block_hash
                for existing_hash, existing_block in self.blocks_by_hash.items()
            ):
                return None, "a different genesis block already exists"
            return ChainState(), None

        parent_state = block_states.get(block.previous_hash)
        if parent_state is None:
            return None, f"missing parent state for block {block.previous_hash[:12]}"

        if block.block_id != parent_state.height + 1:
            return (
                None,
                f"block_id {block.block_id} does not extend parent height "
                f"{parent_state.height}",
            )

        return parent_state, None

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
                if self._apply_transaction_to_state_error(transaction, test_state) is None:
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
            if self._apply_transaction_to_state_error(transaction, test_state) is None:
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

    def _apply_transaction_to_state_error(
        self,
        transaction: Transaction,
        state: ChainState,
    ) -> str | None:
        authenticity_error = self._validate_transaction_authenticity_error(transaction)
        if authenticity_error is not None:
            return authenticity_error

        if (
            not transaction.receiver
        ):
            return "transaction receiver is empty"
        if transaction.amount <= Decimal("0.0"):
            return f"transaction amount must be positive, got {transaction.amount}"
        if transaction.fee < Decimal("0.0"):
            return f"transaction fee must be non-negative, got {transaction.fee}"

        if is_mining_reward_transaction(transaction):
            state.balances[transaction.receiver] = (
                state.balances.get(transaction.receiver, Decimal("0.0")) + transaction.amount
            )
            return None

        if not transaction.sender:
            return "transaction sender is empty"

        expected_nonce = state.nonces.get(transaction.sender, 0)
        if transaction.nonce != expected_nonce:
            return (
                f"transaction nonce {transaction.nonce} does not match "
                f"expected nonce {expected_nonce}"
            )

        sender_balance = state.balances.get(transaction.sender, Decimal("0.0"))
        total_cost = transaction.amount + transaction.fee
        if sender_balance < total_cost:
            return (
                f"sender balance {sender_balance} is below total transaction "
                f"cost {total_cost}"
            )

        state.nonces[transaction.sender] = expected_nonce + 1
        state.balances[transaction.sender] = sender_balance - total_cost
        state.balances[transaction.receiver] = (
            state.balances.get(transaction.receiver, Decimal("0.0")) + transaction.amount
        )
        return None

    def _validate_transaction_authenticity_error(
        self,
        transaction: Transaction,
    ) -> str | None:
        if is_mining_reward_transaction(transaction):
            if transaction.sender_public_key is not None or transaction.signature is not None:
                return "mining reward transaction must not include signature data"
            return None

        if transaction.sender_public_key is None or transaction.signature is None:
            return "transaction is missing sender public key or signature"

        sender_address = Wallet.address_from_public_key(transaction.sender_public_key)
        if transaction.sender != sender_address:
            return "transaction sender does not match sender public key"

        signature_is_valid = Wallet.verify_signature_with_public_key(
            message=transaction.signing_payload(),
            signature=transaction.signature,
            public_key=transaction.sender_public_key,
        )
        if not signature_is_valid:
            return "transaction signature verification failed"
        return None
