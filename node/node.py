import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable

from config import DEFAULT_DIFFICULTY_BITS
from config import DEFAULT_DIFFICULTY_GROWTH_FACTOR
from config import DEFAULT_DIFFICULTY_GROWTH_BITS
from config import DEFAULT_DIFFICULTY_GROWTH_START_HEIGHT
from config import DEFAULT_GENESIS_DIFFICULTY_BITS
from core.block import Block, ProofOfWorkCancelled
from core.genesis import create_genesis_block
from core.blockchain import Blockchain
from core.hashing import sha256_block_hash
from core.native_pow import request_pow_cancel
from core.transaction import Transaction
from core.utils.constants import MINING_REWARD_SENDER
from node.alias_store import load_aliases, save_aliases
from network.p2p_server import P2PServer
from node.message_store import load_messages, save_messages
from node.storage import load_blockchain_state, save_blockchain_state
from wallet import Wallet


@dataclass
class Node:
    host: str
    port: int
    wallet: Wallet | None = None
    blockchain: Blockchain | None = None
    difficulty_bits: int = DEFAULT_DIFFICULTY_BITS
    genesis_difficulty_bits: int = DEFAULT_GENESIS_DIFFICULTY_BITS
    difficulty_growth_factor: int = DEFAULT_DIFFICULTY_GROWTH_FACTOR
    difficulty_growth_start_height: int = DEFAULT_DIFFICULTY_GROWTH_START_HEIGHT
    difficulty_growth_bits: int = DEFAULT_DIFFICULTY_GROWTH_BITS
    p2p_server: P2PServer = field(init=False)
    automine_task: asyncio.Task | None = field(default=None, init=False)
    automine_description: str = field(default="", init=False)
    _automine_stop_requested: bool = field(default=False, init=False)
    _current_automine_tip_hash: str | None = field(default=None, init=False)
    orphan_blocks_by_parent_hash: dict[str, list[Block]] = field(default_factory=dict, init=False)
    orphan_block_hashes: set[str] = field(default_factory=set, init=False)
    message_history: list[dict] = field(default_factory=list, init=False)
    message_ids: set[str] = field(default_factory=set, init=False)
    wallet_aliases: dict[str, str] = field(default_factory=dict, init=False)
    network_notifications_muted: bool = field(default=False, init=False)
    autosend_target: str | None = field(default=None, init=False)
    autosend_last_seen_balance: Decimal = field(default=Decimal("0.0"), init=False)
    autosend_task: asyncio.Task | None = field(default=None, init=False)

    REPO_ROOT = Path(__file__).resolve().parent.parent

    def __post_init__(self) -> None:
        if self.blockchain is None:
            self.blockchain = Blockchain(
                difficulty_bits=self.difficulty_bits,
                hash_function=sha256_block_hash,
                genesis_difficulty_bits=self.genesis_difficulty_bits,
                difficulty_growth_factor=self.difficulty_growth_factor,
                difficulty_growth_start_height=self.difficulty_growth_start_height,
                difficulty_growth_bits=self.difficulty_growth_bits,
            )
        self.p2p_server = P2PServer(
            host=self.host,
            port=self.port,
            on_transaction=self._handle_incoming_transaction,
            on_block=self._handle_incoming_block,
            on_wallet_message=self._handle_wallet_message,
            on_chain_summary=self._handle_chain_summary,
            on_chain_request=self._handle_chain_request,
            on_chain_response=self._handle_chain_response,
            on_notification=self._print_network_notification,
        )

    async def start(self) -> None:
        self._load_persisted_aliases()
        self._load_persisted_messages()
        self._load_persisted_blockchain()
        self._ensure_genesis_block()
        await self.p2p_server.start()
        if self.wallet is not None:
            wallet_name = self.wallet.name or "unnamed"
            print(f"Loaded wallet '{wallet_name}' with address {self.wallet.address}")
        self._reset_autosend_balance_baseline()

    async def serve_forever(self) -> None:
        await self.p2p_server.serve_forever()

    async def stop(self) -> None:
        await self.stop_automine(wait=True)
        self._save_persisted_blockchain()
        self._save_persisted_aliases()
        await self.p2p_server.stop()

    async def connect_to_peer(self, host: str, port: int) -> None:
        try:
            await self.p2p_server.connect_to_peer(host, port)
        except OSError as error:
            raise ValueError(f"Could not connect to peer {host}:{port}: {error.strerror or error}") from error

    async def broadcast(self, message: dict) -> None:
        await self.p2p_server.broadcast(message)

    async def broadcast_transaction(self, transaction: Transaction) -> None:
        await self.p2p_server.broadcast_transaction(transaction)

    async def broadcast_block(self, block: Block) -> None:
        await self.p2p_server.broadcast_block(block)

    async def broadcast_wallet_message(self, wallet_message: dict) -> None:
        await self.p2p_server.broadcast_wallet_message(wallet_message)

    async def discover_peers(self) -> None:
        await self.p2p_server.discover_peers()

    async def sync_chain(self) -> int:
        return await self.p2p_server.request_chain_sync()

    async def send_to_peer(self, host: str, port: int, message: dict) -> None:
        await self.p2p_server.send_to_peer(host, port, message)

    def list_peers(self) -> list[str]:
        return self.p2p_server.list_peers()

    def list_known_peers(self) -> list[str]:
        return self.p2p_server.list_known_peers()

    def get_next_nonce(self, address: str) -> int:
        if self.blockchain is None:
            return 0
        return self.blockchain.get_next_nonce(address)

    def create_signed_transaction(
        self,
        receiver: str,
        amount: str,
        fee: str,
    ) -> Transaction:
        if self.wallet is None:
            raise ValueError("A loaded wallet is required to create signed transactions.")

        try:
            parsed_amount = Decimal(str(amount))
            parsed_fee = Decimal(str(fee))
        except InvalidOperation as error:
            raise ValueError("Amount and fee must be valid decimal numbers.") from error

        transaction = Transaction(
            sender=self.wallet.address,
            receiver=receiver,
            amount=parsed_amount,
            fee=parsed_fee,
            timestamp=datetime.now(),
            nonce=self.get_next_nonce(self.wallet.address),
            sender_public_key=self.wallet.public_key,
        )
        transaction.signature = self.wallet.sign_message(transaction.signing_payload())
        return transaction

    def create_signed_wallet_message(self, receiver: str, content: str) -> dict:
        if self.wallet is None:
            raise ValueError("A loaded wallet is required to send messages.")

        timestamp = datetime.now().isoformat()
        message_id = str(uuid.uuid4())
        payload = (
            f"{self.wallet.address}|{receiver}|{content}|{timestamp}|{message_id}"
        )
        signature = self.wallet.sign_message(payload)
        return {
            "message_id": message_id,
            "sender": self.wallet.address,
            "receiver": receiver,
            "content": content,
            "timestamp": timestamp,
            "sender_public_key": {
                "exponent": str(self.wallet.public_key[0]),
                "modulus": str(self.wallet.public_key[1]),
            },
            "signature": signature,
        }

    def default_block_description(self, prefix: str) -> str:
        if self.wallet is None or not self.wallet.name:
            return prefix
        return f"{prefix} ({self.wallet.name})"

    def _next_mining_difficulty_bits(self) -> int:
        if self.blockchain is None:
            raise ValueError("A blockchain is required to mine.")
        return self.blockchain.get_next_block_difficulty_bits()

    async def mine_pending_transactions(self, description: str) -> Block:
        if self.wallet is None:
            raise ValueError("A loaded wallet is required to mine.")
        if self.blockchain is None:
            raise ValueError("A blockchain is required to mine.")

        block = self.blockchain.mine_pending_transactions(
            miner_address=self.wallet.address,
            description=description,
        )
        await self.broadcast_block(block)
        self._maybe_schedule_autosend()
        return block

    async def mine_pending_transactions_with_progress(self, description: str) -> Block:
        if self.wallet is None:
            raise ValueError("A loaded wallet is required to mine.")
        if self.blockchain is None:
            raise ValueError("A blockchain is required to mine.")

        print(f"Mining... (N={self._next_mining_difficulty_bits()})", flush=True)
        block = self.blockchain.mine_pending_transactions(
            miner_address=self.wallet.address,
            description=description,
            progress_callback=self._report_mining_progress,
        )
        self._clear_mining_progress()
        await self.broadcast_block(block)
        self._maybe_schedule_autosend()
        return block

    async def start_automine(self, description: str) -> None:
        if self.automine_task is not None and not self.automine_task.done():
            raise ValueError("Automine is already running.")
        if self.wallet is None:
            raise ValueError("A loaded wallet is required to mine.")
        if self.blockchain is None:
            raise ValueError("A blockchain is required to mine.")

        self.automine_description = description
        self._automine_stop_requested = False
        self.automine_task = asyncio.create_task(self._automine_loop())

    async def stop_automine(self, wait: bool = False) -> None:
        if self.automine_task is None or self.automine_task.done():
            self.automine_task = None
            return

        self._automine_stop_requested = True
        if wait:
            await self.automine_task

    async def _automine_loop(self) -> None:
        assert self.wallet is not None
        assert self.blockchain is not None

        try:
            while not self._automine_stop_requested:
                self._current_automine_tip_hash = self.blockchain.main_tip_hash
                print(
                    f"Automining... (N={self._next_mining_difficulty_bits()})",
                    flush=True,
                )
                block = await asyncio.to_thread(
                    self.blockchain.mine_pending_transactions,
                    self.wallet.address,
                    self.automine_description,
                    self._report_mining_progress,
                )
                self._clear_mining_progress()
                await self.broadcast_block(block)
                self._maybe_schedule_autosend()
                print(
                    f"\nAuto-mined block {block.block_hash[:12]} at height {block.block_id}",
                    flush=True,
                )
        except ProofOfWorkCancelled:
            self._clear_mining_progress()
            if not self._automine_stop_requested:
                print("\nRestarting automine on newer chain head.", flush=True)
                self.automine_task = asyncio.create_task(self._automine_loop())
                return
        except ValueError as error:
            self._clear_mining_progress()
            print(f"\nAutomine stopped: {error}", flush=True)
        finally:
            self._current_automine_tip_hash = None
            if self.automine_task is asyncio.current_task():
                self.automine_task = None
            self._automine_stop_requested = False

    @staticmethod
    def _report_mining_progress(nonce: int) -> None:
        print(f"\rTried {nonce:,} nonces...", end="", flush=True)

    @staticmethod
    def _clear_mining_progress() -> None:
        print("\r" + (" " * 40) + "\r", end="", flush=True)

    async def interactive_console(self) -> None:
        print("Interactive mode enabled.")
        print(
            'Enter JSON to broadcast, "send host:port {...}" for a direct message, '
            '"peers" to list connected peers, "known-peers" to list discovered peers, '
            '"discover" to ask peers for more peers, "sync" to request the latest chain from '
            'connected peers, "add-peer host:port" to connect manually, '
            '"alias wallet-id alias" to store a local wallet alias, '
            '"autosend wallet-id" to forward future balance increases, '
            '"autosend off" to disable autosend, '
            '"mute" or "unmute" to control incoming network notifications, '
            '"localself" to print this node\'s local address, '
            '"tx receiver amount fee" '
            '"msg wallet content" to send a wallet message, '
            '"messages" to print the local message history, '
            'to broadcast a transaction, "mine [description]" to mine pending transactions, '
            '"automine [description]" to mine continuously, "stop" to stop automining, '
            '"blockchain" to print the canonical chain, "balance [address]" to print a balance, '
            '"balances [>amount|<amount]" to print filtered balances, '
            '"txtbalances <relative-path>" to write balances to a text file, '
            '"clear" to clear the screen, or "quit" to exit.'
        )

        while True:
            try:
                raw_input_line = await asyncio.to_thread(input, "p2p> ")
            except EOFError:
                return

            line = raw_input_line.strip()
            if not line:
                continue

            if line == "quit":
                return

            if line == "clear":
                print("\033[2J\033[H", end="")
                continue

            if line == "peers":
                peers = self.list_peers()
                print("Connected peers:" if peers else "No connected peers.")
                for peer in peers:
                    print(peer)
                continue

            if line == "known-peers":
                peers = self.list_known_peers()
                print("Known peers:" if peers else "No known peers.")
                for peer in peers:
                    print(peer)
                continue

            if line == "discover":
                await self.discover_peers()
                print("Peer discovery request sent.")
                continue

            if line == "sync":
                peer_count = await self.sync_chain()
                print(f"Requested chain sync from {peer_count} peer(s).")
                continue

            if line == "mute":
                self.network_notifications_muted = True
                print("Incoming network notifications muted.")
                continue

            if line == "unmute":
                self.network_notifications_muted = False
                print("Incoming network notifications unmuted.")
                continue

            if line.startswith("autosend"):
                try:
                    autosend_target = line[len("autosend"):].strip()
                    if not autosend_target:
                        print(self.format_autosend_status())
                    elif autosend_target.lower() == "off":
                        self.disable_autosend()
                        print("Autosend disabled.")
                    else:
                        resolved_target = self.enable_autosend(autosend_target)
                        print(
                            "Autosend enabled to "
                            f"{self.format_wallet_reference(resolved_target)}."
                        )
                except ValueError as error:
                    print(f"Invalid autosend command: {error}")
                continue

            if line == "localself":
                print(self.self_peer_address())
                continue

            if line.startswith("alias "):
                try:
                    wallet_reference, alias = line[len("alias "):].split(" ", maxsplit=1)
                    wallet_address = self.set_wallet_alias(wallet_reference, alias.strip())
                    print(
                        f"Stored alias {self.alias_for_wallet(wallet_address)} "
                        f"for {wallet_address}"
                    )
                except ValueError as error:
                    print(f"Invalid alias command: {error}")
                continue

            if line.startswith("add-peer "):
                try:
                    host, port = line[len("add-peer "):].split(":", maxsplit=1)
                    await self.connect_to_peer(host, int(port))
                    print(f"Connected to peer {host}:{port}")
                except ValueError as error:
                    print(f"Invalid add-peer command: {error}")
                continue

            if line == "stop":
                if self.automine_task is None or self.automine_task.done():
                    print("Automine is not running.")
                    continue
                print("Stopping automine after the current block...")
                await self.stop_automine(wait=True)
                print("Automine stopped.")
                continue

            if line == "blockchain":
                print(self.format_canonical_blockchain())
                continue

            if line == "messages":
                print(self.format_message_history())
                continue

            if line.startswith("balances"):
                try:
                    print(self.format_all_balances(line[len("balances"):].strip()))
                except ValueError as error:
                    print(f"Invalid balances command: {error}")
                continue

            if line.startswith("txtbalances"):
                try:
                    path = self.write_all_balances_to_file(
                        line[len("txtbalances"):].strip()
                    )
                    print(f"Balances written to {path}")
                except ValueError as error:
                    print(f"Invalid txtbalances command: {error}")
                continue

            if line.startswith("balance"):
                address = self.resolve_wallet_reference(
                    line[len("balance"):].strip()
                ) or (
                    self.wallet.address if self.wallet is not None else ""
                )
                if not address:
                    print("Balance command requires an address when no wallet is loaded.")
                    continue
                print(
                    f"Balance for {self.format_wallet_reference(address)}: "
                    f"{self.get_balance(address)}"
                )
                continue

            if line.startswith("tx "):
                try:
                    receiver, amount, fee = line[len("tx "):].split(" ", maxsplit=2)
                    transaction = self.create_signed_transaction(
                        receiver=self.resolve_wallet_reference(receiver),
                        amount=amount,
                        fee=fee,
                    )
                    await self.broadcast_transaction(transaction)
                except ValueError as error:
                    print(f"Invalid tx command: {error}")
                continue

            if line.startswith("msg "):
                try:
                    receiver, content = line[len("msg "):].split(" ", maxsplit=1)
                    wallet_message = self.create_signed_wallet_message(
                        self.resolve_wallet_reference(receiver),
                        content,
                    )
                    await self.broadcast_wallet_message(wallet_message)
                except ValueError as error:
                    print(f"Invalid msg command: {error}")
                continue

            if line.startswith("mine"):
                description = (
                    line[len("mine"):].strip()
                    or self.default_block_description("Mined block")
                )
                try:
                    block = await self.mine_pending_transactions_with_progress(description)
                    print(f"Mined and broadcast block {block.block_hash[:12]} at height {block.block_id}")
                except ValueError as error:
                    print(f"Mining failed: {error}")
                continue

            if line.startswith("automine"):
                description = (
                    line[len("automine"):].strip()
                    or self.default_block_description("Auto-mined block")
                )
                try:
                    await self.start_automine(description)
                    print("Automine started.")
                except ValueError as error:
                    print(f"Automine failed: {error}")
                continue

            if line.startswith("send "):
                try:
                    peer_part, message_part = line[len("send "):].split(" ", maxsplit=1)
                    host, port = peer_part.split(":", maxsplit=1)
                    message = json.loads(message_part)
                    await self.send_to_peer(host, int(port), message)
                    print(f"Sent direct message to {host}:{port}")
                except (ValueError, json.JSONDecodeError) as error:
                    print(f"Invalid send command: {error}")
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError as error:
                print(f"Invalid JSON: {error}")
                continue

            await self.broadcast(message)
            print("Broadcast message sent.")

    def _handle_incoming_transaction(self, transaction: Transaction) -> tuple[bool, str | None]:
        if self.blockchain is None:
            return False, "no blockchain is loaded"

        try:
            self.blockchain.add_transaction(transaction)
        except ValueError as error:
            return False, str(error)

        return True, None

    def _handle_incoming_block(self, block: Block) -> tuple[str, str | None]:
        if self.blockchain is None:
            return "rejected", "no blockchain is loaded"

        return self._accept_or_store_block(block)

    def _handle_chain_request(self) -> list[Block]:
        if self.blockchain is None:
            return []
        return self.blockchain.blocks

    def _handle_chain_summary(self) -> tuple[str | None, int]:
        if self.blockchain is None or self.blockchain.main_tip_hash is None:
            return None, -1
        return self.blockchain.main_tip_hash, self.blockchain.blocks[-1].block_id

    def _handle_chain_response(self, blocks: list[Block]) -> dict[str, int]:
        if self.blockchain is None:
            return {
                "accepted": 0,
                "duplicates": 0,
                "orphans": 0,
                "rejected": 0,
            }

        accepted_blocks = 0
        duplicate_blocks = 0
        orphaned_blocks = 0
        rejected_blocks = 0
        for block in blocks:
            if block.block_hash in self.blockchain.blocks_by_hash:
                duplicate_blocks += 1
                continue
            status, reason = self._accept_or_store_block(block)
            if status == "accepted":
                accepted_blocks += 1
            elif status == "orphaned":
                orphaned_blocks += 1
                self._print_network_notification(
                    f"Deferred synced block {block.block_hash[:12]}: "
                    f"{reason or 'waiting for parent'}"
                )
            elif status == "duplicate":
                duplicate_blocks += 1
            else:
                rejected_blocks += 1
                self._print_network_notification(
                    f"Rejected synced block {block.block_hash[:12]}: "
                    f"{reason or 'unknown reason'}"
                )

        self._print_network_notification(
            "Chain sync chunk processed: "
            f"accepted {accepted_blocks}, duplicates {duplicate_blocks}, "
            f"orphans {orphaned_blocks}, rejected {rejected_blocks}."
        )
        self._maybe_schedule_autosend()
        return {
            "accepted": accepted_blocks,
            "duplicates": duplicate_blocks,
            "orphans": orphaned_blocks,
            "rejected": rejected_blocks,
        }

    def _handle_wallet_message(self, wallet_message: dict) -> bool:
        sender_public_key_data = wallet_message.get("sender_public_key")
        signature = wallet_message.get("signature")
        sender = wallet_message.get("sender", "")
        receiver = wallet_message.get("receiver", "")
        content = wallet_message.get("content", "")
        timestamp = wallet_message.get("timestamp", "")
        message_id = wallet_message.get("message_id", "")

        if (
            not sender_public_key_data
            or signature is None
            or not sender
            or not receiver
            or not content
            or not timestamp
            or not message_id
        ):
            return False

        sender_public_key = (
            int(sender_public_key_data["exponent"]),
            int(sender_public_key_data["modulus"]),
        )
        if sender != Wallet.address_from_public_key(sender_public_key):
            return False

        payload = f"{sender}|{receiver}|{content}|{timestamp}|{message_id}"
        if not Wallet.verify_signature_with_public_key(
            message=payload,
            signature=signature,
            public_key=sender_public_key,
        ):
            return False

        if self.wallet is not None and sender == self.wallet.address:
            self._store_wallet_message(
                {
                    "direction": "sent",
                    "message_id": message_id,
                    "sender": sender,
                    "receiver": receiver,
                    "content": content,
                    "timestamp": timestamp,
                }
            )
        elif self.wallet is not None and receiver == self.wallet.address:
            self._store_wallet_message(
                {
                    "direction": "received",
                    "message_id": message_id,
                    "sender": sender,
                    "receiver": receiver,
                    "content": content,
                    "timestamp": timestamp,
                }
            )
            self._print_network_notification(
                f"\nMessage from {self.format_wallet_reference(sender)}: {content}",
                force=True,
            )

        return True

    def _ensure_genesis_block(self) -> None:
        if self.blockchain is None or self.blockchain.blocks_by_hash:
            return

        genesis_block = create_genesis_block(sha256_block_hash)
        self.blockchain.add_block(genesis_block)

    def _load_persisted_blockchain(self) -> None:
        if self.wallet is None:
            return

        try:
            persisted_blockchain = load_blockchain_state(
                self.wallet.address,
                hash_function=sha256_block_hash,
            )
        except ValueError as error:
            print(
                f"Ignoring persisted blockchain for {self.wallet.address}: {error}",
                flush=True,
            )
            return
        if persisted_blockchain is None:
            return

        self.blockchain = persisted_blockchain
        print(
            f"Loaded persisted blockchain for {self.wallet.address} "
            f"({len(self.blockchain.blocks)} blocks)",
            flush=True,
        )

    def _save_persisted_blockchain(self) -> None:
        if self.wallet is None or self.blockchain is None:
            return

        path = save_blockchain_state(self.wallet.address, self.blockchain)
        print(f"Saved blockchain state to {path}", flush=True)

    def format_canonical_blockchain(self) -> str:
        if self.blockchain is None or not self.blockchain.blocks:
            return "Canonical blockchain is empty."

        lines = ["Canonical blockchain:"]
        for block in self.blockchain.blocks:
            lines.append(
                f"#{block.block_id} {block.block_hash[:12]} "
                f"prev={block.previous_hash[:12]} txs={len(block.transactions)} "
                f'"{block.description}"'
            )
        return "\n".join(lines)

    def get_balance(self, address: str) -> str:
        if self.blockchain is None:
            return "0.0"
        return str(self.blockchain.get_balance(address))

    def format_all_balances(self, filter_expression: str = "") -> str:
        if self.blockchain is None or not self.blockchain.blocks:
            return "No balances available."

        addresses: set[str] = set()
        for block in self.blockchain.blocks:
            for transaction in block.transactions:
                if (
                    transaction.sender
                    and transaction.sender != MINING_REWARD_SENDER
                ):
                    addresses.add(transaction.sender)
                if transaction.receiver:
                    addresses.add(transaction.receiver)

        if not addresses:
            return "No wallet balances found."

        comparison = self._parse_balance_filter(filter_expression)
        lines = ["Balances:"]
        for address in sorted(addresses, key=self._wallet_balance_sort_key):
            balance = self.blockchain.get_balance(address)
            if comparison is not None and not comparison(balance):
                continue
            lines.append(f"{self.format_wallet_reference(address)}: {balance}")
        if len(lines) == 1:
            return "No wallet balances matched the filter."
        return "\n".join(lines)

    def write_all_balances_to_file(self, relative_path: str) -> Path:
        if not relative_path:
            raise ValueError("Use txtbalances <relative-path>.")

        output_path = Path(relative_path)
        if output_path.is_absolute():
            raise ValueError("txtbalances requires a relative path.")

        resolved_path = (self.REPO_ROOT / output_path).resolve()
        if not resolved_path.is_relative_to(self.REPO_ROOT.resolve()):
            raise ValueError("txtbalances path must stay within the project root.")

        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(
            f"{self.format_all_balances()}\n",
            encoding="utf-8",
        )
        return resolved_path.relative_to(self.REPO_ROOT)

    def self_peer_address(self) -> str:
        return f"{self.host}:{self.port}"

    def format_message_history(self) -> str:
        if not self.message_history:
            return "No stored messages."

        lines = ["Message history:"]
        for message in self.message_history:
            peer = (
                message["receiver"]
                if message["direction"] == "sent"
                else message["sender"]
            )
            lines.append(
                f"[{message['timestamp']}] {message['direction']} "
                f"{self.format_wallet_reference(peer)}: {message['content']}"
            )
        return "\n".join(lines)

    def format_autosend_status(self) -> str:
        if self.autosend_target is None:
            return "Autosend is disabled."
        return (
            "Autosend is enabled to "
            f"{self.format_wallet_reference(self.autosend_target)}."
        )

    def resolve_wallet_reference(self, wallet_reference: str) -> str:
        stripped_reference = wallet_reference.strip()
        if not stripped_reference:
            return ""
        return self.wallet_aliases.get(stripped_reference, stripped_reference)

    def alias_for_wallet(self, wallet_address: str) -> str | None:
        for alias, address in self.wallet_aliases.items():
            if address == wallet_address:
                return alias
        return None

    def format_wallet_reference(self, wallet_address: str) -> str:
        alias = self.alias_for_wallet(wallet_address)
        if alias is None:
            return wallet_address
        return f"{alias} ({wallet_address[:10]})"

    def set_wallet_alias(self, wallet_reference: str, alias: str) -> str:
        cleaned_alias = alias.strip()
        if not cleaned_alias:
            raise ValueError("Alias must not be empty.")

        wallet_address = self.resolve_wallet_reference(wallet_reference)
        if not wallet_address:
            raise ValueError("Wallet id must not be empty.")

        aliases_to_remove = [
            existing_alias
            for existing_alias, existing_address in self.wallet_aliases.items()
            if existing_alias == cleaned_alias or existing_address == wallet_address
        ]
        for existing_alias in aliases_to_remove:
            self.wallet_aliases.pop(existing_alias, None)

        self.wallet_aliases[cleaned_alias] = wallet_address
        self._save_persisted_aliases()
        return wallet_address

    def enable_autosend(self, wallet_reference: str) -> str:
        if self.wallet is None or self.blockchain is None:
            raise ValueError("A loaded wallet is required to enable autosend.")

        wallet_address = self.resolve_wallet_reference(wallet_reference)
        if not wallet_address:
            raise ValueError("Autosend target must not be empty.")
        if wallet_address == self.wallet.address:
            raise ValueError("Autosend target must be different from the loaded wallet.")

        self.autosend_target = wallet_address
        self._reset_autosend_balance_baseline()
        return wallet_address

    def disable_autosend(self) -> None:
        self.autosend_target = None
        self._reset_autosend_balance_baseline()

    def _wallet_sort_key(self, wallet_address: str) -> tuple[str, str]:
        alias = self.alias_for_wallet(wallet_address)
        return (
            alias.lower() if alias is not None else wallet_address.lower(),
            wallet_address,
        )

    def _wallet_balance_sort_key(self, wallet_address: str) -> tuple[Decimal, str, str]:
        assert self.blockchain is not None
        return (
            self.blockchain.get_balance(wallet_address),
            *self._wallet_sort_key(wallet_address),
        )

    def _parse_balance_filter(
        self,
        filter_expression: str,
    ) -> Callable[[Decimal], bool] | None:
        if not filter_expression:
            return None

        if filter_expression[0] not in {">", "<"}:
            raise ValueError("Use balances, balances >amount, or balances <amount.")

        threshold_text = filter_expression[1:].strip()
        if not threshold_text:
            raise ValueError("Balance filter requires an amount.")

        try:
            threshold = Decimal(threshold_text)
        except InvalidOperation as error:
            raise ValueError("Balance filter amount must be a valid decimal.") from error

        if filter_expression[0] == ">":
            return lambda balance: balance > threshold
        return lambda balance: balance < threshold

    def _accept_or_store_block(self, block: Block) -> tuple[str, str | None]:
        assert self.blockchain is not None

        result = self.blockchain.add_block_result(block)
        status = result.status
        if status == "accepted":
            self.orphan_block_hashes.discard(block.block_hash)
            self._cancel_stale_automine_if_needed()
            self._resolve_orphan_descendants(block.block_hash)
            self._maybe_schedule_autosend()
            return "accepted", None

        if status == "duplicate":
            self.orphan_block_hashes.discard(block.block_hash)
            return "duplicate", result.reason

        if status == "missing_parent":
            self._store_orphan_block(block)
            return "orphaned", result.reason

        self.orphan_block_hashes.discard(block.block_hash)
        return "rejected", result.reason

    def _store_orphan_block(self, block: Block) -> None:
        if block.block_hash in self.orphan_block_hashes:
            return

        self.orphan_block_hashes.add(block.block_hash)
        self.orphan_blocks_by_parent_hash.setdefault(block.previous_hash, []).append(block)

    def _resolve_orphan_descendants(self, parent_hash: str) -> None:
        pending_parent_hashes = [parent_hash]

        while pending_parent_hashes:
            current_parent_hash = pending_parent_hashes.pop()
            orphan_blocks = self.orphan_blocks_by_parent_hash.pop(current_parent_hash, [])

            for orphan_block in orphan_blocks:
                result = self.blockchain.add_block_result(orphan_block)
                status = result.status
                if status == "accepted":
                    self.orphan_block_hashes.discard(orphan_block.block_hash)
                    self._cancel_stale_automine_if_needed()
                    self._print_network_notification(
                        f"Accepted orphan block {orphan_block.block_hash[:12]} "
                        f"at height {orphan_block.block_id}"
                    )
                    pending_parent_hashes.append(orphan_block.block_hash)
                elif status == "missing_parent":
                    self._store_orphan_block(orphan_block)
                elif status == "duplicate":
                    self.orphan_block_hashes.discard(orphan_block.block_hash)
                else:
                    self.orphan_block_hashes.discard(orphan_block.block_hash)
                    self._print_network_notification(
                        f"Rejected orphan block {orphan_block.block_hash[:12]}: "
                        f"{result.reason or 'unknown reason'}"
                    )

    def _cancel_stale_automine_if_needed(self) -> None:
        if (
            self.automine_task is None
            or self.automine_task.done()
            or self._current_automine_tip_hash is None
            or self.blockchain is None
            or self.blockchain.main_tip_hash == self._current_automine_tip_hash
        ):
            return

        request_pow_cancel()

    def _load_persisted_messages(self) -> None:
        if self.wallet is None:
            return

        self.message_history = load_messages(self.wallet.address)
        self.message_ids = {
            message["message_id"]
            for message in self.message_history
        }

    def _store_wallet_message(self, message_entry: dict) -> None:
        if self.wallet is None:
            return

        message_id = message_entry["message_id"]
        if message_id in self.message_ids:
            return

        self.message_history.append(message_entry)
        self.message_ids.add(message_id)
        save_messages(self.wallet.address, self.message_history)

    def _load_persisted_aliases(self) -> None:
        owner_key = self._alias_owner_key()
        if owner_key is None:
            return

        self.wallet_aliases = load_aliases(owner_key)

    def _save_persisted_aliases(self) -> None:
        owner_key = self._alias_owner_key()
        if owner_key is None:
            return

        save_aliases(owner_key, self.wallet_aliases)

    def _alias_owner_key(self) -> str | None:
        if self.wallet is None:
            return None
        return self.wallet.address

    def _print_network_notification(self, message: str, force: bool = False) -> None:
        if self.network_notifications_muted and not force:
            return
        print(message, flush=True)

    def _maybe_schedule_autosend(self) -> None:
        if (
            self.autosend_target is None
            or self.wallet is None
            or self.blockchain is None
        ):
            self._reset_autosend_balance_baseline()
            return

        current_balance = self.blockchain.get_available_balance(self.wallet.address)
        if current_balance < self.autosend_last_seen_balance:
            self.autosend_last_seen_balance = current_balance

        if current_balance <= self.autosend_last_seen_balance or current_balance <= Decimal("0.0"):
            return

        if self.autosend_task is not None and not self.autosend_task.done():
            return

        self.autosend_task = asyncio.create_task(self._autosend_available_balance())

    async def _autosend_available_balance(self) -> None:
        try:
            if (
                self.autosend_target is None
                or self.wallet is None
                or self.blockchain is None
            ):
                return

            balance = self.blockchain.get_available_balance(self.wallet.address)
            if balance <= Decimal("0.0"):
                return

            transaction = self.create_signed_transaction(
                receiver=self.autosend_target,
                amount=str(balance),
                fee="0",
            )
            await self.broadcast_transaction(transaction)
            print(
                "Autosend queued "
                f"{balance} to {self.format_wallet_reference(self.autosend_target)}."
            )
        except ValueError as error:
            print(f"Autosend failed: {error}")
        finally:
            self._reset_autosend_balance_baseline()
            self.autosend_task = None

    def _reset_autosend_balance_baseline(self) -> None:
        if self.wallet is None or self.blockchain is None:
            self.autosend_last_seen_balance = Decimal("0.0")
            return
        self.autosend_last_seen_balance = self.blockchain.get_available_balance(
            self.wallet.address
        )
