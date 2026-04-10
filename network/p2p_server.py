import asyncio
import json
import hashlib
from dataclasses import dataclass, field
from typing import Callable

from core.block import Block
from core.hashing import sha256_block_hash
from core.hashing import sha256_transaction_hash
from core.transaction import Transaction

CHAIN_SYNC_CHUNK_SIZE = 3


@dataclass(frozen=True)
class PeerAddress:
    host: str
    port: int


@dataclass
class P2PServer:
    host: str
    port: int
    on_transaction: Callable[[Transaction], tuple[bool, str | None]] | None = None
    on_block: Callable[[Block], tuple[str, str | None]] | None = None
    on_wallet_message: Callable[[dict], bool] | None = None
    on_chain_summary: Callable[[], tuple[str | None, int]] | None = None
    on_chain_request: Callable[[], list[Block]] | None = None
    on_chain_response: Callable[[list[Block]], dict[str, int] | None] | None = None
    on_notification: Callable[[str], None] | None = None
    peers: set[PeerAddress] = field(default_factory=set)
    seen_transaction_ids: set[str] = field(default_factory=set)
    seen_block_hashes: set[str] = field(default_factory=set)
    seen_wallet_message_ids: set[str] = field(default_factory=set)
    server: asyncio.base_events.Server | None = field(default=None, init=False)
    active_connections: dict[PeerAddress, asyncio.StreamWriter] = field(
        default_factory=dict,
        init=False,
    )

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        self._notify(f"P2P server listening on {self.host}:{self.port}")

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()

        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    async def stop(self) -> None:
        if self.server is None:
            return

        self.server.close()
        await self.server.wait_closed()
        self.server = None

        for writer in list(self.active_connections.values()):
            writer.close()
            await writer.wait_closed()

        self.active_connections.clear()

    async def connect_to_peer(self, host: str, port: int) -> None:
        peer = PeerAddress(host=host, port=port)
        if self._is_self_peer(peer) or peer in self.active_connections:
            return

        reader, writer = await asyncio.open_connection(host, port)
        self.peers.add(peer)
        self.active_connections[peer] = writer

        await self._send_message(writer, self._create_handshake_message())
        asyncio.create_task(self._read_messages(reader, writer, peer))
        self._notify(f"Connected to peer {host}:{port}")

    async def broadcast(self, message: dict) -> None:
        await self._broadcast_to_peers(message)

    async def broadcast_transaction(self, transaction: Transaction) -> None:
        transaction_id = sha256_transaction_hash(transaction)
        if transaction_id in self.seen_transaction_ids:
            print(f"Transaction {transaction_id[:12]} already seen. Skipping broadcast.")
            return

        if self.on_transaction is not None:
            accepted, reason = self.on_transaction(transaction)
            if not accepted:
                print(
                    f"Rejected local transaction {transaction_id[:12]}: "
                    f"{reason or 'unknown reason'}"
                )
                return

        self.seen_transaction_ids.add(transaction_id)

        await self._broadcast_to_peers(
            {
                "type": "transaction",
                "tx_id": transaction_id,
                "transaction": transaction.to_dict(),
            }
        )
        print(
            "Broadcast transaction "
            f"{transaction_id[:12]} from {transaction.sender} to {transaction.receiver}"
        )

    async def broadcast_block(self, block: Block) -> None:
        block_hash = block.block_hash
        if block_hash in self.seen_block_hashes:
            print(f"Block {block_hash[:12]} already seen. Skipping broadcast.")
            return

        self.seen_block_hashes.add(block_hash)
        await self._broadcast_to_peers(
            {
                "type": "block",
                "block_hash": block_hash,
                "block": block.to_dict(),
            }
        )
        print(f"Broadcast block {block_hash[:12]} at height {block.block_id}")

    async def broadcast_wallet_message(self, wallet_message: dict) -> None:
        message_id = wallet_message["message_id"]
        if message_id in self.seen_wallet_message_ids:
            print(f"Message {message_id[:12]} already seen. Skipping broadcast.")
            return

        if self.on_wallet_message is not None and not self.on_wallet_message(wallet_message):
            print(f"Rejected local message {message_id[:12]}.")
            return

        self.seen_wallet_message_ids.add(message_id)
        await self._broadcast_to_peers(
            {
                "type": "wallet_message",
                "message_id": message_id,
                "message": wallet_message,
            }
        )
        print(
            "Broadcast message "
            f"{message_id[:12]} from {wallet_message['sender']} "
            f"to {wallet_message['receiver']}"
        )

    async def _broadcast_to_peers(
        self,
        message: dict,
        exclude_peer: PeerAddress | None = None,
    ) -> None:
        disconnected_peers: list[PeerAddress] = []

        for peer, writer in list(self.active_connections.items()):
            if exclude_peer is not None and peer == exclude_peer:
                continue
            try:
                await self._send_message(writer, message)
            except ConnectionError:
                disconnected_peers.append(peer)

        for peer in disconnected_peers:
            writer = self.active_connections.pop(peer)
            writer.close()
            await writer.wait_closed()

    async def request_peer_list(self, host: str, port: int) -> None:
        await self.send_to_peer(host, port, {"type": "peer_request"})

    async def request_chain(
        self,
        host: str,
        port: int,
        start_height: int = 0,
    ) -> None:
        await self.send_to_peer(
            host,
            port,
            {
                "type": "chain_request",
                "start_height": max(start_height, 0),
            },
        )

    async def discover_peers(self) -> None:
        for peer in list(self.active_connections):
            await self.request_peer_list(peer.host, peer.port)

    async def request_chain_sync(self) -> int:
        peers = list(self.active_connections)
        _, local_height = self._get_chain_summary()
        start_height = max(local_height + 1, 0)
        for peer in peers:
            await self.request_chain(peer.host, peer.port, start_height=start_height)
        return len(peers)

    async def send_to_peer(self, host: str, port: int, message: dict) -> None:
        peer = PeerAddress(host=host, port=port)
        writer = self.active_connections.get(peer)
        if writer is None:
            raise ValueError(f"Peer {host}:{port} is not connected.")

        await self._send_message(writer, message)

    def list_peers(self) -> list[str]:
        return sorted(f"{peer.host}:{peer.port}" for peer in self.active_connections)

    def list_known_peers(self) -> list[str]:
        return sorted(f"{peer.host}:{peer.port}" for peer in self.peers)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = PeerAddress(host=peer_info[0], port=peer_info[1])
        self.peers.add(peer)
        self.active_connections[peer] = writer
        self._notify(f"Accepted peer connection from {peer.host}:{peer.port}")
        await self._send_message(writer, self._create_handshake_message())

        await self._read_messages(reader, writer, peer)

    async def _read_messages(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: PeerAddress,
    ) -> None:
        try:
            while True:
                raw_message = await reader.readline()
                if not raw_message:
                    break

                message = json.loads(raw_message.decode("utf-8"))
                peer = await self._handle_message(message, peer)
        finally:
            self.active_connections.pop(peer, None)
            writer.close()
            await writer.wait_closed()
            self._notify(f"Disconnected from peer {peer.host}:{peer.port}")

    async def _handle_message(self, message: dict, peer: PeerAddress) -> PeerAddress:
        message_type = message.get("type", "unknown")

        if message_type == "handshake":
            advertised_host = message.get("host", peer.host)
            advertised_port = message.get("port", peer.port)
            advertised_peer = PeerAddress(advertised_host, advertised_port)
            remote_tip_hash = message.get("tip_hash")
            remote_height = int(message.get("height", -1))
            self.peers.discard(peer)
            self.peers.add(advertised_peer)
            writer = self.active_connections.pop(peer, None)
            if writer is not None:
                self.active_connections[advertised_peer] = writer
            self._notify(
                f"Handshake received from {advertised_host}:{advertised_port} "
                f"(height {remote_height}, tip {self._short_hash(remote_tip_hash)})"
            )
            if self._should_request_chain(remote_tip_hash, remote_height):
                local_tip_hash, local_height = self._get_chain_summary()
                start_height = 0
                if remote_height > local_height:
                    start_height = local_height + 1
                elif remote_tip_hash == local_tip_hash:
                    start_height = local_height + 1
                await self.request_chain(
                    advertised_host,
                    advertised_port,
                    start_height=max(start_height, 0),
                )
                self._notify(
                    f"Requesting chain sync from {advertised_host}:{advertised_port} "
                    f"after handshake starting at height {max(start_height, 0)}"
                )
            return advertised_peer

        if message_type == "peer_request":
            await self._send_peer_list(peer)
            self._notify(f"Peer list requested by {peer.host}:{peer.port}")
            return peer

        if message_type == "peer_list":
            for discovered_peer in self._parse_peer_list(message.get("peers", [])):
                if self._is_self_peer(discovered_peer):
                    continue

                self.peers.add(discovered_peer)
                if discovered_peer not in self.active_connections:
                    try:
                        await self.connect_to_peer(discovered_peer.host, discovered_peer.port)
                    except OSError:
                        self._notify(
                            "Failed to connect to discovered peer "
                            f"{discovered_peer.host}:{discovered_peer.port}"
                        )
            self._notify(f"Peer list received from {peer.host}:{peer.port}")
            return peer

        if message_type == "chain_request":
            start_height = max(int(message.get("start_height", 0)), 0)
            await self._send_chain_chunk(peer, start_height)
            self._notify(
                f"Chain chunk requested by {peer.host}:{peer.port} "
                f"from height {start_height}"
            )
            return peer

        if message_type in {"chain_chunk", "chain_response"}:
            blocks = [
                Block.from_dict(block_data, hash_function=sha256_block_hash)
                for block_data in message.get("blocks", [])
            ]
            start_height = max(int(message.get("start_height", 0)), 0)
            remote_height = int(message.get("height", -1))
            done = bool(message.get("done", message_type == "chain_response"))
            raw_next_start_height = message.get("next_start_height")
            next_start_height = (
                start_height + len(blocks)
                if raw_next_start_height is None
                else int(raw_next_start_height)
            )
            sync_result = (
                self.on_chain_response(blocks)
                if self.on_chain_response is not None
                else None
            )
            self._notify(
                f"Chain chunk received from {peer.host}:{peer.port} "
                f"({len(blocks)} blocks starting at height {start_height})"
            )

            _, local_height = self._get_chain_summary()
            accepted_blocks = 0 if sync_result is None else sync_result.get("accepted", 0)
            orphaned_blocks = 0 if sync_result is None else sync_result.get("orphans", 0)
            rejected_blocks = 0 if sync_result is None else sync_result.get("rejected", 0)

            if (
                start_height > 0
                and accepted_blocks == 0
                and orphaned_blocks > 0
            ):
                await self.request_chain(peer.host, peer.port, start_height=0)
                self._notify(
                    f"Chain chunk from {peer.host}:{peer.port} did not attach. "
                    "Retrying sync from genesis."
                )
                return peer

            if remote_height > local_height and not done:
                if accepted_blocks == 0 and rejected_blocks > 0 and orphaned_blocks == 0:
                    self._notify(
                        f"Chain sync from {peer.host}:{peer.port} made no progress at "
                        f"height {start_height}. Stopping automatic sync."
                    )
                    return peer

                await self.request_chain(
                    peer.host,
                    peer.port,
                    start_height=max(next_start_height, 0),
                )
                self._notify(
                    f"Requesting next chain chunk from {peer.host}:{peer.port} "
                    f"starting at height {max(next_start_height, 0)}"
                )
            return peer

        if message_type == "transaction":
            transaction = Transaction.from_dict(message["transaction"])
            transaction_id = message.get("tx_id", sha256_transaction_hash(transaction))

            if transaction_id in self.seen_transaction_ids:
                self._notify(f"Ignoring duplicate transaction {transaction_id[:12]}")
                return peer

            if self.on_transaction is not None:
                accepted, reason = self.on_transaction(transaction)
                if not accepted:
                    self._notify(
                        f"Rejected transaction {transaction_id[:12]} "
                        f"from {peer.host}:{peer.port}: {reason or 'unknown reason'}"
                    )
                    return peer

            self.seen_transaction_ids.add(transaction_id)

            self._notify(
                "Received transaction "
                f"{transaction_id[:12]} from {peer.host}:{peer.port}: "
                f"{transaction.sender} -> {transaction.receiver} "
                f"({transaction.amount}, fee {transaction.fee})"
            )
            await self._broadcast_to_peers(message, exclude_peer=peer)
            return peer

        if message_type == "block":
            block = Block.from_dict(message["block"], hash_function=sha256_block_hash)
            block_hash = message.get("block_hash", block.block_hash)

            if block_hash in self.seen_block_hashes:
                self._notify(f"Ignoring duplicate block {block_hash[:12]}")
                return peer

            block_status, reason = (
                self.on_block(block)
                if self.on_block is not None
                else ("rejected", "no block handler is configured")
            )
            if block_status == "accepted":
                self.seen_block_hashes.add(block_hash)
                self._notify(
                    f"Received block {block_hash[:12]} from {peer.host}:{peer.port} "
                    f"at height {block.block_id}"
                )
                await self._broadcast_to_peers(message, exclude_peer=peer)
                return peer

            if block_status == "orphaned":
                self.seen_block_hashes.add(block_hash)
                self._notify(
                    f"Stored orphan block {block_hash[:12]} from {peer.host}:{peer.port} "
                    f"at height {block.block_id}: {reason or 'waiting for parent'}"
                )
                return peer

            if block_status == "duplicate":
                self.seen_block_hashes.add(block_hash)
                self._notify(
                    f"Ignoring duplicate block {block_hash[:12]}: "
                    f"{reason or 'already known'}"
                )
                return peer

            self._notify(
                f"Rejected block {block_hash[:12]} from {peer.host}:{peer.port}: "
                f"{reason or 'unknown reason'}"
            )
            return peer

        if message_type == "wallet_message":
            wallet_message = message["message"]
            message_id = message.get("message_id", _wallet_message_id(wallet_message))

            if message_id in self.seen_wallet_message_ids:
                self._notify(f"Ignoring duplicate message {message_id[:12]}")
                return peer

            if self.on_wallet_message is not None and not self.on_wallet_message(wallet_message):
                self._notify(f"Rejected message {message_id[:12]} from {peer.host}:{peer.port}")
                return peer

            self.seen_wallet_message_ids.add(message_id)
            await self._broadcast_to_peers(message, exclude_peer=peer)
            return peer

        self._notify(f"Received {message_type} from {peer.host}:{peer.port}: {message}")
        return peer

    async def _send_peer_list(self, peer: PeerAddress) -> None:
        await self.send_to_peer(
            peer.host,
            peer.port,
            {
                "type": "peer_list",
                "peers": [
                    {"host": known_peer.host, "port": known_peer.port}
                    for known_peer in self.peers
                    if not self._is_self_peer(known_peer)
                ],
            },
        )

    async def _send_chain_chunk(self, peer: PeerAddress, start_height: int) -> None:
        blocks = self.on_chain_request() if self.on_chain_request is not None else []
        chain_height = blocks[-1].block_id if blocks else -1
        chunk_blocks = blocks[start_height:start_height + CHAIN_SYNC_CHUNK_SIZE]
        next_start_height = start_height + len(chunk_blocks)
        done = next_start_height > chain_height
        await self.send_to_peer(
            peer.host,
            peer.port,
            {
                "type": "chain_chunk",
                "start_height": start_height,
                "height": chain_height,
                "done": done,
                "next_start_height": None if done else next_start_height,
                "blocks": [block.to_dict() for block in chunk_blocks],
            },
        )

    def _parse_peer_list(self, peers: list[dict]) -> list[PeerAddress]:
        return [
            PeerAddress(host=peer["host"], port=int(peer["port"]))
            for peer in peers
        ]

    def _create_handshake_message(self) -> dict:
        tip_hash, height = self._get_chain_summary()
        return {
            "type": "handshake",
            "host": self.host,
            "port": self.port,
            "tip_hash": tip_hash,
            "height": height,
        }

    def _get_chain_summary(self) -> tuple[str | None, int]:
        if self.on_chain_summary is None:
            return None, -1
        return self.on_chain_summary()

    def _should_request_chain(
        self,
        remote_tip_hash: str | None,
        remote_height: int,
    ) -> bool:
        local_tip_hash, local_height = self._get_chain_summary()
        if remote_height > local_height:
            return True
        if (
            remote_tip_hash is not None
            and remote_tip_hash != local_tip_hash
            and remote_height == local_height
        ):
            return True
        return False

    def _is_self_peer(self, peer: PeerAddress) -> bool:
        return peer.host == self.host and peer.port == self.port

    @staticmethod
    def _short_hash(hash_value: str | None) -> str:
        if hash_value is None:
            return "none"
        return hash_value[:12]

    @staticmethod
    async def _send_message(
        writer: asyncio.StreamWriter,
        message: dict,
    ) -> None:
        writer.write(json.dumps(message).encode("utf-8") + b"\n")
        await writer.drain()

    def _notify(self, message: str) -> None:
        if self.on_notification is not None:
            self.on_notification(message)
            return
        print(message)


def _wallet_message_id(wallet_message: dict) -> str:
    return hashlib.sha256(
        json.dumps(wallet_message, sort_keys=True).encode("utf-8")
    ).hexdigest()
