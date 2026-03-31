import asyncio
import json
from dataclasses import dataclass, field
from typing import Callable

from core.block import Block
from core.hashing import sha256_block_hash
from core.hashing import sha256_transaction_hash
from core.transaction import Transaction


@dataclass(frozen=True)
class PeerAddress:
    host: str
    port: int


@dataclass
class P2PServer:
    host: str
    port: int
    on_transaction: Callable[[Transaction], bool] | None = None
    on_block: Callable[[Block], bool] | None = None
    on_chain_request: Callable[[], list[Block]] | None = None
    on_chain_response: Callable[[list[Block]], None] | None = None
    peers: set[PeerAddress] = field(default_factory=set)
    seen_transaction_ids: set[str] = field(default_factory=set)
    seen_block_hashes: set[str] = field(default_factory=set)
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
        print(f"P2P server listening on {self.host}:{self.port}")

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

        await self._send_message(
            writer,
            {
                "type": "handshake",
                "host": self.host,
                "port": self.port,
            },
        )
        asyncio.create_task(self._read_messages(reader, writer, peer))
        print(f"Connected to peer {host}:{port}")

    async def broadcast(self, message: dict) -> None:
        await self._broadcast_to_peers(message)

    async def broadcast_transaction(self, transaction: Transaction) -> None:
        transaction_id = sha256_transaction_hash(transaction)
        if transaction_id in self.seen_transaction_ids:
            print(f"Transaction {transaction_id[:12]} already seen. Skipping broadcast.")
            return

        if self.on_transaction is not None and not self.on_transaction(transaction):
            print(f"Rejected local transaction {transaction_id[:12]}.")
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

    async def request_chain(self, host: str, port: int) -> None:
        await self.send_to_peer(host, port, {"type": "chain_request"})

    async def discover_peers(self) -> None:
        for peer in list(self.active_connections):
            await self.request_peer_list(peer.host, peer.port)

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
        print(f"Accepted peer connection from {peer.host}:{peer.port}")

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
            print(f"Disconnected from peer {peer.host}:{peer.port}")

    async def _handle_message(self, message: dict, peer: PeerAddress) -> PeerAddress:
        message_type = message.get("type", "unknown")

        if message_type == "handshake":
            advertised_host = message.get("host", peer.host)
            advertised_port = message.get("port", peer.port)
            advertised_peer = PeerAddress(advertised_host, advertised_port)
            self.peers.discard(peer)
            self.peers.add(advertised_peer)
            writer = self.active_connections.pop(peer, None)
            if writer is not None:
                self.active_connections[advertised_peer] = writer
            print(f"Handshake received from {advertised_host}:{advertised_port}")
            return advertised_peer

        if message_type == "peer_request":
            await self._send_peer_list(peer)
            print(f"Peer list requested by {peer.host}:{peer.port}")
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
                        print(
                            "Failed to connect to discovered peer "
                            f"{discovered_peer.host}:{discovered_peer.port}"
                        )
            print(f"Peer list received from {peer.host}:{peer.port}")
            return peer

        if message_type == "chain_request":
            await self._send_chain(peer)
            print(f"Chain requested by {peer.host}:{peer.port}")
            return peer

        if message_type == "chain_response":
            blocks = [
                Block.from_dict(block_data, hash_function=sha256_block_hash)
                for block_data in message.get("blocks", [])
            ]
            if self.on_chain_response is not None:
                self.on_chain_response(blocks)
            print(f"Chain received from {peer.host}:{peer.port} ({len(blocks)} blocks)")
            return peer

        if message_type == "transaction":
            transaction = Transaction.from_dict(message["transaction"])
            transaction_id = message.get("tx_id", sha256_transaction_hash(transaction))

            if transaction_id in self.seen_transaction_ids:
                print(f"Ignoring duplicate transaction {transaction_id[:12]}")
                return peer

            if self.on_transaction is not None and not self.on_transaction(transaction):
                print(f"Rejected transaction {transaction_id[:12]} from {peer.host}:{peer.port}")
                return peer

            self.seen_transaction_ids.add(transaction_id)

            print(
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
                print(f"Ignoring duplicate block {block_hash[:12]}")
                return peer

            if self.on_block is not None and not self.on_block(block):
                print(f"Rejected block {block_hash[:12]} from {peer.host}:{peer.port}")
                return peer

            self.seen_block_hashes.add(block_hash)
            print(
                f"Received block {block_hash[:12]} from {peer.host}:{peer.port} "
                f"at height {block.block_id}"
            )
            await self._broadcast_to_peers(message, exclude_peer=peer)
            return peer

        print(f"Received {message_type} from {peer.host}:{peer.port}: {message}")
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

    async def _send_chain(self, peer: PeerAddress) -> None:
        blocks = self.on_chain_request() if self.on_chain_request is not None else []
        await self.send_to_peer(
            peer.host,
            peer.port,
            {
                "type": "chain_response",
                "blocks": [block.to_dict() for block in blocks],
            },
        )

    def _parse_peer_list(self, peers: list[dict]) -> list[PeerAddress]:
        return [
            PeerAddress(host=peer["host"], port=int(peer["port"]))
            for peer in peers
        ]

    def _is_self_peer(self, peer: PeerAddress) -> bool:
        return peer.host == self.host and peer.port == self.port

    @staticmethod
    async def _send_message(
        writer: asyncio.StreamWriter,
        message: dict,
    ) -> None:
        writer.write(json.dumps(message).encode("utf-8") + b"\n")
        await writer.drain()
