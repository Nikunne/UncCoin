import argparse
import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from core.hashing import sha256_transaction_hash
from core.transaction import Transaction
from wallet import Wallet, load_wallet


@dataclass(frozen=True)
class PeerAddress:
    host: str
    port: int


@dataclass
class P2PServer:
    host: str
    port: int
    wallet: Wallet | None = None
    on_transaction: Callable[[Transaction], None] | None = None
    peers: set[PeerAddress] = field(default_factory=set)
    seen_transaction_ids: set[str] = field(default_factory=set)
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
        if self.wallet is not None:
            wallet_name = self.wallet.name or "unnamed"
            print(f"Loaded wallet '{wallet_name}' with address {self.wallet.address}")

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

        self.seen_transaction_ids.add(transaction_id)

        if self.on_transaction is not None:
            self.on_transaction(transaction)

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

        if message_type == "transaction":
            transaction = Transaction.from_dict(message["transaction"])
            transaction_id = message.get("tx_id", sha256_transaction_hash(transaction))

            if transaction_id in self.seen_transaction_ids:
                print(f"Ignoring duplicate transaction {transaction_id[:12]}")
                return peer

            self.seen_transaction_ids.add(transaction_id)
            if self.on_transaction is not None:
                self.on_transaction(transaction)

            print(
                "Received transaction "
                f"{transaction_id[:12]} from {peer.host}:{peer.port}: "
                f"{transaction.sender} -> {transaction.receiver} ({transaction.amount})"
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


async def _interactive_console(server: P2PServer) -> None:
    print("Interactive mode enabled.")
    print(
        'Enter JSON to broadcast, "/send host:port {...}" for a direct message, '
        '"/peers" to list connected peers, "/known-peers" to list discovered peers, '
        '"/discover" to ask peers for more peers, "/tx sender receiver amount" '
        'to broadcast a transaction, "/clear" to clear the screen, or "/quit" to exit.'
    )

    while True:
        try:
            raw_input_line = await asyncio.to_thread(input, "p2p> ")
        except EOFError:
            return

        line = raw_input_line.strip()
        if not line:
            continue

        if line == "/quit":
            return

        if line == "/clear":
            print("\033[2J\033[H", end="")
            continue

        if line == "/peers":
            peers = server.list_peers()
            print("Connected peers:" if peers else "No connected peers.")
            for peer in peers:
                print(peer)
            continue

        if line == "/known-peers":
            peers = server.list_known_peers()
            print("Known peers:" if peers else "No known peers.")
            for peer in peers:
                print(peer)
            continue

        if line == "/discover":
            await server.discover_peers()
            print("Peer discovery request sent.")
            continue

        if line.startswith("/tx "):
            try:
                sender, receiver, amount = line[len("/tx "):].split(" ", maxsplit=2)
                transaction = Transaction(
                    sender=sender,
                    receiver=receiver,
                    amount=float(amount),
                    timestamp=datetime.now(),
                )
                await server.broadcast_transaction(transaction)
            except ValueError as error:
                print(f"Invalid /tx command: {error}")
            continue

        if line.startswith("/send "):
            try:
                peer_part, message_part = line[len("/send "):].split(" ", maxsplit=1)
                host, port = peer_part.split(":", maxsplit=1)
                message = json.loads(message_part)
                await server.send_to_peer(host, int(port), message)
                print(f"Sent direct message to {host}:{port}")
            except (ValueError, json.JSONDecodeError) as error:
                print(f"Invalid /send command: {error}")
            continue

        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            print(f"Invalid JSON: {error}")
            continue

        await server.broadcast(message)
        print("Broadcast message sent.")


async def _run_from_cli() -> None:
    parser = argparse.ArgumentParser(description="Run an UncCoin P2P server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument(
        "--peer",
        action="append",
        default=[],
        help="Optional peer in host:port form. Can be passed multiple times.",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Disable the interactive JSON console.",
    )
    parser.add_argument(
        "--wallet-name",
        help="Optional wallet name to load from the wallets directory.",
    )
    args = parser.parse_args()

    wallet = load_wallet(args.wallet_name) if args.wallet_name else None
    server = P2PServer(host=args.host, port=args.port, wallet=wallet)
    await server.start()

    for peer in args.peer:
        peer_host, peer_port = peer.split(":", maxsplit=1)
        await server.connect_to_peer(peer_host, int(peer_port))

    server_task = asyncio.create_task(server.serve_forever())

    try:
        if args.no_interactive:
            await server_task
        else:
            await _interactive_console(server)
    finally:
        server_task.cancel()
        await server.stop()


def main() -> None:
    asyncio.run(_run_from_cli())


if __name__ == "__main__":
    main()
