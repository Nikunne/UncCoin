from dataclasses import dataclass
from decimal import Decimal
from datetime import datetime


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: Decimal
    fee: Decimal
    timestamp: datetime
    nonce: int = 0
    sender_public_key: tuple[int, int] | None = None
    signature: str | None = None

    def __post_init__(self) -> None:
        self.amount = Decimal(str(self.amount))
        self.fee = Decimal(str(self.fee))

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": str(self.amount),
            "fee": str(self.fee),
            "timestamp": self.timestamp.isoformat(),
            "nonce": self.nonce,
            "sender_public_key": (
                {
                    "exponent": str(self.sender_public_key[0]),
                    "modulus": str(self.sender_public_key[1]),
                }
                if self.sender_public_key is not None
                else None
            ),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, transaction_data: dict) -> "Transaction":
        sender_public_key_data = transaction_data.get("sender_public_key")
        return cls(
            sender=transaction_data["sender"],
            receiver=transaction_data["receiver"],
            amount=Decimal(str(transaction_data["amount"])),
            fee=Decimal(str(transaction_data.get("fee", "0.0"))),
            timestamp=datetime.fromisoformat(transaction_data["timestamp"]),
            nonce=int(transaction_data.get("nonce", 0)),
            sender_public_key=(
                (
                    int(sender_public_key_data["exponent"]),
                    int(sender_public_key_data["modulus"]),
                )
                if sender_public_key_data is not None
                else None
            ),
            signature=transaction_data.get("signature"),
        )

    def signing_payload(self) -> str:
        return (
            f"{self.sender}|{self.receiver}|{self.amount}|{self.fee}|{self.nonce}|"
            f"{self.timestamp.isoformat()}"
        )
