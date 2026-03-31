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
        }

    @classmethod
    def from_dict(cls, transaction_data: dict) -> "Transaction":
        return cls(
            sender=transaction_data["sender"],
            receiver=transaction_data["receiver"],
            amount=Decimal(str(transaction_data["amount"])),
            fee=Decimal(str(transaction_data.get("fee", "0.0"))),
            timestamp=datetime.fromisoformat(transaction_data["timestamp"]),
        )
