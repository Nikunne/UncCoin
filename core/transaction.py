from dataclasses import dataclass
from datetime import datetime


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: float
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, transaction_data: dict) -> "Transaction":
        return cls(
            sender=transaction_data["sender"],
            receiver=transaction_data["receiver"],
            amount=float(transaction_data["amount"]),
            timestamp=datetime.fromisoformat(transaction_data["timestamp"]),
        )
