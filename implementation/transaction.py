from dataclasses import dataclass
from datetime import datetime


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: float
    timestamp: datetime
