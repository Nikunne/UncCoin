import hashlib
from dataclasses import dataclass


@dataclass
class Wallet:
    public_key: tuple[int, int]
    private_key: tuple[int, int]
    name: str | None = None

    @property
    def address(self) -> str:
        public_exponent, modulus = self.public_key
        key_material = f"{public_exponent}:{modulus}".encode("utf-8")
        return hashlib.sha256(key_material).hexdigest()

    def sign_message(self, message: str) -> str:
        digest = self._message_digest(message)
        private_exponent, modulus = self.private_key
        signature = pow(digest, private_exponent, modulus)
        return format(signature, "x")

    def verify_signature(self, message: str, signature: str) -> bool:
        digest = self._message_digest(message)
        public_exponent, modulus = self.public_key
        signature_value = int(signature, 16)
        verified_digest = pow(signature_value, public_exponent, modulus)
        return digest == verified_digest

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": self.address,
            "public_key": {
                "exponent": self.public_key[0],
                "modulus": self.public_key[1],
            },
            "private_key": {
                "exponent": self.private_key[0],
                "modulus": self.private_key[1],
            },
        }

    @classmethod
    def from_dict(cls, wallet_data: dict) -> "Wallet":
        return cls(
            public_key=(
                int(wallet_data["public_key"]["exponent"]),
                int(wallet_data["public_key"]["modulus"]),
            ),
            private_key=(
                int(wallet_data["private_key"]["exponent"]),
                int(wallet_data["private_key"]["modulus"]),
            ),
            name=wallet_data.get("name"),
        )

    @staticmethod
    def _message_digest(message: str) -> int:
        return int(hashlib.sha256(message.encode("utf-8")).hexdigest(), 16)
