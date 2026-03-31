from wallet.crypto import generate_rsa_keypair
from wallet.wallet import Wallet


def create_wallet(name: str | None = None, bit_length: int = 1024) -> Wallet:
    public_key, private_key = generate_rsa_keypair(bit_length=bit_length)
    return Wallet(public_key=public_key, private_key=private_key, name=name)
