import json
from pathlib import Path

from wallet.wallet import Wallet


WALLETS_DIR = Path("wallets")


def ensure_wallets_dir() -> Path:
    WALLETS_DIR.mkdir(exist_ok=True)
    return WALLETS_DIR


def wallet_path(name: str) -> Path:
    return ensure_wallets_dir() / f"{name}.json"


def save_wallet(wallet: Wallet) -> Path:
    if not wallet.name:
        raise ValueError("Wallet name is required for persistence.")

    path = wallet_path(wallet.name)
    if path.exists():
        raise FileExistsError(f"Wallet '{wallet.name}' already exists at {path}.")

    path.write_text(json.dumps(wallet.to_dict(), indent=2), encoding="utf-8")
    return path


def load_wallet(name: str) -> Wallet:
    path = wallet_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Wallet '{name}' does not exist at {path}.")

    wallet_data = json.loads(path.read_text(encoding="utf-8"))
    return Wallet.from_dict(wallet_data)
