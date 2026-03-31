import argparse

from wallet.factory import create_wallet
from wallet.storage import load_wallet, save_wallet


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or inspect UncCoin wallets.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Create and persist a named wallet.")
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--bit-length", type=int, default=1024)

    show_parser = subparsers.add_parser("show", help="Load and display a named wallet.")
    show_parser.add_argument("--name", required=True)

    args = parser.parse_args()

    if args.command == "create":
        wallet = create_wallet(name=args.name, bit_length=args.bit_length)
        path = save_wallet(wallet)
        print(f"Created wallet '{wallet.name}'")
        print(f"Address: {wallet.address}")
        print(f"Saved to: {path}")
        return

    if args.command == "show":
        wallet = load_wallet(args.name)
        print(f"Wallet: {wallet.name}")
        print(f"Address: {wallet.address}")
        print(f"Public key: {wallet.public_key}")
        return


if __name__ == "__main__":
    main()
