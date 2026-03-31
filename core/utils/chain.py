from core.utils.constants import GENESIS_PREVIOUS_HASH


def get_previous_hash(blocks: list) -> str:
    return GENESIS_PREVIOUS_HASH if not blocks else blocks[-1].block_hash
