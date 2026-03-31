import secrets
from math import gcd


def generate_prime(bit_length: int) -> int:
    while True:
        candidate = secrets.randbits(bit_length)
        candidate |= (1 << (bit_length - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def is_probable_prime(number: int, rounds: int = 10) -> bool:
    if number in (2, 3):
        return True
    if number <= 1 or number % 2 == 0:
        return False

    remainder = number - 1
    power_of_two = 0
    while remainder % 2 == 0:
        power_of_two += 1
        remainder //= 2

    for _ in range(rounds):
        witness = secrets.randbelow(number - 3) + 2
        test_value = pow(witness, remainder, number)

        if test_value in (1, number - 1):
            continue

        for _ in range(power_of_two - 1):
            test_value = pow(test_value, 2, number)
            if test_value == number - 1:
                break
        else:
            return False

    return True


def mod_inverse(value: int, modulus: int) -> int:
    gcd_value, inverse, _ = extended_gcd(value, modulus)
    if gcd_value != 1:
        raise ValueError("Modular inverse does not exist.")
    return inverse % modulus


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)
    return gcd_value, y1, x1 - (a // b) * y1


def generate_rsa_keypair(bit_length: int = 1024) -> tuple[tuple[int, int], tuple[int, int]]:
    public_exponent = 65537

    while True:
        prime_p = generate_prime(bit_length // 2)
        prime_q = generate_prime(bit_length // 2)
        if prime_p == prime_q:
            continue

        modulus = prime_p * prime_q
        totient = (prime_p - 1) * (prime_q - 1)
        if gcd(public_exponent, totient) != 1:
            continue

        private_exponent = mod_inverse(public_exponent, totient)
        return (public_exponent, modulus), (private_exponent, modulus)
