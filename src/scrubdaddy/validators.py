import string

__all__ = ["luhn", "mod97"]

_IBAN_ALPHABET = {char: str(index + 10) for index, char in enumerate(string.ascii_uppercase)}


def luhn(digits: str) -> bool:
    """Check the digit that payment cards carry.

    Without it, any long number in a document looks like a card.

    >>> luhn("4111111111111111")
    True
    >>> luhn("4111111111111112")
    False
    """
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:  # noqa: PLR2004  # the rule is stated in terms of this number
                digit -= 9
        total += digit
    return total % 10 == 0


def mod97(account: str) -> bool:
    """Check the two digits an international bank account number carries.

    Spaces are ignored, since bank accounts are usually written in groups.

    >>> mod97("GB82 WEST 1234 5698 7654 32")
    True
    >>> mod97("GB82 WEST 1234 5698 7654 33")
    False
    """
    compact = account.replace(" ", "").upper()
    min_length, max_length = 15, 34
    if not (min_length <= len(compact) <= max_length) or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = "".join(_IBAN_ALPHABET[char] if char.isalpha() else char for char in rearranged)
    except KeyError:
        return False
    return int(numeric) % 97 == 1
