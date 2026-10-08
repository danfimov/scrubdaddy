import pytest

from scrubdaddy.validators import luhn, mod97


@pytest.mark.parametrize(
    ("digits", "valid"),
    [
        ("4111111111111111", True),
        ("5500005555555559", True),
        ("378282246310005", True),
        ("4111111111111112", False),
        ("1234567890123456", False),
        ("", False),
        ("abc", False),
        ("4111 1111 1111 1111", False),
    ],
)
def test_luhn(digits, valid):
    assert luhn(digits) is valid


@pytest.mark.parametrize(
    ("account", "valid"),
    [
        ("GB82 WEST 1234 5698 7654 32", True),
        ("GB82WEST12345698765432", True),
        ("gb82west12345698765432", True),
        ("DE89 3704 0044 0532 0130 00", True),
        ("GB82 WEST 1234 5698 7654 33", False),
        ("GB82", False),
        ("", False),
        ("GB82 WEST 1234 5698 7654 32!", False),
    ],
)
def test_mod97(account, valid):
    assert mod97(account) is valid
