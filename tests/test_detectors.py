import pytest

from scrubdaddy.detectors.base import Detector
from scrubdaddy.detectors.credential import PasswordDetector
from scrubdaddy.detectors.credit_card import CreditCardDetector
from scrubdaddy.detectors.email import EmailDetector
from scrubdaddy.detectors.iban import IbanDetector
from scrubdaddy.detectors.ip import IpDetector
from scrubdaddy.detectors.secret import SecretDetector
from scrubdaddy.detectors.url import UrlDetector
from scrubdaddy.detectors.uuid import UuidDetector


def found(detector: type[Detector], text: str) -> list[str]:
    return [f.text for f in detector().find(text)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail joe@example.com now", ["joe@example.com"]),
        ("JOE.BLOGGS+tag@sub.example.co.uk", ["JOE.BLOGGS+tag@sub.example.co.uk"]),
        ("two a@b.io and c@d.io", ["a@b.io", "c@d.io"]),
        ("<joe@example.com>", ["joe@example.com"]),
        ("joe@example.com.", ["joe@example.com"]),
        ("no at sign here", []),
        ("joe@localhost", []),
        ("joe@.com", []),
        ("@example.com", []),
        ("joe@example..com", []),
    ],
)
def test_email(text, expected):
    assert found(EmailDetector, text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://example.com/a?b=1 ok", ["https://example.com/a?b=1"]),
        ("visit www.example.com today", ["www.example.com"]),
        ("ends a sentence https://example.com.", ["https://example.com"]),
        ("in parens (https://example.com)", ["https://example.com"]),
        ("http://localhost:8080/path", ["http://localhost:8080/path"]),
        ("nothing to see", []),
    ],
)
def test_url(text, expected):
    assert found(UrlDetector, text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("host 192.168.1.1 up", ["192.168.1.1"]),
        ("v6 2001:db8::1 up", ["2001:db8::1"]),
        ("full 2001:0db8:0000:0000:0000:0000:0000:0001", ["2001:0db8:0000:0000:0000:0000:0000:0001"]),
        ("256.1.1.1 is not an address", []),
        ("version 1.2.3.4.5", []),
        ("time 12:30:45", []),
        ("a plain 1.2.3 version", []),
    ],
)
def test_ip(text, expected):
    assert found(IpDetector, text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("card 4111111111111111 ok", ["4111111111111111"]),
        ("card 4111 1111 1111 1111 ok", ["4111 1111 1111 1111"]),
        ("card 4111-1111-1111-1111 ok", ["4111-1111-1111-1111"]),
        ("amex 378282246310005", ["378282246310005"]),
        ("failing checksum 4111111111111112", []),
        ("order 1234567890123456", []),
        ("short 41111111111", []),
    ],
)
def test_credit_card(text, expected):
    assert found(CreditCardDetector, text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("pay to GB82 WEST 1234 5698 7654 32 today", ["GB82 WEST 1234 5698 7654 32"]),
        ("pay to DE89370400440532013000 today", ["DE89370400440532013000"]),
        ("bad checksum GB82 WEST 1234 5698 7654 33", []),
        ("not an account AB12 CD34", []),
    ],
)
def test_iban(text, expected):
    assert found(IbanDetector, text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("id 123e4567-e89b-12d3-a456-426614174000", ["123e4567-e89b-12d3-a456-426614174000"]),
        ("id 123E4567-E89B-12D3-A456-426614174000", ["123E4567-E89B-12D3-A456-426614174000"]),
        ("not-a-uuid 123e4567-e89b-12d3-a456", []),
    ],
)
def test_uuid(text, expected):
    assert found(UuidDetector, text) == expected


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("key AKIAIOSFODNN7EXAMPLE here", "aws_access_key"),
        ("token ghp_" + "a" * 36, "github_token"),
        ("slack xoxb-123456789012-abcdef", "slack_token"),
        ("claude sk-ant-api03-" + "x" * 30, "anthropic_key"),
        ("google AIza" + "b" * 35, "google_api_key"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "jwt"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key_block"),
        ("postgres://user:hunter2@db:5432/app", "credentials_in_url"),
    ],
)
def test_secret_reports_its_kind(text, kind):
    findings = list(SecretDetector().find(text))
    assert [f.context["kind"] for f in findings if f.context["kind"] == kind] == [kind]


@pytest.mark.parametrize("text", ["nothing secret here", "AKIA_too_short", "ghp_short"])
def test_secret_leaves_ordinary_text_alone(text):
    assert found(SecretDetector, text) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password: hunter2", ["hunter2"]),
        ("password=hunter2", ["hunter2"]),
        ("PWD: hunter2", ["hunter2"]),
        ('api_key: "abc123"', ["abc123"]),
        ("token = abc123", ["abc123"]),
        ("password: REDACTED", []),
        ("password: none", []),
        ("just the word password", []),
    ],
)
def test_password_reports_only_the_value(text, expected):
    assert found(PasswordDetector, text) == expected
