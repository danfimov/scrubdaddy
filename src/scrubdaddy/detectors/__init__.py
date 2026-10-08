import importlib.util

from scrubdaddy.detectors.base import Detector, RegexDetector
from scrubdaddy.registry import Entry, Registry

__all__ = ["Detector", "RegexDetector", "default_registry"]


def _installed(module: str) -> bool:
    """Whether an optional dependency is importable, without importing it.

    A detector that needs a missing dependency stays registered but out of the
    default set: installing the extra enables it, and until then a scrubber
    built with defaults does not fail on an import nobody asked for.
    """
    return importlib.util.find_spec(module) is not None


def default_registry(plugins: bool = True) -> Registry:
    """A fresh registry holding every detector that ships with scrubdaddy.

    Returned per call rather than shared, so that customising it in one place
    cannot reach another part of the process. Detectors advertised by other
    installed packages are listed too, but stay out of the default set.
    """
    registry = Registry([
        Entry("email", "scrubdaddy.detectors.email:EmailDetector"),
        Entry("url", "scrubdaddy.detectors.url:UrlDetector"),
        Entry("ip", "scrubdaddy.detectors.ip:IpDetector"),
        Entry("credit_card", "scrubdaddy.detectors.credit_card:CreditCardDetector"),
        Entry("iban", "scrubdaddy.detectors.iban:IbanDetector"),
        Entry("secret", "scrubdaddy.detectors.secret:SecretDetector"),
        Entry("password", "scrubdaddy.detectors.credential:PasswordDetector"),
        Entry("uuid", "scrubdaddy.detectors.uuid:UuidDetector", autoload=False),
        Entry(
            "phone",
            "scrubdaddy.detectors.phone:PhoneDetector",
            autoload=_installed("phonenumbers"),
            extra="phone",
        ),
    ])
    if plugins:
        registry.add_plugins()
    return registry
