import pytest

from scrubdaddy.detectors import default_registry
from scrubdaddy.detectors.base import Detector
from scrubdaddy.exceptions import DuplicateDetectorError, MissingDependencyError, UnknownDetectorError
from scrubdaddy.registry import Entry, Registry


class Dummy(Detector):
    name = "dummy"
    pii_type = "dummy"

    def find(self, text, document=None):
        del text, document
        return iter(())


@pytest.mark.parametrize("name", ["email", "url", "ip", "credit_card", "iban", "secret", "password", "uuid", "phone"])
def test_shipped_detectors_are_registered_and_loadable(name):
    assert default_registry().load(name).name == name


@pytest.mark.parametrize(
    ("name", "autoload"),
    [
        ("email", True),
        ("credit_card", True),
        ("secret", True),
        ("uuid", False),
    ],
)
def test_default_set(name, autoload):
    assert default_registry().entry(name).autoload is autoload


def test_registries_are_independent():
    one, other = default_registry(), default_registry()
    one.remove("email")
    assert "email" not in one
    assert "email" in other


def test_copy_does_not_share_changes():
    original = default_registry()
    branch = original.copy()
    branch.remove("email")
    branch.register(Dummy, autoload=True)
    assert "email" in original
    assert "dummy" not in original


@pytest.mark.parametrize("missing_ok", [True, False])
def test_removing_an_absent_detector(missing_ok):
    registry = default_registry()
    if missing_ok:
        registry.remove("nope", missing_ok=True)
    else:
        with pytest.raises(UnknownDetectorError):
            registry.remove("nope", missing_ok=False)


def test_duplicate_names_are_refused_but_can_be_replaced():
    registry = Registry([Entry("dummy", Dummy)])
    with pytest.raises(DuplicateDetectorError):
        registry.register(Dummy)
    registry.register(Dummy, replace_existing=True)
    assert registry.names() == ("dummy",)


def test_registering_does_not_quietly_join_the_default_set():
    registry = default_registry()
    registry.register(Dummy)
    assert registry.entry("dummy").autoload is False
    registry.set_autoload("dummy", autoload=True)
    assert registry.entry("dummy").autoload is True


def test_unknown_name_names_the_alternatives():
    with pytest.raises(UnknownDetectorError) as caught:
        default_registry().entry("emial")
    assert "email" in str(caught.value)


def test_a_missing_optional_dependency_names_the_extra_to_install():
    registry = Registry([Entry("nowhere", "scrubdaddy_missing_module:Thing", extra="phone")])
    with pytest.raises(MissingDependencyError, match=r"scrubdaddy\[phone\]"):
        registry.load("nowhere")


@pytest.mark.parametrize(
    ("locale", "locales", "selected"),
    [
        ("en_US", None, True),
        ("en_US", frozenset({"en"}), True),
        ("en_GB", frozenset({"en_GB"}), True),
        ("ru_RU", frozenset({"en_GB"}), False),
    ],
)
def test_selection_filters_by_locale(locale, locales, selected):
    registry = Registry([Entry("dummy", Dummy, locales=locales)])
    assert bool(registry.select(locale=locale)) is selected


def test_naming_detectors_overrides_the_default_set_but_not_the_locale():
    registry = Registry([
        Entry("dummy", Dummy, autoload=False),
        Entry("elsewhere", Dummy, autoload=False, locales=frozenset({"ru_RU"})),
    ])
    assert [e.name for e in registry.select(locale="en_US", names=["dummy", "elsewhere"])] == ["dummy"]
