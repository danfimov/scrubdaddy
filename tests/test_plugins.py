import re
from collections.abc import Iterator
from importlib.metadata import EntryPoint

import pytest

from scrubdaddy import Scrubber
from scrubdaddy.detectors import default_registry
from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.registry import PLUGIN_GROUP, Registry, plugin_entries


class PluginDetector(RegexDetector):
    """Stands in for a detector shipped by another package."""

    name = "employee_id"
    pii_type = "employee_id"
    pattern = re.compile(r"\bEMP-\d{6}\b")


def advertise(monkeypatch: pytest.MonkeyPatch, *values: tuple[str, str]) -> None:
    points = tuple(EntryPoint(name=name, value=value, group=PLUGIN_GROUP) for name, value in values)

    def fake_entry_points(group: str) -> Iterator[EntryPoint]:
        assert group == PLUGIN_GROUP
        return iter(points)

    monkeypatch.setattr("scrubdaddy.registry.entry_points", fake_entry_points)


@pytest.fixture
def advertised(monkeypatch: pytest.MonkeyPatch) -> None:
    advertise(monkeypatch, ("employee_id", "tests.test_plugins:PluginDetector"))


@pytest.mark.usefixtures("advertised")
@pytest.mark.parametrize("autoload", [False, True])
def test_advertised_detectors_are_discovered(autoload):
    entries = plugin_entries(autoload=autoload)
    assert [(e.name, e.autoload) for e in entries] == [("employee_id", autoload)]


@pytest.mark.usefixtures("advertised")
def test_discovery_does_not_import_the_plugin():
    assert plugin_entries()[0].target == "tests.test_plugins:PluginDetector"


@pytest.mark.usefixtures("advertised")
def test_a_plugin_is_listed_but_stays_out_of_the_default_set():
    registry = default_registry()
    assert "employee_id" in registry
    assert registry.entry("employee_id").autoload is False
    assert "employee_id" not in [e.name for e in registry.select(locale="en_US")]


@pytest.mark.usefixtures("advertised")
def test_a_plugin_can_be_opted_into():
    registry = default_registry()
    registry.set_autoload("employee_id", autoload=True)
    assert Scrubber(registry=registry).clean("ticket from EMP-123456") == "ticket from {{EMPLOYEE_ID}}"


@pytest.mark.usefixtures("advertised")
def test_a_plugin_is_usable_when_named():
    scrubber = Scrubber(registry=default_registry(), detectors=["employee_id"])
    assert scrubber.clean("ticket from EMP-123456") == "ticket from {{EMPLOYEE_ID}}"


@pytest.mark.usefixtures("advertised")
def test_discovery_can_be_turned_off():
    assert "employee_id" not in default_registry(plugins=False)


@pytest.mark.parametrize("taken", ["email", "credit_card", "phone"])
def test_a_plugin_cannot_shadow_a_name_already_in_use(monkeypatch, taken):
    advertise(monkeypatch, (taken, "tests.test_plugins:PluginDetector"))
    registry = default_registry()
    assert registry.load(taken).name == taken
    assert registry.entry(taken).target != "tests.test_plugins:PluginDetector"


def test_the_names_a_plugin_lost_can_be_told_apart(monkeypatch):
    advertise(
        monkeypatch,
        ("email", "tests.test_plugins:PluginDetector"),
        ("employee_id", "tests.test_plugins:PluginDetector"),
    )
    registry = default_registry(plugins=False)
    advertised_names = {entry.name for entry in plugin_entries()}
    added = set(registry.add_plugins())
    assert added == {"employee_id"}
    assert advertised_names - added == {"email"}


def test_a_plugin_pointing_at_nothing_fails_when_used_not_when_listed(monkeypatch):
    advertise(monkeypatch, ("broken", "scrubdaddy_no_such_package:Detector"))
    registry = Registry()
    assert registry.add_plugins() == ("broken",)
    with pytest.raises(ImportError):
        registry.load("broken")
