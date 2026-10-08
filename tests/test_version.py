import pathlib
import re
import tomllib

import pytest

import scrubdaddy

# The version is written down twice: the release workflow patches both from the
# tag, and nothing else keeps them from drifting apart.
PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"


def declared_version() -> str:
    with PYPROJECT.open("rb") as stream:
        project: dict[str, str] = tomllib.load(stream)["project"]
    return project["version"]


@pytest.mark.parametrize("version", [scrubdaddy.__version__, declared_version()])
def test_version_looks_like_a_release(version):
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[.-]?(?:a|b|rc|dev)\d+)?", version), version


def test_the_two_places_the_version_is_written_agree():
    assert scrubdaddy.__version__ == declared_version()
