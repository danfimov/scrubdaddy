import json
import subprocess
import sys

import pytest

# Importing the library, and scrubbing with the detectors that need nothing but
# the standard library, must not drag in a dependency tree. That is what keeps a
# scanner's CVE report about some NLP package from becoming this library's
# problem, and it holds only as long as nothing imports an optional dependency
# at module level.
REPORT_OUTSIDERS = """
import json
import sys

outside = sorted({
    name.split(".")[0]
    for name in sys.modules
    if not name.startswith("_")
    and name.split(".")[0] not in sys.stdlib_module_names
    and not name.startswith("scrubdaddy")
})
print(json.dumps(outside))
"""

PROBES = {
    "import": "import scrubdaddy\n",
    "clean": """
import scrubdaddy

scrubdaddy.clean(
    "joe@example.com, 4111 1111 1111 1111, GB82 WEST 1234 5698 7654 32, 10.0.0.1, password: hunter2",
    detectors=["email", "credit_card", "iban", "ip", "url", "secret", "password", "uuid"],
)
""",
}


def outsiders(probe: str) -> list[str]:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe + REPORT_OUTSIDERS],
        capture_output=True,
        text=True,
        check=True,
    )
    names: list[str] = json.loads(completed.stdout)
    return names


@pytest.mark.parametrize("probe", PROBES.values(), ids=list(PROBES))
def test_nothing_outside_the_standard_library_is_imported(probe):
    assert outsiders(probe) == []


@pytest.mark.parametrize("unwanted", ["phonenumbers", "dateparser", "sklearn", "numpy", "pandas", "nltk", "textblob"])
def test_named_optional_dependencies_stay_out(unwanted):
    assert unwanted not in outsiders(PROBES["import"])
