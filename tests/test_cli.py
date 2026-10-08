import io
import json

import pytest

from scrubdaddy.cli import main

TEXT = "mail joe@example.com, card 4111 1111 1111 1111"


def run(argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err, stdin=io.StringIO(stdin))
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["clean"], "mail {{EMAIL}}, card {{CREDIT_CARD}}"),
        (["clean", "-"], "mail {{EMAIL}}, card {{CREDIT_CARD}}"),
        (["clean", "--count"], "mail {{EMAIL-0}}, card {{CREDIT_CARD-0}}"),
        (["clean", "--detectors", "email"], "mail {{EMAIL}}, card 4111 1111 1111 1111"),
        (["clean", "--renderer", "remove"], "mail , card "),
        (["clean", "--renderer", "mask", "--mask-char", "#"], "mail ###############, card ###################"),
        (["clean", "--renderer", "mask", "--keep-last", "4"], "mail ***********.com, card ***************1111"),
    ],
)
def test_clean_reads_standard_input_and_writes_the_result(argv, expected):
    code, out, err = run(argv, TEXT)
    assert (code, out, err) == (0, expected, "")


def test_clean_reads_a_file(tmp_path):
    path = tmp_path / "note.txt"
    path.write_text(TEXT, encoding="utf-8")
    code, out, _ = run(["clean", str(path)])
    assert (code, out) == (0, "mail {{EMAIL}}, card {{CREDIT_CARD}}")


def test_a_fingerprint_needs_a_salt_and_then_is_stable():
    first = run(["clean", "--hash-salt", "pepper"], TEXT)[1]
    again = run(["clean", "--hash-salt", "pepper"], TEXT)[1]
    other = run(["clean", "--hash-salt", "other"], TEXT)[1]
    assert first == again
    assert first != other
    assert "joe@example.com" not in first


@pytest.mark.parametrize(
    ("argv", "expected_lines"),
    [
        (["find"], 2),
        (["find", "--detectors", "email"], 1),
        (["find", "--detectors", "uuid"], 0),
    ],
)
def test_find_reports_one_line_per_finding(argv, expected_lines):
    code, out, _ = run(argv, TEXT)
    assert code == 0
    assert len([line for line in out.splitlines() if line]) == expected_lines


def test_find_withholds_the_matched_text_by_default():
    assert "joe@example.com" not in run(["find"], TEXT)[1]
    assert "joe@example.com" in run(["find", "--include-text"], TEXT)[1]


@pytest.mark.parametrize("include_text", [False, True])
def test_find_as_json_is_one_object_per_line(include_text):
    argv = ["find", "--json"] + (["--include-text"] if include_text else [])
    code, out, _ = run(argv, TEXT)
    payloads = [json.loads(line) for line in out.splitlines() if line]
    assert code == 0
    assert [p["pii_type"] for p in payloads] == ["email", "credit_card"]
    assert all(("text" in p) is include_text for p in payloads)


@pytest.mark.parametrize(
    ("text", "code"),
    [
        (TEXT, 1),
        ("nothing to see here", 0),
    ],
)
def test_find_can_report_through_the_exit_code(text, code):
    assert run(["find", "--exit-code"], text)[0] == code


def test_find_names_the_document_each_finding_came_from(tmp_path):
    first, second = tmp_path / "a.txt", tmp_path / "b.txt"
    first.write_text("joe@example.com", encoding="utf-8")
    second.write_text("nothing", encoding="utf-8")
    code, out, _ = run(["find", str(first), str(second)])
    assert code == 0
    assert out.startswith(f"{first}:0-15\temail")


@pytest.mark.parametrize("argv", [["list-detectors"], ["list-detectors", "--locale", "ru_RU"]])
def test_list_detectors_marks_what_runs_by_default(argv):
    code, out, _ = run(argv)
    assert code == 0
    assert "email\tdefault" in out
    assert "uuid\topt-in" in out


def test_list_detectors_as_json():
    code, out, _ = run(["list-detectors", "--json"])
    rows = json.loads(out)
    assert code == 0
    assert {"name": "uuid", "default": False, "locales": None, "extra": None, "plugin": False} in rows


@pytest.mark.parametrize(
    "argv",
    [
        ["clean", "--detectors", "nope"],
        ["clean", "does-not-exist.txt"],
        ["find", "does-not-exist.txt"],
    ],
)
def test_failures_are_reported_on_standard_error(argv):
    code, out, err = run(argv, TEXT)
    assert code == 2
    assert out == ""
    assert err.startswith("scrubdaddy: ")


@pytest.mark.parametrize("argv", [[], ["nonsense"], ["clean", "--renderer", "nonsense"]])
def test_misuse_is_refused_by_the_parser(argv):
    with pytest.raises(SystemExit) as caught:
        run(argv, TEXT)
    assert caught.value.code == 2
