import pytest

import scrubdaddy
from scrubdaddy import Limits, Mask, Scrubber, Strategy, Token, TokenMap
from scrubdaddy.detectors.base import Detector
from scrubdaddy.exceptions import DetectorError, LimitExceededError
from scrubdaddy.models import Finding


class Broken(Detector):
    name = "broken"
    pii_type = "broken"

    def find(self, text, document=None):
        del text, document
        msg = "detector is broken"
        raise RuntimeError(msg)


class Unsure(Detector):
    name = "unsure"
    pii_type = "name"
    default_score = 0.3

    def find(self, text, document=None):
        index = text.find("Mike")
        if index >= 0:
            yield self.finding(beg=index, end=index + 4, text="Mike", document=document)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail joe@example.com", "mail {{EMAIL}}"),
        ("joe@example.com", "{{EMAIL}}"),
        ("joe@example.com and kim@example.com", "{{EMAIL}} and {{EMAIL}}"),
        ("nothing here", "nothing here"),
        ("", ""),
    ],
)
def test_clean(text, expected):
    assert scrubdaddy.clean(text) == expected


@pytest.mark.parametrize(
    ("renderer", "expected"),
    [
        (Token(), "{{EMAIL}}"),
        (Token(include_count=True), "{{EMAIL-0}}"),
        (Mask(), "***************"),
    ],
)
def test_the_renderer_decides_the_replacement(renderer, expected):
    assert Scrubber(renderer=renderer).clean("joe@example.com") == expected


@pytest.mark.parametrize(
    ("documents", "expected"),
    [
        ({"a": "joe@example.com"}, {"a": "{{EMAIL-0}}"}),
        ({"a": "joe@example.com", "b": "joe@example.com"}, {"a": "{{EMAIL-0}}", "b": "{{EMAIL-0}}"}),
        ({"a": "joe@example.com", "b": "kim@example.com"}, {"a": "{{EMAIL-0}}", "b": "{{EMAIL-1}}"}),
        ({"a": "clean", "b": "kim@example.com"}, {"a": "clean", "b": "{{EMAIL-0}}"}),
    ],
)
def test_documents_share_one_numbering(documents, expected):
    assert Scrubber(renderer=Token(include_count=True)).clean_documents(documents) == expected


def test_documents_given_as_a_list_are_named_by_position():
    cleaned = Scrubber().clean_documents(["joe@example.com", "clean"])
    assert cleaned == {"0": "{{EMAIL}}", "1": "clean"}


@pytest.mark.parametrize(
    ("min_score", "cleaned"),
    [
        (0.0, "{{NAME}} wrote"),
        (0.2, "{{NAME}} wrote"),
        (0.5, "Mike wrote"),
    ],
)
def test_the_threshold_decides_what_a_weak_detector_contributes(min_score, cleaned):
    scrubber = Scrubber(detectors=[Unsure()], min_score=min_score)
    assert scrubber.clean("Mike wrote") == cleaned


@pytest.mark.parametrize(
    ("on_error", "expectation"),
    [
        ("ignore", None),
        ("warn", RuntimeWarning),
        ("raise", DetectorError),
    ],
)
def test_one_broken_detector_does_not_decide_the_whole_run(on_error, expectation):
    scrubber = Scrubber(detectors=["email", Broken()], on_detector_error=on_error)
    if expectation is DetectorError:
        with pytest.raises(DetectorError):
            scrubber.clean("joe@example.com")
    elif expectation is RuntimeWarning:
        with pytest.warns(RuntimeWarning, match="broken"):
            assert scrubber.clean("joe@example.com") == "{{EMAIL}}"
    else:
        assert scrubber.clean("joe@example.com") == "{{EMAIL}}"


def test_a_failure_warning_carries_no_document_text():
    scrubber = Scrubber(detectors=[Broken()])
    with pytest.warns(RuntimeWarning) as caught:
        scrubber.clean("joe@example.com")
    assert "joe@example.com" not in str(caught[0].message)


@pytest.mark.parametrize(
    ("limits", "text"),
    [
        (Limits(max_chars=5), "joe@example.com"),
        (Limits(max_findings=1), "a@b.io c@d.io e@f.io"),
    ],
)
def test_limits_stop_runaway_work(limits, text):
    with pytest.raises(LimitExceededError):
        Scrubber(limits=limits).clean(text)


@pytest.mark.parametrize("kwargs", [{"max_chars": 0}, {"max_total_chars": -1}, {"max_findings": 0}])
def test_nonsensical_limits_are_refused(kwargs):
    with pytest.raises(ValueError, match="must be positive"):
        Limits(**kwargs)


def test_detectors_can_be_named_added_and_removed():
    scrubber = Scrubber(detectors=["email"])
    assert [d.name for d in scrubber.detectors] == ["email"]
    scrubber.add_detector(Unsure())
    assert "unsure" in [d.name for d in scrubber.detectors]
    scrubber.remove_detector("unsure")
    scrubber.remove_detector("never-was-there")
    assert [d.name for d in scrubber.detectors] == ["email"]


def test_two_scrubbers_do_not_share_numbering():
    one = Scrubber(renderer=Token(include_count=True))
    other = Scrubber(renderer=Token(include_count=True))
    assert one.clean("a@b.io") == "{{EMAIL-0}}"
    assert other.clean("c@d.io") == "{{EMAIL-0}}"


def test_numbering_can_be_carried_between_runs():
    first = Scrubber(renderer=Token(include_count=True))
    assert first.clean("a@b.io") == "{{EMAIL-0}}"
    later = Scrubber(
        renderer=Token(include_count=True),
        tokens=TokenMap.from_dict(first.tokens.to_dict()),
    )
    assert later.clean("c@d.io and a@b.io") == "{{EMAIL-1}} and {{EMAIL-0}}"


def test_findings_are_reported_alongside_the_cleaned_text():
    result = Scrubber().scrub("mail joe@example.com")
    assert result.text == "mail {{EMAIL}}"
    assert [f.pii_type for f in result.findings] == ["email"]
    assert isinstance(result.findings[0], Finding)


@pytest.mark.parametrize("strategy", [Strategy.HIGHEST_SCORE, Strategy.LONGEST, Strategy.MERGE])
def test_replacement_covers_every_character_of_a_finding(strategy):
    scrubber = Scrubber(strategy=strategy, renderer=Mask(char="#"))
    cleaned = scrubber.clean("mail joe@example.com now")
    assert "example" not in cleaned
    assert cleaned.startswith("mail ")
    assert cleaned.endswith(" now")


def test_auditing_overlaps_does_not_corrupt_the_text():
    scrubber = Scrubber(detectors=["email", "url"], strategy=Strategy.KEEP_ALL)
    cleaned = scrubber.clean("see https://example.com/joe@example.com here")
    assert "see " in cleaned
    assert cleaned.endswith(" here")


@pytest.mark.parametrize(
    ("documents", "expected"),
    [
        ({"a": "joe@example.com"}, [("a", "email")]),
        ({"a": "clean", "b": "joe@example.com"}, [("b", "email")]),
        (["joe@example.com", "clean"], [("0", "email")]),
    ],
)
def test_findings_carry_the_document_they_came_from(documents, expected):
    findings = Scrubber().find_documents(documents)
    assert [(f.document, f.pii_type) for f in findings] == expected


def test_documents_report_findings_and_text_together():
    result = Scrubber().scrub_documents({"a": "joe@example.com", "b": "clean"})
    assert result.documents == {"a": "{{EMAIL}}", "b": "clean"}
    assert [f.document for f in result.findings] == ["a"]


def test_the_total_size_of_a_batch_is_capped():
    scrubber = Scrubber(limits=Limits(max_chars=10, max_total_chars=15))
    with pytest.raises(LimitExceededError, match="total input length"):
        scrubber.clean_documents(["0123456789", "0123456789"])
