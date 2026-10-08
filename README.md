# scrubdaddy

Finds and removes personal data in text: email addresses, phone numbers,
payment cards, bank accounts, IP addresses, API keys and passwords.

The core installs no third-party packages, so adding it to a service does not
add a dependency tree to audit. Everything that needs one — phone number
parsing, date parsing, named entity models — lives behind an extra.

```python
import scrubdaddy

scrubdaddy.clean("contact joe@example.com or call +44 20 7183 8750")
# 'contact {{EMAIL}} or call {{PHONE}}'
```

## Install

```bash
pip install scrubdaddy            # core, no dependencies
pip install 'scrubdaddy[phone]'   # adds phone number detection
```

Installing an extra is all it takes: the detector it enables joins the default
set, and until then nothing fails on an import nobody asked for.

## Command line

```bash
scrubdaddy clean notes.txt                  # cleaned text on standard output
cat app.log | scrubdaddy clean - --count    # {{EMAIL-0}}, numbered per entity
scrubdaddy find notes.txt --json            # one JSON object per finding
scrubdaddy list-detectors --locale ru_RU    # what would run here
```

`find` leaves the matched text out of its output unless `--include-text` is
given, and `--exit-code` makes it exit non-zero when anything was found, which
is enough to fail a build on a leaked key:

```bash
scrubdaddy find --detectors secret,password --exit-code src/**/*.py
```

## Finding without replacing

Every finding carries its position, kind, detector and confidence, so it can be
reviewed or logged instead of replaced. The matched text is left out of the
serialised form unless asked for, since the usual reason to keep findings is an
audit trail stored somewhere less protected than the document.

```python
for finding in scrubdaddy.find("card 4111 1111 1111 1111"):
    print(finding.to_dict())
# {'beg': 5, 'end': 24, 'pii_type': 'credit_card', 'detector': 'credit_card',
#  'score': 1.0, 'locale': 'en_US'}
```

## Readable output

A bare placeholder loses the fact that two mentions are the same person.
Numbering keeps it, within a document and across a batch:

```python
from scrubdaddy import Scrubber, Token

scrubber = Scrubber(renderer=Token(include_count=True))
scrubber.clean_documents({
    "a.txt": "joe@example.com wrote",
    "b.txt": "joe@example.com and kim@example.com replied",
})
# {'a.txt': '{{EMAIL-0}} wrote', 'b.txt': '{{EMAIL-0}} and {{EMAIL-1}} replied'}
```

The numbering lives on the scrubber, not on the class, so two scrubbers in one
process cannot bleed into each other. It can also be stored and handed to a
later run, so the same person keeps the same token tomorrow:

```python
from scrubdaddy import TokenMap

stored = scrubber.tokens.to_dict()
later = Scrubber(renderer=Token(include_count=True), tokens=TokenMap.from_dict(stored))
```

Instead of numbering, a salted fingerprint gives the same stability without
keeping a map. The salt is required rather than generated, because the space of
phone or card numbers is small enough to walk through, which would make an
unsalted fingerprint reversible by whoever holds the output:

```python
Scrubber(renderer=Token(include_hash=True, salt="…")).clean("joe@example.com")
# '{{EMAIL-7C9A4F12}}'
```

`Mask` and `Remove` cover the cases where no label is wanted.

## Confidence, and detectors that disagree

Detectors report how sure they are, so the caller sets the bar rather than the
library:

```python
Scrubber(min_score=0.8)
```

When two detectors claim overlapping text, the conflict is settled by a
strategy you choose: the most confident match, the longest one, both fused into
one replacement, or all of them kept for auditing. A long weak match that loses
does not hide short strong ones underneath it. Findings that merely touch are
never glued together.

```python
from scrubdaddy import Strategy

Scrubber(strategy=Strategy.LONGEST)
Scrubber(strategy=Strategy.KEEP_ALL)  # for review, not for replacing
```

## Locales

Identifiers like national insurance or tax numbers are country-specific, so a
scrubber runs in a locale and only uses detectors that make sense there:

```python
Scrubber(locale="en_GB")
```

## Custom detectors

```python
import re
from scrubdaddy import RegexDetector, Scrubber
from scrubdaddy.detectors import default_registry

class EmployeeIdDetector(RegexDetector):
    name = "employee_id"
    pii_type = "employee_id"
    pattern = re.compile(r"\bEMP-\d{6}\b")

registry = default_registry()
registry.register(EmployeeIdDetector, autoload=True)
Scrubber(registry=registry).clean("ticket from EMP-123456")
# 'ticket from {{EMPLOYEE_ID}}'
```

Registering does not enrol a detector into the default set unless asked, so
importing a module cannot quietly change what every scrubber does. The registry
is an object, not process-wide state: `default_registry()` hands out a fresh one
and `copy()` branches it.

A package can also advertise its detectors so that they appear without being
imported by hand:

```toml
[project.entry-points."scrubdaddy.detectors"]
employee_id = "my_package.detectors:EmployeeIdDetector"
```

They are listed by `scrubdaddy list-detectors` and usable by name, but stay out
of the default set until enabled, and a plugin claiming a name that is already
taken is passed over rather than allowed to shadow it. Nothing from the plugin
is imported until the detector is used.

Patterns are expected to be free of nested unbounded quantifiers so that they
stay linear on hostile input. The test suite runs every shipped pattern against
a corpus of pathological strings under a time budget, with a known-bad pattern
as a canary to prove the check still has teeth.
