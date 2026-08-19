# Per-locale entity values, for the leak test

`entities_by_locale.json` holds one value of each of `PERSON`, `EMAIL`, `PHONE`,
`NATIONAL_ID`, `IBAN` and `CARD` for each of the 26 supported locales. Every value is correct
by construction: a real checksum where the scheme has one, and the documented format where it
does not, which is Malta's and Azerbaijan's national identifiers.

Generated once by `border_train.pii_fill._surface` in the training repository, seeded per
locale, and committed here so `tests/test_no_leak.py` runs in CI without access to that
repository or to any corpus. Regenerate it there if a locale's generator changes; do not
hand-edit a value, because a wrong checksum would make the test assert something else.

## Why it exists

`tests/test_ordinary_text_sweep.py` measures over-redaction, and nothing measured the
opposite direction end to end. On 2026-08-19 that gap held a disclosure: the `NATIONAL_ID`
shape gate required four digits, an Azerbaijani identifier carries as few as zero, and a
rejected shape is dropped, so **52 of 272 held-out Azerbaijani identifiers reached the caller
verbatim** with the model having tagged every one of them correctly.

The measurement that existed, `heldout_ner_eval`'s token coverage, could not see it. It asks
whether every gold token is covered by *some* predicted span, and these spans were predicted
before being dropped a layer later. **Coverage in the tagger is not survival through the
library**, and only the second is what a caller receives.
