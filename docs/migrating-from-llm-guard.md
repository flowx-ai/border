# Migrating from llm-guard

`flowx_border.adapters.llm_guard_compat` keeps llm-guard's `scan_prompt` and
`scan_output` signatures and its tuple return shape, so a migration starts as an import
change. This table is generated from `SUPPORTED` and `UNSUPPORTED` in that module, so it
cannot drift away from what the code actually does.

## The one thing to read before migrating

**A scanner with no equivalent raises `UnsupportedScannerError`.** It does not pass and it
does not warn. A shim that accepted `BanCode` and did nothing would leave you believing
code was blocked, and the only way to find out otherwise would be an incident. Every
scanner llm-guard shipped is in one of the two tables below.

## Supported

| llm-guard scanner | detector | tier | side |
|---|---|---|---|
| `Anonymize` | `pii` | T1 | input, output |
| `BanCompetitors` | `banned_terms` | T1 | input, output |
| `BanSubstrings` | `banned_terms` | T1 | input, output |
| `BanTopics` | `topic_scope` | T3 | input |
| `Bias` | `bias` | T2 | output |
| `Deanonymize` | `output_leakage` | T1 | output |
| `FactualConsistency` | `groundedness` | T3 | output |
| `Gibberish` | `gibberish` | T1 | input |
| `JSON` | `output_format` | T1 | output |
| `NSFW` | `nsfw` | T2 | input, output |
| `NoRefusal` | `politeness` | T2 | output |
| `PromptInjection` | `injection` | T2 | input |
| `ReadingTime` | `output_format` | T1 | output |
| `Regex` | `output_format` | T1 | output |
| `Relevance` | `topic_scope` | T3 | input |
| `Secrets` | `secrets` | T0 | input |
| `Sensitive` | `output_leakage` | T1 | output |
| `Toxicity` | `toxicity` | T2 | input, output |
| `URLReachability` | `url_reachability` | T3 | output |

Two of these are worth a note.

`Anonymize` and `Deanonymize` were a pair in llm-guard: the first replaced entities with
placeholders and the second put them back. This library does not put them back. Redaction
is one way, because a vault mapping placeholders to real values is a second copy of the
data you were trying not to expose. `Deanonymize` therefore maps to `output_leakage`,
which answers the question the pair was usually being used for: did personal data appear
in the output that the user never supplied.

`NoRefusal` maps to `politeness`, and the fit is loose. llm-guard looked for a model
refusing to answer; `politeness` scores whether the tone is acceptable. If you relied on
`NoRefusal` to detect capability failures rather than rudeness, this is not the same check
and you should say so in your policy rather than assume it carried over.

## Unsupported

| llm-guard scanner | why not |
|---|---|
| `BanCode` | no code detector. sql_injection parses generated SQL and says nothing about code in any other language, or about whether prose contains a code block. |
| `Code` | no code detector, as above. |
| `InvisibleText` | no detector reports these characters yet. Half the work is done: detectors/multilingual.py drops zero-width and format characters before matching, so they cannot be used to evade a term. What is missing is a detector that reports their presence as a finding in its own right. |
| `Language` | no language identification detector. The library supports 26 languages in every detector rather than gating on which one a text is in. |
| `LanguageSame` | no language identification, as above. |
| `MaliciousURLs` | no URL reputation detector. url_reachability asks whether a link answers, which is a different question from whether it is hostile, and answering the second needs a reputation feed this library does not ship. |
| `Sentiment` | no sentiment detector. politeness is the nearest, and it is not the same. |
| `TokenLimit` | output_format counts graphemes and words, and a token limit is neither. Tokens depend on the tokenizer of the model you are calling, which this library does not know, so mapping this onto max_length would report a different number than the one you asked about. |

`InvisibleText` is the one on that list worth flagging as a genuine gap rather than a
rejected idea. Zero-width and bidi-control characters are a real prompt-injection vector,
the check is pure rules, and it would be a T0 detector costing nothing. It is absent
because the detector set is fixed for v1 and adding a fourteenth needs an explicit
instruction, not because it is a bad idea.

## What changes in your code

```python
# before
from llm_guard import scan_prompt
from llm_guard.input_scanners import Anonymize, PromptInjection

sanitised, valid, scores = scan_prompt(prompt, [Anonymize(vault), PromptInjection()])

# after
from flowx_border.adapters.llm_guard_compat import scan_prompt

sanitised, valid, scores = scan_prompt(prompt, ["Anonymize", "PromptInjection"])
```

Behaviour differences that the tuple cannot express:

- **Configuration is a policy file, not constructor arguments.** llm-guard configured a
  scan by how you built the scanners. Here it is YAML validated by a schema, so a
  compliance officer who does not write Python can read what runs. Pass `policy=` to use
  one; without it you get the named scanners at their defaults.
- **There is an evidence record.** The tuple has nowhere to put it. `decision_for()`
  returns the real `Decision`, and the record is the reason to be here at all.
- **T0 always runs.** `secrets` and `disclosure` are in every scan whether you asked or
  not, because T0 cannot be disabled. They are set to `flag` in the compat policy, so a
  migration does not start blocking traffic that llm-guard was allowing.

## Scanners we added that llm-guard had no equivalent for

- `disclosure` (T0, output)
- `regulated_advice` (T2, output)
- `banned_terms` (T1, input and output)
- `system_prompt_leakage` (T1, output)
- `markup_injection` (T1, input and output)
- `internal_domains` (T1, output)
- `output_format` (T1, output)
- `sql_injection` (T1, output, needs the `sql` extra)
- `url_reachability` (T3, output, makes an HTTP request)
- `invisible_text` (T0, input and output)
- `postal_code` (T1, output)

The last nine arrived on 2026-08-11 with the Guardrails Hub port, and six of them
moved a scanner out of the unsupported table above.

## Scanners that gained a detector on 2026-08-11

`BanSubstrings`, `BanCompetitors`, `JSON`, `Regex`, `ReadingTime` and `URLReachability`
were all declined before that date because the detector they need did not exist. It
does now, and they are mapped.

**Five of them raise unless you pass a policy.** llm-guard configured a scan by how you
built the scanner, `BanSubstrings(substrings=[...])`. Here configuration is policy, and
this shim cannot read a constructor argument even when you pass an instance, because
those attribute names are private to llm-guard and guessing one wrong yields an empty
list rather than an error. An empty list is the case that matters: `banned_terms` with
no terms reports `terms_not_configured` and finds nothing, so accepting the call would
hand you a clean-looking tuple for a check that never ran. `UnconfiguredScannerError`
names the option to set.

| scanner | set this in your policy |
|---|---|
| `BanSubstrings` | `banned_terms.options.terms`, with `whole_words: false` |
| `BanCompetitors` | `banned_terms.options.terms` |
| `Regex` | `output_format.options.regex` |
| `ReadingTime` | `output_format.options.max_reading_seconds` |
| `JSON` | `output_format.options.json: true` |

`URLReachability` is not on that list because it has usable defaults. It is the one
mapping that changes what your deployment needs: `url_reachability` declares
`requires={"network"}`, so enabling it puts a third party in the latency path of every
scan. `registry.deployment_notes` returns a line saying so. It also refuses to request
private addresses, which llm-guard's version does not, so a URL resolving to your
intranet is reported rather than fetched.

## Three that are still refused, and why the near miss was refused too

`TokenLimit` looks like it maps to `output_format` and does not. That detector counts
graphemes and words; a token limit counts tokens, and tokens depend on the tokenizer of
the model you are calling, which this library does not know. Mapping it would report a
different number than the one you asked about.

`MaliciousURLs` looks like it maps to `url_reachability` and does not. Whether a link
answers and whether a link is hostile are different questions, and the second needs a
reputation feed this library does not ship.

`InvisibleText` is no longer one of them. `invisible_text` closes it: it reports
bidirectional controls, tag characters and zero-width characters, at T0, on both sides.
The shim still raises for the scanner name, for the same reason as the entries above,
and the mapping is a one-line change to `SUPPORTED` whenever somebody wants it.

`disclosure` is the one to look at if you are here for an AI Act evidence trail: it
reports whether a required disclosure is present in the output, in any of 26 languages,
and records the affirmative rather than only the absence.
