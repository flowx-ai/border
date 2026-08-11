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
| `BanTopics` | `topic_scope` | T3 | input |
| `Bias` | `bias` | T2 | output |
| `Deanonymize` | `output_leakage` | T1 | output |
| `FactualConsistency` | `groundedness` | T3 | output |
| `Gibberish` | `gibberish` | T1 | input |
| `NSFW` | `nsfw` | T2 | input, output |
| `NoRefusal` | `politeness` | T2 | output |
| `PromptInjection` | `injection` | T2 | input |
| `Relevance` | `topic_scope` | T3 | input |
| `Secrets` | `secrets` | T0 | input |
| `Sensitive` | `output_leakage` | T1 | output |
| `Toxicity` | `toxicity` | T2 | input, output |

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
| `BanCode` | no code detector. Out of scope for v1; the detector set is fixed. |
| `BanCompetitors` | a competitor wordlist is customer-specific data, not a model. Express it as a policy over topic_scope, or keep it in your own code. |
| `BanSubstrings` | a substring list belongs in your code, not behind a model download. |
| `Code` | no code detector, as above. |
| `InvisibleText` | no zero-width or bidi-control detector yet. This is a real gap rather than a rejected idea: it is cheap and rule-based, and it would be a T0 addition. |
| `JSON` | output shape validation is not a security check and is better done by your schema. |
| `Language` | no language identification detector. The library supports 26 languages in every detector rather than gating on which one a text is in. |
| `LanguageSame` | no language identification, as above. |
| `MaliciousURLs` | no URL reputation detector. It would need a network call at scan time, which constraint 1 rules out. |
| `ReadingTime` | not a security check. |
| `Regex` | a regex list belongs in your code, not behind a model download. |
| `Sentiment` | no sentiment detector. politeness is the nearest, and it is not the same. |
| `TokenLimit` | token counting is the caller's concern, not a security check. |
| `URLReachability` | reachability is a network call at scan time, which constraint 1 rules out. |

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

The last four arrived on 2026-08-11 with the Guardrails Hub port, and two of them change
what the unsupported table above is really saying.

**`BanSubstrings` and `BanCompetitors` now have a detector-level answer.** `banned_terms`
is that mechanism, with word boundaries and 26-language folding, so the reason those two
scanners were declined ("keep it in your own code") is weaker than it was. The shim
above still raises for them: mapping them across is an edit to
`adapters/llm_guard_compat.py` that the port did not make, and a doc that claimed the
mapping existed while the code raised would be worse than one that says this plainly.
See `docs/porting-guardrails-validators.md`.

**`InvisibleText` is closer than it was.** The zero-width and format-character stripping
that the note above asks for is implemented, in `detectors/multilingual.py`, and every
ported detector matches through it. What is missing is a detector that reports the
presence of those characters as a finding in its own right rather than quietly seeing
past them. That is still a gap, and it is still cheap.

`disclosure` is the one to look at if you are here for an AI Act evidence trail: it
reports whether a required disclosure is present in the output, in any of 26 languages,
and records the affirmative rather than only the absence.
