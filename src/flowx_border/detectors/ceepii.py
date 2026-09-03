# SPDX-License-Identifier: Apache-2.0
"""cee-pii: a GLiNER span model, policy-selectable for `pii` via `options.model`.

Set `pii: { options: { model: cee-pii } }` and `PiiDetector.run` dispatches here
instead of the default XLM-RoBERTa BIO tagger. Person-name precision on a
hand-verified 13-document legal/press corpus was 0.915 to 0.924, against 0.229 for
the incumbent, which is why this exists despite being a second architecture to
maintain.

Why this is a from-scratch reimplementation and not a call into the `gliner`
package
--------------------------------------------------------------------------

Every other model-backed detector in this library reduces its training-time
architecture to the same thing at runtime: an onnxruntime session, the
`tokenizers` fast tokenizer, and a bespoke decode function. Nothing here pulls in
`torch` or a training framework, which is what makes CORE run on a laptop with the
network interface down. `gliner` unconditionally depends on `torch`, so calling
`GLiNER.from_pretrained(..., load_onnx_model=True)` from inside a detector would
still pull in the full PyTorch install for one alternative model inside one
detector, which is a different order of dependency than `sqlglot` or `jsonschema`
and would break that property for every caller, not just the ones who select
`cee-pii`.

So this module ports the pre/post-processing by hand: word splitting, the
`<<ENT>>`/label/`<<SEP>>` prompt GLiNER prepends to the text, span enumeration,
sigmoid decoding with greedy non-overlap resolution, and mapping word indices back
to character offsets. Each piece is a direct port of a specific function in
`gliner`'s own source (versions pinned in the training repo's
`border_train/export/gliner_to_onnx.py`, which is also where the ONNX export and
its equivalence check live), cited in place so a future reader can diff against
upstream if cee-pii is ever retrained on a newer GLiNER release:

    `_split_words` ports `WhitespaceTokenSplitter.__call__`, in
      `gliner/data_processing/tokenizer.py`.
    `_prompt_words` ports `BaseProcessor.prepare_inputs`, in
      `gliner/data_processing/processor.py`.
    `_words_mask` ports `prepare_word_mask`, in
      `gliner/data_processing/utils.py`.
    `_span_candidates` ports `prepare_span_idx`, in
      `gliner/data_processing/utils.py`.
    `_decode` ports `SpanDecoder._decode_explicit_spans`, in
      `gliner/decoding/decoder.py`.
    `_greedy_search` ports `BaseDecoder.greedy_search` plus `has_overlapping`, in
      `gliner/decoding/decoder.py` and `gliner/decoding/utils.py`.
    The word-index-to-character mapping in `run`, below, ports
      `GLiNER._map_entities_to_original`, in `gliner/model.py`.

Verified against the real `gliner` package rather than against this port's own
reading of the source: `border_train/export/gliner_to_onnx.py`'s `verify()`
round-trips text through both `GLiNER.predict_entities` and the exported ONNX
graph and diffs the decoded spans and scores. That check is what caught, before
this module existed, that a naive tokenizer call would have silently disagreed
with GLiNER's own: the Rust `tokenizers` library loaded straight from
`tokenizer.json` was confirmed byte-identical to GLiNER's HF-tokenizer wrapper,
token ids and word ids both, on the exact prompt shape this module builds.

batch_size=1, always. The ONNX export this module loads was only proven exact at
batch_size=1 (see `gliner_to_onnx.py`'s module docstring for why packing a padded
LSTM batch could not be avoided any other way), and this module never builds a
batch, which is also just what every other detector here already does: one
window, one call.

The label mapping
------------------

cee-pii tags 34 fine-grained types; `pii`'s vocabulary is the 8 border already
has (CARD, DATE, EMAIL, IBAN, NATIONAL_ID, PERSON, PHONE, LOCATION). `_LABEL_MAP`
is the correspondence, and fifteen of the 34 have no honest one:

- `aba`, `uk_sort_code` are bank routing codes, not personal identifiers.
- `uk_account_number`, `uz_account` are domestic account numbers with no IBAN
  checksum. Mapping either to `iban` would mean every span of that type fails
  `checksummed.iban_ok` and gets silently downgraded by the shape gate below,
  which is a worse lie than not offering the type at all.
- `ein`, `company_number_uk`, `employer` identify a business, not a person.
- `plate` identifies a vehicle.
- `postal` has no home in `pii`'s type set; `detectors/postal_code.py` is the
  library's answer to postal codes, a different detector with a different shape.
- `policy_ref`, `contract_ref`, `account_ref` are generic reference numbers with
  no personal-identity claim attached to the string itself.
- `health_condition` is sensitive health data, and none of the 8 types covers it.
  Dropping it here is the honest answer; inventing a ninth type is not this
  module's call to make.
- `first_name`, `surname` are not a coverage gap, they are measured to actively
  hurt: prompting them alongside `person_name` splits the model's confidence
  across three overlapping phrasings for one concept. See `_LABEL_MAP`'s own
  comment for the number.

Every mapped span still passes through `pii.apply_shape_gate`, the same function
`PiiDetector.run` uses: whether an EMAIL has an `@` in it does not depend on which
model tagged it, so CARD, IBAN, NATIONAL_ID and PHONE spans from cee-pii get the
same checksum treatment piiguard's do.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from flowx_border.detectors.base import DetectorConfig
from flowx_border.detectors.pii import (
    ENTITY_TYPES,
    apply_shape_gate,
    entity_actions,
    entity_thresholds,
    wanted_entities,
)
from flowx_border.types import Finding

if TYPE_CHECKING:
    import numpy as np
    from tokenizers import Tokenizer

    from flowx_border.models.onnx import LoadedModel

MODEL_ID: Final = "cee-pii"

#: GLiNER's own special tokens for this model, from its config. Verbatim, not
#: guessed: a wrong marker token tokenizes as ordinary text instead of the
#: single reserved id the model was trained to recognise as "a label follows".
ENT_TOKEN: Final = "<<ENT>>"  # noqa: S105 - a model marker token, not a credential
SEP_TOKEN: Final = "<<SEP>>"  # noqa: S105

#: `max_width` from cee-pii's own `gliner_config.json`: the widest span, in words,
#: the model was trained to score. Not derived from the ONNX graph because the
#: graph's span dimension is dynamic; this is a property of training, not of the
#: export.
MAX_WIDTH: Final = 12

#: `WhitespaceTokenSplitter.whitespace_pattern` from
#: `gliner/data_processing/tokenizer.py`, copied rather than imported for the
#: reason the module docstring gives. A run of word characters (letters, digits,
#: underscore) optionally hyphen- or underscore-joined, or any single non-space
#: character standing alone. `re.finditer` over this pattern is GLiNER's own word
#: splitter, char-for-char: verified against it in
#: `border_train/export/gliner_to_onnx.py`.
_WORD_SPLIT: Final = re.compile(r"\w+(?:[-_]\w+)*|\S")

#: (short type, the exact phrasing cee-pii was fine-tuned on, border's entity type
#: or None). The phrasing has to be the literal string from
#: `flowxai/cee-pii`'s `inference_contract/labels_ceepii_v1.json`: GLiNER
#: labels are the prompt, not a lookup key, and a paraphrase is a different,
#: untrained prompt.
_LABEL_MAP: Final[tuple[tuple[str, str, str | None], ...]] = (
    ("cnp", "Romanian personal numeric code (CNP)", "national_id"),
    ("ci_ro", "Romanian ID card series and number", "national_id"),
    ("pesel", "Polish PESEL national identification number", "national_id"),
    ("nip", "Polish NIP tax identification number", "national_id"),
    ("taj", "Hungarian TAJ social security number", "national_id"),
    (
        "szemelyi",
        "Hungarian personal identification number (szemelyi szam)",
        "national_id",
    ),
    ("pinfl", "Uzbek personal identification number (PINFL)", "national_id"),
    ("iban", "IBAN bank account number", "iban"),
    ("card", "payment card number", "card"),
    ("nhs", "UK NHS number", "national_id"),
    ("aba", "US bank ABA routing number", None),
    ("ssn", "US Social Security Number (SSN)", "national_id"),
    ("itin", "US Individual Taxpayer Identification Number (ITIN)", "national_id"),
    ("ein", "US Employer Identification Number (EIN)", None),
    ("nino", "UK National Insurance number (NINO)", "national_id"),
    ("utr", "UK Unique Taxpayer Reference (UTR)", "national_id"),
    ("company_number_uk", "UK Companies House company registration number", None),
    ("uk_sort_code", "UK bank sort code", None),
    ("uk_account_number", "UK bank account number", None),
    ("uz_account", "Uzbek domestic bank account number", None),
    ("phone", "telephone number", "phone"),
    ("email", "email address", "email"),
    ("plate", "vehicle registration plate", None),
    ("postal", "postal code", None),
    ("dob", "date of birth", "date"),
    ("person_name", "person name", "person"),
    # `first_name` and `surname` are not mapped, deliberately, and measured rather
    # than assumed: prompting all three "person" phrasings at once on "Ionescu
    # Bogdan" split the signal across them, `person's surname` 0.4044 on
    # "Ionescu" and `person's first name` 0.3679 on "Bogdan", both under any
    # reasonable threshold. Dropping the two redundant phrasings and prompting
    # `person_name` alone finds the whole span, "Ionescu Bogdan", at 0.9948.
    # Three overlapping prompts for one concept cost recall; they do not add any.
    ("first_name", "person's first name", None),
    ("surname", "person's surname", None),
    ("address", "street address", "location"),
    ("policy_ref", "insurance policy number", None),
    ("contract_ref", "contract reference number", None),
    ("account_ref", "internal account reference number", None),
    ("employer", "employer or company name", None),
    ("health_condition", "health condition or medical status", None),
)

#: phrasing -> border entity type, for the labels that map to one.
_PHRASING_TO_BORDER: Final[dict[str, str]] = {
    phrasing: border for _short, phrasing, border in _LABEL_MAP if border is not None
}

#: border entity type -> every phrasing that maps to it, in `_LABEL_MAP`'s order.
#: Order matters here: it becomes the prompt order, which becomes the order of
#: the model's own output columns (see `_decode`).
_BORDER_TO_PHRASINGS: Final[dict[str, tuple[str, ...]]] = {
    border: tuple(p for _s, p, b in _LABEL_MAP if b == border)
    for border in dict.fromkeys(b for _s, _p, b in _LABEL_MAP if b is not None)
}

#: Every border entity type cee-pii can produce. Used both to validate
#: `options.entities` and, together with `pii.ENTITY_TYPES`, to confirm this
#: table covers what it claims to: `tests/test_ceepii.py` asserts the two sets
#: are equal, so a future edit to either dictionary that silently drops a type
#: fails a test rather than shipping a detector that always finds one fewer
#: thing than the policy asked for.
MAPPED_ENTITY_TYPES: Final[tuple[str, ...]] = tuple(sorted(_BORDER_TO_PHRASINGS))

_TOKENIZER_CACHE: dict[str, Tokenizer] = {}


def _tokenizer(model_id: str) -> Tokenizer:
    cached = _TOKENIZER_CACHE.get(model_id)
    if cached is not None:
        return cached
    from tokenizers import Tokenizer

    from flowx_border.models.registry import companion

    tokenizer = Tokenizer.from_file(str(companion(model_id, "tokenizer.json")))
    _TOKENIZER_CACHE[model_id] = tokenizer
    return tokenizer


def _split_words(text: str) -> list[tuple[str, int, int]]:
    """`(word, char_start, char_end)` triples. See `_WORD_SPLIT`'s docstring."""
    return [(m.group(), m.start(), m.end()) for m in _WORD_SPLIT.finditer(text)]


def _prompt_words(phrasings: list[str]) -> list[str]:
    """`[<<ENT>>, phrasing, <<ENT>>, phrasing, ..., <<SEP>>]`.

    Ports `BaseProcessor.prepare_inputs`. Each phrasing is one element of the
    word list even though it contains spaces: GLiNER's own tokenizer call passes
    labels the same way, `is_split_into_words=True`, treating a multi-word
    phrasing as one pre-tokenized unit whose internal words share one word id.
    """
    words: list[str] = []
    for phrasing in phrasings:
        words.append(ENT_TOKEN)
        words.append(phrasing)
    words.append(SEP_TOKEN)
    return words


def _words_mask(word_ids: list[int | None], prompt_length: int) -> list[int]:
    """Ports `prepare_word_mask` at `subtoken_pooling="first"`, cee-pii's own config.

    0 for a special token, a prompt word, or a non-first subtoken. Otherwise the
    word's 1-indexed position within the text, not counting the prompt: word id
    `prompt_length` becomes 1, `prompt_length + 1` becomes 2, and so on. Word ids
    from a pre-tokenized encode are already 0-indexed and monotonic with no gaps,
    so `seen_words` in the original (a running count of distinct ids so far) is
    always `word_id + 1` at the moment a new word starts, which is what lets this
    be a direct formula instead of a running counter.
    """
    mask: list[int] = []
    previous: int | None = None
    for word_id in word_ids:
        if word_id is None or word_id < prompt_length or word_id == previous:
            mask.append(0)
        else:
            mask.append(word_id - prompt_length + 1)
        previous = word_id
    return mask


def _span_candidates(num_text_words: int) -> np.ndarray:
    """Ports `prepare_span_idx`: every `(start, end)` word-index pair, `end`
    inclusive, widths 1 to `MAX_WIDTH` words, in start-major order.

    Includes spans whose `end` runs past the text (filtered by `span_mask`
    afterwards), because that is what `prepare_span_idx` itself does: it has no
    knowledge of where the text ends, only of how many words there are to start a
    span from.
    """
    import numpy as np

    starts = np.repeat(np.arange(num_text_words), MAX_WIDTH)
    offsets = np.tile(np.arange(MAX_WIDTH), num_text_words)
    return np.stack([starts, starts + offsets], axis=1).astype(np.int64)


def _build_inputs(
    tokenizer: Tokenizer, phrasings: list[str], text_words: list[str]
) -> dict[str, np.ndarray]:
    import numpy as np

    prompt_words = _prompt_words(phrasings)
    encoded = tokenizer.encode(prompt_words + text_words, is_pretokenized=True)
    words_mask = _words_mask(encoded.word_ids, len(prompt_words))

    num_text_words = len(text_words)
    span_idx = _span_candidates(num_text_words)
    span_mask = span_idx[:, 1] < num_text_words

    input_ids = np.asarray([encoded.ids], dtype=np.int64)
    return {
        "input_ids": input_ids,
        "attention_mask": np.ones_like(input_ids),
        "words_mask": np.asarray([words_mask], dtype=np.int64),
        "text_lengths": np.asarray([[num_text_words]], dtype=np.int64),
        "span_idx": span_idx[None, :, :],
        "span_mask": span_mask[None, :],
    }


def _sigmoid(logits: np.ndarray) -> np.ndarray:
    """`1 / (1 + exp(-x))`, split by sign so neither branch overflows.

    A span the model is confident is *not* a match reads a large negative logit,
    and `exp(-x)` on the plain formula overflows there: correct once IEEE infinity
    propagates (`1 / (1 + inf) == 0.0`), but a RuntimeWarning on every ordinary
    scan is not something a caller of this library should see. `exp(x)/(1+exp(x))`
    is the same function and does not overflow on that side.
    """
    import numpy as np

    positive = logits >= 0
    probabilities = np.empty_like(logits, dtype=np.float64)
    probabilities[positive] = 1.0 / (1.0 + np.exp(-logits[positive]))
    negative_exp = np.exp(logits[~positive])
    probabilities[~positive] = negative_exp / (1.0 + negative_exp)
    return probabilities


def _greedy_search(
    candidates: list[tuple[int, int, str, float]],
) -> list[tuple[int, int, str, float]]:
    """Ports `BaseDecoder.greedy_search` + `has_overlapping`, `flat_ner=True` and
    `multi_label=False`, which is what `predict_entities` defaults to and what
    `pii`'s own single-label-per-span model already assumes.

    Highest score wins any overlap, including two different labels claiming the
    exact same span. Kept spans are returned in start order.
    """
    selected: list[tuple[int, int, str, float]] = []
    for start, end, label, score in sorted(candidates, key=lambda c: -c[3]):
        overlaps = any(
            (start, end) == (s_start, s_end) or not (start > s_end or s_start > end)
            for s_start, s_end, _, _ in selected
        )
        if not overlaps:
            selected.append((start, end, label, score))
    selected.sort(key=lambda c: c[0])
    return selected


def _decode(
    logits: np.ndarray,
    span_idx: np.ndarray,
    span_mask: np.ndarray,
    phrasings: list[str],
    threshold: float,
) -> list[tuple[int, int, str, float]]:
    """Ports `SpanDecoder._decode_explicit_spans`: sigmoid, threshold, then
    `_greedy_search`. Returns `(word_start, word_end, phrasing, score)`, both
    ends inclusive, matching `prepare_span_idx`'s own convention.

    The graph's raw output is `(num_text_words, MAX_WIDTH, num_labels)`, not
    pre-flattened against `span_idx`'s own `(num_spans, 2)`. Reshaping to
    `(num_text_words * MAX_WIDTH, num_labels)` lines the two up because both are
    word-major, width-minor in the same order: `span_idx` was built that way by
    `_span_candidates`, and a C-order reshape of the graph's output walks the
    same order, width fastest within a word. `SpanDecoder._decode_explicit_spans`
    does the equivalent flatten on the torch side for a 4-D batched tensor
    (`probabilities.flatten(1, 2)`); this is that reshape for the unbatched
    3-D case this module always has, batch_size=1.
    """
    import numpy as np

    probabilities = _sigmoid(logits).reshape(-1, logits.shape[-1])
    candidate_mask = span_mask[:, None] & (probabilities > threshold)
    span_positions, class_indices = np.where(candidate_mask)
    positions = zip(span_positions, class_indices, strict=True)
    candidates = [
        (
            int(span_idx[span_position, 0]),
            int(span_idx[span_position, 1]),
            phrasings[class_index],
            float(probabilities[span_position, class_index]),
        )
        for span_position, class_index in positions
    ]
    return _greedy_search(candidates)


def run(text: str, cfg: DetectorConfig, *, model_id: str = MODEL_ID) -> list[Finding]:
    """`pii`'s `run`, for `options.model: cee-pii`. See the module docstring."""
    if not text.strip():
        return []

    from flowx_border.models.onnx import DEFAULT_THREADS, session_for
    from flowx_border.models.registry import attestation_for

    wanted = wanted_entities(cfg, MAPPED_ENTITY_TYPES)
    phrasings = [
        phrasing
        for border in sorted(wanted)
        for phrasing in _BORDER_TO_PHRASINGS[border]
    ]
    if not phrasings:
        return []

    text_words = _split_words(text)
    if not text_words:
        return []
    words = [word for word, _start, _end in text_words]

    tokenizer = _tokenizer(model_id)
    inputs = _build_inputs(tokenizer, phrasings, words)

    threads = int(cfg.options.get("threads", DEFAULT_THREADS))
    loaded: LoadedModel = session_for(model_id, threads=threads)
    outputs = loaded.run(inputs)
    logits = outputs[0][0]

    decoded = _decode(
        logits, inputs["span_idx"][0], inputs["span_mask"][0], phrasings, cfg.threshold
    )

    # weights_sha256 is not part of Finding; it lives on the top-level detector
    # attestation, which `PiiDetector.run` already sets before dispatching here.
    model_id_attest, revision, _sha256 = attestation_for(model_id)
    actions = entity_actions(cfg, MAPPED_ENTITY_TYPES)
    bars = entity_thresholds(cfg, MAPPED_ENTITY_TYPES)
    validate = bool(cfg.options.get("validate_shapes", True))

    out: list[Finding] = []
    for word_start, word_end, phrasing, score in decoded:
        char_start = text_words[word_start][1]
        char_end = text_words[word_end][2]
        entity = _PHRASING_TO_BORDER[phrasing]
        span = (char_start, char_end)
        out.extend(
            apply_shape_gate(
                entity,
                text[char_start:char_end],
                span,
                score,
                actions=actions,
                bars=bars,
                on_fail=cfg.on_fail,
                validate=validate,
                detector_id="pii",
                tier="T1",
                model_id=model_id_attest,
                model_revision=revision,
            )
        )
    return out


if not set(MAPPED_ENTITY_TYPES) <= set(ENTITY_TYPES):  # pragma: no cover - a code bug
    # Not an assert: stripped under -O, which is not a property to rely on for a
    # security library. This checks the two label tables agree at import time
    # rather than trusting a comment; see tests/test_ceepii.py for the same check
    # kept independently of whether this module was ever imported with -O.
    raise RuntimeError(
        "cee-pii's label map produces a border entity type piiguard does not know, "
        "which would make options.entities validate against one model and mean "
        "something different against the other"
    )
