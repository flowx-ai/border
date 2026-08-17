# SPDX-License-Identifier: Apache-2.0
"""Which weights a detector loads, pinned to a commit.

Every entry names a revision that is a commit sha, never a branch. A branch name means
the model can change under a deployed library without the version changing, and an
evidence record that attests `main` attests nothing: an auditor asked to reproduce a
decision from six months ago would get whatever `main` is today. `revision` here is what
makes `EvidenceRecord.detectors[].revision` a fact.

Each entry also carries the expected sha256 of its weight file. Two reasons, and the
second is the one that matters:

1. Attestation. The record says which bytes ran, and the hash has to come from somewhere
   that is not the file itself, or it only says "this file hashes to its own hash".
2. Integrity. A truncated download and a substituted file look alike to a loader that
   only checks the path exists. `resolve` compares and refuses.

Three detectors have no entry, and that is deliberate rather than unfinished:
`injection`, `regulated_advice` and `groundedness` were trained but their artifacts are
published yet. CLAUDE.md requires they ship unavailable and loudly, so the registry
names the intended repo and `resolve` raises with that name in the message. There is no
silent fallback to a smaller model, because a security library that quietly substitutes
a different detector is worse than one that refuses to start.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from flowx_border.detectors.multilingual import LANGUAGES

# The default cache location. Overridden by HF_HOME or HF_HUB_CACHE, which
# huggingface-hub reads itself; this constant exists only so that error messages can
# name a concrete path instead of saying "the cache".
DEFAULT_CACHE_HINT: Final = "~/.cache/huggingface/hub"


class ModelUnavailableError(RuntimeError):
    """The weights a detector needs cannot be obtained.

    Carries the repo id in the message on purpose. The most common reason for this in v1
    is a detector whose model is not published yet, and the useful thing to tell someone
    is which repo to watch.
    """


@dataclass(frozen=True)
class ModelSpec:
    """One model: where it lives, which commit, and what its bytes should hash to."""

    model_id: str
    repo: str
    # A commit sha. Enforced in __post_init__ rather than trusted, because a branch name
    # here silently unpins the model.
    revision: str
    filename: str
    sha256: str
    # Files fetched alongside the weights. The tokenizer is not optional: character
    # offsets come from it, and a span computed against a different tokenizer than the
    # one the model was trained with is a wrong span, not an approximate one.
    extra_files: tuple[str, ...] = ()
    # True when these weights came from a directory on this machine rather than from a
    # pinned commit on the hub. It changes what may be attested: see __post_init__.
    local: bool = False
    # The token length the model was trained at. Windowing uses it, and the latency
    # figures quoted anywhere have to say which length they describe.
    trained_max_length: int = 96
    # Languages these particular weights were trained on, or None when that cannot be
    # established. A property of the artifact, exactly as `trained_max_length` is.
    #
    # It lives here rather than as a constant in the detector because the detector's
    # constant was a claim about one artifact, and it stopped being true the moment
    # another was loaded. Published `piiguard` covers 9 of the 26; the retrain taken
    # 2026-08-13 covers all 26. One frozenset cannot be right about both, and it was
    # silently wrong about whichever was not in front of it.
    #
    # None is not "unknown, so assume the best". It means the library cannot say, and
    # `coverage_note` renders it as a refusal to claim. A weights directory carries no
    # metadata proving what trained it, and inventing an answer is the forgery that
    # `local:<sha>` already exists to prevent for revisions.
    trained_languages: frozenset[str] | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if self.local:
            # A local spec is explicitly not pinned, and its revision has to look
            # different from a commit so that no reader mistakes one for the other. An
            # evidence record claiming a published revision for a file somebody had on
            # their laptop would be a forgery, so the shape of the string is enforced
            # rather than left to whoever constructs it.
            if not self.revision.startswith("local:"):
                raise ValueError(
                    f"{self.model_id}: a local revision must start with 'local:', "
                    "so that it cannot be mistaken for a published commit."
                )
            return
        if len(self.revision) != 40 or not all(
            c in "0123456789abcdef" for c in self.revision
        ):
            raise ValueError(
                f"{self.model_id}: revision {self.revision!r} is not a 40 "
                "character commit sha. A branch or tag would let the weights "
                "change under a released library, and the evidence record would "
                "attest a moving target."
            )
        if len(self.sha256) != 64:
            raise ValueError(f"{self.model_id}: sha256 must be 64 hex characters")


#: Published, pinned, loadable.
MODELS: Final[dict[str, ModelSpec]] = {
    "piiguard": ModelSpec(
        model_id="flowxai/piiguard",
        repo="flowxai/piiguard",
        # The 26-locale retrain, published 2026-08-16. It replaced the nine-locale
        # artifact this entry pinned until then, and the superseded ONNX exports were
        # deleted from the repo rather than left beside it: a stale file at the old
        # pinned filename is a model the library would go on fetching for as long as
        # anybody forgot to move the pin.
        revision="246866fa594820aab1a6fe8a71abd83cfaa5078c",
        # fp16, and specifically not onnx/model.onnx, which is no longer published
        # either: the fp32 export kept its weights in a sibling model.onnx.data, so the
        # .onnx file alone was 1.8 MB of graph. Loading it without the sidecar fails,
        # and hashing it would attest a graph rather than a model.
        #
        # fp16 rather than INT8 for this artifact. The export gate for a tagger compares
        # decoded character spans, and fp16 changed no span set on 300 texts and lost no
        # covered character.
        filename="onnx/model.fp16.onnx",
        sha256="d47475fa20ee0e296b6d5dd2fc606ceddae441200899b33963b392b787cc0733",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        # All 26. This read as 9 until 2026-08-16, which was true of the artifact then
        # pinned and false the moment the retrain was published. A language list is a
        # fact about one set of weights, so it moves when the revision above moves.
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, BIO tagging over 7 entity types (CARD, DATE, "
            "EMAIL, IBAN, NATIONAL_ID, PERSON, PHONE), trained on all 26 "
            "supported languages. Held out, it misses nothing: token coverage "
            "is 1.0 on every entity type and no sensitive token is left "
            "uncovered. What it gets wrong is the type name, NATIONAL_ID worst "
            "at 0.1429 F1 with every span found and 16 of 208 named right. In "
            "the training generator, locale en is labelled United Kingdom but "
            "uses the German Steuer-IdNr algorithm as a numeric fallback, so do "
            "not claim English national IDs are checksum validated."
        ),
    ),
    "bias": ModelSpec(
        model_id="flowxai/bias",
        repo="flowxai/bias",
        revision="82469a209703212bc54de29a346f6a28a222898e",
        filename="onnx/model.int8.onnx",
        sha256="70b49a9e3edfe0550c1e5738a6b79b94daa9a2924d7954013ef175f600c419b9",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 5 labels. Retrained 2026-08-14 on a corpus "
            "carrying mundane registers and balanced length bands: mean "
            "per-language F1 0.9771, worst language 0.824, calibrated "
            "threshold 0.57, 0 of 300 decisions moved by the INT8 export. "
            "Single-digit per-language positives, so read the score as "
            "understated rather than as a ceiling."
        ),
    ),
    "gibberish": ModelSpec(
        model_id="flowxai/gibberish",
        repo="flowxai/gibberish",
        revision="5cd15c2c87ff605d01f7bff52b5eb9b23788d3e6",
        filename="onnx/model.int8.onnx",
        sha256="7e57cd2516054708d6c5ac63b7b849e2d0dad7884426dce34cce5ebd1919865e",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=32,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 3 labels. Trained at max_length 32, which is "
            "why trained_max_length is 32 here and 96 everywhere else: the "
            "library windows at trained_max_length - 2, and a window larger "
            "than the model ever saw is extrapolation. The ONNX sequence "
            "axis is dynamic, so nothing stops a larger window except that "
            "it would be wrong. Macro F1 0.966 after the corpus rebuild, "
            "worst language 0.870."
        ),
    ),
    "injection": ModelSpec(
        model_id="flowxai/injection",
        repo="flowxai/injection",
        revision="e837ff99cb68909142f36d7eee4b177997e44cac",
        filename="onnx/model.int8.onnx",
        sha256="b360035204ffca5a5a534bc6dfd54979d0810879130e99752b4896117767fec6",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 3 labels. The v3 artifact, adopted for "
            "firing on 0 of 20 mundane sentences where its predecessor "
            "fired on 1, accepting a worse Maltese tail for that. Policy "
            "threshold 0.43 sits deliberately above the calibrated 0.26. "
            "Single-digit per-language positives."
        ),
    ),
    "moderation": ModelSpec(
        model_id="flowxai/moderation",
        repo="flowxai/moderation",
        revision="0b445577dd9e11b33521a6c96dcee8b1d27af3ac",
        filename="onnx/model.int8.onnx",
        sha256="f7950676f8d29ae8553f6f5cabb4a230727eb602d88ee989e05d677d020c8f03",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, and a twelve-label head against a thirteen-label "
            "taxonomy. `child_safety` is deliberately not trained: the label covers "
            "sexualisation of minors and grooming, generating either synthetically is "
            "not acceptable at any severity, and it needs a vetted source with "
            "recorded "
            "provenance instead. The corpus generator excludes it by name and a test "
            "keeps it excluded. Trained 2026-08-17: mean per-language F1 0.9919, worst "
            "language 0.966 (mt), calibrated threshold 0.84, 1 of 300 decisions moved "
            "by the INT8 export and that one within 0.0003 of the threshold. Positives "
            "score 0.984 to 1.000 per label and the false positives sit in the "
            "near-miss registers, worst `fraud_deception_near_miss` at 0.058. All "
            "three "
            "mundane registers are at 0.000, which is the nsfw failure mode not "
            "repeating: this corpus carried ordinary prose from the first run."
        ),
    ),
    "nsfw": ModelSpec(
        model_id="flowxai/nsfw",
        repo="flowxai/nsfw",
        revision="9585fcf77242d5479de37d43578265d6057be6fb",
        filename="onnx/model.int8.onnx",
        sha256="3c29d003bb2a5d1595b9a61f831c17318deb07d49b05119e0893bac3b5b9c8ce",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 2 labels. The 2026-08-14 retrain: mean "
            "per-language F1 0.9337, worst language 0.600, threshold 0.76. "
            "Lower than the 0.976 of the superseded rebuild on purpose, "
            "which fired on 55 percent of ordinary business prose because "
            "its corpus held only hard negatives."
        ),
    ),
    "politeness": ModelSpec(
        model_id="flowxai/politeness",
        repo="flowxai/politeness",
        revision="824708066cfb2711a501100fa7f60150605460ee",
        filename="onnx/model.int8.onnx",
        sha256="0a58cdbf68b7964eb0dcc52228ed518e12b48ebe151800121705b628229f9930",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 1 label. Calibrated threshold 0.89. "
            "Single-digit per-language positives, so the score is "
            "understated rather than a ceiling."
        ),
    ),
    "regulated_advice": ModelSpec(
        model_id="flowxai/regulated-advice",
        repo="flowxai/regulated-advice",
        revision="7e045e07af9f4c93936ec9e61612cb5a9517d1be",
        filename="onnx/model.int8.onnx",
        sha256="534a27e4137b2538bc6952c2e5e9e0031b9ceaf00805de64fffe39b53d0953b5",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 3 labels. Known to over-fire on ordinary "
            "text: it fires on 0.145 of 234 mundane rows in 26 languages "
            "against a 0.10 ceiling, pinned as a strict xfail in "
            "tests/test_ordinary_text_sweep.py. It flags rather than "
            "redacts, so the cost is a noisy record and not damaged text."
        ),
    ),
    "topic_scope": ModelSpec(
        model_id="flowxai/topic-scope",
        repo="flowxai/topic-scope",
        revision="0da1f9c2c6ef3404a56b6a1efeabcb04b6bfca21",
        filename="onnx/model.int8.onnx",
        sha256="56b931f527556116b4bb4854d2dad657933b83aeb3fc3c8eacce9a58fd024f12",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=128,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base as a bi-encoder, not a classification head: "
            "it emits token embeddings of shape (batch, sequence, 768) and "
            "the detector pools and compares against the policy's taxonomy. "
            "Trained at max_length 128, hence trained_max_length 128. This "
            "is the distilled encoder that flowxai/semantic-mapper could "
            "not be: that is a 4B generative model published as GGUF, which "
            "is a local LLM call inside a detector and cannot meet a 300 ms "
            "CPU budget."
        ),
    ),
    "toxicity": ModelSpec(
        model_id="flowxai/toxicity",
        repo="flowxai/toxicity",
        revision="e43c0158f0a8b4ee600aa15259ece37471dbe9cd",
        filename="onnx/model.int8.onnx",
        sha256="0482d1c7a47bab575e2b434825df32df31339d825f200e24dd58c1d238b7f56e",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 4 labels. Third attempt: the second was "
            "refused by the decision-flip gate at a margin of 0.0687 "
            "against a 0.02 band, so the older model kept shipping until "
            "2026-08-14. Positives per language went from about 4 to "
            "between 197 and 209, mean per-language F1 0.9915, worst "
            "language 0.950, threshold 0.81."
        ),
    ),
}

# `_HELD_BACK` stood here until 2026-08-16: one shared sentence saying an artifact was
# trained, verified and deliberately unpublished until a single release at the end. Six
# detectors used it. All six are published now and pinned in MODELS above, so the
# template has no callers and is deleted rather than kept for a case that may not recur.
#
# Deleting it also removed six figures that had been superseded and were still being
# quoted: toxicity at macro-F1 0.882, nsfw at 0.817, bias at 0.869 and gibberish at
# 0.834, all pre-retrain, with thresholds to match. The retrains landed on 2026-08-13
# and 2026-08-14 and nothing brought these along, which is this project's most repeated
# failure. See the notes on each MODELS entry for the current numbers.

#: Named, intended, and not published. `resolve` raises for these with the repo in the
#: message. Listed rather than omitted so that "not built yet" and "typo" are different
#: errors.
UNPUBLISHED: Final[dict[str, str]] = {
    "cee-pii": (
        "flowxai/cee-pii is published but has no ONNX export, only "
        "pytorch_model.bin. It is a GLiNER model with 34 labels weighted toward "
        "central and eastern Europe. Wiring it means doing the ONNX export first."
    ),
    "groundedness": (
        "no ONNX artifact is published for groundedness, and neither trained model "
        "should be. Two attempts, and the second is the more useful failure.\n\n"
        "The first leaked. Its corpus named a register on the candidate sentence and "
        "asked for ten items of one label per request, so each class came out "
        "stylistically uniform and the model classified the style: judging test "
        "examples against an unrelated source in another language left the verdict "
        "unchanged for four of eight registers and identical for paraphrase. It "
        "reported 0.882 exact-match accuracy, and that number was measuring the "
        "generator rather than the task. It does, however, get hand-written probes "
        "right: near-verbatim support reads supported at 0.9999, invention reads "
        "unsupported, a real contradiction reads contradicted.\n\n"
        "The second was rebuilt as source-side pairs, so the same sentence appears "
        "against a source that supports it and one that does not and style cannot "
        "predict the label by construction. That worked on the thing it targeted: the "
        "leak check went from a verdict that survived an unrelated source to one that "
        "does not, and overall retention fell to 0.40. Accuracy fell with it, 0.882 to "
        "0.819, which is the honest direction because the task is now harder to cheat "
        "at.\n\n"
        "It is still not adopted, because it regressed on the cases the first model got"
        " right. Against the same 500 character source, a near-verbatim restatement now"
        " reads unsupported at 0.9994 and a contradiction reads unsupported at 0.6393. "
        "It has learned to doubt rather than to compare.\n\n"
        "So the pair design is necessary and not sufficient, which is the finding worth"
        " keeping. The corpus is at data/groundedness_*.jsonl and the model is parked "
        "at artifacts_local/groundedness-pairs-v2-not-adopted. What the next attempt "
        "needs is both: the pair structure, and enough near-verbatim and multi-sentence"
        " support that the model learns what support looks like rather than only what "
        "it is not. Two of three SUPPORT_RELATIONS in the generator ask for support in "
        "different words, which on this evidence is too few clear positives. Run "
        "border_train.leak_check and the four tests in the library's tests/test_t3.py "
        "against any replacement: passing one and failing the other is what happened "
        "here and neither alone would have shown it."
    ),
    "semantic-mapper": (
        "flowxai/semantic-mapper is a 4B Qwen3 LoRA published as GGUF. It "
        "generates JSON against a frozen prompt, which is a local LLM call "
        "inside a detector and is ruled out by constraint 4, and 4B cannot meet "
        "a 300 ms CPU budget. topic_scope needs a distilled encoder or an "
        "explicit exception first."
    ),
}


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def offline() -> bool:
    """Whether the hub is in offline mode.

    Read from the environment on every call rather than cached, because a test that sets
    HF_HUB_OFFLINE and a process that sets it at startup should behave the same way.
    """
    return os.environ.get("HF_HUB_OFFLINE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


#: Where to look for unreleased weights. A directory holding one folder per model, in
#: the layout the training repo produces: `<root>/<model>-full/onnx/model.int8.onnx`, or
#: `model.fp16.onnx` where int8 was not tolerable. See WEIGHT_NAMES.
LOCAL_DIR_ENV: Final = "FLOWX_BORDER_MODEL_DIR"

#: Specs that `resolve` actually used, keyed by model id. `attestation_for` reads this
#: first, which is what makes a record describe the weights that ran rather than the
#: ones the table hoped for. Without it, loading a local override and then attesting the
#: published revision would be trivial and silent.
_RESOLVED: dict[str, ModelSpec] = {}


def local_root() -> Path | None:
    """The local model directory, if one is configured and exists."""
    raw = os.environ.get(LOCAL_DIR_ENV, "").strip()
    if not raw:
        return None
    root = Path(raw).expanduser()
    return root if root.is_dir() else None


#: Local specs, keyed by model id, because building one hashes the whole weights file. A
#: 533 MB sha256 is about 240 ms, and `warm()` asks for the attestation, so two
#: detectors sharing one model hashed it twice: measured 2026-08-12, output_leakage's
#: warm took 238 ms after piiguard grew from 266 MB to 533, and a test that exists to
#: prove the second warm reuses the cached session was measuring the second hash
#: instead. Safe to cache for the life of the process for the same reason the session
#: cache is:
#: the file a model id resolves to cannot change while the process runs, and if it did,
#: the revision this records would be the honest answer for the file that was actually
#: loaded.
_LOCAL_SPECS: dict[tuple[str, str, int, int], ModelSpec | None] = {}


def local_spec_for(model_id: str) -> ModelSpec | None:
    """A spec for weights found on this machine, or None.

    Exists because nothing is published until the end of the project. Without it, every
    detector past the T0 pair would be unloadable and phases 4 and 5 could not be tested
    at all.

    The revision is `local:` plus the first 12 characters of the file's own hash. It is
    deliberately not a commit and cannot be mistaken for one, which is the point: a
    reader of an evidence record must be able to tell "these were the pinned published
    weights" from "this was a file on a laptop".
    """
    # Keyed by the file's identity rather than by the model id alone. Caching on the id
    # made the integrity check order-dependent: a test that corrupts a weights file and
    # expects the loader to refuse passed or failed depending on whether something
    # earlier in the process had already hashed it. Size and mtime are not a
    # cryptographic identity, and they do not need to be: they exist to notice that the
    # file changed, and the sha256 is what is then recomputed and recorded.
    folder = local_folder(model_id)
    if folder is None:
        return None
    weights = _weights_in(folder / "onnx")
    if weights is None:
        return None
    try:
        stat = weights.stat()
    except OSError:
        return None
    key = (model_id, str(weights), stat.st_size, stat.st_mtime_ns)
    if key in _LOCAL_SPECS:
        return _LOCAL_SPECS[key]
    spec = _build_local_spec(model_id)
    _LOCAL_SPECS[key] = spec
    return spec


#: The names a shrunk export can have, in the order they are tried.
#:
#: int8 first because seven of the shipped detectors are int8, so the common case costs
#: one stat call. fp16 exists because int8 is not always tolerable: `groundedness` is a
#: cross-encoder over a candidate and a source, and its int8 export moved probabilities
#: by 0.07591 at the p99 against the export gate's 0.05 ceiling, which is a different
#: model rather than a quantisation of this one. Its fp16 export changes no decisions at
#: a p99 of 0.01288, for 21 MB more.
WEIGHT_NAMES: Final = ("model.int8.onnx", "model.fp16.onnx")


def _weights_in(onnx_dir: Path) -> Path | None:
    """The one shrunk export in `onnx_dir`, or None.

    Raises when both an int8 and an fp16 export are present. Picking one silently would
    mean the evidence record attests a file nobody chose, and both names do appear
    together in practice: a directory keeps its refused int8 while the fp16 that
    replaced it is exported beside it. An ambiguous directory is a question for a human.
    """
    found = [onnx_dir / name for name in WEIGHT_NAMES if (onnx_dir / name).exists()]
    if len(found) > 1:
        raise ModelUnavailableError(
            f"{onnx_dir} holds more than one shrunk export: "
            f"{', '.join(path.name for path in found)}. The evidence record names the "
            "weights it read, so the loader will not choose between them. Keep the one "
            "that ships and move the other out, naming it for why it was superseded."
        )
    return found[0] if found else None


def _build_local_spec(model_id: str) -> ModelSpec | None:
    """The uncached body of `local_spec_for`. Hashes the weights file."""
    root = local_root()
    if root is None:
        return None

    # Both layouts, because the training repo writes `<detector>-full` and a hand-made
    # directory is more likely to be named after the detector alone.
    for folder in (f"{model_id}-full", model_id, model_id.replace("_", "") + "-full"):
        candidate = _weights_in(root / folder / "onnx")
        if candidate is not None:
            digest = sha256_of(candidate)
            return ModelSpec(
                model_id=f"local/{model_id}",
                repo=str(root / folder),
                revision=f"local:{digest[:12]}",
                filename=str(candidate),
                sha256=digest,
                local=True,
                notes=(
                    f"loaded from {candidate}, not from the hub. Unreleased "
                    "weights, see the held-back note in UNPUBLISHED."
                ),
            )
    return None


def local_folder(model_id: str) -> Path | None:
    """The directory holding these weights under the local override, without hashing.

    Split out from `local_spec_for` because that function hashes 535 MB to build a spec,
    and the callers that only need a path should not pay for it.
    """
    root = local_root()
    if root is None:
        return None
    for folder in (f"{model_id}-full", model_id, model_id.replace("_", "") + "-full"):
        if _weights_in(root / folder / "onnx") is not None:
            return root / folder
    return None


def companion(model_id: str, filename: str) -> Path:
    """A file that ships beside the weights: the tokenizer, the config, the taxonomy.

    One function because there are two places a model can live and every detector needs
    the same two files. Before this, each detector called `hf_hub_download` directly,
    which is correct for a published repo and fails outright for a local one: the "repo
    id" is a filesystem path and the hub client rejects it. The failure was in `warm`,
    which is the right place for it, but it meant no unreleased model could be loaded at
    all despite `resolve` handling its weights perfectly well.
    """
    folder = local_folder(model_id)
    if folder is not None:
        path = folder / filename
        if not path.exists():
            raise ModelUnavailableError(
                f"{folder} has no {filename}. A local artifact directory needs the "
                "tokenizer and config saved with the weights: a span computed "
                "against a different tokenizer is wrong, not approximate."
            )
        return path

    from huggingface_hub import hf_hub_download

    spec = spec_for(model_id)
    return Path(
        hf_hub_download(repo_id=spec.repo, filename=filename, revision=spec.revision)
    )


def available(model_id: str) -> bool:
    """Whether these weights can be obtained without asking the network.

    Deliberately cheap. `spec_for` hashes the file to build a local spec, and `_build`
    needs this answer for seven models on the first call to `loaded_detectors`: hashing
    3.7 GB to decide what goes in a dictionary would put four seconds on the first scan
    of every process.

    True means published and pinned, or present on disk under the local override. It
    does not mean the file is intact, which `resolve` checks when it loads.
    """
    if model_id in MODELS:
        return True
    root = local_root()
    if root is None:
        return False
    return any(
        _weights_in(root / folder / "onnx") is not None
        for folder in (
            f"{model_id}-full",
            model_id,
            model_id.replace("_", "") + "-full",
        )
    )


def spec_for(model_id: str) -> ModelSpec:
    """The spec for a short model id, or a useful error naming what is missing.

    A local override wins over the published table. That ordering is intentional for a
    project mid-development: if someone has pointed at a directory of weights they mean
    it, and silently preferring a published file would make the override untestable.
    """
    local = local_spec_for(model_id)
    if local is not None:
        return local
    if model_id in MODELS:
        return MODELS[model_id]
    if model_id in UNPUBLISHED:
        raise ModelUnavailableError(
            f"{model_id} ships unavailable in this version: {UNPUBLISHED[model_id]} "
            "The detector raises rather than returning no findings, because a detector "
            "that silently finds nothing is indistinguishable from a clean scan."
        )
    raise ModelUnavailableError(
        f"unknown model id {model_id!r}. Known: {', '.join(sorted(MODELS))}. "
        f"Named but unpublished: {', '.join(sorted(UNPUBLISHED))}."
    )


def resolve(model_id: str, *, verify: bool = True) -> tuple[Path, ModelSpec]:
    """Local path to the weight file, downloading once if it is not cached.

    Downloads happen here and only here, which is what keeps `scan_input` and
    `scan_output` free of network access: a detector calls this from `warm`, never from
    `run`. Constraint 1 says a scan must work with the network interface down, and the
    way that stays true is that nothing on the scan path can reach this function.

    With HF_HUB_OFFLINE set and nothing cached, the error names the model, the repo, the
    revision and the cache directory, because the fix depends on which of those is
    wrong.
    """
    spec = spec_for(model_id)

    if spec.local:
        # Nothing to fetch and nothing to compare: the hash in the spec came from this
        # file a moment ago. Recorded as resolved so the attestation is honest about it.
        _RESOLVED[model_id] = spec
        return Path(spec.filename), spec

    from huggingface_hub import hf_hub_download
    from huggingface_hub.errors import LocalEntryNotFoundError

    try:
        located = Path(
            hf_hub_download(
                repo_id=spec.repo, filename=spec.filename, revision=spec.revision
            )
        )
        for extra in spec.extra_files:
            hf_hub_download(repo_id=spec.repo, filename=extra, revision=spec.revision)
    except LocalEntryNotFoundError as error:
        cache = (
            os.environ.get("HF_HUB_CACHE")
            or os.environ.get("HF_HOME")
            or DEFAULT_CACHE_HINT
        )
        raise ModelUnavailableError(
            f"{spec.model_id} is not in the local cache and the hub is unreachable"
            f"{' because HF_HUB_OFFLINE is set' if offline() else ''}.\n"
            f"  repo      {spec.repo}\n"
            f"  revision  {spec.revision}\n"
            f"  file      {spec.filename}\n"
            f"  cache     {cache}\n"
            "Fetch it once with network access, or point HF_HUB_CACHE at a cache that "
            "already has it. Weights are downloaded at install or first load, never "
            "during a scan."
        ) from error

    if verify:
        actual = sha256_of(located)
        if actual != spec.sha256:
            raise ModelUnavailableError(
                f"{spec.model_id} at {located} hashes to {actual}, expected "
                f"{spec.sha256}. A truncated download and a substituted file "
                "look the same to a loader that only checks the path, so this "
                "is refused. Delete the cached file and fetch it again."
            )

    return located, spec


def attestation_for(model_id: str) -> tuple[str, str, str]:
    """(model_id, revision, weights sha256) for the evidence record.

    Taken from the spec rather than recomputed, because `resolve` has already compared
    the file against it. Hashing 279 MB on every scan to restate a value that was
    verified at load time would be work with no answer attached.
    """
    spec = spec_for(model_id)
    return spec.model_id, spec.revision, spec.sha256
