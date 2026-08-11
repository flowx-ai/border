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
        revision="018e7f0355c0576938007c2bbfdd22d9275edbb9",
        # The INT8 build, and specifically not onnx/model.onnx: the fp32 export on this
        # repo keeps its weights in a sibling model.onnx.data, so the .onnx file alone
        # is 1.8 MB of graph. Loading it without the sidecar fails, and hashing it would
        # attest a graph rather than a model.
        filename="onnx/model.int8.onnx",
        sha256="d59a4ece4ac6ea69cb97188eb7b1e88d5c87fd97c6d7cb1aa1d57daef830ab5a",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        notes=(
            "XLM-RoBERTa base, BIO tagging over 7 entity types (CARD, DATE, "
            "EMAIL, IBAN, NATIONAL_ID, PERSON, PHONE). Trained on 9 locales: "
            "en, ro, bg, hu, sl, hr, de, it, fr. The other 17 of the 26 "
            "supported languages are untested rather than covered. In the "
            "training generator, locale en is labelled United Kingdom but uses "
            "the German Steuer-IdNr algorithm as a numeric fallback, so do not "
            "claim English national IDs are checksum validated."
        ),
    ),
}

#: The reason shared by every artifact that exists and is deliberately unreleased. Held
#: back on the owner's instruction of 2026-08-11: one release at the end rather than a
#: trickle, so that what is public is a set somebody chose.
_HELD_BACK: Final = (
    "{detector} is trained, exported and verified, and deliberately not published yet: "
    "everything ships in one release at the end of the project. Measured {note}. "
    "Point FLOWX_BORDER_MODEL_DIR at a directory of artifact folders to load it from "
    "disk in the meantime."
)

#: Named, intended, and not published. `resolve` raises for these with the repo in the
#: message. Listed rather than omitted so that "not built yet" and "typo" are different
#: errors.
UNPUBLISHED: Final[dict[str, str]] = {
    "cee-pii": (
        "flowxai/cee-pii is published but has no ONNX export, only "
        "pytorch_model.bin. It is a GLiNER model with 34 labels weighted toward "
        "central and eastern Europe. Wiring it means doing the ONNX export first."
    ),
    "injection": (
        "no ONNX artifact is published for injection yet. A model was trained on "
        "2026-08-11 and reached macro-F1 0.889 across 26 languages at threshold 0.43."
    ),
    "regulated_advice": (
        "no ONNX artifact is published for regulated_advice yet. A model was "
        "trained and reached 0.983 macro-F1, still at an uncalibrated threshold."
    ),
    "groundedness": (
        "no ONNX artifact is published for groundedness yet. The trained model scores "
        "1.000, which is saturated rather than good, so the corpus needs hard cases "
        "before the number means anything."
    ),
    "toxicity": _HELD_BACK.format(
        detector="toxicity", note="macro-F1 0.882 at threshold 0.32"
    ),
    "nsfw": _HELD_BACK.format(detector="nsfw", note="macro-F1 0.817 at threshold 0.31"),
    "bias": _HELD_BACK.format(detector="bias", note="macro-F1 0.869 at threshold 0.22"),
    "gibberish": _HELD_BACK.format(
        detector="gibberish", note="macro-F1 0.834 at threshold 0.37"
    ),
    "politeness": _HELD_BACK.format(
        detector="politeness", note="macro-F1 0.887 at threshold 0.5"
    ),
    "topic_scope": _HELD_BACK.format(
        detector="topic_scope",
        note=(
            "a bi-encoder with 15 taxonomy nodes embedded at export time, verified at "
            "0.99928 minimum cosine to the fp32 model"
        ),
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
#: the
#: layout the training repo produces: `<root>/<model>-full/onnx/model.int8.onnx`.
LOCAL_DIR_ENV: Final = "FLOWX_BORDER_MODEL_DIR"

#: Specs that `resolve` actually used, keyed by model id. `attestation_for` reads this
#: first, which is what makes a record describe the weights that ran rather than the
#: ones
#: the table hoped for. Without it, loading a local override and then attesting the
#: published revision would be trivial and silent.
_RESOLVED: dict[str, ModelSpec] = {}


def local_root() -> Path | None:
    """The local model directory, if one is configured and exists."""
    raw = os.environ.get(LOCAL_DIR_ENV, "").strip()
    if not raw:
        return None
    root = Path(raw).expanduser()
    return root if root.is_dir() else None


def local_spec_for(model_id: str) -> ModelSpec | None:
    """A spec for weights found on this machine, or None.

    Exists because nothing is published until the end of the project. Without it,
    every detector past the T0 pair would be unloadable and phases 4 and 5 could not
    be tested at all.

    The revision is `local:` plus the first 12 characters of the file's own hash. It is
    deliberately not a commit and cannot be mistaken for one, which is the point: a
    reader of an evidence record must be able to tell "these were the pinned published
    weights" from "this was a file on a laptop".
    """
    root = local_root()
    if root is None:
        return None

    # Both layouts, because the training repo writes `<detector>-full` and a hand-made
    # directory is more likely to be named after the detector alone.
    for folder in (f"{model_id}-full", model_id, model_id.replace("_", "") + "-full"):
        candidate = root / folder / "onnx" / "model.int8.onnx"
        if candidate.exists():
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
