# SPDX-License-Identifier: Apache-2.0
"""T1. Is the text longer than the token budget of the model it is going for?

From llm-guard's `TokenLimit`. It was declined during the port with a note saying a
token count depends on the tokenizer of the model you are calling, which this library
does not know. That is true, and it is a reason to make the policy name the tokenizer
rather than a reason to refuse: `output_format` already counts graphemes and words, and
quietly reporting a different number from the one the caller asked about is worse than
not answering.

**The tokenizer has to be pinned, and this is the whole design.** A count from an
unspecified tokenizer is not reproducible, and default 6 says a scan must be
reproducible given the same inputs and model revisions, because an evidence record
exists to be checked later by somebody who was not there. So a policy names one of two
things:

- `tokenizer_path`, a local `tokenizer.json`. The detector hashes it and reports the
  revision as `local:<sha256 prefix>`, exactly as `models/registry.py` does for weights
  under a local override, for the same reason: a record claiming a published revision
  for a file on somebody's laptop would be a forgery.
- `tokenizer_model`, an id already pinned in `models/registry.py`, carrying a commit.

A bare Hugging Face repo id is refused. Not because fetching is forbidden, entry 1
allows a fetch that caches, but because a repo id without a revision names a moving
target, and the resulting count could not be reproduced from the evidence record that
reported it. Naming the revision is the caller's one obligation here and the error says
so.

**Unconfigured it reports rather than passing**, like `banned_terms` with no term list.
A detector that silently counts nothing when the policy forgot the limit is the no-op
this library treats as a vulnerability.

No network, no weights of its own, and `tokenizers` is already in the base install, so
this is in CORE. That corrects the proposal in `docs/proposed-detectors.md`, which put
it outside CORE with `requires={"dependency"}` on the assumption that it needed a new
package.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding


class TokenLimitError(ValueError):
    """A configuration this detector cannot act on."""


UNCONFIGURED_LABEL: Final = "token_limit_unconfigured"
OVER_LIMIT_LABEL: Final = "token_limit_exceeded"

#: How much of the file hash goes into the reported revision. Twelve hex characters, the
#: same as a short git sha and the same as the local override in models/registry.py
#: uses, so the two read alike in an evidence record.
_REVISION_PREFIX: Final = 12


def _local_revision(path: Path) -> str:
    """`local:<sha256 prefix>` for a tokenizer file on this machine.

    Deliberately not a version string the caller supplies. The point is that the record
    says which bytes produced the count, and a caller-supplied label could be wrong or
    stale without anything noticing.
    """
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"local:{digest[:_REVISION_PREFIX]}"


class TokenLimitDetector:
    """Counts tokens with a pinned tokenizer and reports when the text is over."""

    id = "token_limit"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    def __init__(self) -> None:
        # Keyed on the resolved identity of the tokenizer rather than on the option
        # value, so two policies naming the same file share one load.
        self._loaded: dict[str, Any] = {}

    def warm(self) -> None:
        """Nothing to load without a policy, because the policy names the tokenizer.

        Not a gap. Every other warm() in the library loads a fixed artifact; here the
        artifact is a configuration value, so the first run does the load and caches it.
        """

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        limit = options.get("max_tokens")
        path_option = options.get("tokenizer_path")
        model_option = options.get("tokenizer_model")

        if options.get("tokenizer") is not None:
            raise TokenLimitError(
                "token_limit was given `tokenizer`, which is ambiguous between a local "
                "file and a repo id. Use `tokenizer_path` for a file on this machine, "
                "or `tokenizer_model` for an id pinned in models/registry.py."
            )
        if limit is None or (path_option is None and model_option is None):
            # Both halves are needed to answer anything, and a missing half is a
            # configuration gap rather than a clean text.
            return [self._unconfigured()]
        if path_option is not None and model_option is not None:
            raise TokenLimitError(
                "token_limit was given both tokenizer_path and tokenizer_model. Name "
                "one, so the evidence record says unambiguously which tokenizer "
                "produced the count."
            )

        max_tokens = int(limit)
        if max_tokens < 1:
            raise TokenLimitError(
                f"token_limit max_tokens must be at least 1, got {max_tokens}. A limit "
                "of zero would report every text including an empty one."
            )

        model_id, revision, tokenizer = self._tokenizer(path_option, model_option)
        counted = len(tokenizer.encode(text, add_special_tokens=False).ids)
        if counted <= max_tokens:
            return []
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=OVER_LIMIT_LABEL,
                # How far over, as a fraction of the limit, capped at 1.0. A text at
                # twice the limit scores 1.0 and one a token over scores near zero, so a
                # policy can act on the degree. The raw count is not in the finding
                # because the evidence record carries no text-derived quantity beyond
                # what a score is.
                score=round(min(1.0, (counted - max_tokens) / max_tokens), 6),
                span=None,
                action=cfg.on_fail,
                model_id=model_id,
                model_revision=revision,
            )
        ]

    def _tokenizer(
        self,
        path_option: object,
        model_option: object,
    ) -> tuple[str, str, Any]:
        """The pinned tokenizer named by the policy, loaded once per identity."""
        from tokenizers import Tokenizer

        if path_option is not None:
            path = Path(str(path_option)).expanduser()
            if not path.is_file():
                raise TokenLimitError(
                    f"token_limit tokenizer_path {str(path)!r} is not a file. It must "
                    "be a tokenizer.json on this machine, because a count from a "
                    "tokenizer nobody can identify cannot be reproduced."
                )
            model_id = path.name
            revision = _local_revision(path)
            key = f"{path}:{revision}"
            if key not in self._loaded:
                self._loaded[key] = Tokenizer.from_file(str(path))
            return model_id, revision, self._loaded[key]

        from flowx_border.models.onnx import tokenizer_for
        from flowx_border.models.registry import MODELS

        model_id = str(model_option)
        spec = MODELS.get(model_id)
        if spec is None:
            raise TokenLimitError(
                f"token_limit tokenizer_model {model_id!r} is not pinned in "
                f"models/registry.py. Known ids are {sorted(MODELS)}. A bare Hugging "
                "Face repo id is not accepted here: without a revision it names a "
                "moving target, so the count could not be reproduced from the evidence "
                "record that reported it. Either add the id to the registry with a "
                "commit, or download the tokenizer and use tokenizer_path."
            )
        return model_id, spec.revision, tokenizer_for(model_id)

    def _unconfigured(self) -> Finding:
        """Says the check could not run, always as `log`.

        `log` rather than the policy's action, for the reason `summary_support` uses: an
        absent configuration is the operator's gap, and blocking a user's request over
        it would make the detector unusable in the case where somebody enabled it and
        forgot to say how many tokens.
        """
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=UNCONFIGURED_LABEL,
            score=1.0,
            span=None,
            action="log",
        )
