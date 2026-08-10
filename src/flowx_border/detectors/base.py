# SPDX-License-Identifier: Apache-2.0
"""The detector contract.

Every detector implements this shape, with no exceptions and no special cases for a
particular detector in the engine. If a task tempts you to branch on detector.id
inside engine.py, the abstraction is wrong, so stop and raise it.
"""

from __future__ import annotations

from typing import Any, ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from flowx_border.types import Action, Finding

INPUT = "input"
OUTPUT = "output"


class DetectorConfig(BaseModel):
    """The resolved policy for one detector.

    Policy is data, not code, so this holds values and never a callable. options is
    the per-detector bag: entity types for pii, the entropy threshold for secrets, the
    taxonomy for topic_scope. Each detector validates its own options, because the
    engine has no business knowing what they mean.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    on_fail: Action = "flag"
    # T3 only. Without it a T3 detector runs only when a lower tier flags.
    always: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


class Context(BaseModel):
    """What the caller knows that the text does not say.

    Optional in the public API. sources is the one field with teeth: groundedness
    needs it, and when it is empty that detector records a no-op rather than passing
    silently.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    sources: tuple[str, ...] = ()
    # BCP 47 hint. A detector may use it to pick a rule set, and must still work
    # without it, because callers rarely know the language of user input.
    locale: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    """What the engine requires of a detector.

    warm is separate from run so that model loading and the first slow inference
    happen before a scan is on the clock, never during one.
    """

    id: str
    tier: str
    sides: frozenset[str]

    def warm(self) -> None:
        """Load weights and run a throwaway pass.

        Idempotent, and never called on the hot path.
        """
        ...

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        """Inspect text. Returns findings, possibly empty. Must not call the network."""
        ...
