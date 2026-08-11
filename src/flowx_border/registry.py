# SPDX-License-Identifier: Apache-2.0
"""Which detectors are actually loaded, as opposed to which ones a policy asks for.

This distinction is the whole point of the module. A policy describes intent. The
catalogue describes what exists in principle. This describes what is importable and
loadable right now, in this install, and those three sets are not the same.

**The failure this prevents.** With nothing loaded, every scan would return `allow`, and
a caller would see a library that runs, produces evidence records, and checks nothing. A
silent no-op in a security library is a vulnerability, so `missing_for` exists to make
the gap visible and `assert_satisfiable` exists to refuse rather than pretend.

Detectors register themselves here as each phase lands. The dictionary is deliberately
explicit rather than a plugin scan of the package: an import-time side effect deciding
which security checks run is not a property worth having.
"""

from __future__ import annotations

from collections.abc import Mapping

from flowx_border.detectors.base import Detector
from flowx_border.detectors.catalogue import (
    CATALOGUE,
    REQUIREMENTS,
    requirements_for,
)
from flowx_border.policy import Policy, PolicyError


class DetectorUnavailableError(PolicyError):
    """A policy needs a detector this install cannot provide.

    Subclasses PolicyError because from the caller's point of view it is the same class
    of problem: the policy as written cannot be honoured, and the scan must not start.
    """


def _build() -> dict[str, Detector]:
    """Instantiate every detector this install can provide.

    Each phase of BUILD_PLAN.md adds entries.

    Instantiation is cheap for both T0 detectors: patterns compile at import and the
    phrasings file is read on first use, not here. Nothing in this function touches the
    network, which is what lets `loaded_detectors` be called from a scan path.
    """
    from flowx_border.detectors.banned_terms import BannedTermsDetector
    from flowx_border.detectors.disclosure import DisclosureDetector
    from flowx_border.detectors.internal_domains import InternalDomainsDetector
    from flowx_border.detectors.invisible_text import InvisibleTextDetector
    from flowx_border.detectors.markup_injection import MarkupInjectionDetector
    from flowx_border.detectors.output_format import OutputFormatDetector
    from flowx_border.detectors.output_leakage import OutputLeakageDetector
    from flowx_border.detectors.pii import PiiDetector
    from flowx_border.detectors.postal_code import PostalCodeDetector
    from flowx_border.detectors.repetition import RepetitionDetector
    from flowx_border.detectors.secrets import SecretsDetector
    from flowx_border.detectors.system_prompt_leakage import (
        SystemPromptLeakageDetector,
    )

    pii = PiiDetector()

    built: dict[str, Detector] = {
        # T0: rules, no weights, no download. This is what lets the library do
        # something useful on a machine that has never fetched a model.
        "secrets": SecretsDetector(),
        "disclosure": DisclosureDetector(),
        "invisible_text": InvisibleTextDetector(),
        # T1 rules, ported from the Guardrails Hub. Also no weights and no download,
        # so they are available on the same machine the T0 pair is. Two of them need a
        # list from the policy and report that they have none rather than reporting a
        # clean scan, which is why they are loaded here but disabled in the shipped
        # policies.
        "banned_terms": BannedTermsDetector(),
        "system_prompt_leakage": SystemPromptLeakageDetector(),
        "markup_injection": MarkupInjectionDetector(),
        "internal_domains": InternalDomainsDetector(),
        "output_format": OutputFormatDetector(),
        "postal_code": PostalCodeDetector(),
        "repetition": RepetitionDetector(),
        # T1. Both share one piiguard session: constructing them does not load weights,
        # `warm()` does, and the second `warm()` is a cache hit rather than another
        # 279 MB.
        "pii": pii,
        # The same instance, not another one. They share the session either way; sharing
        # the object also shares the inference cache, so an output-side scan runs the
        # encoder once instead of twice over the same text.
        "output_leakage": OutputLeakageDetector(shared=pii),
    }

    # Outside CORE, and therefore conditional. Absent rather than broken when the
    # `sql` extra is not installed: a policy that enables it then gets
    # DetectorUnavailableError at load, which is earlier and clearer than an ImportError
    # from inside a scan. `missing_for` reports it by name either way.
    from flowx_border.detectors.sql_injection import (
        SqlInjectionDetector,
        is_available,
    )

    if is_available():
        built["sql_injection"] = SqlInjectionDetector()

    from flowx_border.detectors.json_schema import JsonSchemaDetector
    from flowx_border.detectors.json_schema import is_available as schema_available

    if schema_available():
        built["json_schema"] = JsonSchemaDetector()

    # Also outside CORE, but always importable: it needs a network rather than a
    # package. Loaded here and disabled in the shipped policies, so nothing reaches the
    # network unless a caller turns it on and reads the deployment note.
    from flowx_border.detectors.url_reachability import UrlReachabilityDetector

    built["url_reachability"] = UrlReachabilityDetector()

    # Phase 4 adds: injection, regulated_advice, toxicity, nsfw, bias, gibberish,
    # politeness. Phase 5 adds: topic_scope, groundedness.

    return built


_LOADED: dict[str, Detector] | None = None


def loaded_detectors() -> Mapping[str, Detector]:
    """The detectors this install provides. Built once, then reused.

    Cached because `warm` is expensive and a scan must never pay model load cost on the
    hot path. The cache is process-wide and there is no invalidation, which is correct:
    the set of importable detectors cannot change while the process runs.
    """
    global _LOADED
    if _LOADED is None:
        _LOADED = _build()
    return _LOADED


def missing_for(policy: Policy, side: str | None = None) -> tuple[str, ...]:
    """Detector ids the policy enables that this install cannot provide.

    Restricted to the given side when one is passed, because a policy enabling
    `groundedness` is not missing anything on the input path.
    """
    loaded = loaded_detectors()
    out = []
    for detector_id, spec in sorted(CATALOGUE.items()):
        if side is not None and side not in spec.sides:
            continue
        if policy.enabled_for(detector_id) and detector_id not in loaded:
            out.append(detector_id)
    return tuple(out)


def assert_satisfiable(policy: Policy, side: str | None = None) -> None:
    """Refuse to scan when a policy asks for a check that would silently not happen.

    Only the enforcing actions count. A policy asking a missing detector to `flag` or
    `log` degrades to a gap in the audit trail, which the record shows. A policy asking
    a missing detector to `block` or `redact` degrades to text passing through unchecked
    while the caller believes it was enforced, and that is worth refusing over.
    """
    enforcing = []
    for detector_id in missing_for(policy, side):
        if policy.for_detector(detector_id).on_fail in ("block", "redact", "rewrite"):
            enforcing.append(detector_id)

    if enforcing:
        raise DetectorUnavailableError(
            f"policy {policy.policy_id!r} expects these detectors to enforce, and this "
            f"install cannot provide them: {', '.join(enforcing)}. They would not run, "
            "and text would pass as if checked. Either install the detector, or change "
            "its on_fail to 'flag' or 'log' so the gap is recorded rather than hidden."
        )


def deployment_notes(policy: Policy) -> tuple[str, ...]:
    """What this policy needs from the machine, beyond a CPU and the base install.

    Empty for a policy that stays inside CORE, which is the common case and should stay
    silent. One line per requirement otherwise, naming the detectors that bring it in.

    This returns lines rather than raising or warning, on purpose. Needing a GPU is not
    an error, and a library that logged a warning would put the message somewhere the
    caller may not be looking. Handing back the lines lets the caller print them at
    startup, put them in a health check, or ignore them, which is their call to make.
    A caller that wants the check to be loud can treat a non-empty result as fatal.
    """
    enabled = [
        detector_id for detector_id in CATALOGUE if policy.enabled_for(detector_id)
    ]
    return tuple(
        f"{requirement}: {REQUIREMENTS[requirement]}. Required by "
        f"{', '.join(detectors)}."
        for requirement, detectors in requirements_for(enabled).items()
    )
