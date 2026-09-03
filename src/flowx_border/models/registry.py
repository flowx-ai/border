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

`MODELS` and `UNPUBLISHED` are disjoint, and `tests/test_registry_weights.py` asserts
it. `resolve` checks `MODELS` first, so an id in both would load fine while its
`UNPUBLISHED` note went on saying the opposite, unread and unfalsifiable. Six ids were
in both once, and their notes carried pre-retrain scores for months.

**Every detector in the catalogue now has an entry**, `groundedness` included as of
2026-08-17. `cee-pii`, a policy-selectable alternative for `pii`, moved from
`UNPUBLISHED` to `MODELS` on 2026-09-03, once its fp32 ONNX export was pushed to the
hub. The one remaining `UNPUBLISHED` id is not a detector: `semantic-mapper` is the
4B generative model `topic_scope` was going to use before it got its own encoder.
Where a detector's weights cannot be obtained, `resolve` raises with the repo id in
the message rather than falling back to a smaller model, because a security library
that quietly substitutes a different detector is worse than one that refuses to start.

This paragraph has been wrong twice in one day, which is worth leaving visible. It named
`injection` and `regulated_advice` as unpublished after both were wired on 2026-08-16,
and it named `groundedness` as unpublished for the hour between being corrected and that
model being published. A sentence counting entries goes stale; the count itself is
asserted in `tests/test_reference.py` against the computation.
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


#: The length assumed when an artifact does not declare one. Named rather than
#: inline so the fallback in `_local_trained_length` can cite the same value it
#: warns about.
DEFAULT_TRAINED_MAX_LENGTH: Final = 96


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
    trained_max_length: int = DEFAULT_TRAINED_MAX_LENGTH
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
        # Gained an eighth entity type, LOCATION, on 2026-08-20. The 26-locale retrain
        # this entry pinned before had no way to say "place" and tagged one as PERSON
        # instead: measured over 234 ordinary rows, every toponym that reached the
        # library came back mislabelled, `Regensburg` and `Valletta` among them, and
        # the policy carried a score bar on `person` to compensate. That bar is gone
        # from `policies/default.yaml` as of this revision, because its only job was
        # filtering toponyms mislabelled as person, and this model does that by
        # tagging rather than by confidence: zero exceptions found across the same
        # 234 rows.
        revision="ed1fa965e00a503d6a5b1dbfcc4ccf405167c794",
        # fp16 again. The tagger's export gate compares decoded character spans, and
        # INT8 moved 1 of 300 span sets with Gather already the narrowest op set left to
        # narrow, so there was nothing left to try. fp16 changed 0 of 300.
        filename="onnx/model.fp16.onnx",
        sha256="89c924a1b5b5badfa0d91e317b3cb03cf9b058433618a8f736272792e469bff0",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, BIO tagging over 8 entity types (CARD, DATE, "
            "EMAIL, IBAN, LOCATION, NATIONAL_ID, PERSON, PHONE), trained on "
            "all 26 supported languages. LOCATION F1 0.9938 on the held-out "
            "split, PERSON recall unchanged at 1.0000. Over 234 ordinary "
            "rows: person findings fall from 66 to 56, all of them genuine "
            "since none are toponyms any more, and national_id false "
            "positives fall from 8 to 4. NATIONAL_ID is still the weak type, "
            "worst F1 with every span found and the type name wrong more "
            "often than right. In the training generator, locale en is "
            "labelled United Kingdom but uses the German Steuer-IdNr "
            "algorithm as a numeric fallback, so do not claim English "
            "national IDs are checksum validated."
        ),
    ),
    "cee-pii": ModelSpec(
        model_id="flowxai/cee-pii",
        repo="flowxai/cee-pii",
        # Pushed 2026-09-03: the onnx/ folder and a card update, alongside the
        # pytorch_model.bin already on the repo since 2026-07-06. This is the commit
        # that added them.
        revision="e32cce0e244d242ddf83275b5af30f5e98220849",
        # fp32 only. GLiNER's export_to_onnx() fails on this architecture's LSTM span
        # head (pack_padded_sequence does not survive tracing); the export here works
        # around that with a patched forward pass exact at batch_size=1, which is the
        # only shape this detector ever calls with. Naive dynamic INT8 destroyed the
        # model (every real entity score below 0.004). fp16 hit a genuine operand
        # dtype mismatch in mDeBERTa's embeddings block in onnxconverter_common, not a
        # metadata slip, and was not shipped rather than shipped broken. See
        # border_train/export/gliner_to_onnx.py in the training repo for both.
        filename="onnx/model.fp32.onnx",
        sha256="2376902c9a6dc5aed7578b24e34109e71224b219a64004058523112ead80155c",
        extra_files=("tokenizer.json",),
        # GLiNER's own gliner_config.json max_len, mDeBERTa-v3 base. Not the
        # trained_max_length - 2 subword-window convention piiguard and the
        # classifiers use: GLiNER windows in words (max_width 12) via its own span
        # enumeration, not through this field, and detectors/ceepii.py never reads it
        # for that reason. Recorded because it is still a true fact about the
        # artifact, not because anything computes with it.
        trained_max_length=384,
        # en, ro, pl and hu only, the four of the training run's five languages that
        # are in this library's 26. The fifth, Uzbek, is real about the weights and
        # not a claim this library makes: LANGUAGES - {trained} silently drops
        # anything not in LANGUAGES, so including "uz" here would have inflated
        # coverage_note's "N of 26" count by a language outside the 26 it counts
        # against. Say Uzbek in prose, not in a set this field's own consumers assume
        # is a subset of the supported languages.
        trained_languages=frozenset({"en", "ro", "pl", "hu"}),
        notes=(
            "GLiNER (mDeBERTa-v3 base, ~300M params), 34 entity-type prompts mapped "
            "onto this library's types; first_name and surname are dropped rather "
            "than merged into person, because prompting all three at once measurably "
            "splits confidence across redundant phrasings (0.40/0.68 individually "
            "against 0.99 for person_name alone on a real name). Verified against "
            "the unmodified PyTorch model at export time: 7 fixtures across "
            "en/ro/pl/hu, 0 span mismatches, max score drift 0.00001. Also trained "
            "on Uzbek, which this library does not claim as a supported language. "
            "No per-language evaluation table exists yet, unlike piiguard's; "
            "quality figures for this model read 'not recorded' rather than a "
            "number until one does. Needs a GPU to run at any usable latency: "
            "registry.deployment_notes(policy) reports that the moment a policy "
            "selects it."
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
        # Test positives per language went from 9-12 to 28-32 on 2026-08-20, the same
        # thickening campaign as nsfw. Mean per-language F1 0.9664 -> 0.9915.
        revision="9d71506eb25cc4ac140c6ccbcf7b2af0f88b80a0",
        filename="onnx/model.int8.onnx",
        sha256="1fcca6c00698340e47d02a884468879a780be84a3c9a355764b9b97452f95e60",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=32,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 3 labels. Trained at max_length 32, which is "
            "why trained_max_length is 32 here and 96 everywhere else: the "
            "library windows at trained_max_length - 2, and a window larger "
            "than the model ever saw is extrapolation. The ONNX sequence "
            "axis is dynamic, so nothing stops a larger window except that "
            "it would be wrong. Retrained 2026-08-20 on the thickened "
            "corpus: macro F1 0.9915, worst language 0.9892."
        ),
    ),
    "injection": ModelSpec(
        model_id="flowxai/injection",
        repo="flowxai/injection",
        # The v5 corpus retrain, published 2026-08-18, hours after v4. Both pins moved
        # for
        # the same reason and v5 finishes the job: v4 took ordinary support questions
        # from 7
        # of 12 to 1, and v5 takes them to 0 by adding one register,
        # `mundane_account_access`, to the corpus generator's shared mundane set.
        #
        # Not a clean sweep. A bare UUID reads direct_injection at 0.944 under v5,
        # clearing
        # the shipped 0.43 where v4 had it at zero, and staying under 0.95. Net across
        # both
        # shapes v5 is ahead and the regression is recorded rather than netted away.
        revision="e2dd543f8373c0a35786f4b5b85ce615a3d0ad7c",
        filename="onnx/model.int8.onnx",
        sha256="560567f9bf77f41e972d82da7333d39a30d621c029b569db8bd76a2fc7991886",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, three independent labels: direct_injection, "
            "indirect_injection, jailbreak. Held out at the shipped 0.43, per-label F1 "
            "0.9738, 0.9804 and 0.9603 with FPR 0.0057, 0.0021 and 0.0077. Mean "
            "per-language F1 0.9891, weakest mt 0.8817, then ga 0.9762 and cs 0.9767. "
            "Corpus 45,541 examples, 27.0 percent attacks, 26 languages, 19 registers. "
            "What the retrains bought, measured through the shipped configuration: "
            "ordinary support questions it fires on went 7 of 12, "
            "then 1, then 0 across "
            "v3, v4 and v5, and technical identifiers 4 of 4 to 0 at 0.95, while the "
            "three canonical attacks are still caught. The old model read a "
            "bare UUID, a git commit "
            "hash, a data URI and a sha256 digest as jailbreak or direct_injection, "
            "and "
            "read 'Someone is using my account, how do I lock it?' as direct_injection "
            "at 0.98. Both came from one corpus property: every benign register was "
            "conversational prose, so an imperative request and a high-entropy "
            "identifier were equally out of distribution. "
            "The residual v4 could not reach is gone. 'Please cancel my subscription.' "
            "read direct_injection at 0.9775 under v4, identical at 0.43 and 0.95, and "
            "two rows of 35,025 matched that phrasing; v5 has 1,862 "
            "account-access rows "
            "and 16 carrying it as benign. What remains is a bare UUID at 0.944, over "
            "0.43 and under 0.95. "
            "The calibrated 0.02 from this run is deliberately not adopted: its own "
            "report flags it as the lowest value in the sweep, which compresses scores "
            "toward zero, and macro F1 is 0.9671 even at 0.95, so the sweep is a "
            "plateau "
            "rather than a peak. A missed injection costs more than a review. "
            "INT8 Gather-only: 0 of 300 decisions changed, probability drift p99 "
            "0.00004, max 0.00767."
        ),
    ),
    "groundedness": ModelSpec(
        model_id="flowxai/groundedness",
        repo="flowxai/groundedness",
        revision="9e665d59f99f953ce2ee5fc35566241ce1ad0091",
        # fp16 rather than int8, and the earlier int8 attempt for this detector is why
        # the loader accepts either name. int8 was refused at a p99 probability drift of
        # 0.07591 against a 0.05 ceiling; this fp16 export moved 0 of 300 decisions at a
        # p99 of 0.03351, verified at the 0.78 bar it ships with rather than at argmax.
        filename="onnx/model.fp16.onnx",
        sha256="d3113d45d2b2570eb37d8fdbcdb4477a5bf6f2b7d515ff3bd1f15fa2398d315b",
        extra_files=("tokenizer.json", "config.json"),
        # 512, and it is the one entry here where the wrong value was silently wrong
        # rather than loud: the local override defaulted this to 96 until 2026-08-17,
        # and a 512-token pair truncated to 96 made the model answer a question at
        # 0.9216 instead of 0.7681. Every graph has a dynamic sequence axis, so nothing
        # raised.
        trained_max_length=512,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base cross-encoder over (source, candidate), two classes: "
            "grounded and not_grounded. Use it at 0.78 rather than argmax. Corpus "
            "held-out accuracy 0.9471 at that bar, not-grounded recall 0.9612, pair "
            "accuracy 0.8991, per-language 0.887 (pl) to 1.000. Against 42 "
            "hand-written "
            "probes it is 0.6905 alone and 0.7381 with detectors/claim_conflict.py in "
            "front, so roughly one call in four is wrong on a set no generator made "
            "against one in twenty on the generator's own split. Both are real and the "
            "gap is the point. It is the only one of seven candidates whose verdict "
            "depends on the source: the same candidate reads 0.7681 against a source "
            "that contradicts it, 0.0070 against an unrelated passage, 0.8365 against "
            "one that states it, where the best three-way candidate answered 0.9991, "
            "0.9994 and 0.0007, which is inverted and source-blind. Known weakness is "
            "false not_grounded on claims weaker than their source, 0.8625 on the "
            "clearest case, which is the safe direction for a guardrail and still a "
            "cost. Disabled in both shipped policies for that reason."
        ),
    ),
    "moderation": ModelSpec(
        model_id="flowxai/moderation",
        repo="flowxai/moderation",
        revision="9acf05edb5b28588d99db297d7a98c8757ff4d30",
        filename="onnx/model.int8.onnx",
        sha256="7caaf54902872573802b9927573ac0025aacf2db35ad1043430c1264221b0f2f",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, and a twelve-label head against a thirteen-label "
            "taxonomy. `child_safety` is deliberately not trained: the label covers "
            "sexualisation of minors and grooming, generating either synthetically is "
            "not acceptable at any severity, and it needs a vetted source with "
            "recorded provenance instead. The corpus generator excludes it by name and "
            "a test keeps it excluded. Retrained 2026-08-24, prompt_version "
            "moderation_solicitation_v5: the shared positive-spec prompt was tightened "
            "against a measured defect in the model this one replaces, 762 of "
            "`sexual_exploitation`'s positives and 151 of `self_harm`'s were victim "
            "support, protection or reporting text labelled as if it were the hazard "
            "('offers help for sexual exploitation' on a trafficking shelter offer). "
            "Every label's positives were regenerated under the corrected prompt, not "
            "just the two worst-affected. Mean per-language F1 fell from 0.9925 to "
            "0.9708 and every one of the twelve labels reads lower, which is expected "
            "rather than a regression: the removed rows were the easy, "
            "wrongly-labelled kind, and self_harm's remaining positives lean more "
            "oblique and euphemistic ('help me with an irreversible step') than the "
            "templated phrasing the old corpus leaned on, the same trade this "
            "project's `nsfw` retrain made "
            "deliberately (0.976 to 0.918) for the same reason. Worst language 0.863 "
            "(mt). 2 of 300 decisions moved by the INT8 export, both within 0.0149 of "
            "the threshold and inside the 0.02 tolerance band. Calibration moved to "
            "0.91 from a single run, against the shipped 0.84: the curve is not flat "
            "this time (macro F1 0.8658 at 0.50 rising to 0.9037 at 0.91), but 0.84 "
            "reads 0.8996, within 0.0041 of the peak, at meaningfully higher recall "
            "(0.9915 against 0.9687), so the shipped default is kept for that reason "
            "rather than because the calibration is noise."
        ),
    ),
    "nsfw": ModelSpec(
        model_id="flowxai/nsfw",
        repo="flowxai/nsfw",
        # Test positives per language went from 9-10 to 23-24 on 2026-08-20, above the
        # bar `toxicity` set at 19-20 when it came off this same list. Mean per-language
        # F1 0.9337 -> 0.9738, and Maltese's seed-to-seed spread, the number that named
        # the original problem, went 0.3294 -> 0.1179 on the new corpus: more positives
        # made the score mean something rather than just raising it.
        revision="6c54edcd94ab9454d84f8510f2217e9329508c66",
        filename="onnx/model.int8.onnx",
        sha256="f8abb31c288bd45d9833d128f14b4ad43179397472aba9fb15cb8e0e8821baed",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 2 labels. Retrained 2026-08-20 on the "
            "thickened corpus: mean per-language F1 0.9738, worst language "
            "0.8679. The calibrated threshold is not authoritative: two "
            "seeds read 0.63 and 0.86 with a flat validation curve, macro "
            "F1 0.8969 to 0.9190 across 0.50 to 0.95, so the shipped policy "
            "keeps 0.76 unchanged. Lower than the 0.976 of the pre-2026-08-14 "
            "rebuild on purpose, which fired on 55 percent of ordinary "
            "business prose because its corpus held only hard negatives."
        ),
    ),
    "politeness": ModelSpec(
        model_id="flowxai/politeness",
        repo="flowxai/politeness",
        # Test positives per language went from 15-16 to 20-21 on 2026-08-20, the
        # same thickening campaign as nsfw and gibberish. Mean per-language F1
        # 0.9619 -> 0.9779, worst language (mt) 0.7879 -> 0.8261.
        revision="63c3e6f1519eb4597c73e858cd71bde633cc0257",
        filename="onnx/model.int8.onnx",
        sha256="ce977510b5071c3d2e1876b6fbecfdb2648443bc3374664558d5bc7daed1be8c",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 1 label. Retrained 2026-08-20 on the "
            "thickened corpus. The calibrated threshold is not "
            "authoritative: two seeds read 0.10 and 0.36, so the shipped "
            "policy keeps 0.89 unchanged, the same flat-curve finding as "
            "nsfw from the same campaign."
        ),
    ),
    "regulated_advice": ModelSpec(
        model_id="flowxai/regulated-advice",
        repo="flowxai/regulated-advice",
        revision="5141792fe64fa8e90c5ccd6862b1905c05a119fa",
        filename="onnx/model.int8.onnx",
        sha256="9d76be7ee815bea38f08734f953f9a8f1a37c7dff046c3166069becf9e0563a7",
        extra_files=("tokenizer.json", "config.json"),
        trained_max_length=96,
        trained_languages=frozenset(LANGUAGES),
        notes=(
            "XLM-RoBERTa base, 3 labels, retrained 2026-08-20 on a corrected "
            "corpus split. Two things moved. Its ordinary-text firing rate "
            "went from 0.5256 of 234 mundane rows to 0.0600, below the 0.10 "
            "ceiling in tests/test_ordinary_text_sweep.py, which is what took "
            "it off that file's known-over list. And financial_advice has a "
            "score for the first time, 0.8927 at a support of 260: the "
            "previous split was cut along domain lines and gave that label "
            "2,542 training rows and no test rows, so its reported f1 of 0.0 "
            "was a division by nothing. All three labels now read 0.876 to "
            "0.902. Read those rather than the per-language table, which asks "
            "whether the detector fires at all and reads 1.000 in sixteen "
            "languages on that easier question."
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
#:
#: fp32 last, added for `cee-pii`. Not a preference, an absence: naive INT8 dynamic
#: quantisation destroyed the model (every real name below 0.004) and fp16 hit a real
#: type-mismatch bug in mDeBERTa's embeddings block via this project's own converter,
#: not a metadata slip this time, see border_train/export/gliner_to_onnx.py. fp32 is
#: what passed the equivalence check, so it is what the loader is asked to find.
WEIGHT_NAMES: Final = ("model.int8.onnx", "model.fp16.onnx", "model.fp32.onnx")


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
            length, length_source = _local_trained_length(model_id, root / folder)
            return ModelSpec(
                model_id=f"local/{model_id}",
                repo=str(root / folder),
                revision=f"local:{digest[:12]}",
                filename=str(candidate),
                sha256=digest,
                local=True,
                trained_max_length=length,
                notes=(
                    f"loaded from {candidate}, not from the hub. Unreleased "
                    "weights, see the held-back note in UNPUBLISHED. "
                    f"trained_max_length {length} from {length_source}."
                ),
            )
    return None


def _local_trained_length(model_id: str, folder: Path) -> tuple[int, str]:
    """The length this artifact was trained at, read rather than assumed.

    This defaulted to the dataclass's 96 until 2026-08-17, and the cost was silent.
    Every
    ONNX graph here has a dynamic sequence axis, so feeding a model a length it never
    saw
    raises nothing at all: it answers, differently. `groundedness` trains at 512, so
    under
    the override its 512-token pairs were truncated to 96, and the temporal-
    contradiction
    probe read 0.9216 truncated against 0.7757 at full length. Every figure this project
    recorded for that probe through the library was measured on a truncated source.

    Order of preference, most specific first:

    1. `run.json`, which the training repo writes next to the weights and which records
    the
       `max_length` the run actually used. An artifact describing itself.
    2. The published `MODELS` entry for the same id, when there is one, because a local
       re-export of a published model is nearly always the same length.
    3. The dataclass default, and the notes say so, so a reader of an evidence record
    can
       see that the length was assumed rather than read.
    """
    import json

    run = folder / "run.json"
    if run.exists():
        try:
            declared = json.loads(run.read_text(encoding="utf-8")).get("max_length")
        except (OSError, ValueError):
            declared = None
        if isinstance(declared, int) and declared > 0:
            return declared, "run.json"

    published = MODELS.get(model_id)
    if published is not None:
        return published.trained_max_length, f"the published {model_id} spec"

    return DEFAULT_TRAINED_MAX_LENGTH, (
        "the default, because this artifact carries no run.json and the id is not in "
        "MODELS. If the model was not trained at that length, it is being fed a length "
        "it never saw"
    )


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
    from huggingface_hub.errors import LocalEntryNotFoundError

    spec = spec_for(model_id)
    try:
        return Path(
            hf_hub_download(
                repo_id=spec.repo, filename=filename, revision=spec.revision
            )
        )
    except LocalEntryNotFoundError as error:
        # The same wrapping `resolve` does for the weights file, missing here until
        # 2026-09-03: every caller above reads this as "the weights are unavailable",
        # and a raw huggingface_hub exception for the tokenizer or config file is the
        # same fact in a shape nothing catches, since `engine.py` only knows to expect
        # `ModelUnavailableError` on the scan path.
        reason = " because HF_HUB_OFFLINE is set" if offline() else ""
        raise ModelUnavailableError(
            f"{spec.model_id} is missing {filename}: not in the local cache and the "
            f"hub is unreachable{reason}.\n"
            f"  repo      {spec.repo}\n"
            f"  revision  {spec.revision}\n"
            f"  file      {filename}"
        ) from error


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
