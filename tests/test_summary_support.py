# SPDX-License-Identifier: Apache-2.0
"""Tests for the summary support detector, and the thing it deliberately cannot do.

The detector asks whether each sentence of a summary has a close counterpart in the
source. It answers with string overlap, and the most important test in this file is the
one that pins what that costs: a true paraphrase reads as unsupported, because it shares
no words.

That is a contract rather than a defect, and it is tested as one. The alternative would
be to imply entailment, and this project already has a detector that implied entailment
and did not deliver it: `groundedness`, whose model turned out to recognise its
generator's paraphrase style rather than compare a claim to a source. A detector honest
about counting shared words is worth more than one that overstates.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.detectors.summary_support import (
    DEFAULT_MIN_WORDS,
    SummarySupportDetector,
    SummarySupportError,
)

CFG = DetectorConfig(on_fail="flag")

SOURCE = (
    "The account pays 3.1 percent annual interest, calculated daily and credited "
    "on the last business day of each month. Withdrawals made within the first "
    "twelve months "
    "incur a handling fee of 5 EUR per transaction. After twelve months have elapsed, "
    "withdrawals are free of charge and may be made without notice."
)


@pytest.fixture
def detector() -> SummarySupportDetector:
    found = SummarySupportDetector()
    found.warm()
    return found


def sourced() -> Context:
    return Context(sources=(SOURCE,))


# ------------------------------------------------------------------ what it is for


def test_a_sentence_taken_from_the_source_is_supported(
    detector: SummarySupportDetector,
) -> None:
    sentence = (
        "Withdrawals made within the first twelve months incur a handling fee of 5 EUR "
        "per transaction."
    )
    assert detector.run(sentence, CFG, sourced()) == []


def test_a_lightly_reworded_sentence_is_still_supported(
    detector: SummarySupportDetector,
) -> None:
    # The reason the threshold is 0.75 rather than 1.0: dropping a few words or
    # reordering a clause is what an extractive summariser does, and it is not an
    # invention.
    sentence = (
        "Withdrawals within the first twelve months incur a handling fee of 5 EUR."
    )
    assert detector.run(sentence, CFG, sourced()) == []


def test_an_invented_sentence_is_reported(detector: SummarySupportDetector) -> None:
    found = detector.run(
        "The account includes free travel insurance for all holders.", CFG, sourced()
    )
    assert [f.label for f in found] == ["unsupported_sentence"]
    assert found[0].score > 0.0


def test_the_span_points_at_the_sentence_it_judged(
    detector: SummarySupportDetector,
) -> None:
    text = (
        "After twelve months have elapsed, withdrawals are free of charge. "
        "The bank also waives the annual card fee for every customer."
    )
    found = detector.run(text, CFG, sourced())
    assert len(found) == 1
    start, end = found[0].span or (0, 0)
    assert "annual card fee" in text[start:end]


def test_the_score_grows_with_the_distance_from_the_source(
    detector: SummarySupportDetector,
) -> None:
    """A policy threshold should be able to act on the degree, not only the fact.

    Both sentences are scored at the same threshold, deliberately. The score is the
    shortfall normalised by the threshold, so a score from a 0.95 run and one from a
    0.75 run are not comparable, and the first version of this test compared them and
    failed for that reason rather than because the detector was wrong.
    """
    strict = DetectorConfig(on_fail="flag", options={"similarity": 0.95})
    near = detector.run(
        "Withdrawals made within the first twelve months incur a handling fee of "
        "5 EUR.",
        strict,
        sourced(),
    )
    far = detector.run(
        "Sharks are the largest fish in the northern Atlantic ocean.", strict, sourced()
    )
    assert near and far, "both should fall short of a 0.95 threshold"
    assert far[0].score > near[0].score, (
        f"a sentence about sharks scored {far[0].score} and a near copy scored "
        f"{near[0].score}; the shortfall should grow with the distance"
    )


# ----------------------------------------------------- what it deliberately cannot do


def test_a_true_paraphrase_reads_as_unsupported(
    detector: SummarySupportDetector,
) -> None:
    """The documented limitation, pinned so nobody mistakes this for entailment.

    "You pay nothing to take money out once a year has passed" is exactly what the
    source says and shares almost none of its words, so it scores as maximally
    unsupported. Anyone reaching for this detector to check groundedness needs to meet
    this test first.
    """
    paraphrase = detector.run(
        "You pay nothing to take money out once a year has passed.", CFG, sourced()
    )
    assert [f.label for f in paraphrase] == ["unsupported_sentence"]

    # The sharpest available statement of the limitation: a true paraphrase and a
    # sentence about sharks score within a hundredth of each other, 0.509 and 0.501 as
    # measured on 2026-08-12. An overlap measure cannot tell a correct restatement from
    # an unrelated claim, because neither shares vocabulary with the source. Anyone
    # tempted to read this detector's score as a degree of unsupportedness should read
    # that number twice.
    unrelated = detector.run(
        "Sharks are the largest fish in the northern Atlantic ocean.", CFG, sourced()
    )
    assert unrelated
    assert abs(paraphrase[0].score - unrelated[0].score) < 0.05, (
        f"the paraphrase scored {paraphrase[0].score} and an unrelated sentence "
        f"{unrelated[0].score}. If those have separated, this detector has stopped "
        "being a pure overlap measure and its docstring needs rewriting."
    )


def test_a_copied_sentence_with_its_meaning_reversed_reads_as_supported(
    detector: SummarySupportDetector,
) -> None:
    """The other half of the same limitation, and the more dangerous half.

    Inserting a negation changes the claim completely and barely moves the overlap, so
    this detector calls it supported. It is in the docstring and it is here, because a
    caller who only reads the label would draw the opposite conclusion.
    """
    sentence = (
        "Withdrawals made within the first twelve months do not incur a handling "
        "fee of 5 EUR per transaction."
    )
    assert detector.run(sentence, CFG, sourced()) == [], (
        "a negated copy is still mostly the same words, so an overlap measure "
        "accepts it. If this now reports, the detector has become something other "
        "than an overlap measure and its docstring needs rewriting."
    )


# -------------------------------------------------- saying so rather than passing


def test_no_source_is_reported_rather_than_passed(
    detector: SummarySupportDetector,
) -> None:
    found = detector.run("Any claim at all about the account.", CFG, Context())
    assert [f.label for f in found] == ["summary_support_unverifiable"]
    # log rather than the policy's action: an absent source is a configuration gap, and
    # blocking a response over one would make the detector unusable without retrieval.
    assert found[0].action == "log"


def test_a_source_of_only_fragments_says_so(detector: SummarySupportDetector) -> None:
    found = detector.run(
        "The account pays interest monthly on the closing balance.",
        CFG,
        Context(sources=("Ok. Yes. Fine.",)),
    )
    assert [f.label for f in found] == ["summary_support_no_source_sentences"]


def test_sources_may_come_from_the_policy(detector: SummarySupportDetector) -> None:
    cfg = DetectorConfig(on_fail="flag", options={"sources": [SOURCE]})
    sentence = "After twelve months have elapsed, withdrawals are free of charge."
    assert detector.run(sentence, cfg, Context()) == []


def test_truncation_is_reported_rather_than_silent(
    detector: SummarySupportDetector,
) -> None:
    text = " ".join(
        f"Claim number {n} about the account and its fees." for n in range(8)
    )
    cfg = DetectorConfig(on_fail="flag", options={"max_sentences": 2})
    labels = [f.label for f in detector.run(text, cfg, sourced())]
    assert "summary_support_truncated" in labels


def test_a_fragment_is_not_judged(detector: SummarySupportDetector) -> None:
    # "Thanks." carries no claim, and a short string matches something in any long
    # source.
    assert detector.run("Ok.", CFG, sourced()) == []


def test_a_zero_similarity_is_refused(detector: SummarySupportDetector) -> None:
    cfg = DetectorConfig(on_fail="flag", options={"similarity": 0.0})
    with pytest.raises(SummarySupportError, match="above 0"):
        detector.run("Any claim about the account.", cfg, sourced())


# ------------------------------------------------------------- the languages


#: One source, one sentence lifted from it, and one sentence that is not in it, per
#: language. The same banking passage throughout, so a failure points at the language
#: rather than at the subject matter.
#: What this is really testing is composition. The folding and the sentence splitting
#: belong to the shared multilingual core and have their own tests; what has to hold
#: here is that a sentence lifted from a Greek source is recognised through both of
#: them, and an invented Maltese one is not. Every `invented` entry deliberately opens
#: with the same word as its source, so a detector that matched on a prefix rather than
#: on the sentence would pass the supported case and fail this one.
CASES: dict[str, tuple[str, str, str]] = {
    "en": (
        "The account pays 3.1 percent annual interest. Withdrawals in the first "
        "twelve months incur a fee of 5 EUR.",
        "Withdrawals in the first twelve months incur a fee of 5 EUR.",
        "The account includes free travel insurance for all customers.",
    ),
    "ro": (
        "Contul plătește o rată anuală de 3,1 procente. Retragerile în primele "
        "douăsprezece luni au un comision de 5 EUR.",
        "Retragerile în primele douăsprezece luni au un comision de 5 EUR.",
        "Contul include asigurare de călătorie gratuită pentru toți clienții.",
    ),
    "bg": (
        "Сметката плаща 3,1 процента годишна лихва. Тегленията през първите "
        "дванадесет месеца се таксуват с 5 EUR.",
        "Тегленията през първите дванадесет месеца се таксуват с 5 EUR.",
        "Сметката включва безплатна застраховка при пътуване за всички клиенти.",
    ),
    "cs": (
        "Účet platí roční úrok 3,1 procenta. Výběry v prvních dvanácti měsících "
        "podléhají poplatku 5 EUR.",
        "Výběry v prvních dvanácti měsících podléhají poplatku 5 EUR.",
        "Účet zahrnuje bezplatné cestovní pojištění pro všechny klienty.",
    ),
    "da": (
        "Kontoen giver 3,1 procent i årlig rente. Udbetalinger i de første tolv "
        "måneder koster et gebyr på 5 EUR.",
        "Udbetalinger i de første tolv måneder koster et gebyr på 5 EUR.",
        "Kontoen indeholder gratis rejseforsikring for alle kunder.",
    ),
    "de": (
        "Das Konto zahlt einen Jahreszins von 3,1 Prozent. Abhebungen in den "
        "ersten zwölf Monaten kosten eine Gebühr von 5 EUR.",
        "Abhebungen in den ersten zwölf Monaten kosten eine Gebühr von 5 EUR.",
        "Das Konto beinhaltet eine kostenlose Reiseversicherung für alle Kunden.",
    ),
    "el": (
        "Ο λογαριασμός αποδίδει ετήσιο επιτόκιο 3,1 τοις εκατό. Οι αναλήψεις στους "
        "πρώτους δώδεκα μήνες έχουν χρέωση 5 EUR.",
        "Οι αναλήψεις στους πρώτους δώδεκα μήνες έχουν χρέωση 5 EUR.",
        "Ο λογαριασμός περιλαμβάνει δωρεάν ταξιδιωτική ασφάλιση για κάθε πελάτη.",
    ),
    "es": (
        "La cuenta paga un interés anual del 3,1 por ciento. Las retiradas en los "
        "primeros doce meses tienen una comisión de 5 EUR.",
        "Las retiradas en los primeros doce meses tienen una comisión de 5 EUR.",
        "La cuenta incluye un seguro de viaje gratuito para todos los clientes.",
    ),
    "et": (
        "Konto maksab aastas 3,1 protsenti intressi. Esimese kaheteistkümne kuu "
        "väljamaksete eest võetakse 5 EUR tasu.",
        "Esimese kaheteistkümne kuu väljamaksete eest võetakse 5 EUR tasu.",
        "Konto sisaldab tasuta reisikindlustust kõikidele klientidele.",
    ),
    "fi": (
        "Tili maksaa 3,1 prosentin vuosikoron. Ensimmäisten kahdentoista kuukauden "
        "nostoista veloitetaan 5 EUR maksu.",
        "Ensimmäisten kahdentoista kuukauden nostoista veloitetaan 5 EUR maksu.",
        "Tili sisältää ilmaisen matkavakuutuksen kaikille asiakkaille.",
    ),
    "fr": (
        "Le compte verse un intérêt annuel de 3,1 pour cent. Les retraits pendant "
        "les douze premiers mois entraînent des frais de 5 EUR.",
        "Les retraits pendant les douze premiers mois entraînent des frais de 5 EUR.",
        "Le compte comprend une assurance voyage gratuite pour tous les clients.",
    ),
    "ga": (
        "Íocann an cuntas ús bliantúil de 3,1 faoin gcéad. Gearrtar táille 5 EUR ar "
        "aistarraingtí sa chéad dhá mhí dhéag.",
        "Gearrtar táille 5 EUR ar aistarraingtí sa chéad dhá mhí dhéag.",
        "Íocann an cuntas árachas taistil saor in aisce do gach custaiméir.",
    ),
    "hr": (
        "Račun plaća godišnju kamatu od 3,1 posto. Povlačenja u prvih dvanaest "
        "mjeseci imaju naknadu od 5 EUR.",
        "Povlačenja u prvih dvanaest mjeseci imaju naknadu od 5 EUR.",
        "Račun uključuje besplatno putno osiguranje za sve klijente.",
    ),
    "hu": (
        "A számla évi 3,1 százalék kamatot fizet. Az első tizenkét hónapban a "
        "kifizetésekre 5 EUR díj vonatkozik.",
        "Az első tizenkét hónapban a kifizetésekre 5 EUR díj vonatkozik.",
        "A számla ingyenes utasbiztosítást tartalmaz minden ügyfél számára.",
    ),
    "it": (
        "Il conto paga un interesse annuo del 3,1 per cento. I prelievi nei primi "
        "dodici mesi comportano una commissione di 5 EUR.",
        "I prelievi nei primi dodici mesi comportano una commissione di 5 EUR.",
        "Il conto offre una copertura di viaggio gratuita per tutti i clienti.",
    ),
    "lt": (
        "Sąskaita moka 3,1 procento metines palūkanas. Per pirmuosius dvylika "
        "mėnesių išėmimams taikomas 5 EUR mokestis.",
        "Per pirmuosius dvylika mėnesių išėmimams taikomas 5 EUR mokestis.",
        "Sąskaita apima nemokamą kelionių draudimą visiems klientams.",
    ),
    "lv": (
        "Kontam ir 3,1 procenta gada procentu likme. Izmaksām pirmajos divpadsmit "
        "mēnešos piemēro 5 EUR maksu.",
        "Izmaksām pirmajos divpadsmit mēnešos piemēro 5 EUR maksu.",
        "Kontam ir bezmaksas ceļojumu apdrošināšana visiem klientiem.",
    ),
    "mt": (
        "Il-kont iħallas imgħax annwali ta' 3,1 fil-mija. L-irtirar fl-ewwel "
        "tnax-il xahar għandu tariffa ta' 5 EUR.",
        "L-irtirar fl-ewwel tnax-il xahar għandu tariffa ta' 5 EUR.",
        "Il-kont jinkludi assigurazzjoni tal-ivvjaġġar bla ħlas għall-klijenti kollha.",
    ),
    "nl": (
        "De rekening betaalt 3,1 procent jaarlijkse rente. Opnames in de eerste "
        "twaalf maanden kosten een vergoeding van 5 EUR.",
        "Opnames in de eerste twaalf maanden kosten een vergoeding van 5 EUR.",
        "De rekening bevat een gratis reisverzekering voor alle klanten.",
    ),
    "pl": (
        "Rachunek płaci 3,1 procent odsetek w skali roku. Wypłaty w pierwszych "
        "dwunastu miesiącach podlegają opłacie 5 EUR.",
        "Wypłaty w pierwszych dwunastu miesiącach podlegają opłacie 5 EUR.",
        "Rachunek obejmuje bezpłatne ubezpieczenie podróżne dla wszystkich klientów.",
    ),
    "pt": (
        "A conta paga juros anuais de 3,1 por cento. Os saques nos primeiros doze "
        "meses têm uma taxa de 5 EUR.",
        "Os saques nos primeiros doze meses têm uma taxa de 5 EUR.",
        "A conta inclui seguro de viagem gratuito para todos os clientes.",
    ),
    "sk": (
        "Účet platí ročný úrok 3,1 percenta. Výbery v prvých dvanástich mesiacoch "
        "podliehajú poplatku 5 EUR.",
        "Výbery v prvých dvanástich mesiacoch podliehajú poplatku 5 EUR.",
        "Účet zahŕňa bezplatné cestovné poistenie pre všetkých klientov.",
    ),
    "sl": (
        "Račun plačuje 3,1 odstotka letnih obresti. Dvigi v prvih dvanajstih "
        "mesecih so obremenjeni s 5 EUR.",
        "Dvigi v prvih dvanajstih mesecih so obremenjeni s 5 EUR.",
        "Račun vključuje brezplačno potovalno zavarovanje za vse stranke.",
    ),
    "sv": (
        "Kontot ger 3,1 procent årlig ränta. Uttag under de första tolv månaderna "
        "kostar en avgift på 5 EUR.",
        "Uttag under de första tolv månaderna kostar en avgift på 5 EUR.",
        "Kontot innehåller en gratis reseförsäkring för alla kunder.",
    ),
    "tr": (
        "Hesap yıllık yüzde 3,1 faiz ödüyor. İlk on iki ayda yapılan çekimler için "
        "5 EUR ücret alınır.",
        "İlk on iki ayda yapılan çekimler için 5 EUR ücret alınır.",
        "Hesap tüm müşteriler için ücretsiz seyahat sigortası içerir.",
    ),
    "az": (
        "Hesab illik 3,1 faiz gəlir ödəyir. İlk on iki ayda çıxarışlar üçün 5 EUR "
        "komissiya tutulur.",
        "İlk on iki ayda çıxarışlar üçün 5 EUR komissiya tutulur.",
        "Hesab bütün müştərilər üçün pulsuz səyahət sığortası daxil edir.",
    ),
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(CASES) == CLAIMED


@pytest.mark.parametrize("code", sorted(CASES))
def test_a_sentence_lifted_from_the_source_is_recognised(code: str) -> None:
    source, supported, _ = CASES[code]
    context = Context(sources=(source,))
    assert detector_for().run(supported, CFG, context) == [], code


@pytest.mark.parametrize("code", sorted(CASES))
def test_a_sentence_absent_from_the_source_is_reported(code: str) -> None:
    """Which is what gives the test above its meaning.

    Without this the pair would pass for a detector that reported nothing ever, and
    "reports nothing ever" is the failure mode this library treats as a vulnerability.
    """
    source, _, invented = CASES[code]
    context = Context(sources=(source,))
    found = detector_for().run(invented, CFG, context)
    assert [f.label for f in found] == ["unsupported_sentence"], code


@pytest.mark.parametrize("code", sorted(CASES))
def test_every_lifted_sentence_is_long_enough_to_be_judged(code: str) -> None:
    """A fixture below `min_words` would pass the supported case by being skipped.

    The compounding languages are the risk: a Finnish or Hungarian sentence carrying the
    same content as an English one can do it in fewer words, and five is the floor.
    """
    _, supported, invented = CASES[code]
    assert len(supported.split()) >= DEFAULT_MIN_WORDS, code
    assert len(invented.split()) >= DEFAULT_MIN_WORDS, code


def detector_for() -> SummarySupportDetector:
    """A warmed detector for the sweeps above, which are parametrized on a code.

    The `detector` fixture would work too. This is a plain function because the sweeps
    read better taking one argument, and warming costs nothing: there is no model.
    """
    found = SummarySupportDetector()
    found.warm()
    return found
