# SPDX-License-Identifier: Apache-2.0
"""Tests for the infra_leakage detector.

Most of this file is about what must not fire. The shapes themselves are easy: an RFC
1918 address, a home directory, a metadata endpoint. What makes the detector usable is
that a version number shaped like an address, a date, a documentation address and an
ordinary sentence in any of the 26 languages all come back empty.

The positive case that motivated it is the proposal's own: a stack trace carrying
`/Users/<name>/secrets/config.yaml` and `10.0.4.17:8443` produced nothing from the
shipped configuration but a spurious `pii:date`.
"""

from __future__ import annotations

import itertools

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.infra_leakage import KINDS, InfraLeakageDetector
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED

CFG = DetectorConfig(on_fail="flag")
CTX = Context()
DETECTOR = InfraLeakageDetector()


def found(text: str, cfg: DetectorConfig = CFG) -> list[tuple[str, str]]:
    """(label, matched text) for each finding, in order."""
    out = []
    for finding in DETECTOR.run(text, cfg, CTX):
        assert finding.span is not None
        start, end = finding.span
        out.append((finding.label, text[start:end]))
    return out


def labels(text: str, cfg: DetectorConfig = CFG) -> list[str]:
    return [label for label, _ in found(text, cfg)]


# ----------------------------------------------------------------- the motivating case


def test_the_proposal_stack_trace_is_found() -> None:
    text = (
        'Traceback (most recent call last):\n  File "/Users/andrei/secrets/'
        'config.yaml", line 12\nConnectionError: 10.0.4.17:8443 refused'
    )
    assert found(text) == [
        ("user_home_path", "/Users/andrei/secrets/config.yaml"),
        ("private_ip", "10.0.4.17"),
    ]


# ------------------------------------------------------------------------- addresses


@pytest.mark.parametrize(
    "address",
    [
        "10.0.4.17",  # RFC 1918
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.20",
        "100.64.0.1",  # RFC 6598 carrier-grade NAT
        "100.127.255.254",
        "fd12:3456:789a::1",  # RFC 4193 unique local
        "fc00::5",
    ],
)
def test_private_addresses_are_found(address: str) -> None:
    assert found(f"The database is at {address} behind the firewall.") == [
        ("private_ip", address)
    ]


@pytest.mark.parametrize("address", ["127.0.0.1", "127.8.9.10", "::1"])
def test_loopback_addresses_are_found(address: str) -> None:
    assert found(f"It listens on {address} only.") == [("loopback_ip", address)]


@pytest.mark.parametrize("address", ["169.254.10.20", "fe80::1ff:fe23:4567:890a"])
def test_link_local_addresses_are_found(address: str) -> None:
    assert found(f"The interface came up as {address} without DHCP.") == [
        ("link_local_ip", address)
    ]


@pytest.mark.parametrize(
    "endpoint",
    [
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "100.100.100.200",
        "metadata.google.internal",
    ],
)
def test_cloud_metadata_endpoints_are_their_own_label(endpoint: str) -> None:
    """Checked before the ranges they sit in, so 169.254.169.254 is not link-local."""
    assert found(f"curl http://{endpoint}/ returned the role.") == [
        ("metadata_endpoint", endpoint)
    ]


def test_metadata_paths_are_found_without_an_address() -> None:
    assert labels("GET /latest/meta-data/iam/security-credentials/ worked") == [
        "metadata_endpoint"
    ]
    assert labels("then GET /computeMetadata/v1/instance/ with the header") == [
        "metadata_endpoint"
    ]


def test_an_address_with_a_port_or_a_prefix_is_reported_without_it() -> None:
    assert found("connect to 192.168.0.10:5432 now") == [("private_ip", "192.168.0.10")]
    assert found("route 10.20.0.0/16 via the vpn") == [("private_ip", "10.20.0.0")]


def test_a_bracketed_ipv6_address_with_a_port_is_found() -> None:
    assert found("http://[fd00::10]:8080/health") == [("private_ip", "fd00::10")]


def test_an_address_inside_a_url_is_found() -> None:
    assert found("see http://10.1.2.3/admin for the panel") == [
        ("private_ip", "10.1.2.3")
    ]


def test_an_address_at_the_end_of_a_sentence_is_found() -> None:
    assert found("The gateway is 192.168.1.1.") == [("private_ip", "192.168.1.1")]


# ------------------------------------------------------------ addresses that are not


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "151.101.1.69",
        "2a00:1450:4001:80b::200e",
        "172.32.0.1",  # just outside 172.16/12
        "100.128.0.1",  # just outside 100.64/10
    ],
)
def test_public_addresses_are_not_reported(address: str) -> None:
    assert labels(f"The resolver at {address} answered.") == []


@pytest.mark.parametrize(
    "address", ["192.0.2.10", "198.51.100.7", "203.0.113.254", "2001:db8::1"]
)
def test_documentation_addresses_are_not_reported(address: str) -> None:
    """RFC 5737 and RFC 3849 reserve these for examples, which is what they are.

    The stdlib's `is_private` says True for all of them, which is why the detector
    names its own networks rather than calling it.
    """
    assert labels(f"For example, point the client at {address}.") == []


def test_the_unspecified_address_is_not_reported() -> None:
    assert labels("bind to 0.0.0.0 and :: to accept every interface") == []


@pytest.mark.parametrize(
    "text",
    [
        "Please upgrade to version 10.0.0.1 before Friday.",
        "Release 10.2.3.4 fixes the login bug.",
        "firmware 192.168.1.2 is not a real firmware number but reads like one",
        "Build 10.0.19041.1 of Windows",
        "running v10.0.0.1 on the edge nodes",
    ],
)
def test_version_numbers_are_not_addresses(text: str) -> None:
    assert labels(text) == []


def test_a_version_word_elsewhere_in_the_sentence_does_not_hide_an_address() -> None:
    text = "The server at 10.0.0.5 runs nginx, and version 1.25 is fine."
    assert labels(text) == ["private_ip"]


@pytest.mark.parametrize(
    "text",
    [
        "The meeting is on 10.04.2026 at 10.30.",
        "Invoice dated 01.02.2024, due 15.03.2024.",
        "The total is 10.100.100.100 EUR over the contract term.",
        "Population 10.000.000.000 by the end of the century.",
        "OID 1.3.6.1.4.1.311 identifies the vendor.",
        "Section 10.1.2 covers refunds.",
    ],
)
def test_dates_and_dotted_numbers_are_not_addresses(text: str) -> None:
    assert labels(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "The call lasted 12:30:45 in total.",
        "MAC 00:1a:2b:3c:4d:5e is on the label.",
        "Use std::vector and a[::2] for the slice.",
        "Ratio 3:2 and time 10:00.",
    ],
)
def test_colon_separated_things_are_not_ipv6(text: str) -> None:
    assert labels(text) == []


# ---------------------------------------------------------------------------- paths


@pytest.mark.parametrize(
    ("text", "path"),
    [
        ("see /home/maria/projects/api/.env for it", "/home/maria/projects/api/.env"),
        ("opened /Users/andrei/Desktop/report.pdf", "/Users/andrei/Desktop/report.pdf"),
        (
            r"at C:\Users\ioana\AppData\Roaming\app.ini",
            r"C:\Users\ioana\AppData\Roaming\app.ini",
        ),
        ("at c:/users/ioana/notes.txt", "c:/users/ioana/notes.txt"),
        (r'"C:\\Users\\ioana\\key.pem"', r"C:\\Users\\ioana\\key.pem"),
        ("file:///home/maria/notes.md was attached", "/home/maria/notes.md"),
        ("the home dir is /home/maria.", "/home/maria"),
    ],
)
def test_home_directories_are_found(text: str, path: str) -> None:
    assert found(text) == [("user_home_path", path)]


@pytest.mark.parametrize(
    "text",
    [
        "Replace /home/<user>/app with your own path.",
        "Put it in /Users/username/Library/.",
        "Use /home/$USER/.config or /home/{user}/.cache.",
        r"Check C:\Users\Public\Documents for the shared copy.",
        "Save to /Users/Shared/exports.",
        "Paths look like /home/you/project.",
        "Paths look like /home/user/project.",
        "en Linux, /home/usuario/archivo.txt.",
        "Wykonaj: rm -r /home/użytkownik",
        "Pfad: /home/benutzer/daten",
        "polecenie ‘rm -rf /home/*’ w razie potrzeby",
    ],
)
def test_placeholder_home_directories_are_not_reported(text: str) -> None:
    """A path written as a template exposes no one's layout."""
    assert labels(text) == []


@pytest.mark.parametrize(
    ("text", "path"),
    [
        ("read /etc/shadow as root", "/etc/shadow"),
        (
            "config is /etc/nginx/sites-enabled/api.conf",
            "/etc/nginx/sites-enabled/api.conf",
        ),
        ("data lives in /var/lib/postgresql/16/main", "/var/lib/postgresql/16/main"),
        ("tail /var/log/app/error.log", "/var/log/app/error.log"),
        ("the key is in /root/.ssh/id_rsa", "/root/.ssh/id_rsa"),
        ("cat /proc/self/environ", "/proc/self/environ"),
        ("deployed under /opt/acme/billing/", "/opt/acme/billing/"),
        (
            r"C:\Windows\System32\drivers\etc\hosts was edited",
            r"C:\Windows\System32\drivers\etc\hosts",
        ),
        (r"C:\ProgramData\Acme\license.key", r"C:\ProgramData\Acme\license.key"),
    ],
)
def test_system_paths_are_found(text: str, path: str) -> None:
    assert found(text) == [("system_path", path)]


@pytest.mark.parametrize(
    "text",
    [
        "Go to https://example.com/home/maria/profile to see it.",
        "https://example.com/Users/andrei is a web page, not a disk.",
        "The route https://api.example.com/etc/status is public.",
        "See src/etc/config.py in the repository.",
        "The ./etc/app.conf file is relative.",
        "Put it under /etc and restart.",
        "Speed 90 km/h, and/or 3/4 of the time.",
        "the ~/projects folder",
    ],
)
def test_url_paths_relative_paths_and_bare_roots_are_not_reported(text: str) -> None:
    assert labels(text) == []


# ------------------------------------------------------------------------ hostnames


@pytest.mark.parametrize(
    "host",
    [
        "db01.internal",
        "wiki.corp",
        "printer.local",
        "nas.lan",
        "jenkins.build.intranet",
        "gw.home.arpa",
        "api.default.svc.cluster.local",
        "box.localdomain",
    ],
)
def test_internal_hostnames_are_found(host: str) -> None:
    assert found(f"It pulls from {host} every hour.") == [("internal_hostname", host)]


def test_an_internal_hostname_in_an_email_or_url_is_found() -> None:
    assert found("mail ops@mx.corp or open https://grafana.internal:3000/d/x") == [
        ("internal_hostname", "mx.corp"),
        ("internal_hostname", "grafana.internal"),
    ]


@pytest.mark.parametrize(
    "text",
    [
        "import com.acme.internal;",
        "The class org.apache.internal.Util is private API.",
        "Copy .env.local and settings.local before you start.",
        "Acme Corp. and Beta Corp are partners.",
        "It is a local matter for the lan party.",
        "Visit example.com or example.internal.example.org.",
        "The file config.local.php holds overrides.",
    ],
)
def test_package_names_filenames_and_prose_are_not_hostnames(text: str) -> None:
    assert labels(text) == []


# -------------------------------------------------------------------------- options


def test_kinds_restricts_what_is_reported() -> None:
    text = "10.0.0.5 and 127.0.0.1 and /home/maria/x"
    cfg = DetectorConfig(on_fail="flag", options={"kinds": ["private_ip"]})
    assert labels(text, cfg) == ["private_ip"]


def test_an_unknown_kind_is_refused_rather_than_ignored() -> None:
    cfg = DetectorConfig(on_fail="flag", options={"kinds": ["private_ips"]})
    with pytest.raises(ValueError, match="private_ips"):
        DETECTOR.run("x", cfg, CTX)


def test_kind_actions_override_the_detector_action() -> None:
    cfg = DetectorConfig(
        on_fail="flag",
        options={"kind_actions": {"metadata_endpoint": "block", "loopback_ip": "log"}},
    )
    got = {
        f.label: f.action
        for f in DETECTOR.run("169.254.169.254 127.0.0.1 10.0.0.1", cfg, CTX)
    }
    assert got == {
        "metadata_endpoint": "block",
        "loopback_ip": "log",
        "private_ip": "flag",
    }


def test_a_bad_kind_action_is_refused() -> None:
    for bad in ({"private_ip": "shout"}, {"nope": "flag"}, ["private_ip"]):
        cfg = DetectorConfig(on_fail="flag", options={"kind_actions": bad})
        with pytest.raises(ValueError):
            DETECTOR.run("x", cfg, CTX)


def test_every_kind_is_documented_by_a_test_above() -> None:
    assert set(KINDS) == {
        "private_ip",
        "loopback_ip",
        "link_local_ip",
        "metadata_endpoint",
        "user_home_path",
        "system_path",
        "internal_hostname",
    }


def test_spans_do_not_overlap_and_are_ordered() -> None:
    text = (
        "http://metadata.google.internal/computeMetadata/v1/ from "
        "/home/maria/app on 10.0.0.9 and db.internal"
    )
    spans = [f.span for f in DETECTOR.run(text, CFG, CTX) if f.span is not None]
    assert len(spans) == 5
    assert spans == sorted(spans)
    for (_, end), (start, _) in itertools.pairwise(spans):
        assert end <= start


def test_empty_text_finds_nothing() -> None:
    assert labels("") == []
    assert labels("   \n") == []


# ---------------------------------------------------------------------- the languages


#: Ordinary prose in each of the 26 languages, which must come back clean.
PROSE: dict[str, str] = {
    "en": "Your balance is 412 EUR and the branch opens at nine in the morning.",
    "ro": "Soldul este de 412 EUR și sucursala se deschide la nouă dimineața.",
    "bg": "Салдото ви е 412 EUR и клонът отваря в девет сутринта.",
    "cs": "Váš zůstatek je 412 EUR a filiálka otevírá v devět ráno.",
    "da": "Din saldo er 412 EUR, og filialen åbner klokken ni om morgenen.",
    "de": "Ihr Guthaben beträgt 412 EUR und die Filiale öffnet um neun Uhr.",
    "el": "Το υπόλοιπό σας είναι 412 EUR και το κατάστημα ανοίγει στις εννέα.",
    "es": "Su saldo es de 412 EUR y la sucursal abre a las nueve de la mañana.",
    "et": "Teie jääk on 412 EUR ja kontor avatakse hommikul kell üheksa.",
    "fi": "Saldosi on 412 EUR ja konttori avataan yhdeksältä aamulla.",
    "fr": "Votre solde est de 412 EUR et l'agence ouvre à neuf heures.",
    "ga": "Is é 412 EUR do iarmhéid agus osclaíonn an brainse ar a naoi.",
    "hr": "Vaše stanje je 412 EUR, a poslovnica se otvara u devet ujutro.",
    "hu": "Az egyenlege 412 EUR, és a fiók reggel kilenckor nyit.",
    "it": "Il tuo saldo è di 412 EUR e la filiale apre alle nove del mattino.",
    "lt": "Jūsų likutis yra 412 EUR, o skyrius atidaromas devintą ryto.",
    "lv": "Jūsu atlikums ir 412 EUR, un filiāle tiek atvērta deviņos.",
    "mt": "Il-bilanc tieghek huwa 412 EUR u l-fergha tiftah fid-disgha.",
    "nl": "Uw saldo is 412 EUR en het filiaal opent om negen uur.",
    "pl": "Twoje saldo wynosi 412 EUR, a oddział otwiera się o dziewiątej.",
    "pt": "O seu saldo é de 412 EUR e a agência abre às nove da manhã.",
    "sk": "Váš zostatok je 412 EUR a filiálka otvára o deviatej ráno.",
    "sl": "Vaše stanje je 412 EUR in poslovalnica se odpre ob devetih.",
    "sv": "Ditt saldo är 412 EUR och kontoret öppnar klockan nio.",
    "tr": "Bakiyeniz 412 EUR ve şube sabah dokuzda açılıyor.",
    "az": "Balansınız 412 EUR və filial səhər doqquzda açılır.",
}

#: "Please install version 10.0.0.1 of the app." The version word sits before the
#: number in most of the 26 and after it in Hungarian, Turkish and Azerbaijani, which is
#: why the cue is looked for on both sides.
VERSION: dict[str, str] = {
    "en": "Please install version 10.0.0.1 of the app.",
    "ro": "Vă rugăm să instalați versiunea 10.0.0.1 a aplicației.",
    "bg": "Моля, инсталирайте версия 10.0.0.1 на приложението.",
    "cs": "Nainstalujte si prosím verzi 10.0.0.1 aplikace.",
    "da": "Installer venligst version 10.0.0.1 af appen.",
    "de": "Bitte installieren Sie Version 10.0.0.1 der App.",
    "el": "Εγκαταστήστε την έκδοση 10.0.0.1 της εφαρμογής.",
    "es": "Instale la versión 10.0.0.1 de la aplicación.",
    "et": "Palun installige rakenduse versioon 10.0.0.1.",
    "fi": "Asenna sovelluksen versio 10.0.0.1.",
    "fr": "Veuillez installer la version 10.0.0.1 de l'application.",
    "ga": "Suiteáil leagan 10.0.0.1 den aip, le do thoil.",
    "hr": "Instalirajte verziju 10.0.0.1 aplikacije.",
    "hu": "Kérjük, telepítse az alkalmazás 10.0.0.1-es verzióját.",
    "it": "Installa la versione 10.0.0.1 dell'app.",
    "lt": "Įdiekite programėlės versiją 10.0.0.1.",
    "lv": "Lūdzu, instalējiet lietotnes versiju 10.0.0.1.",
    "mt": "Jekk jogħġbok installa l-verżjoni 10.0.0.1 tal-app.",
    "nl": "Installeer versie 10.0.0.1 van de app.",
    "pl": "Zainstaluj wersję 10.0.0.1 aplikacji.",
    "pt": "Instale a versão 10.0.0.1 da aplicação.",
    "sk": "Nainštalujte si verziu 10.0.0.1 aplikácie.",
    "sl": "Namestite različico 10.0.0.1 aplikacije.",
    "sv": "Installera version 10.0.0.1 av appen.",
    "tr": "Lütfen uygulamanın 10.0.0.1 sürümünü yükleyin.",
    "az": "Zəhmət olmasa tətbiqin 10.0.0.1 versiyasını quraşdırın.",
}

#: A home directory named in each language's script and diacritics, because the user
#: segment is matched with a Unicode word class and an ASCII one would miss most of
#: these.
USERS: dict[str, str] = {
    "en": "alice",
    "ro": "ștefan",
    "bg": "иван",
    "cs": "jiří",
    "da": "søren",
    "de": "jürgen",
    "el": "νίκος",
    "es": "íñigo",
    "et": "jüri",
    "fi": "väinö",
    "fr": "hélène",
    "ga": "seán",
    "hr": "đuro",
    "hu": "győző",
    "it": "niccolò",
    "lt": "jonas",
    "lv": "jānis",
    "mt": "ġorġ",
    "nl": "joost",
    "pl": "łukasz",
    "pt": "joão",
    "sk": "ľubo",
    "sl": "žiga",
    "sv": "åsa",
    "tr": "çağrı",
    "az": "əli",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(PROSE) == set(VERSION) == set(USERS) == CLAIMED


@pytest.mark.parametrize("code", sorted(PROSE))
def test_ordinary_prose_in_each_language_is_clean(code: str) -> None:
    assert labels(PROSE[code]) == [], code


@pytest.mark.parametrize("code", sorted(VERSION))
def test_a_version_number_in_each_language_is_not_an_address(code: str) -> None:
    assert labels(VERSION[code]) == [], code


@pytest.mark.parametrize("code", sorted(USERS))
def test_a_leak_is_found_whatever_the_surrounding_language(code: str) -> None:
    path = f"/home/{USERS[code]}/app/config.yaml"
    text = f"{PROSE[code]} {path} 10.0.4.17:8443"
    assert found(text) == [("user_home_path", path), ("private_ip", "10.0.4.17")], code


# -------------------------------------------------------------- catalogue agreement


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    spec = CATALOGUE[DETECTOR.id]
    assert (spec.tier, spec.sides) == (DETECTOR.tier, DETECTOR.sides)
    assert spec.budget_ms == 5.0
    assert not spec.requires, "stdlib ipaddress and re, so it needs nothing"
    assert DETECTOR.id in CORE


def test_it_is_reachable_through_the_registry() -> None:
    from flowx_border.registry import implemented_detectors

    assert "infra_leakage" in implemented_detectors()
