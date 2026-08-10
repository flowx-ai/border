# SPDX-License-Identifier: Apache-2.0
"""The offline guard in conftest.py has to actually bite.

Without this, the guard could silently stop working and every claim about the default
suite running with no network would still look green. The scan-path assertion itself
is tests/test_offline.py, which arrives in phase 7.
"""

from __future__ import annotations

import socket

import pytest


def test_opening_a_socket_is_blocked_by_default() -> None:
    with pytest.raises(RuntimeError, match="network access during a test"):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_resolving_a_name_is_blocked_by_default() -> None:
    with pytest.raises(RuntimeError, match="network access during a test"):
        socket.getaddrinfo("huggingface.co", 443)


@pytest.mark.network
def test_the_marker_lifts_the_guard() -> None:
    # No connection is attempted. This only proves the exemption path exists, so that
    # a genuine first-run download test can be written later without fighting the
    # fixture.
    assert callable(socket.socket)
