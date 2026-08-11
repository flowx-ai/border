# SPDX-License-Identifier: Apache-2.0
"""The offline guard in conftest.py has to actually bite.

Without this, the guard could silently stop working and every claim about the default
suite running with no network would still look green. The scan-path assertion itself
is tests/test_offline.py, which arrives in phase 7.
"""

from __future__ import annotations

import socket

import pytest


def test_connecting_out_is_blocked_by_default() -> None:
    # Connecting, not constructing. The guard used to block construction, which was
    # a proxy for egress and a wrong one: asyncio builds a socketpair for its own
    # self-pipe, so every test touching an event loop failed with a message about
    # network access it never attempted.
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(RuntimeError, match="network access during a test"),
    ):
        sock.connect(("huggingface.co", 443))


def test_constructing_a_socket_is_allowed() -> None:
    # A socket that never connects is not egress, and asyncio needs to make them.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        assert sock.family == socket.AF_INET


def test_an_in_process_socketpair_is_allowed() -> None:
    # This is what asyncio's self-pipe uses. It cannot leave the machine.
    left, right = socket.socketpair()
    with left, right:
        left.send(b"x")
        assert right.recv(1) == b"x"


def test_resolving_a_name_is_blocked_by_default() -> None:
    with pytest.raises(RuntimeError, match="network access during a test"):
        socket.getaddrinfo("huggingface.co", 443)


@pytest.mark.network
def test_the_marker_lifts_the_guard() -> None:
    # No connection is attempted. This only proves the exemption path exists, so that
    # a genuine first-run download test can be written later without fighting the
    # fixture.
    assert callable(socket.socket)
