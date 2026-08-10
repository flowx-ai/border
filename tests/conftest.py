# SPDX-License-Identifier: Apache-2.0
"""Test-wide configuration.

The default suite runs with no network. This is enforced here rather than trusted,
because a detector that quietly reaches for a hosted model would otherwise pass CI on
a machine that happens to be online.

A test that genuinely needs a socket, for example a first-run model download, marks
itself with @pytest.mark.network and is skipped from the default selection.
"""

from __future__ import annotations

import socket
from typing import Any, NoReturn

import pytest

_MESSAGE = (
    "network access during a test. Nothing on the scan path may open a socket. "
    "If this test genuinely needs one, mark it @pytest.mark.network."
)


def _blocked(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise RuntimeError(_MESSAGE)


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("network") is not None:
        return
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
