# SPDX-License-Identifier: Apache-2.0
"""Test-wide configuration.

The default suite runs with no network. This is enforced here rather than trusted,
because a detector that quietly reaches for a hosted model would otherwise pass CI on
a machine that happens to be online.

What is blocked, and why it changed
-----------------------------------

The guard blocks **outbound connections and name resolution**, not the construction
of a socket object. It used to block construction, which was a proxy for blocking
egress, and the proxy was wrong in a way that mattered: asyncio builds a socketpair
for its own self-pipe, so any test touching an event loop failed with a message about
network access it was not attempting. The FastAPI adapter tests hit exactly that.

Blocking `connect` on an AF_INET or AF_INET6 socket, plus `getaddrinfo` and
`create_connection`, states the invariant precisely: nothing on the scan path reaches
another machine. A socket created and never connected is not egress, and neither is a
unix socket or a socketpair.

A test that genuinely needs egress, for example a first-run model download, marks itself
with @pytest.mark.network. The marker lifts the guard; it does not deselect the test.
"""

from __future__ import annotations

import socket
from typing import Any, NoReturn

import pytest

_MESSAGE = (
    "network access during a test. Nothing on the scan path may reach another machine. "
    "If this test genuinely needs egress, mark it @pytest.mark.network."
)

#: The families that can leave the machine. AF_UNIX and a socketpair cannot, so they are
#: deliberately absent.
_REMOTE_FAMILIES = {socket.AF_INET, socket.AF_INET6}

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _blocked(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise RuntimeError(_MESSAGE)


def _guarded_connect(self: socket.socket, address: Any) -> Any:
    if self.family in _REMOTE_FAMILIES:
        raise RuntimeError(_MESSAGE)
    return _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> Any:
    if self.family in _REMOTE_FAMILIES:
        raise RuntimeError(_MESSAGE)
    return _real_connect_ex(self, address)


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("network") is not None:
        return
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
