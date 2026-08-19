"""Shutdown resilience.

Regression test for a bug found during live verification: NetworkWatcher.stop() raised
PermissionError (Scapy socket teardown without root), which aborted the shutdown
sequence before the firewall cleanup ran — leaving live DROP rules and a linked PHANTOM
chain on the host after the process exited.

Every shutdown step must be isolated so the iptables teardown always runs.
"""

import pytest

from backend.main import lifespan, state


class Recorder:
    """Stands in for a watcher; optionally explodes on stop()."""

    def __init__(self, name, explode=False, is_async=True):
        self.name = name
        self.explode = explode
        self.is_async = is_async
        self.stopped = False

    def start(self):
        if self.is_async:
            async def _noop():
                return None
            return _noop()
        return None

    def stop(self):
        self.stopped = True
        if self.explode:
            raise PermissionError(f"{self.name} cannot be stopped")
        if self.is_async:
            async def _noop():
                return None
            return _noop()
        return None


@pytest.fixture
def stubbed_state(monkeypatch):
    """Replace watchers, LLM init and responder with inert doubles."""
    cleanup_calls = []

    log_w = Recorder("log_watcher")
    net_w = Recorder("network_watcher")
    file_w = Recorder("file_watcher", is_async=False)

    async def fake_ensure_chain():
        return True

    async def fake_cleanup_chain():
        cleanup_calls.append(True)

    async def fake_gemma_init():
        return None

    monkeypatch.setattr(state.responder, "ensure_chain", fake_ensure_chain)
    monkeypatch.setattr(state.responder, "cleanup_chain", fake_cleanup_chain)
    monkeypatch.setattr(state.gemma, "initialize", fake_gemma_init)

    # The startup half constructs real watchers; replace them immediately after.
    monkeypatch.setattr("backend.main.LogWatcher", lambda *a, **k: log_w)
    monkeypatch.setattr("backend.main.NetworkWatcher", lambda *a, **k: net_w)
    monkeypatch.setattr("backend.main.FileWatcher", lambda *a, **k: file_w)
    return {"log": log_w, "net": net_w, "file": file_w, "cleanup_calls": cleanup_calls}


async def test_firewall_cleanup_runs_even_when_a_watcher_fails(stubbed_state):
    """The original bug: one raising watcher skipped the iptables teardown."""
    stubbed_state["net"].explode = True

    async with lifespan(None):
        pass

    assert stubbed_state["cleanup_calls"], "iptables cleanup was skipped after a watcher error"


async def test_later_watchers_still_stop_after_an_earlier_failure(stubbed_state):
    stubbed_state["log"].explode = True

    async with lifespan(None):
        pass

    assert stubbed_state["net"].stopped
    assert stubbed_state["file"].stopped
    assert stubbed_state["cleanup_calls"]


async def test_clean_shutdown_stops_everything(stubbed_state):
    async with lifespan(None):
        pass

    assert stubbed_state["log"].stopped
    assert stubbed_state["net"].stopped
    assert stubbed_state["file"].stopped
    assert stubbed_state["cleanup_calls"]
