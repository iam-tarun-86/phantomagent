"""Responder execution paths -- asserts what actually reaches the shell.

Every test here stubs Responder._run, so no privileged command is ever executed. The
point is to prove that rejected input produces *zero* subprocess calls.
"""

import pytest

from backend.config import IPTABLES_CHAIN
from backend.pipeline.responder import Responder


class FakeResult:
    def __init__(self, returncode=0, stderr=b""):
        self.returncode = returncode
        self.stderr = stderr


@pytest.fixture
def responder(monkeypatch, tmp_path):
    """Responder with _run stubbed and forensic reports redirected to tmp_path."""
    r = Responder()
    r.calls = []

    async def fake_run(argv, check=False):
        r.calls.append(list(argv))
        # -C existence probes report "no such rule" so blocks proceed.
        if "-C" in argv:
            return FakeResult(returncode=1)
        return FakeResult(returncode=0)

    monkeypatch.setattr(r, "_run", fake_run)

    async def fake_report(threat):
        return str(tmp_path / "report.txt")

    monkeypatch.setattr(r, "_generate_forensic_report", fake_report)
    return r


def iptables_calls(responder):
    return [c for c in responder.calls if "iptables" in c]


# ===== Malicious model output must not execute =====

async def test_rejected_command_produces_no_subprocess_call(responder):
    """A model verdict containing `iptables -F` must reach the shell zero times."""
    threat = {
        "id": "T1",
        "source_ip": "172.28.0.10",
        "active_defense_actions": ["iptables -F"],
    }
    result = await responder.execute("CONTAIN", threat)

    assert not any("-F" in call for call in responder.calls)
    assert any("Rejected unauthorized command" in a for a in result["actions_taken"])


async def test_rejected_structured_action_produces_no_subprocess_call(responder):
    threat = {
        "id": "T2",
        "source_ip": "172.28.0.10",
        "defense_action": {"action": "EXEC_SHELL", "target_ip": "172.28.0.10"},
    }
    result = await responder.execute("CONTAIN", threat)

    assert any("Rejected unauthorized action" in a for a in result["actions_taken"])
    # The core IP block still runs -- rejecting the model's request must not disable containment.
    assert any(c[:2] == ["iptables", "-A"] for c in responder.calls)


# ===== Chain wiring =====

async def test_chain_is_linked_from_both_input_and_forward(responder):
    """FORWARD is required: container-to-container lab traffic never traverses INPUT."""
    await responder.ensure_chain()

    inserts = [c for c in responder.calls if c[:2] == ["iptables", "-I"]]
    parents = {c[2] for c in inserts}
    assert parents == {"INPUT", "FORWARD"}
    assert all(c[-1] == IPTABLES_CHAIN for c in inserts)


async def test_chain_creation_is_idempotent(responder):
    await responder.ensure_chain()
    first = len(responder.calls)
    await responder.ensure_chain()
    assert len(responder.calls) == first, "second ensure_chain() should be a no-op"


async def test_existing_jump_is_not_reinserted(monkeypatch):
    """When -C reports the jump already exists, we must not insert a duplicate."""
    r = Responder()
    r.calls = []

    async def fake_run(argv, check=False):
        r.calls.append(list(argv))
        return FakeResult(returncode=0)  # everything already exists

    monkeypatch.setattr(r, "_run", fake_run)
    await r.ensure_chain()

    assert not [c for c in r.calls if c[:2] == ["iptables", "-I"]]


# ===== Blocking =====

async def test_block_writes_into_phantom_chain(responder):
    await responder._block_ip("172.28.0.10")

    appends = [c for c in responder.calls if c[:2] == ["iptables", "-A"]]
    assert appends == [["iptables", "-A", IPTABLES_CHAIN, "-s", "172.28.0.10", "-j", "DROP"]]
    assert "172.28.0.10" in responder.get_blocked_ips()


async def test_duplicate_block_is_skipped(monkeypatch, tmp_path):
    """When -C says the rule exists, no second -A is issued."""
    r = Responder()
    r.calls = []

    async def fake_run(argv, check=False):
        r.calls.append(list(argv))
        return FakeResult(returncode=0)  # rule already present

    monkeypatch.setattr(r, "_run", fake_run)
    await r._block_ip("172.28.0.10")

    assert not [c for c in r.calls if c[:2] == ["iptables", "-A"]]
    assert "172.28.0.10" in r.get_blocked_ips()


async def test_loopback_is_never_blocked(responder):
    await responder._block_ip("127.0.0.1")
    assert not [c for c in responder.calls if c[:2] == ["iptables", "-A"]]


async def test_unblock_removes_the_rule(responder):
    await responder._block_ip("172.28.0.10")
    responder.calls.clear()

    await responder.unblock_ip("172.28.0.10")
    deletes = [c for c in responder.calls if c[:2] == ["iptables", "-D"]]
    assert deletes == [["iptables", "-D", IPTABLES_CHAIN, "-s", "172.28.0.10", "-j", "DROP"]]
    assert "172.28.0.10" not in responder.get_blocked_ips()


async def test_cleanup_unlinks_and_removes_chain(responder):
    await responder.ensure_chain()
    responder.calls.clear()

    await responder.cleanup_chain()
    flat = [" ".join(c) for c in responder.calls]
    assert f"iptables -D INPUT -j {IPTABLES_CHAIN}" in flat
    assert f"iptables -D FORWARD -j {IPTABLES_CHAIN}" in flat
    assert f"iptables -F {IPTABLES_CHAIN}" in flat
    assert f"iptables -X {IPTABLES_CHAIN}" in flat


# ===== Happy path =====

async def test_valid_structured_action_executes(responder):
    threat = {
        "id": "T3",
        "source_ip": "172.28.0.10",
        "defense_action": {"action": "BLOCK_IP", "target_ip": "172.28.0.10"},
    }
    result = await responder.execute("LOCKDOWN", threat)

    assert result["success"] is True
    assert any("Executed:" in a for a in result["actions_taken"])
    assert any("Blocked IP" in a for a in result["actions_taken"])


async def test_log_action_touches_nothing(responder):
    result = await responder.execute("LOG", {"id": "T4", "source_ip": "172.28.0.10"})
    assert responder.calls == []
    assert result["actions_taken"] == ["Event logged for review"]
