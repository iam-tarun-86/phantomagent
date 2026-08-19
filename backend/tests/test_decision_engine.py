"""DecisionEngine severity routing boundaries.

The 4-tier matrix in config.SEVERITY_THRESHOLDS is the contract every downstream
consumer relies on, so the boundaries are pinned explicitly here.
"""

import pytest

from backend.pipeline.decision_engine import DecisionEngine


@pytest.fixture
def engine():
    return DecisionEngine()


@pytest.mark.parametrize("severity", [1, 2, 3])
def test_low_severity_is_logged_only(engine, severity):
    d = engine.decide({"severity": severity})
    assert d["action"] == "LOG"
    assert d["requires_approval"] is False
    assert d["auto_execute"] is False


@pytest.mark.parametrize("severity", [4, 6, 8])
def test_mid_severity_auto_contains(engine, severity):
    d = engine.decide({"severity": severity})
    assert d["action"] == "CONTAIN"
    assert d["auto_execute"] is True
    assert d["requires_approval"] is False


@pytest.mark.parametrize("severity", [9, 10])
def test_critical_severity_requires_human_approval(engine, severity):
    d = engine.decide({"severity": severity})
    assert d["action"] == "LOCKDOWN"
    assert d["requires_approval"] is True
    assert d["auto_execute"] is False


def test_approval_and_auto_execute_are_mutually_exclusive(engine):
    """Nothing may both wait for a human and fire on its own."""
    for severity in range(1, 11):
        d = engine.decide({"severity": severity})
        assert not (d["requires_approval"] and d["auto_execute"]), severity


def test_stats_track_routing(engine):
    engine.decide({"severity": 2})
    engine.decide({"severity": 5})
    engine.decide({"severity": 9})

    stats = engine.get_stats()
    assert stats["logged"] == 1
    assert stats["auto_contained"] == 1
    assert stats["pending"] == 1
