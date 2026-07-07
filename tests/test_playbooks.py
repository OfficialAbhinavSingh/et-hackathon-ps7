import pytest

from orchestrator.playbooks import PlaybookEngine
from orchestrator.schemas import ActionType


def _run(engine, requires_approval, action=ActionType.isolate_host):
    return engine.run(
        action=action,
        event_id="evt_0001",
        target="10.0.0.5",
        requires_human_approval=requires_approval,
        audit_log_id="aud_0001",
    )


def test_auto_action_runs_immediately():
    engine = PlaybookEngine()
    action = _run(engine, requires_approval=False, action=ActionType.block_ip)
    assert action.status == "simulated_success"
    assert engine.pending() == []


def test_high_risk_action_is_held_for_approval():
    engine = PlaybookEngine()
    action = _run(engine, requires_approval=True)
    assert action.status == "pending_approval"
    assert len(engine.pending()) == 1


def test_approving_releases_a_held_action():
    engine = PlaybookEngine()
    _run(engine, requires_approval=True)
    released = engine.approve("evt_0001", approver="alice")
    assert released.status == "simulated_success"
    assert released.actor == "human:alice"
    assert engine.pending() == []


def test_approving_unknown_action_raises():
    engine = PlaybookEngine()
    with pytest.raises(KeyError):
        engine.approve("evt_9999")
