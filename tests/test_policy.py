from orchestrator.policy import decide


def test_high_severity_high_score_isolates_and_needs_approval():
    d = decide(0.93, "high")
    assert d.action == "isolate_host"
    assert d.requires_human_approval is True


def test_mid_score_blocks_ip_automatically():
    d = decide(0.8, "high")
    assert d.action == "block_ip"
    assert d.requires_human_approval is False


def test_low_score_only_monitors():
    d = decide(0.5, "critical")
    assert d.action == "monitor"
    assert d.requires_human_approval is False


def test_high_score_but_low_severity_does_not_isolate():
    # score alone isn't enough — isolate needs high/critical severity too
    d = decide(0.95, "low")
    assert d.action == "block_ip"
    assert d.requires_human_approval is False
