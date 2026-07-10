from intel.eval_attribution import compute_accuracy
from orchestrator.schemas import ActionType, AttackTechnique, EnrichedIncident, Severity

LABELLED = [
    {"event": {"schema_version": "1.0", "event_id": "e1", "timestamp": "t", "src_ip": "a",
               "dst_ip": "b", "anomaly_score": 0.9, "is_anomaly": True, "top_features": [],
               "raw_features": {}},
     "ground_truth_technique": "T1048"},
    {"event": {"schema_version": "1.0", "event_id": "e2", "timestamp": "t", "src_ip": "a",
               "dst_ip": "b", "anomaly_score": 0.9, "is_anomaly": True, "top_features": [],
               "raw_features": {}},
     "ground_truth_technique": "T1021"},
]


def _incident(event_id, technique_id):
    return EnrichedIncident(
        event_id=event_id, attack_technique=AttackTechnique(id=technique_id, name="x"),
        confidence=0.8, severity=Severity.low, cve_refs=[], certin_refs=[],
        narrative="x", predicted_next=None, suggested_action=ActionType.monitor,
    )


def test_compute_accuracy_counts_exact_technique_matches():
    responses = {"e1": _incident("e1", "T1048"), "e2": _incident("e2", "T9999")}
    acc = compute_accuracy(LABELLED, lambda event: responses[event.event_id])
    assert acc == 0.5


def test_compute_accuracy_returns_zero_for_empty_labelled_set():
    # guards the `if not labelled: return 0.0` branch — a division-by-zero otherwise
    assert compute_accuracy([], lambda event: _incident("x", "T1048")) == 0.0
