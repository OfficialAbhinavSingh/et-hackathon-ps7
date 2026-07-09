"""Attribution accuracy % against the labelled eval set (issue #17 DoD, finalplan §6/GAP3).

Run: .venv/bin/python -m intel.eval_attribution
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from orchestrator.schemas import AnomalyEvent, EnrichedIncident

FIXTURE = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "labelled_eval.json"


def compute_accuracy(labelled: list[dict], enrich_fn: Callable[[AnomalyEvent], EnrichedIncident]) -> float:
    if not labelled:
        return 0.0
    correct = 0
    for row in labelled:
        event = AnomalyEvent(**row["event"])
        result = enrich_fn(event)
        if result.attack_technique.id == row["ground_truth_technique"]:
            correct += 1
    return correct / len(labelled)


def main() -> None:
    from intel.agent import enrich
    from intel.ingest import build_collection

    collection = build_collection([], persist_dir="data/intel/chroma")
    labelled = json.loads(FIXTURE.read_text())
    acc = compute_accuracy(labelled, lambda event: enrich(event, collection))
    print(f"attribution accuracy: {acc:.1%} ({len(labelled)} labelled events)")


if __name__ == "__main__":
    main()
