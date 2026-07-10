"""Cited attribution agent: enrich(AnomalyEvent) -> EnrichedIncident (issue #17).

Retrieve-then-cite, always (finalplan §10): the model can only cite what search_attack/
lookup_cve/search_certin actually returned from Chroma. Force + validate structured JSON;
retry on malformed rather than let bad output reach the orchestrator.
"""

from __future__ import annotations

import json

from intel.ingest import query
from intel.llm import LLMCallError, ToolSpec, run_agentic_tool_loop
from orchestrator.schemas import (
    ActionType,
    AttackTechnique,
    EnrichedIncident,
    PredictedNext,
    Severity,
)
from orchestrator.schemas import AnomalyEvent

MAX_JSON_RETRIES = 2

SYSTEM_PROMPT = """You are a cited cyber-attribution analyst. Given a network anomaly event,
use the search_attack, lookup_cve, and search_certin tools to find grounding evidence, then
respond with ONLY a JSON object (no prose, no markdown fences) matching exactly:
{
  "attack_technique": {"id": "T####", "name": "..."},
  "confidence": 0.0-1.0,
  "severity": "low"|"medium"|"high"|"critical",
  "cve_refs": ["CVE-..."],
  "certin_refs": [],
  "narrative": "1-3 sentences explaining the call, referencing what you retrieved",
  "predicted_next": {"tactic": "...", "note": "..."},
  "suggested_action": "isolate_host"|"block_ip"|"revoke_credential"|"snapshot_vm"|"monitor"
}
Rule: NEVER invent an attack_technique.id you did not retrieve via search_attack. If nothing
relevant was retrieved, use confidence <= 0.3 and say so plainly in narrative. Citing an
attack_technique.id, cve_refs entry, or certin_refs entry that was not actually returned by
one of your tool calls will be rejected and you will be asked to retry — only cite ids that
appeared verbatim in a tool result, or use attack_technique.id="UNKNOWN" if nothing relevant
was retrieved."""

TOOLS = [
    ToolSpec("search_attack", "Search MITRE ATT&CK techniques relevant to a description",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    ToolSpec("lookup_cve", "Search known CVEs relevant to a description",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    ToolSpec("search_certin", "Search CERT-In advisories relevant to a description",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
]

_TOOL_TO_SOURCE = {"search_attack": "attack", "lookup_cve": "cve", "search_certin": "certin"}


def _make_tool_executor(collection, seen_ids: set[str]):
    def executor(name: str, args: dict) -> str:
        results = query(collection, args["query"], n_results=3)
        source = _TOOL_TO_SOURCE[name]
        filtered = [r for r in results if r["source_type"] == source]
        seen_ids.update(r["id"] for r in filtered)
        return json.dumps(filtered)
    return executor


def _fallback(event: AnomalyEvent, reason: str) -> EnrichedIncident:
    return EnrichedIncident(
        event_id=event.event_id,
        attack_technique=AttackTechnique(id="UNKNOWN", name="Unattributed"),
        confidence=0.0,
        severity=Severity.low,
        cve_refs=[],
        certin_refs=[],
        narrative=f"Attribution failed: {reason}. Falling back to unattributed, low confidence.",
        predicted_next=None,
        suggested_action=ActionType.monitor,
    )


def enrich(event: AnomalyEvent, collection) -> EnrichedIncident:
    user_prompt = (
        f"Anomaly event {event.event_id}: score={event.anomaly_score}, "
        f"top_features={event.top_features}, src={event.src_ip}, dst={event.dst_ip}, "
        f"raw_features={event.raw_features}"
    )
    seen_ids: set[str] = set()
    executor = _make_tool_executor(collection, seen_ids)

    last_error = ""
    grounding_failure = False
    llm_call_failure = False
    for _ in range(MAX_JSON_RETRIES):
        try:
            raw = run_agentic_tool_loop(SYSTEM_PROMPT, user_prompt, TOOLS, executor)
        except LLMCallError as exc:
            # Distinct failure mode from malformed JSON: the provider call itself failed
            # (e.g. Groq's llama-3.3-70b-versatile emitting a non-standard <function=...>
            # tag that the API rejects server-side with a 400). Treat it like malformed
            # JSON for retry/fallback purposes rather than letting it crash the pipeline.
            grounding_failure = False
            llm_call_failure = True
            last_error = f"LLM provider call failed: {exc}"
            user_prompt += (
                "\n\nYour previous attempt failed at the provider API level (e.g. a malformed "
                "tool-call generation was rejected before any response was produced) — this is "
                "not a JSON formatting issue on your end. Try again, responding with ONLY the "
                "JSON object described above and using well-formed tool calls."
            )
            continue
        llm_call_failure = False
        try:
            data = json.loads(raw)
            technique_id = data["attack_technique"]["id"]
            cve_refs = data.get("cve_refs", [])
            certin_refs = data.get("certin_refs", [])

            ungrounded_ids = set()
            if technique_id != "UNKNOWN" and technique_id not in seen_ids:
                ungrounded_ids.add(technique_id)
            ungrounded_ids.update(ref for ref in cve_refs if ref not in seen_ids)
            ungrounded_ids.update(ref for ref in certin_refs if ref not in seen_ids)

            if ungrounded_ids:
                grounding_failure = True
                last_error = f"cited id(s) not retrieved via tool call: {sorted(ungrounded_ids)}"
                user_prompt += (
                    "\n\nYour attack_technique.id, cve_refs, or certin_refs cited an id that was "
                    "not one you actually retrieved via search_attack/lookup_cve/search_certin — "
                    "you may only cite ids that appeared in a tool result. If nothing relevant was "
                    "retrieved, use attack_technique.id='UNKNOWN' and confidence <= 0.3."
                )
                continue

            return EnrichedIncident(
                event_id=event.event_id,
                attack_technique=AttackTechnique(**data["attack_technique"]),
                confidence=float(data["confidence"]),
                severity=Severity(data["severity"]),
                cve_refs=cve_refs,
                certin_refs=certin_refs,
                narrative=data["narrative"],
                predicted_next=PredictedNext(**data["predicted_next"]) if data.get("predicted_next") else None,
                suggested_action=ActionType(data["suggested_action"]),
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            grounding_failure = False
            last_error = str(exc)
            user_prompt += "\n\nYour last response was not valid JSON matching the schema. Try again — JSON ONLY."

    if grounding_failure:
        return _fallback(event, f"ungrounded citation after {MAX_JSON_RETRIES} attempts ({last_error})")
    if llm_call_failure:
        return _fallback(event, f"LLM provider call failed on every attempt "
                                 f"({MAX_JSON_RETRIES} attempts, {last_error})")
    return _fallback(event, f"malformed JSON after {MAX_JSON_RETRIES} attempts ({last_error})")
