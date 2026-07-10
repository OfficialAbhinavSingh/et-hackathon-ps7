/**
 * MITRE ATT&CK tactic mapping for the kill-chain grid. Tactics are laid out in kill-chain
 * order (left = earliest stage) so the grid encodes attack progression, not a flat list.
 * Covers all 858 real ATT&CK techniques (see mitreTactics.generated.ts) since the live
 * attribution agent (intel/agent.py) can cite any of them, not just a fixed sample. Tactics
 * with no kill-chain column here (Reconnaissance, Resource Development, Defense Evasion)
 * and techniques with no recognized phase fall back to "Other".
 */
import { MITRE_TACTICS } from "./mitreTactics.generated";

export const KILL_CHAIN: string[] = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command & Control",
  "Exfiltration",
  "Impact",
];

export function baseTechnique(id: string): string {
  return id.split(".")[0];
}

export function tacticFor(techniqueId: string): string {
  return MITRE_TACTICS[baseTechnique(techniqueId)] ?? "Other";
}
