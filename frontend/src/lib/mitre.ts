/**
 * MITRE ATT&CK tactic mapping for the kill-chain grid. Tactics are laid out in kill-chain
 * order (left = earliest stage) so the grid encodes attack progression, not a flat list.
 * Covers the techniques present in the fixtures; unknown techniques fall back to "Other".
 */
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

/** base technique id (strip sub-technique) -> tactic */
const TECHNIQUE_TACTIC: Record<string, string> = {
  T1046: "Discovery",
  T1110: "Credential Access",
  T1210: "Lateral Movement",
  T1021: "Lateral Movement",
  T1005: "Collection",
  T1071: "Command & Control",
  T1105: "Command & Control",
  T1571: "Command & Control",
  T1048: "Exfiltration",
};

export function baseTechnique(id: string): string {
  return id.split(".")[0];
}

export function tacticFor(techniqueId: string): string {
  return TECHNIQUE_TACTIC[baseTechnique(techniqueId)] ?? "Other";
}
