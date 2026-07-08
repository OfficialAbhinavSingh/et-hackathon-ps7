import { describe, it, expect } from "vitest";
import { sha256Hex, hashEntry, verifyChain, GENESIS_PREV_HASH } from "./hashChain";
import type { AuditEntry } from "@/types/contracts";

describe("sha256Hex", () => {
  it("matches known digests (identical to Python hashlib.sha256)", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

function build(n: number): AuditEntry[] {
  const entries: AuditEntry[] = [];
  let prev = GENESIS_PREV_HASH;
  for (let i = 1; i <= n; i++) {
    const base = {
      audit_log_id: `aud_${String(i).padStart(4, "0")}`,
      timestamp: `2026-07-08T00:00:0${i}Z`,
      event_id: `evt_${i}`,
      action: "isolate_host",
      actor: "system" as const,
      detail: `entry ${i}`,
    };
    const entry: AuditEntry = { ...base, prev_hash: prev, entry_hash: hashEntry(base, prev) };
    entries.push(entry);
    prev = entry.entry_hash;
  }
  return entries;
}

describe("verifyChain", () => {
  it("verifies an untampered chain", () => {
    expect(verifyChain(build(5))).toEqual({ ok: true, brokenAt: -1 });
  });

  it("detects a tampered entry (payload changed without re-hashing)", () => {
    const entries = build(5);
    entries[2] = { ...entries[2], detail: "TAMPERED" }; // hash no longer matches
    const res = verifyChain(entries);
    expect(res.ok).toBe(false);
    expect(res.brokenAt).toBe(2);
  });

  it("detects a broken prev_hash link", () => {
    const entries = build(4);
    entries[3] = { ...entries[3], prev_hash: "deadbeef" };
    expect(verifyChain(entries).ok).toBe(false);
  });
});
