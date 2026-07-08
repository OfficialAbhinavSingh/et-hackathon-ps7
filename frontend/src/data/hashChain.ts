/**
 * SHA-256 hash chain for the tamper-evident audit log.
 *
 * Format (MUST byte-match orchestrator/audit.py — see docs/DEV-1-detection-and-spine.md §C5):
 *   entry_hash = sha256_hex( prev_hash + canonical(entry) )
 * where canonical(entry) is the JSON of exactly these fields, in exactly this order,
 * with no extra whitespace:
 *   {"audit_log_id":..,"timestamp":..,"event_id":..,"action":..,"actor":..,"detail":..}
 * `prev_hash` of the genesis entry is the empty string "".
 * Python side: hashlib.sha256((prev_hash + canonical).encode()).hexdigest() over the same
 * canonical string produces an identical hex digest.
 *
 * Chain GENERATION happens ONLY in MockDataService. In live mode GET /audit returns the
 * backend's already-chained log — we render it and only ever RE-VERIFY, never re-generate.
 * A self-contained synchronous SHA-256 keeps chain generation race-free (each entry_hash is
 * available before the next entry links to it).
 */
import type { AuditEntry } from "../types/contracts";

export const GENESIS_PREV_HASH = "";

type Chainable = Omit<AuditEntry, "prev_hash" | "entry_hash">;

/** Canonical serialization used as the hash input. Field order is part of the contract. */
export function canonicalize(entry: Chainable): string {
  return JSON.stringify({
    audit_log_id: entry.audit_log_id,
    timestamp: entry.timestamp,
    event_id: entry.event_id,
    action: entry.action,
    actor: entry.actor,
    detail: entry.detail,
  });
}

// ---- minimal synchronous SHA-256 (public-domain style implementation) ----

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

export function sha256Hex(message: string): string {
  const bytes = new TextEncoder().encode(message);
  const l = bytes.length;
  const bitLen = l * 8;
  // padded length: multiple of 64, room for 0x80 + 8-byte length
  const withLen = l + 9;
  const padded = new Uint8Array(Math.ceil(withLen / 64) * 64);
  padded.set(bytes);
  padded[l] = 0x80;
  // 64-bit big-endian length (high 32 bits assumed 0 for our message sizes)
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 4, bitLen >>> 0, false);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return Array.from(h).map((x) => x.toString(16).padStart(8, "0")).join("");
}

/** Compute the entry_hash for one entry given the previous entry's hash. Synchronous. */
export function hashEntry(entry: Chainable, prevHash: string): string {
  return sha256Hex(prevHash + canonicalize(entry));
}

export interface VerifyResult {
  ok: boolean;
  /** index of the first broken entry, or -1 if the whole chain verifies */
  brokenAt: number;
}

/**
 * Recompute the chain over the given (ordered) entries and confirm each entry_hash and
 * prev_hash link. Returns the first tampered index if any link fails.
 */
export function verifyChain(entries: AuditEntry[]): VerifyResult {
  let prev = GENESIS_PREV_HASH;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prev_hash !== prev) return { ok: false, brokenAt: i };
    if (e.entry_hash !== hashEntry(e, prev)) return { ok: false, brokenAt: i };
    prev = e.entry_hash;
  }
  return { ok: true, brokenAt: -1 };
}
