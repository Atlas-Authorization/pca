import { canonicalBytes, sha256 } from './hash';

/**
 * Trusted-setup bookkeeping for the Groth16 circuits (pure; no file or process access, safe for bundlers).
 *
 * A verifying key is only as trustworthy as the ceremony that made it. This module answers one question honestly:
 * "was this key produced by a multi-party ceremony we can check?". The answer is `multi-party` ONLY when the caller
 * supplies a transcript, pins its SHA-256 (published out of band by the ceremony coordinator), the transcript is
 * well-formed (>= 2 distinct contributions chained from the initial key, a public random beacon applied last) and
 * names exactly this verifying key. Everything else is `single-party`. The cryptographic check of the contributions
 * themselves (`snarkjs zkey verify`) is done by `circuits/ceremony/ceremony.ts verify`, which also re-derives the
 * transcript hashes from the files; this function never claims more than the pinned transcript says.
 */

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const H64 = /^[0-9a-f]{64}$/;

export interface CeremonyContribution {
  index: number;
  name: string;
  /** SHA-256 of the proving key before and after this contribution. */
  prevZkeySha256: string;
  zkeySha256: string;
}

export interface CeremonyTranscript {
  version: 1;
  /** Circuit id, e.g. `pca-policyvm-v1`. */
  circuit: string;
  curve: 'bn128' | 'bls12-381';
  /** SHA-256 of the compiled constraint system (.r1cs) and of the phase-1 powers-of-tau file the ceremony started from. */
  r1csSha256: string;
  ptauSha256: string;
  /** SHA-256 of the proving key straight out of `groth16 setup`, before any contribution. */
  initZkeySha256: string;
  minContributions: number;
  contributions: CeremonyContribution[];
  /** The public randomness applied after the last contribution (e.g. a future block hash) and the key it produced. */
  beacon?: { hashHex: string; iterationsExp: number; prevZkeySha256: string; zkeySha256: string };
  finalZkeySha256?: string;
  /** Id of the verifying key exported from the final key (see {@link vkId}). */
  vkId?: string;
}

/** Id of a verifying key: `vk_` + SHA-256 of its canonical JSON. A re-setup always yields a new id. */
export function vkId(vkey: object): string {
  return `vk_${hex(sha256(canonicalBytes(vkey)))}`;
}

export function transcriptSha256(t: CeremonyTranscript): string {
  return hex(sha256(canonicalBytes(t)));
}

/** The first problem with a transcript, or `null` when it is well-formed. Fails closed on any odd shape. */
export function checkTranscript(t: unknown, opts: { minContributions?: number; r1csSha256?: string; circuit?: string } = {}): string | null {
  const x = t as Partial<CeremonyTranscript> | null;
  if (!x || typeof x !== 'object' || x.version !== 1) return 'not a version-1 transcript';
  if (typeof x.circuit !== 'string' || x.circuit === '') return 'no circuit id';
  if (opts.circuit !== undefined && x.circuit !== opts.circuit) return 'transcript is for another circuit';
  if (x.curve !== 'bn128' && x.curve !== 'bls12-381') return 'unknown curve';
  for (const k of ['r1csSha256', 'ptauSha256', 'initZkeySha256'] as const) if (!H64.test(String(x[k]))) return `${k} is not a SHA-256`;
  if (opts.r1csSha256 !== undefined && x.r1csSha256 !== opts.r1csSha256) return 'transcript is for a different constraint system';
  const min = Math.max(2, opts.minContributions ?? 2, Number.isSafeInteger(x.minContributions) ? (x.minContributions as number) : 2);
  const cs = x.contributions;
  if (!Array.isArray(cs) || cs.length < min) return `fewer than ${min} contributions`;
  const names = new Set<string>();
  const keys = new Set<string>();
  let prev = x.initZkeySha256!;
  for (const [i, c] of cs.entries()) {
    if (!c || c.index !== i || typeof c.name !== 'string' || c.name === '') return `contribution ${i} is malformed`;
    if (!H64.test(String(c.zkeySha256)) || c.prevZkeySha256 !== prev) return `contribution ${i} does not chain from the previous key`;
    if (names.has(c.name) || keys.has(c.zkeySha256)) return `contribution ${i} repeats a name or key`;
    names.add(c.name);
    keys.add(c.zkeySha256);
    prev = c.zkeySha256;
  }
  const b = x.beacon;
  if (!b || !H64.test(String(b.hashHex)) || !Number.isSafeInteger(b.iterationsExp) || b.iterationsExp < 10 || b.iterationsExp > 63) return 'no valid random beacon';
  if (b.prevZkeySha256 !== prev || !H64.test(String(b.zkeySha256))) return 'beacon is not applied after the last contribution';
  if (x.finalZkeySha256 !== b.zkeySha256) return 'final key is not the beacon output';
  if (typeof x.vkId !== 'string' || !/^vk_[0-9a-f]{64}$/.test(x.vkId)) return 'no verifying-key id';
  return null;
}

export type CeremonyKind = 'single-party' | 'multi-party';

/**
 * `multi-party` only when `pinnedSha256` equals the transcript's hash, the transcript is well-formed and names `vkey`.
 * Anything else, including a thrown error, is `single-party`.
 */
export function ceremonyOf(vkey: object | undefined, evidence?: { transcript: unknown; sha256: string; r1csSha256?: string; circuit?: string }): CeremonyKind {
  try {
    if (!vkey || !evidence) return 'single-party';
    const t = evidence.transcript as CeremonyTranscript;
    if (checkTranscript(t, { r1csSha256: evidence.r1csSha256, circuit: evidence.circuit }) !== null) return 'single-party';
    if (transcriptSha256(t) !== evidence.sha256 || t.vkId !== vkId(vkey)) return 'single-party';
    return 'multi-party';
  } catch {
    return 'single-party';
  }
}
