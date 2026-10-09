/**
 * pq-threshold — post-quantum t-of-n threshold AUTHORIZATION by composition (a "quorum certificate").
 *
 * WHAT THIS IS
 *   A registered signer set of n public keys (each under a PQ suite: ml-dsa-65/87, slh-dsa-sha2-128f/256s,
 *   or an ed25519+PQ hybrid), a threshold t, and a proof made of >= t INDEPENDENT per-signer signatures from
 *   DISTINCT registered signers over one domain-separated message (quorum-set id + epoch + action digest).
 *   Every signature is produced and verified by the vetted suite seam in pq.ts (signWithSuite /
 *   verifyWithSuite, @noble/post-quantum ML-DSA / SLH-DSA). No new cryptography is introduced here: this
 *   module only counts, binds, and de-duplicates signatures.
 *
 * WHAT THIS IS NOT
 *   It is NOT a threshold SIGNATURE scheme. There is no distributed key generation, no key sharing, no
 *   aggregation: the proof is t separate signatures and its size is t * |sig| (NOT compact; see
 *   {@link quorumProofSize}). Genuinely compact post-quantum threshold signing (e.g. threshold ML-DSA with
 *   DKG) has no vetted implementation and remains research-gated. This closes the *authorization* need
 *   ("t of these n parties approved this action, post-quantum-safely"), not the *single compact signature*
 *   need. It is the PQ counterpart to the interim FROST+ML-DSA hybrid cosign (which has a compact Ed25519
 *   FROST threshold signature but only a PQ leaf signature); here every counted approval is itself PQ.
 *
 * GUARANTEES
 *   - set id = b64u(sha384(canonical{t, minHashBased, sorted signers})): binds keys + suites + t + diversity.
 *   - each signature covers (set id, epoch, action digest) under a domain prefix: no cross-set, cross-epoch,
 *     or cross-action replay.
 *   - distinctness: a set whose entries share ANY key component is rejected at construction/load; a proof
 *     that names a signer twice is rejected; any invalid signature in the proof rejects the whole proof.
 *   - assumption diversity: the set may commit `minHashBased` = k; at least k counted signers must carry a
 *     hash-based (SLH-DSA) component, so a lattice break alone cannot satisfy the quorum.
 *   - rotation: old quorum signs (new set id, epoch+1); chain verification enforces linkage and monotone epoch.
 *   - verification never throws; it returns a typed reason.
 */
import { b64u, canonicalBytesStrict, decodeB64uStrict, sha384, utf8 } from './hash';
import {
  SIG_SUITES,
  type SigAlg,
  type SuiteSecretKeys,
  type SuitePublicKeys,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from './pq';

const SET_DOMAIN = 'atlas-pca/pq-quorum-set/v1';
const MSG_DOMAIN = 'atlas-pca/pq-quorum-msg/v1\0';
const ROTATION_KIND = 'pq-quorum-rotation';
export const PQ_QUORUM_MAX_SIGNERS = 256;
export const PQ_QUORUM_MAX_CHAIN = 1024;
const ED_PK_BYTES = 32;

/** One registered signer, normalized: suite + the key component(s) that suite needs (b64u, canonical). */
export interface QuorumSignerEntry {
  alg: SigAlg;
  /** Ed25519 public key (hybrid suites only). */
  ed?: string;
  /** The PQ public key (ML-DSA / SLH-DSA per suite). */
  pq: string;
}

/** A committed quorum set. `id` is derived; loaders recompute it and reject a mismatch. */
export interface QuorumSet {
  t: number;
  /** Minimum number of counted signers carrying a hash-based (SLH-DSA) component. */
  minHashBased: number;
  /** Sorted canonically; the index into this array is the signer index used by proofs. */
  signers: QuorumSignerEntry[];
  id: string;
}

export interface QuorumSignerInput {
  alg: SigAlg;
  keys: SuitePublicKeys;
}

export interface QuorumShare {
  /** Index into `QuorumSet.signers`. */
  i: number;
  sig: string;
  pq_sig?: string;
}

export interface QuorumProof {
  set_id: string;
  sigs: QuorumShare[];
}

export type QuorumReason =
  | 'malformed'
  | 'bad-set'
  | 'set-mismatch'
  | 'epoch-mismatch'
  | 'too-many-signatures'
  | 'unknown-signer'
  | 'duplicate-signer'
  | 'bad-signature'
  | 'below-threshold'
  | 'diversity-unmet'
  | 'chain-broken'
  | 'non-monotone-epoch'
  | 'bad-rotation'
  | 'chain-too-long';

export type QuorumVerdict =
  | { ok: true; signers: number[]; count: number; hashBased: number }
  | { ok: false; reason: QuorumReason; detail?: number };

export type SetResult = { ok: true; set: QuorumSet } | { ok: false; reason: 'bad-set' };

type Rec = Record<string, unknown>;
const isRec = (x: unknown): x is Rec => typeof x === 'object' && x !== null && !Array.isArray(x);
const isEpoch = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;

function isHashBased(alg: SigAlg): boolean {
  const s = SIG_SUITES[alg];
  return s.hasSlhDsa || s.hasSlhDsa256s;
}

function isPqAlg(alg: SigAlg): boolean {
  const s = SIG_SUITES[alg];
  return s.hasMlDsa || s.hasMlDsa87 || s.hasSlhDsa || s.hasSlhDsa256s;
}

function pqKeyOf(alg: SigAlg, k: SuitePublicKeys): unknown {
  const s = SIG_SUITES[alg];
  if (s.hasMlDsa) return k.mlDsaPub;
  if (s.hasMlDsa87) return k.mlDsa87Pub;
  if (s.hasSlhDsa) return k.slhDsaPub;
  return k.slhDsa256sPub;
}

function normalizeEntry(alg: unknown, ed: unknown, pq: unknown): QuorumSignerEntry | null {
  const suite = resolveSigAlg(alg);
  if (suite === null || !isPqAlg(suite.alg)) return null;
  if (decodeB64uStrict(pq, suite.pqPkBytes) === null) return null;
  if (suite.hasEd25519) {
    if (decodeB64uStrict(ed, ED_PK_BYTES) === null) return null;
    return { alg: suite.alg, ed: ed as string, pq: pq as string };
  }
  if (ed !== undefined) return null;
  return { alg: suite.alg, pq: pq as string };
}

function entryKey(e: QuorumSignerEntry): string {
  return `${e.alg}|${e.ed ?? ''}|${e.pq}`;
}

function computeId(t: number, minHashBased: number, signers: QuorumSignerEntry[]): string {
  const body = { d: SET_DOMAIN, t, k: minHashBased, s: signers.map((e) => ({ a: e.alg, e: e.ed ?? null, p: e.pq })) };
  return b64u(sha384(canonicalBytesStrict(body)));
}

function finalize(entries: QuorumSignerEntry[], t: unknown, k: unknown): SetResult {
  const n = entries.length;
  if (n < 1 || n > PQ_QUORUM_MAX_SIGNERS) return { ok: false, reason: 'bad-set' };
  if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 1 || t > n) return { ok: false, reason: 'bad-set' };
  if (typeof k !== 'number' || !Number.isSafeInteger(k) || k < 0 || k > t) return { ok: false, reason: 'bad-set' };
  const sorted = [...entries].sort((a, b) => {
    const x = entryKey(a);
    const y = entryKey(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  // distinct keys: no key component (ed25519 or PQ) may appear in two entries (or twice in one).
  const seen = new Set<string>();
  for (const e of sorted) {
    for (const c of e.ed === undefined ? [e.pq] : [e.ed, e.pq]) {
      if (seen.has(c)) return { ok: false, reason: 'bad-set' };
      seen.add(c);
    }
  }
  if (sorted.filter((e) => isHashBased(e.alg)).length < k) return { ok: false, reason: 'bad-set' };
  return { ok: true, set: { t, minHashBased: k, signers: sorted, id: computeId(t, k, sorted) } };
}

/** Build a committed quorum set from public keys. Never throws; `bad-set` on any invalid input. */
export function buildQuorumSet(signers: readonly QuorumSignerInput[], t: number, minHashBased = 0): SetResult {
  try {
    if (!Array.isArray(signers)) return { ok: false, reason: 'bad-set' };
    const entries: QuorumSignerEntry[] = [];
    for (const s of signers) {
      if (!isRec(s) || !isRec(s.keys)) return { ok: false, reason: 'bad-set' };
      const alg = s.alg;
      const suite = resolveSigAlg(alg);
      if (suite === null) return { ok: false, reason: 'bad-set' };
      const e = normalizeEntry(alg, s.keys.edPub, pqKeyOf(suite.alg, s.keys as SuitePublicKeys));
      if (e === null) return { ok: false, reason: 'bad-set' };
      entries.push(e);
    }
    return finalize(entries, t, minHashBased);
  } catch {
    return { ok: false, reason: 'bad-set' };
  }
}

/** Load an untrusted wire quorum set, RE-DERIVING the id (a supplied id must match). Never throws. */
export function loadQuorumSet(x: unknown): SetResult {
  try {
    if (!isRec(x) || !Array.isArray(x.signers) || typeof x.id !== 'string') return { ok: false, reason: 'bad-set' };
    const entries: QuorumSignerEntry[] = [];
    for (const s of x.signers) {
      if (!isRec(s)) return { ok: false, reason: 'bad-set' };
      const e = normalizeEntry(s.alg, s.ed, s.pq);
      if (e === null) return { ok: false, reason: 'bad-set' };
      entries.push(e);
    }
    const r = finalize(entries, x.t, x.minHashBased);
    if (!r.ok) return r;
    // wire order must already be canonical (otherwise indices would be ambiguous) and the id must match.
    if (r.set.signers.some((e, i) => entryKey(e) !== entryKey(entries[i]!))) return { ok: false, reason: 'bad-set' };
    return r.set.id === x.id ? r : { ok: false, reason: 'bad-set' };
  } catch {
    return { ok: false, reason: 'bad-set' };
  }
}

/** The domain-separated bytes every signer signs: binds set id + epoch + action digest. */
export function quorumMessage(setId: string, epoch: number, actionDigest: string): Uint8Array {
  const d = sha384(canonicalBytesStrict({ set_id: setId, epoch, action: actionDigest }));
  const pre = utf8(MSG_DOMAIN);
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}

/** Digest an arbitrary message (e.g. `thresholdMessage(pcactn)`) into the `actionDigest` string. */
export function quorumActionDigest(message: Uint8Array): string {
  return b64u(sha384(message));
}

/** Sign one share as signer `index`. Throws on bad input (signer side may throw; verification never does). */
export function signQuorumShare(set: QuorumSet, index: number, epoch: number, actionDigest: string, keys: SuiteSecretKeys): QuorumShare {
  const e = set.signers[index];
  if (e === undefined) throw new RangeError('signQuorumShare: no such signer index');
  const p = signWithSuite(e.alg, keys, quorumMessage(set.id, epoch, actionDigest));
  return p.pq_sig === undefined ? { i: index, sig: p.sig } : { i: index, sig: p.sig, pq_sig: p.pq_sig };
}

export function assembleQuorumProof(set: QuorumSet, shares: readonly QuorumShare[]): QuorumProof {
  return { set_id: set.id, sigs: [...shares] };
}

function publicKeysOf(e: QuorumSignerEntry): SuitePublicKeys {
  const s = SIG_SUITES[e.alg];
  const k: SuitePublicKeys = {};
  if (e.ed !== undefined) k.edPub = e.ed;
  if (s.hasMlDsa) k.mlDsaPub = e.pq;
  else if (s.hasMlDsa87) k.mlDsa87Pub = e.pq;
  else if (s.hasSlhDsa) k.slhDsaPub = e.pq;
  else k.slhDsa256sPub = e.pq;
  return k;
}

export interface VerifyQuorumInput {
  set: unknown;
  proof: unknown;
  epoch: number;
  actionDigest: string;
  /** Verifier-side pin: the set id the verifier trusts (defends against being handed another set). */
  expectedSetId?: string;
  /** Verifier-side floor for hash-based signers; the effective k is max(set commitment, this). */
  requireHashBased?: number;
}

/** Verify a quorum proof. Never throws; every failure is a typed reason. */
export function verifyQuorum(input: VerifyQuorumInput): QuorumVerdict {
  try {
    if (!isRec(input)) return { ok: false, reason: 'malformed' };
    const loaded = loadQuorumSet(input.set);
    if (!loaded.ok) return { ok: false, reason: 'bad-set' };
    const set = loaded.set;
    if (input.expectedSetId !== undefined && input.expectedSetId !== set.id) return { ok: false, reason: 'set-mismatch' };
    if (!isEpoch(input.epoch) || typeof input.actionDigest !== 'string') return { ok: false, reason: 'malformed' };
    const p = input.proof;
    if (!isRec(p) || typeof p.set_id !== 'string' || !Array.isArray(p.sigs)) return { ok: false, reason: 'malformed' };
    if (p.set_id !== set.id) return { ok: false, reason: 'set-mismatch' };
    if (p.sigs.length > set.signers.length) return { ok: false, reason: 'too-many-signatures' };
    const msg = quorumMessage(set.id, input.epoch, input.actionDigest);
    const seen = new Set<number>();
    let hashBased = 0;
    for (const raw of p.sigs) {
      if (!isRec(raw) || typeof raw.sig !== 'string') return { ok: false, reason: 'malformed' };
      const i = raw.i;
      if (typeof i !== 'number' || !Number.isSafeInteger(i) || i < 0 || i >= set.signers.length) return { ok: false, reason: 'unknown-signer' };
      if (seen.has(i)) return { ok: false, reason: 'duplicate-signer', detail: i };
      seen.add(i);
      const e = set.signers[i]!;
      const hybrid = SIG_SUITES[e.alg].needsPqSig;
      if (hybrid !== (raw.pq_sig !== undefined)) return { ok: false, reason: 'bad-signature', detail: i };
      if (!verifyWithSuite(e.alg, publicKeysOf(e), msg, { sig: raw.sig, pq_sig: raw.pq_sig })) return { ok: false, reason: 'bad-signature', detail: i };
      if (isHashBased(e.alg)) hashBased++;
    }
    if (seen.size < set.t) return { ok: false, reason: 'below-threshold' };
    const k = Math.max(set.minHashBased, input.requireHashBased ?? 0);
    if (!Number.isSafeInteger(k) || k < 0) return { ok: false, reason: 'malformed' };
    if (hashBased < k) return { ok: false, reason: 'diversity-unmet' };
    return { ok: true, signers: [...seen].sort((a, b) => a - b), count: seen.size, hashBased };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

/** Boolean adapter shaped for a guardian-approval check slot: `(message, epoch, set, proof) => ok`. */
export function verifyQuorumApproval(set: unknown, proof: unknown, message: Uint8Array, epoch: number, opts: { expectedSetId?: string; requireHashBased?: number } = {}): boolean {
  try {
    if (!(message instanceof Uint8Array)) return false;
    return verifyQuorum({ set, proof, epoch, actionDigest: quorumActionDigest(message), ...opts }).ok;
  } catch {
    return false;
  }
}

// ---- rotation ---------------------------------------------------------------------------------

export interface RotationCert {
  from_set_id: string;
  from_epoch: number;
  to_set: QuorumSet;
  to_epoch: number;
  /** Signed by the OLD quorum at `from_epoch` over {@link rotationActionDigest}. */
  proof: QuorumProof;
}

export function rotationActionDigest(toSetId: string, toEpoch: number): string {
  return b64u(sha384(canonicalBytesStrict({ kind: ROTATION_KIND, to_set_id: toSetId, to_epoch: toEpoch })));
}

export function buildRotationCert(from: QuorumSet, fromEpoch: number, to: QuorumSet, shares: readonly QuorumShare[]): RotationCert {
  return { from_set_id: from.id, from_epoch: fromEpoch, to_set: to, to_epoch: fromEpoch + 1, proof: assembleQuorumProof(from, shares) };
}

/** Sign one rotation share as old-quorum signer `index`. */
export function signRotationShare(from: QuorumSet, index: number, fromEpoch: number, to: QuorumSet, keys: SuiteSecretKeys): QuorumShare {
  return signQuorumShare(from, index, fromEpoch, rotationActionDigest(to.id, fromEpoch + 1), keys);
}

export type ChainVerdict =
  | { ok: true; set: QuorumSet; epoch: number; length: number }
  | { ok: false; reason: QuorumReason; at: number };

/**
 * Verify a rotation chain from a trusted genesis (set, epoch). Each cert must be signed by the quorum
 * current at that point, link by id, and advance the epoch by exactly 1. Never throws.
 */
export function verifyRotationChain(genesisSet: unknown, genesisEpoch: number, chain: unknown): ChainVerdict {
  try {
    const g = loadQuorumSet(genesisSet);
    if (!g.ok || !isEpoch(genesisEpoch)) return { ok: false, reason: 'bad-set', at: -1 };
    if (!Array.isArray(chain)) return { ok: false, reason: 'malformed', at: -1 };
    if (chain.length > PQ_QUORUM_MAX_CHAIN) return { ok: false, reason: 'chain-too-long', at: -1 };
    let cur = g.set;
    let epoch = genesisEpoch;
    for (let n = 0; n < chain.length; n++) {
      const c: unknown = chain[n];
      if (!isRec(c) || typeof c.from_set_id !== 'string' || !isEpoch(c.from_epoch) || !isEpoch(c.to_epoch)) return { ok: false, reason: 'malformed', at: n };
      if (c.from_set_id !== cur.id) return { ok: false, reason: 'chain-broken', at: n };
      if (c.from_epoch !== epoch) return { ok: false, reason: 'non-monotone-epoch', at: n };
      if (c.to_epoch !== epoch + 1) return { ok: false, reason: 'non-monotone-epoch', at: n };
      const next = loadQuorumSet(c.to_set);
      if (!next.ok) return { ok: false, reason: 'bad-rotation', at: n };
      if (next.set.id === cur.id) return { ok: false, reason: 'bad-rotation', at: n };
      const v = verifyQuorum({ set: cur, proof: c.proof, epoch, actionDigest: rotationActionDigest(next.set.id, c.to_epoch), expectedSetId: cur.id });
      if (!v.ok) return { ok: false, reason: v.reason, at: n };
      cur = next.set;
      epoch = c.to_epoch;
    }
    return { ok: true, set: cur, epoch, length: chain.length };
  } catch {
    return { ok: false, reason: 'malformed', at: -1 };
  }
}

/** True when two certs rotate the SAME (set, epoch) to DIFFERENT successor sets (a fork / equivocation). */
export function isRotationFork(a: unknown, b: unknown): boolean {
  if (!isRec(a) || !isRec(b) || !isRec(a.to_set) || !isRec(b.to_set)) return false;
  return a.from_set_id === b.from_set_id && a.from_epoch === b.from_epoch && typeof a.to_set.id === 'string' && typeof b.to_set.id === 'string' && a.to_set.id !== b.to_set.id;
}

// ---- size accounting --------------------------------------------------------------------------

export interface QuorumSizeReport {
  /** Raw signature bytes (decoded) of the cheapest valid t-subset. */
  minBytes: number;
  /** Raw signature bytes of the most expensive t-subset. */
  maxBytes: number;
  /** Raw signature bytes for the given signer indices, when supplied. */
  chosenBytes?: number;
  t: number;
  /** Always false: the proof is t independent signatures, not a compact threshold signature. */
  compact: false;
}

function shareBytes(e: QuorumSignerEntry): number {
  const s = SIG_SUITES[e.alg];
  return s.sigBytes + s.pqSigBytes;
}

/** Honest size accounting: the proof grows linearly in t (t * |sig|); it is NOT compact. */
export function quorumProofSize(set: QuorumSet, indices?: readonly number[]): QuorumSizeReport {
  const sizes = set.signers.map(shareBytes).sort((a, b) => a - b);
  const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
  const r: QuorumSizeReport = { minBytes: sum(sizes.slice(0, set.t)), maxBytes: sum(sizes.slice(sizes.length - set.t)), t: set.t, compact: false };
  if (indices !== undefined) r.chosenBytes = sum(indices.map((i) => (set.signers[i] === undefined ? 0 : shareBytes(set.signers[i]!))));
  return r;
}
