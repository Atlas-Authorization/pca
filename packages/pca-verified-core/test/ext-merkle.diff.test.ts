/* eslint-disable @typescript-eslint/no-explicit-any */
// Differential tests: the PROVED Merkle verifiers (formal/dafny/Merkle.dfy -> generated/pca_merkle.js) vs the production TypeScript
// (packages/pca/src/merkle.ts and ledger.ts). Scale via env: PCA_MERKLE_N (random tree count), PCA_MERKLE_MAXN (max tree size),
// PCA_MERKLE_EXH (exhaustive n bound), PCA_MERKLE_MUT (mutations per proof). Defaults keep the Mac run short; the bulk run is on a cloud box.
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, decodeB64uStrict, sha256 } from '../../pca/src/hash';
import { leafHash, merkleProof, merkleRoot, planLeaf, verifyInclusion } from '../../pca/src/merkle';
import { TransparencyLedger, verifyLedgerConsistency } from '../../pca/src/ledger';
import {
  b64uDecodeStrict,
  b64uEncode,
  consistencyProofVerified,
  inclusionProofVerified,
  merkleRootVerified,
  verifyConsistencyVerified,
  verifyInclusionVerified,
} from '../src/ext-merkle';
import { RevocationSet, verifyMembership } from '../../pca/src/revocation';
import { inclusionRootVerified, verifyMembershipVerified } from '../src/ext-merkle';
import { loadCorpus } from './support/corpus';

const N = Number(process.env.PCA_MERKLE_N ?? 40);
const MAXN = Number(process.env.PCA_MERKLE_MAXN ?? 600);
const EXH = Number(process.env.PCA_MERKLE_EXH ?? 40);
const MUT = Number(process.env.PCA_MERKLE_MUT ?? 6);

function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  return { next, int, pick: <T>(xs: readonly T[]): T => xs[int(xs.length)]! };
}
const leafStr = (i: number, tag = 'x') => `leaf-${tag}-${i}`;
const leafBytes = (s: string) => canonicalBytes(s);
const JUNK: unknown[] = [undefined, null, NaN, Infinity, -1, -0, 0, 1, 2, 3, 2 ** 31, 2 ** 32, 2 ** 53, 2 ** 53 - 1, 1.5, '1', '', [], {}, true];

const prodIncl = (root: unknown, proof: any, leaf: string): boolean => verifyInclusion(root as string, proof, leaf);
const verIncl = (root: unknown, proof: any, leaf: string): boolean => verifyInclusionVerified(root, proof, leafBytes(leaf));

describe('ext-merkle: strict base64url (adapter glue) vs production decodeB64uStrict', () => {
  it('random strings agree on decode result', () => {
    const r = rng(1);
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ \n';
    let ok = 0;
    for (let i = 0; i < 20000; i++) {
      const len = r.int(70);
      let s = '';
      for (let j = 0; j < len; j++) s += alpha[r.int(i % 3 === 0 ? alpha.length : 64)]!;
      const a = decodeB64uStrict(s);
      const b = b64uDecodeStrict(s);
      expect(b ? Buffer.from(b).toString('hex') : null).toBe(a ? Buffer.from(a).toString('hex') : null);
      if (a) ok++;
      if (a) expect(b64uEncode(b!)).toBe(s);
    }
    expect(ok).toBeGreaterThan(500);
  });
});

describe('ext-merkle: tree builders and inclusion proofs vs merkle.ts', () => {
  it('root, honest proof and verification agree for every size 1..EXH and every index (both suites)', () => {
    let proofs = 0;
    for (const suite of ['sha256', 'sha384'] as const) {
      for (let n = 1; n <= EXH; n++) {
        const strs = Array.from({ length: n }, (_, i) => leafStr(i));
        const bytes = strs.map(leafBytes);
        const root = merkleRoot(strs, suite);
        expect(b64uEncode(merkleRootVerified(bytes, suite))).toBe(root);
        for (let i = 0; i < n; i++) {
          const p = merkleProof(strs, i, suite);
          expect(inclusionProofVerified(bytes, i, suite)).toEqual(p);
          expect(prodIncl(root, p, strs[i]!)).toBe(true);
          expect(verIncl(root, p, strs[i]!)).toBe(true);
          proofs++;
        }
      }
    }
    expect(proofs).toBeGreaterThan(EXH * 10);
  });

  it('random trees up to MAXN: root/proof equality, completeness, and mutated-proof agreement (zero disagreements)', () => {
    const r = rng(7);
    let accepted = 0;
    let rejected = 0;
    for (let t = 0; t < N; t++) {
      const n = t % 10 === 0 ? 1 + r.int(MAXN) : 1 + r.int(Math.min(MAXN, 200));
      const suite = r.int(4) === 0 ? 'sha384' : 'sha256';
      const strs = Array.from({ length: n }, (_, i) => leafStr(i, String(t)));
      const bytes = strs.map(leafBytes);
      const root = merkleRoot(strs, suite);
      expect(b64uEncode(merkleRootVerified(bytes, suite))).toBe(root);
      const idxs = n <= 8 ? Array.from({ length: n }, (_, i) => i) : [0, n - 1, r.int(n), r.int(n), r.int(n)];
      for (const i of idxs) {
        const p = merkleProof(strs, i, suite);
        expect(inclusionProofVerified(bytes, i, suite)).toEqual(p);
        expect(verIncl(root, p, strs[i]!)).toBe(true);
        for (let k = 0; k < MUT; k++) {
          const q: any = structuredClone(p);
          let leaf = strs[i]!;
          let rt: unknown = root;
          switch (r.int(14)) {
            case 0: {
              if (q.path.length) {
                const s = q.path[r.int(q.path.length)];
                const c = r.int(s.hash.length);
                s.hash = s.hash.slice(0, c) + (s.hash[c] === 'A' ? 'B' : 'A') + s.hash.slice(c + 1);
              }
              break;
            }
            case 1:
              if (q.path.length) {
                const s = q.path[r.int(q.path.length)];
                s.side = s.side === 'L' ? 'R' : 'L';
              }
              break;
            case 2:
              q.path.pop();
              break;
            case 3:
              if (q.path.length) q.path.splice(r.int(q.path.length), 0, structuredClone(q.path[r.int(q.path.length)]));
              break;
            case 4:
              q.index = r.pick(JUNK);
              break;
            case 5:
              q.size = r.pick(JUNK);
              break;
            case 6:
              q.size = p.size + r.pick([-1, 1, 2]);
              break;
            case 7:
              q.index = p.index + r.pick([-1, 1, 2]);
              break;
            case 8:
              q.hash_suite = r.pick(['sha256', 'sha384', 'md5', 7, null, '']);
              break;
            case 9:
              leaf = leafStr(i + 1, 'other');
              break;
            case 10:
              rt = r.pick([root + 'A', root.slice(1), '', 7, null, root.toUpperCase(), root + '=']);
              break;
            case 11: {
              // non-canonical trailing bits: change the last char of a sibling to another char with the same high bits
              if (q.path.length) {
                const s = q.path[r.int(q.path.length)];
                const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
                const last = s.hash[s.hash.length - 1]!;
                s.hash = s.hash.slice(0, -1) + A[(A.indexOf(last) + 1 + r.int(3)) % 64]!;
              }
              break;
            }
            case 12:
              if (q.path.length) q.path[r.int(q.path.length)] = r.pick([null, undefined, {}, { side: 'L' }, { hash: 'AA' }, 5]);
              break;
            default:
              q.path = r.pick([null, undefined, {}, 'x', 7]);
          }
          const a = prodIncl(rt, q, leaf);
          const b = verIncl(rt, q, leaf);
          expect({ a, b, q: JSON.stringify(q), n, i }).toEqual({ a, b: a, q: JSON.stringify(q), n, i });
          if (a) accepted++;
          else rejected++;
        }
      }
    }
    expect(rejected).toBeGreaterThan(N);
    expect(accepted).toBeGreaterThanOrEqual(0);
  });

  it('conformance corpus: plan inclusion proofs (valid and adversarial) agree', () => {
    const { core, adversarial } = loadCorpus();
    let seen = 0;
    let acc = 0;
    for (const v of [...core, ...adversarial]) {
      let pc = v.pcactn;
      if (!pc && v.pcactn_json) {
        try {
          pc = JSON.parse(v.pcactn_json);
        } catch {
          continue;
        }
      }
      const plan = pc?.plan;
      if (!plan || typeof plan !== 'object' || !pc.action) continue;
      let leafObj: unknown;
      let bytes: Uint8Array | null = null;
      try {
        leafObj = planLeaf(plan.node_id, pc.action, plan.conditions_digest);
        bytes = canonicalBytes(leafObj);
      } catch {
        bytes = null;
      }
      const a = (() => {
        try {
          return verifyInclusion(plan.root, plan.inclusion_proof, leafObj);
        } catch {
          return false;
        }
      })();
      const b = bytes ? verifyInclusionVerified(plan.root, plan.inclusion_proof, bytes) : false;
      expect({ name: v.name, b }).toEqual({ name: v.name, b: a });
      seen++;
      if (a) acc++;
    }
    expect(seen).toBeGreaterThan(100);
    expect(acc).toBeGreaterThan(5);
  });
});

// ---- consistency -----------------------------------------------------------------------------------------------------------------------
function ledgerOf(n: number, tag: string): TransparencyLedger {
  const l = new TransparencyLedger('p');
  for (let i = 0; i < n; i++) l.appendCommitment(`commit-${tag}-${i}`);
  return l;
}
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Why a TS-accepted input is legitimately rejected by the STRICT proved verifier (documented in the notes). Empty => unexplained. */
function strictReasons(oldRoot: unknown, newRoot: unknown, proof: any): string[] {
  const why: string[] = [];
  if (!Number.isSafeInteger(proof?.oldSize) || !Number.isSafeInteger(proof?.newSize)) why.push('non-safe integer size');
  if (b64uDecodeStrict(oldRoot) === null || b64uDecodeStrict(newRoot) === null) why.push('non-canonical root encoding');
  if (Array.isArray(proof?.path) && proof.path.some((e: unknown) => b64uDecodeStrict(e) === null)) why.push('non-canonical element');
  if (Array.isArray(proof?.path) && proof.path.some((e: unknown) => b64uDecodeStrict(e) && b64uDecodeStrict(e)!.length !== 32)) why.push('wrong-length element');
  const o = b64uDecodeStrict(oldRoot);
  const nn = b64uDecodeStrict(newRoot);
  if ((o && o.length !== 32) || (nn && nn.length !== 32)) why.push('root not 32 bytes');
  return why;
}

describe('ext-merkle: consistency proofs vs ledger.ts', () => {
  it('exhaustive: every (m, n) with 0 <= m <= n <= EXH: proof equality, completeness, agreement', () => {
    let cnt = 0;
    for (let n = 1; n <= EXH; n++) {
      const led = ledgerOf(n, 'e');
      const bytes = led.commits().map(leafBytes);
      for (let m = 0; m <= n; m++) {
        const oldRoot = led.rootAt(m);
        const newRoot = led.head().root;
        const p = led.consistencyProof(m, n);
        expect(consistencyProofVerified(bytes, m)).toEqual(p);
        expect(verifyLedgerConsistency(oldRoot, newRoot, p)).toBe(true);
        expect(verifyConsistencyVerified(oldRoot, newRoot, p)).toBe(true);
        cnt++;
      }
    }
    expect(cnt).toBeGreaterThan((EXH * EXH) / 3);
  });

  it('random trees: honest agreement, then mutated proofs (zero unexplained disagreements)', () => {
    const r = rng(11);
    let tsAcc = 0;
    let tsRej = 0;
    const explained: Record<string, number> = {};
    for (let t = 0; t < N; t++) {
      const n = t % 10 === 0 ? 1 + r.int(MAXN) : 1 + r.int(Math.min(MAXN, 150));
      const led = ledgerOf(n, 'r' + t);
      const bytes = led.commits().map(leafBytes);
      const heads = Array.from({ length: Math.min(n + 1, 24) }, () => r.int(n + 1));
      for (const m of heads) {
        const oldRoot = led.rootAt(m);
        const newRoot = led.head().root;
        const p0 = led.consistencyProof(m, n);
        expect(consistencyProofVerified(bytes, m)).toEqual(p0);
        expect(verifyConsistencyVerified(oldRoot, newRoot, p0)).toBe(true);
        for (let k = 0; k < MUT; k++) {
          const q: any = structuredClone(p0);
          let o: unknown = oldRoot;
          let nw: unknown = newRoot;
          switch (r.int(13)) {
            case 0:
              if (q.path.length) {
                const j = r.int(q.path.length);
                const c = r.int(q.path[j].length);
                q.path[j] = q.path[j].slice(0, c) + (q.path[j][c] === 'A' ? 'B' : 'A') + q.path[j].slice(c + 1);
              }
              break;
            case 1:
              q.path.pop();
              break;
            case 2:
              q.path.push(b64u(sha256(new Uint8Array([r.int(256)]))));
              break;
            case 3:
              if (q.path.length) q.path.splice(r.int(q.path.length), 1);
              break;
            case 4:
              if (q.path.length >= 2) {
                const a = r.int(q.path.length);
                const b = r.int(q.path.length);
                [q.path[a], q.path[b]] = [q.path[b], q.path[a]];
              }
              break;
            case 5:
              q.oldSize = r.pick([...JUNK, m + 1, m - 1, n, Math.max(0, m - 2)]);
              break;
            case 6:
              q.newSize = r.pick([...JUNK, n + 1, n - 1, m]);
              break;
            case 7:
              o = r.pick([nw, led.rootAt(Math.max(0, m - 1)), led.rootAt(Math.min(n, m + 1)), '', 5, null, (oldRoot as string) + 'A']);
              break;
            case 8:
              nw = r.pick([o, led.rootAt(Math.max(0, n - 1)), '', 5, undefined, newRoot.slice(1)]);
              break;
            case 9:
              if (q.path.length) {
                const j = r.int(q.path.length);
                const last = q.path[j][q.path[j].length - 1]!;
                q.path[j] = q.path[j].slice(0, -1) + A[(A.indexOf(last) + 1 + r.int(3)) % 64]!; // non-canonical trailing bits
              }
              break;
            case 10:
              if (q.path.length) q.path[r.int(q.path.length)] = r.pick([null, 5, '', 'AA', 'A'.repeat(43) + '=', 'A'.repeat(44), 'A'.repeat(42)]);
              break;
            case 11:
              q.path = r.pick([null, undefined, {}, 'x']);
              break;
            default: {
              // a proof for another (m2, n2) of the same log
              const m2 = r.int(n + 1);
              const n2 = m2 + r.int(n - m2 + 1);
              Object.assign(q, led.consistencyProof(m2, n2));
            }
          }
          const a = (() => {
            try {
              return verifyLedgerConsistency(o as string, nw as string, q);
            } catch {
              return false;
            }
          })();
          const b = verifyConsistencyVerified(o, nw, q);
          if (a) tsAcc++;
          else tsRej++;
          if (b && !a) throw new Error(`proved verifier ACCEPTS what ledger.ts rejects: ${JSON.stringify({ o, nw, q, n, m })}`);
          if (a && !b) {
            const why = strictReasons(o, nw, q);
            if (why.length === 0) throw new Error(`unexplained strictness: ${JSON.stringify({ o, nw, q, n, m })}`);
            for (const w of why) explained[(q.oldSize === 0 ? 'm=0 ' : 'm>0 ') + w] = (explained[(q.oldSize === 0 ? 'm=0 ' : 'm>0 ') + w] ?? 0) + 1;
          }
        }
      }
    }
    expect(tsRej).toBeGreaterThan(N);
    // eslint-disable-next-line no-console
    console.log('ext-merkle consistency: TS accepted', tsAcc, 'rejected', tsRej, 'strict-only rejections', JSON.stringify(explained));
  });
});

describe('ext-merkle: findings PoC (ledger.ts verifyLedgerConsistency) - F1/F2 FIXED in production', () => {
  it('F1 (fixed): oldSize = 0 requires oldRoot == SHA-256("") and an empty path, exactly like the proved verifier', () => {
    const p = { oldSize: 0, newSize: 5, path: [] as string[] };
    expect(verifyLedgerConsistency('not-a-root', 'neither', p)).toBe(false);
    expect(verifyConsistencyVerified('not-a-root', 'neither', p)).toBe(false);
    const led = ledgerOf(5, 'f1');
    expect(verifyLedgerConsistency(b64u(sha256(new Uint8Array(0))), led.head().root, p)).toBe(true);
    expect(verifyConsistencyVerified(b64u(sha256(new Uint8Array(0))), led.head().root, p)).toBe(true);
  });

  it('F2 (fixed): sizes >= 2^32 are no longer truncated by 32-bit bit operations: a proof for (m, n) is refused for (m + 2^32, n + 2^32)', () => {
    const led = ledgerOf(7, 'f2');
    const m = 3;
    const p = led.consistencyProof(m, 7);
    const forged = { oldSize: m + 2 ** 32, newSize: 7 + 2 ** 32, path: p.path };
    const old = led.rootAt(m);
    const nw = led.head().root;
    expect(verifyLedgerConsistency(old, nw, p)).toBe(true);
    expect(verifyLedgerConsistency(old, nw, forged)).toBe(false);
    expect(verifyConsistencyVerified(old, nw, forged)).toBe(false);
  });

  it('2^32 boundaries: production and the proved verifier agree on shifted sizes (both reject; Merkle.NoAliasShiftK)', () => {
    for (const n of [2, 5, 7, 8, 9, 16, 17]) {
      const led = ledgerOf(n, 'b' + n);
      for (let m = 0; m < n; m++) {
        const p = led.consistencyProof(m, n);
        const o = m === 0 ? b64u(sha256(new Uint8Array(0))) : led.rootAt(m);
        const nw = led.head().root;
        expect(verifyLedgerConsistency(o, nw, p)).toBe(true);
        expect(verifyConsistencyVerified(o, nw, p)).toBe(true);
        for (const shift of [2 ** 32, 2 ** 31, 2 ** 33, 2 ** 40, 2 ** 52]) {
          for (const q of [
            { ...p, oldSize: m + shift, newSize: n + shift },
            { ...p, oldSize: m, newSize: n + shift },
            { ...p, oldSize: m + shift, newSize: n },
          ]) {
            const a = verifyLedgerConsistency(o, nw, q);
            const b = verifyConsistencyVerified(o, nw, q);
            // from the empty tree (oldSize 0) consistency is vacuous (RFC 9162): accepted for any new size; every other shift is refused
            const want = q.oldSize === 0;
            expect({ m, n, shift, q: [q.oldSize, q.newSize], a, b }).toEqual({ m, n, shift, q: [q.oldSize, q.newSize], a: want, b: want });
          }
        }
      }
    }
    // 2^32 - 1 / 2^32 / 2^32 + 1 as sizes with junk paths, and >= 2^53: identical verdicts
    const e = b64u(sha256(new Uint8Array(0)));
    for (const [m, n] of [[2 ** 32 - 1, 2 ** 32], [2 ** 32, 2 ** 32 + 1], [2 ** 32 - 1, 2 ** 32 + 1], [0, 2 ** 32], [2 ** 53 - 2, 2 ** 53 - 1], [0, 2 ** 53]]) {
      for (const path of [[], [e], Array(33).fill(e), Array(200).fill(e)]) {
        const q = { oldSize: m!, newSize: n!, path };
        expect(verifyConsistencyVerified(e, e, q)).toBe(verifyLedgerConsistency(e, e, q));
      }
    }
  });

  it('every shift k * 2^j (k >= 1, n <= 2^j) is refused by both, incl. non-power-of-two multiples of 2^32 (Merkle.NoAliasShiftK)', () => {
    let cases = 0;
    for (const n of [1, 2, 3, 5, 7, 8, 13, 16]) {
      const led = ledgerOf(n, 'k' + n);
      for (let m = 0; m < n; m++) {
        const p = led.consistencyProof(m, n);
        const o = m === 0 ? b64u(sha256(new Uint8Array(0))) : led.rootAt(m);
        const nw = led.head().root;
        expect(verifyConsistencyVerified(o, nw, p)).toBe(true);
        for (const j of [0, 1, 2, 3, 4, 5, 6, 32]) {
          if (n > 2 ** j) continue; // outside the theorem (see the DyadicTwins test)
          for (const k of [1, 2, 3, 5, 6, 7, 12, 1023]) {
            const K = k * 2 ** j;
            const q = { ...p, oldSize: m + K, newSize: n + K };
            expect({ m, n, j, k, a: verifyLedgerConsistency(o, nw, q), b: verifyConsistencyVerified(o, nw, q) }).toEqual({ m, n, j, k, a: false, b: false });
            cases++;
          }
        }
      }
    }
    expect(cases).toBeGreaterThan(300);
  });

  it('the n <= 2^j bound is necessary: (1, 2) and (2, 3) are the same RFC 9162 problem and decide identically in both (Merkle.DyadicTwins)', () => {
    const led2 = ledgerOf(2, 'tw');
    const p = led2.consistencyProof(1, 2);
    const o = led2.rootAt(1);
    const nw = led2.head().root;
    expect(verifyLedgerConsistency(o, nw, p)).toBe(true);
    const q = { ...p, oldSize: 2, newSize: 3 };
    expect(verifyConsistencyVerified(o, nw, q)).toBe(true);
    expect(verifyLedgerConsistency(o, nw, q)).toBe(true);
    // sound per pair: against a REAL 3-leaf log, only the true 2-prefix root is consistent with its root
    const led3 = ledgerOf(3, 'tw3');
    const p3 = led3.consistencyProof(2, 3);
    expect(verifyConsistencyVerified(led3.rootAt(2), led3.head().root, p3)).toBe(true);
    expect(verifyConsistencyVerified(led3.rootAt(1), led3.head().root, p3)).toBe(false);
  });

  it('F3: inclusion proofs do not authenticate (index, size): a (2, 3) proof verifies leaf b against the root of the 2-leaf tree [a, b]', () => {
    const strs = ['a', 'b'];
    const root = merkleRoot(strs);
    const sibling = b64u(leafHash('a'));
    const forged = { index: 2, size: 3, path: [{ side: 'L', hash: sibling }] };
    expect(verifyInclusion(root, forged as any, 'b')).toBe(true);
    expect(verifyInclusionVerified(root, forged, leafBytes('b'))).toBe(true); // identical decision: it is a property of RFC 6962 proofs, proved in Merkle.IndexSizeNotAuthenticated
  });
});

describe('ext-merkle: revocation.ts verifyMembership (size-bound root) vs proved fold', () => {
  it('honest and mutated membership proofs agree', () => {
    const r = rng(23);
    let acc = 0;
    let rej = 0;
    for (let t = 0; t < Math.max(10, N); t++) {
      const n = 1 + r.int(Math.min(MAXN, 120));
      const ids = Array.from({ length: n }, (_, i) => (i % 5 === 0 ? `id-é-${i}-😀` : `id-${t}-${i}`));
      const set = new RevocationSet(ids);
      const root = set.root;
      for (let k = 0; k < 6; k++) {
        const id = ids[r.int(n)]!;
        const p: any = structuredClone(set.membershipProof(id));
        let rt: unknown = root;
        let q = id;
        switch (r.int(8)) {
          case 0:
            if (p.path.length) p.path[r.int(p.path.length)].side = r.pick(['L', 'R', 'X']);
            break;
          case 1:
            if (p.path.length) p.path[r.int(p.path.length)].hash = b64u(sha256(new Uint8Array([r.int(256)])));
            break;
          case 2:
            p.size = r.pick([...JUNK, p.size + 1, p.size - 1]);
            break;
          case 3:
            p.index = r.pick([...JUNK, p.index + 1]);
            break;
          case 4:
            q = id + 'x';
            break;
          case 5:
            rt = r.pick([root.slice(1), '', 3, null]);
            break;
          case 6:
            p.path.pop();
            break;
          default:
            break;
        }
        const a = (() => {
          try {
            return verifyMembership(rt as string, p, q);
          } catch {
            return false;
          }
        })();
        const b = (() => {
          try {
            return verifyMembershipVerified(rt, p, canonicalBytes(q));
          } catch {
            return false;
          }
        })();
        expect({ a, b, p: JSON.stringify(p) }).toEqual({ a, b: a, p: JSON.stringify(p) });
        if (a) acc++;
        else rej++;
        const ir = inclusionRootVerified(p, canonicalBytes(q));
        if (a) expect(ir).not.toBeNull();
      }
    }
    expect(acc).toBeGreaterThan(5);
    expect(rej).toBeGreaterThan(5);
  });
});
