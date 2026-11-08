// k05 oracle: optimistic-path wire checks (Java Optimistic and every native port). TS reference: packages/pca/src/optimistic.ts
// (claimCheck, fraudProofWireCheck) and packages/pca/src/bond-settlement.ts (settlementWireCheck). Extends
// conformance/optimistic-vectors.json with every member of a claim / proof / settlement record retyped, deleted or bounded (claims
// and records both unsigned and RE-SIGNED, so the shape check is not masked by the signature), the window policy at its edges,
// numbers outside the strict canonical profile (claims and records sign the lenient form), the fraud-kind x decision x margin grid, and the slash-split conservation grid.
// Ed25519 only (no PQ suite). Writes tools/pca-audit/k05-oracles/out/k05-optimistic.json.gz. Deterministic.
// PORTING (fn -> Java). Compare the check string.
//   claimCheck(claim, expectedDigest, signerPublic, serverNow, {minWindowMs, maxWindowMs, maxSkewMs})
//                                                Optimistic.claimCheck(claim, expectedDigest, signerPublic, serverNow, policy)
//   fraudProofWireCheck(claim, proof)            Optimistic.fraudProofWireCheck(claim, proof)
//   settlementWireCheck(record, guardianPublic)  Optimistic.settlementWireCheck(record, guardianPublic)
import { claimCheck, fraudProofWireCheck } from '../../../packages/pca/src/optimistic.ts';
import { settlementWireCheck } from '../../../packages/pca/src/bond-settlement.ts';
import { b64u, canonicalBytesLenient, utf8 } from '../../../packages/pca/src/hash.ts';
import { publicKeyOf, sign } from '../../../packages/pca/src/keys.ts';
import { Oracle, variants, ser } from './lib.mjs';

const o = new Oracle('optimistic', 'tools/pca-audit/k05-oracles/optimistic-oracle.mts', 'TS-reference oracle for the optimistic path: bonded-claim checks, fraud-proof wire checks and settlement-record wire checks.');
const isPlain = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
// The lenient canonical form is server-only and not portable: JSON.stringify escapes a lone surrogate and writes 1e-7 / 1e+21 in
// exponent form, where the natives write U+FFFD and plain decimals. A body holding such a value is left out of the SIGNED cases
// (the natives answer `signature` for a body the reference signed; both refuse it unsigned).
const portable = (v: unknown): boolean => {
  if (typeof v === 'string') return !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(v);
  if (typeof v === 'number') return v === 0 || (Math.abs(v) >= 1e-6 && Math.abs(v) < 1e21);
  if (Array.isArray(v)) return v.every(portable);
  if (v !== null && typeof v === 'object') return Object.entries(v).every(([k, x]) => portable(k) && portable(x));
  return true;
};
const cat = (a: Uint8Array, b: Uint8Array) => { const m = new Uint8Array(a.length + b.length); m.set(a); m.set(b, a.length); return m; };
const SIGNER = new Uint8Array(32).fill(91), OTHER = new Uint8Array(32).fill(92), GUARD = new Uint8Array(32).fill(93);
const SPK = b64u(publicKeyOf(SIGNER)), OPK = b64u(publicKeyOf(OTHER)), GPK = b64u(publicKeyOf(GUARD));
const NOW = 1_800_000_000_000;

// ---- claims ----
const CLAIM_DOMAIN = 'atlas-pca/optimistic/v1\0';
const signClaim = (c: unknown, sk = SIGNER): unknown => {
  if (!isPlain(c)) return c;
  const { sig: _s, ...body } = c;
  try { return { ...body, sig: b64u(sign(sk, cat(utf8(CLAIM_DOMAIN), canonicalBytesLenient(body)))) }; } catch { return c; }
};
const C0 = signClaim({ pcactn_digest: 'D', bond_ref: 'B', claimed_r: 0.25, reversibility_class: 'reversible', issued_at: NOW, challenge_window_ms: 60_000 }) as Record<string, unknown>;
const DEF = { minWindowMs: 1000, maxWindowMs: 86_400_000, maxSkewMs: 5000 };
const cc = (n: string, claim: unknown, expected = 'D', signer = SPK, now = NOW, p: Record<string, number> = DEF) =>
  o.run('claimCheck', n, (c: never, e: string, s: string, t: number, pol: Record<string, number>) => claimCheck(c, e, s, { serverNow: t, windowPolicy: { ...pol, defaultWindowMs: pol.minWindowMs } as never }).check, [claim, expected, signer, now, p]);
await cc('base', C0);
for (const [n, v] of variants(C0, { lens: [0, 1] })) {
  await cc('unsigned' + n, v);
  if (!n.startsWith('/sig') && portable(v)) await cc('re-signed' + n, signClaim(v));
}
for (const [n, p] of [
  ['skew +5000', { issued_at: NOW + 5000 }], ['skew +5001', { issued_at: NOW + 5001 }], ['skew -5000', { issued_at: NOW - 5000 }], ['skew -5001', { issued_at: NOW - 5001 }],
  ['window 1000', { challenge_window_ms: 1000 }], ['window 999', { challenge_window_ms: 999 }], ['window 86400000', { challenge_window_ms: 86_400_000 }], ['window 86400001', { challenge_window_ms: 86_400_001 }],
  ['window 1000.5', { challenge_window_ms: 1000.5 }], ['claimed_r 1e-7', { claimed_r: 1e-7 }], ['claimed_r 0', { claimed_r: 0 }], ['claimed_r -0', { claimed_r: -0 }], ['claimed_r -3', { claimed_r: -3 }],
  ['claimed_r 2^53', { claimed_r: 2 ** 53 }], ['claimed_r string', { claimed_r: '0.25' }], ['extra lone surrogate', { note: '\ud800' }], ['extra -0', { note: -0 }], ['extra 1e-7', { note: 1e-7 }],
  ['extra 2^53', { note: 2 ** 53 }], ['extra deep', { note: JSON.parse('['.repeat(40) + ']'.repeat(40)) }], ['irreversible', { reversibility_class: 'irreversible' }], ['digest number', { pcactn_digest: 7 }],
] as [string, Record<string, unknown>][]) {
  if (portable(p)) await cc('patch ' + n, signClaim({ ...C0, ...p }));
  await cc('patch unsigned ' + n, { ...C0, ...p });
  const { sig: _s, ...noSig } = { ...C0, ...p };
  await cc('patch no sig ' + n, noSig);
}
await cc('another signer', signClaim(C0, OTHER));
await cc('expected X', C0, 'X');
await cc('signer other', C0, 'D', OPK);
await cc('signer junk', C0, 'D', 'junk');
for (const now of [NOW + 5000, NOW + 5001, NOW - 5000, NOW - 5001, 0]) await cc(`server now ${now - NOW}`, C0, 'D', SPK, now);
for (const [pn, p] of [['zero', { minWindowMs: 0, maxWindowMs: 0, maxSkewMs: 0 }], ['exact', { minWindowMs: 60_000, maxWindowMs: 60_000, maxSkewMs: 0 }], ['tight', { minWindowMs: 60_001, maxWindowMs: 86_400_000, maxSkewMs: 5000 }], ['narrow', { minWindowMs: 1000, maxWindowMs: 59_999, maxSkewMs: 5000 }]] as [string, Record<string, number>][])
  await cc(`policy ${pn}`, C0, 'D', SPK, NOW, p);
for (const x of [null, 'x', 5, [], true]) await cc(`claim ${ser(x)}`, x);

// ---- fraud proofs ----
const PC = { pcactn_digest: 'D', bond_ref: 'B', claimed_r: 0.5, reversibility_class: 'reversible', issued_at: NOW, challenge_window_ms: 60_000, sig: 'x' };
const PF = { pcactn_digest: 'D', bond_ref: 'B', claimed_r: 0.5, kind: 'risk-understated', decision: { releaseGuardianShare: true, r: 0.9, optimisticAllowed: true }, reason: 'r' };
const fp = (n: string, c: unknown, p: unknown) => o.run('fraudProofWireCheck', n, (a: never, b: never) => fraudProofWireCheck(a, b), [c, p]);
await fp('base', PC, PF);
for (const [n, v] of variants(PF)) await fp('proof' + n, PC, v);
for (const [n, v] of variants(PC)) await fp('claim' + n, v, PF);
for (const kind of ['risk-understated', 'policy-denied', 'optimistic-not-allowed', 'irreversible', 'other'])
  for (const rel of [true, false]) for (const opt of [true, false])
    for (const [rn, r, margin] of [['above', 0.9, undefined], ['equal', 0.5, 0], ['at default margin', 0.5 + 1e-9, undefined], ['just above default', 0.5 + 2e-9, undefined], ['below', 0.4, undefined], ['below neg margin', 0.0, -1], ['above neg margin', 0.6, -1], ['equal neg margin', 0.5, -1], ['margin 0.1 at', 0.6, 0.1], ['margin 0.1 above', 0.7, 0.1], ['margin string', 0.9, '0']] as [string, number, unknown][]) {
      const proof: Record<string, unknown> = { ...PF, kind, decision: { releaseGuardianShare: rel, r, optimisticAllowed: opt } };
      if (margin !== undefined) proof.r_margin = margin;
      await fp(`${kind} rel=${rel} opt=${opt} ${rn}`, PC, proof);
    }
const IRR = { ...PF, kind: 'irreversible' };
for (const [n, ev] of [['none', undefined], ['null', null], ['string', 'x'], ['empty', {}], ['action null', { action: null }], ['action string', { action: 'x' }], ['action empty', { action: {} }], ['action.action null', { action: { action: null } }],
  ['irreversible', { action: { action: { reversibility_class: 'irreversible' } } }], ['reversible', { action: { action: { reversibility_class: 'reversible' } } }], ['array', { action: [] }]] as [string, unknown][]) {
  await fp(`irreversible evidence ${n}`, PC, ev === undefined ? IRR : { ...IRR, evidence: ev });
  await fp(`irreversible claim, evidence ${n}`, { ...PC, reversibility_class: 'irreversible' }, ev === undefined ? IRR : { ...IRR, evidence: ev });
}
for (const [n, a, b] of [['both string', 'x', 'x'], ['strings differ', 'x', 'y'], ['both true', true, true], ['both objects', {}, {}], ['both arrays', [1], [1]], ['number vs string', 0.5, '0.5'], ['-0 vs 0', -0, 0], ['null vs absent', null, undefined]] as [string, unknown, unknown][]) {
  const c: Record<string, unknown> = { ...PC, claimed_r: a };
  const p: Record<string, unknown> = { ...PF, claimed_r: b };
  if (b === undefined) delete p.claimed_r;
  await fp(`claimed_r ${n}`, c, p);
  const { claimed_r: _x, ...c2 } = c;
  const { claimed_r: _y, ...p2 } = p;
  if (n === 'both string') await fp('claimed_r both absent', c2, p2);
}
for (const [n, a, b] of [['bond objects', { x: 1 }, 'B'], ['digest object', { x: 1 }, 'D']] as [string, unknown, string][]) await fp(n, { ...PC, bond_ref: a, pcactn_digest: a }, PF);

// ---- settlement records ----
const SET_DOMAIN = 'atlas-pca/bond-settlement/v1\0';
const signRec = (r: unknown, sk = GUARD): unknown => {
  if (!isPlain(r)) return r;
  const { sig: _s, pq_sig: _q, ...body } = r;
  try { return { ...r, sig: b64u(sign(sk, cat(utf8(SET_DOMAIN), canonicalBytesLenient(body)))) }; } catch { return r; }
};
const OPEN = { claimId: 'c1', action: 'open', amount: 100, from: 'agent', to: 'escrow', at: NOW, evidenceDigest: '' };
const SPLIT = { amount: 100, challengerReward: 50, victimCompensation: 40, treasuryRemainder: 10, victimAccount: 'victim', treasuryAccount: 'treasury', challengerAccount: 'challenger' };
const SLASH = { claimId: 'c1', action: 'slash', amount: 100, from: 'escrow', to: 'treasury', at: NOW, evidenceDigest: 'E', split: SPLIT };
const sw = (n: string, r: unknown, g = GPK) => o.run('settlementWireCheck', n, (a: never, b: string) => settlementWireCheck(a, b), [r, g]);
for (const [bn, b] of [['open', OPEN], ['release', { ...OPEN, action: 'release', from: 'escrow', to: 'agent' }], ['slash', SLASH], ['open epoch', { ...OPEN, guardian_epoch: 3 }], ['open alg', { ...OPEN, alg: 'ed25519' }]] as [string, Record<string, unknown>][]) {
  const s = signRec(b);
  await sw(`${bn} base`, s);
  for (const [n, v] of variants(s, { lens: [0, 1] })) {
    await sw(`${bn} unsigned${n}`, v);
    if (!n.startsWith('/sig') && portable(v)) await sw(`${bn} re-signed${n}`, signRec(v));
  }
}
const sp = (n: string, split: unknown, over: Record<string, unknown> = {}) => sw(`split ${n}`, signRec({ ...SLASH, ...over, split }));
for (const [n, p] of [
  ['anonymous', { challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100, challengerAccount: null }], ['anonymous paid', { challengerReward: 50, victimCompensation: 0, treasuryRemainder: 50, challengerAccount: null }],
  ['anonymous victim', { challengerReward: 0, victimCompensation: 40, treasuryRemainder: 60, challengerAccount: null }], ['empty challenger, all treasury', { challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100, challengerAccount: '' }],
  ['named, all treasury', { challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100 }], ['no challenger', { challengerAccount: undefined }], ['over', { treasuryRemainder: 11 }], ['under', { treasuryRemainder: 9 }],
  ['negative', { challengerReward: -10, treasuryRemainder: 70 }], ['string reward', { challengerReward: '50' }], ['amount differs', { amount: 101 }], ['amount string', { amount: '100' }],
  ['treasury elsewhere', { treasuryAccount: 'x' }], ['victim empty', { victimAccount: '' }], ['victim number', { victimAccount: 5 }], ['floats', { amount: 1, challengerReward: 0.1, victimCompensation: 0.2, treasuryRemainder: 0.7 }],
  ['floats ok', { amount: 1, challengerReward: 0.5, victimCompensation: 0.25, treasuryRemainder: 0.25 }], ['-0 reward', { challengerReward: -0, victimCompensation: 0, treasuryRemainder: 100, challengerAccount: null }],
] as [string, Record<string, unknown>][]) {
  const split = { ...SPLIT, ...p };
  for (const k of Object.keys(split)) if (split[k as keyof typeof split] === undefined) delete split[k as keyof typeof split];
  await sp(n, split, n.startsWith('floats') ? { amount: 1 } : {});
}
for (const [n, s] of [['array', []], ['null', null], ['string', 'x'], ['empty', {}]] as [string, unknown][]) await sp(n, s);
await sw('signed by another key', signRec(OPEN, OTHER));
await sw('guardian junk', signRec(OPEN), 'junk');
await sw('alg bogus', signRec({ ...OPEN, alg: 'bogus' }));
await sw('alg null', signRec({ ...OPEN, alg: null }));
await sw('open with split', signRec({ ...OPEN, split: SPLIT }));
await sw('open with null split', signRec({ ...OPEN, split: null }));
await sw('epoch -0', signRec({ ...OPEN, guardian_epoch: -0 }));
await sw('epoch 1.5', signRec({ ...OPEN, guardian_epoch: 1.5 }));
await sw('epoch 2^53', signRec({ ...OPEN, guardian_epoch: 2 ** 53 }));
await sw('epoch null', signRec({ ...OPEN, guardian_epoch: null }));
await sw('pq_sig ignored', { ...(signRec(OPEN) as object), pq_sig: 'x' });
for (const x of [null, 'x', 5, [], true]) await sw(`record ${ser(x)}`, x);
o.write();
