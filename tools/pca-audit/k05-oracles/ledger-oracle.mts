// k05 oracle: transparency-ledger verification (Java Ledger and every native port). TS reference: packages/pca/src/ledger.ts.
// Extends conformance/ledger-vectors.json with: RFC 9162 consistency over every (m, n) pair of small trees plus hostile proofs
// (sizes retyped / -0 / fractional / swapped, paths cut, extended, reordered, undecodable, roots swapped or junk), witnessed
// heads, tree heads and witness cosignatures with every member retyped or deleted (unsigned AND re-signed, so the shape check is
// not masked by the signature), the k-of-n threshold over trusted / unknown / duplicate / mis-bound witnesses, head-to-head
// consistency, checkpoint chains and split-view detection over JS === semantics. Ed25519 only.
// Writes tools/pca-audit/k05-oracles/out/k05-ledger.json.gz. Deterministic.
// PORTING (fn -> Java). Compare by JSON value.
//   verifyLedgerConsistency(oldRoot, newRoot, proof)     Ledger.verifyLedgerConsistency
//   verifyLedgerInclusion(root, proof, commit)           Ledger.verifyLedgerInclusion
//   verifyWitnessedHead(wh, witness) / detectEquivocation(a, b, witness)
//   verifyWitnessCosignature(sth, cosig, witness) / verifyWitnessCosignatures(sth, policy)
//   verifyTreeHead(sth, guardian, policy|null) / verifyHeadConsistency(older, newer, proof, guardian, policy|null)
//   verifyCheckpointChain(chain, guardian, policy|null) -> {ok: true} | {ok: false, at}
import * as L from '../../../packages/pca/src/ledger.ts';
import { b64u, canonicalBytes, utf8 } from '../../../packages/pca/src/hash.ts';
import { publicKeyOf, sign } from '../../../packages/pca/src/keys.ts';
import { Oracle, variants, ser } from './lib.mjs';

const o = new Oracle('ledger', 'tools/pca-audit/k05-oracles/ledger-oracle.mts', 'TS-reference oracle for the transparency ledger: consistency and inclusion proofs, witnessed heads, tree heads, witness cosignatures, head consistency, checkpoint chains and equivocation.');
const isPlain = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
const cat = (a: Uint8Array, b: Uint8Array) => { const m = new Uint8Array(a.length + b.length); m.set(a); m.set(b, a.length); return m; };
const sk = (n: number) => new Uint8Array(32).fill(n);
const GUARD = sk(101), W1 = sk(102), W2 = sk(103), W3 = sk(104), ROGUE = sk(105);
const pk = (s: Uint8Array) => b64u(publicKeyOf(s));
const GPK = pk(GUARD), W1K = pk(W1), W2K = pk(W2), W3K = pk(W3), RK = pk(ROGUE);
const sig = (s: Uint8Array, domain: string, body: unknown) => b64u(sign(s, cat(utf8(domain), canonicalBytes(body))));
const pickAll = (r: Record<string, unknown>, keys: string[]) => Object.fromEntries(keys.map((k) => [k, r[k]]));

// ---- consistency ----
const led = new L.TransparencyLedger('p');
for (let i = 0; i < 17; i++) led.appendCommitment(`c${i}`);
const root = (n: number) => led.rootAt(n);
const vc = (n: string, a: unknown, b: unknown, p: unknown) => o.run('verifyLedgerConsistency', n, (x: never, y: never, z: never) => L.verifyLedgerConsistency(x, y, z), [a, b, p]);
for (let m = 0; m <= 17; m++) for (let n = m; n <= 17; n++) {
  const p = led.consistencyProof(m, n);
  await vc(`valid ${m}->${n}`, root(m), root(n), p);
  if (n > m) await vc(`swapped roots ${m}->${n}`, root(n), root(m), p);
  if (p.path.length > 0) {
    await vc(`path cut ${m}->${n}`, root(m), root(n), { ...p, path: p.path.slice(0, -1) });
    await vc(`path extended ${m}->${n}`, root(m), root(n), { ...p, path: [...p.path, p.path[0]] });
    await vc(`path first dropped ${m}->${n}`, root(m), root(n), { ...p, path: p.path.slice(1) });
    if (p.path.length > 1) await vc(`path reversed ${m}->${n}`, root(m), root(n), { ...p, path: [...p.path].reverse() });
  }
  if (n < 17) await vc(`newSize+1 ${m}->${n}`, root(m), root(n), { ...p, newSize: n + 1 });
  if (m > 0) await vc(`oldSize-1 ${m}->${n}`, root(m), root(n), { ...p, oldSize: m - 1 });
  if ((m & (m - 1)) === 0 && m > 0 && n > m) {
    await vc(`junk old root ${m}->${n}`, 'not base64!', root(n), p);
    await vc(`padded old root ${m}->${n}`, root(m) + '=', root(n), p);
  }
}
for (const [n, v] of variants(led.consistencyProof(5, 13))) await vc('5->13 proof' + n, root(5), root(13), v);
for (const [n, v] of variants(led.consistencyProof(4, 13))) await vc('4->13 proof' + n, root(4), root(13), v);
for (const [n, v] of variants(led.consistencyProof(7, 7))) await vc('7->7 proof' + n, root(7), root(7), v);
for (const [n, v] of variants(led.consistencyProof(0, 0))) await vc('0->0 proof' + n, root(0), root(0), v);
for (const [n, v] of variants(led.consistencyProof(0, 3))) await vc('0->3 proof' + n, root(0), root(3), v);
for (const [n, a, b, p] of [
  ['old root number', 5, root(13), led.consistencyProof(5, 13)], ['new root null', root(5), null, led.consistencyProof(5, 13)], ['proof null', root(5), root(13), null],
  ['proof array', root(5), root(13), []], ['0->0 wrong new', root(0), root(1), { oldSize: 0, newSize: 0, path: [] }], ['0->3 wrong old', root(1), root(3), { oldSize: 0, newSize: 3, path: [] }],
  ['path 108 junk', root(5), root(13), { oldSize: 5, newSize: 13, path: Array(108).fill('AA') }], ['path 109 junk', root(5), root(13), { oldSize: 5, newSize: 13, path: Array(109).fill('AA') }],
  ['path 60 valid-looking', root(5), root(13), { oldSize: 5, newSize: 13, path: Array(60).fill(root(1)) }], ['path element number', root(5), root(13), { oldSize: 5, newSize: 13, path: [5] }],
  ['sizes 2^53', root(5), root(13), { oldSize: 2 ** 53, newSize: 2 ** 53, path: [] }], ['sizes 2^53-1 equal', root(5), root(5), { oldSize: 2 ** 53 - 1, newSize: 2 ** 53 - 1, path: [] }],
  ['wrapped sizes', root(3), root(7), { ...led.consistencyProof(3, 7), oldSize: 3 + 2 ** 32, newSize: 7 + 2 ** 32 }], ['old > new', root(7), root(3), { oldSize: 7, newSize: 3, path: [] }],
] as [string, unknown, unknown, unknown][]) await vc(n, a, b, p);

// ---- inclusion ----
const vi = (n: string, r: unknown, p: unknown, c: unknown) => o.run('verifyLedgerInclusion', n, (x: never, y: never, z: never) => L.verifyLedgerInclusion(x, y, z), [r, p, c]);
await vi('valid', root(17), led.inclusionProof(5), 'c5');
await vi('wrong commit', root(17), led.inclusionProof(5), 'c6');
await vi('proof null', root(17), null, 'c5');
await vi('proof string', root(17), 'x', 'c5');

// ---- witnessed heads ----
const HEAD_DOMAIN = 'atlas-pca/ledger-head/v1\0';
const reHead = (h: unknown, s = W1): unknown => { if (!isPlain(h)) return h; try { return { ...h, sig: sig(s, HEAD_DOMAIN, pickAll(h, ['principal', 'size', 'root'])) }; } catch { return h; } };
const wled = new L.TransparencyLedger('alice');
for (let i = 0; i < 5; i++) wled.appendCommitment(`w${i}`);
const WH = wled.witnessHead(W1) as unknown as Record<string, unknown>;
const vw = (n: string, h: unknown, k: unknown = W1K) => o.run('verifyWitnessedHead', n, (x: never, y: never) => L.verifyWitnessedHead(x, y), [h, k]);
await vw('base', WH);
for (const [n, v] of variants(WH, { lens: [0, 1] })) {
  await vw('unsigned' + n, v);
  if (!n.startsWith('/sig')) await vw('re-signed' + n, reHead(v));
}
await vw('witness null', WH, null);
await vw('other witness', WH, W2K);
await vw('signed by another key', reHead(WH, W2));
await vw('alg bogus', reHead({ ...WH, alg: 'bogus' }));
await vw('alg ed25519', reHead({ ...WH, alg: 'ed25519' }));
const de = (n: string, a: unknown, b: unknown, k: unknown = W1K) => o.run('detectEquivocation', n, (x: never, y: never, z: never) => L.detectEquivocation(x, y, z), [a, b, k]);
const H = (over: Record<string, unknown>, s = W1) => reHead({ ...WH, ...over }, s);
for (const [n, a, b] of [
  ['same head', WH, WH], ['different root', WH, H({ root: root(3) })], ['different size', WH, H({ size: 6, root: root(3) })], ['different principal', WH, H({ principal: 'bob', root: root(3) })],
  ['size 5 vs "5"', WH, H({ size: '5', root: root(3) })], ['size "5" vs "6"', H({ size: '5' }), H({ size: '6', root: root(3) })], ['size "5" both', H({ size: '5' }), H({ size: '5', root: root(3) })],
  ['roots 1 vs 1', H({ root: 1 }), H({ root: 1 })], ['roots 1 vs "1"', H({ root: 1 }), H({ root: '1' })], ['roots objects', H({ root: {} }), H({ root: {} })], ['roots null', H({ root: null }), H({ root: null })],
  ['roots null vs string', H({ root: null }), WH], ['principal objects', H({ principal: {} }), H({ principal: {}, root: root(3) })], ['principal null', H({ principal: null }), H({ principal: null, root: root(3) })],
  ['size -0 vs 0', H({ size: -0 }), H({ size: 0, root: root(3) })], ['size 1.5 both', H({ size: 1.5 }), H({ size: 1.5, root: root(3) })], ['second unsigned', WH, { ...WH, root: root(3) }],
  ['second by another witness', WH, H({ root: root(3) }, W2)], ['first not object', 'x', WH], ['second array', WH, []],
] as [string, unknown, unknown][]) await de(n, a, b);
await de('witness null', WH, H({ root: root(3) }), null);

// ---- tree heads, cosignatures ----
const STH_KEYS = ['instance_id', 'principal', 'size', 'root', 'prev_root', 'timestamp'];
const COS_KEYS = ['instance_id', 'principal', 'size', 'root', 'prev_root', 'guardian_epoch'];
const reSth = (h: unknown, s = GUARD): unknown => { if (!isPlain(h)) return h; try { return { ...h, sig: sig(s, L.STH_DOMAIN, pickAll(h, STH_KEYS)) }; } catch { return h; } };
const cosig = (h: Record<string, unknown>, s: Uint8Array) => { try { return { key: pk(s), sig: sig(s, L.STH_WITNESS_DOMAIN, { ...pickAll(h, COS_KEYS), guardian_epoch: h.guardian_epoch ?? 0 }) }; } catch { return { key: pk(s), sig: 'x' }; } };
const sthAt = (n: number, over: Record<string, unknown> = {}) => {
  const base = L.signTreeHead(GUARD, { instance_id: 'ins1', principal: 'alice', size: n, root: root(n), prev_root: n > 0 ? root(n - 1) : '', timestamp: 1_800_000_000_000 + n }) as unknown as Record<string, unknown>;
  return reSth({ ...base, ...over }) as Record<string, unknown>;
};
const withWitnesses = (h: Record<string, unknown>, ws: unknown[]) => ({ ...h, witnesses: ws });
const S5 = sthAt(5);
const vt = (n: string, h: unknown, g: unknown = GPK, pol: unknown = null) => o.run('verifyTreeHead', n, (x: never, y: never, z: never) => L.verifyTreeHead(x, y, (z ?? undefined) as never), [h, g, pol]);
await vt('base', S5);
for (const [n, v] of variants(S5, { lens: [0, 1] })) {
  await vt('unsigned' + n, v);
  if (!n.startsWith('/sig') && !n.startsWith('/guardian')) await vt('re-signed' + n, reSth(v));
}
await vt('guardian null', S5, null);
await vt('other guardian', S5, RK);
await vt('signed by another key', reSth(S5, ROGUE));
await vt('alg bogus', reSth({ ...S5, alg: 'bogus' }));
const POL = (threshold: unknown, keys: unknown = [W1K, W2K, W3K]) => ({ witnessKeys: keys, threshold });
const S5w = (ws: unknown[]) => withWitnesses(S5, ws);
const C1 = cosig(S5, W1), C2 = cosig(S5, W2), C3 = cosig(S5, W3), CR = cosig(S5, ROGUE);
const WSETS: [string, unknown[]][] = [
  ['none', []], ['w1', [C1]], ['w1 w2', [C1, C2]], ['w1 w1', [C1, C1]], ['w1 w2 w3', [C1, C2, C3]], ['rogue', [CR]], ['rogue w1', [CR, C1]], ['w1 bad sig', [{ ...C1, sig: C2.sig }]],
  ['w1 sig number', [{ ...C1, sig: 5 }]], ['key number', [{ key: 5, sig: C1.sig }, C2]], ['null entry', [null, C1, C2]], ['string entry', ['x', C1]], ['w1 for another head', [cosig(sthAt(6), W1), C2]],
  ['w2 key with w1 sig', [{ key: W2K, sig: C1.sig }, C1]], ['w1 missing sig', [{ key: W1K }, C2]],
];
const POLS: [string, unknown][] = [['t0', POL(0)], ['t1', POL(1)], ['t2', POL(2)], ['t3', POL(3)], ['t4', POL(4)], ['t1.5', POL(1.5)], ['t-1', POL(-1)], ['t"1"', POL('1')], ['tnull', POL(null)], ['t2^53', POL(2 ** 53)],
  ['t1 no keys', POL(1, [])], ['t1 keys not array', POL(1, 'abc')], ['t1 keys with number', POL(1, [5, W1K])], ['t1 keys absent', { threshold: 1 }], ['t0 no keys', POL(0, [])], ['t-0', POL(-0)]];
const vws = (n: string, h: unknown, p: unknown) => o.run('verifyWitnessCosignatures', n, (x: never, y: never) => L.verifyWitnessCosignatures(x, y), [h, p]);
for (const [wn, ws] of WSETS) for (const [pn, p] of POLS) await vws(`${wn} ${pn}`, S5w(ws), p);
await vws('witnesses absent t1', S5, POL(1));
await vws('witnesses not array t1', { ...S5, witnesses: 'x' }, POL(1));
await vws('sth null', null, POL(1));
const vwc = (n: string, h: unknown, c: unknown, k: unknown = W1K) => o.run('verifyWitnessCosignature', n, (x: never, y: never, z: never) => L.verifyWitnessCosignature(x, y, z), [h, c, k]);
await vwc('base', S5, C1);
for (const [n, v] of variants(C1)) await vwc('cosig' + n, S5, v);
for (const k of COS_KEYS) {
  const { [k]: _d, ...rest } = S5 as Record<string, unknown>;
  await vwc(`sth without ${k}`, rest, cosig(rest, W1));
}
for (const e of [0, 3, null, '3', -0]) {
  const h = { ...S5, guardian_epoch: e };
  await vwc(`epoch ${ser(e)} cosigned`, h, cosig(h, W1));
  await vwc(`epoch ${ser(e)} cosigned as 0`, h, C1);
}
await vwc('witness null', S5, C1, null);
await vwc('cosig null', S5, null);
await vwc('alg bogus', S5, { ...C1, alg: 'bogus' });
for (const [wn, ws] of WSETS.slice(0, 6)) for (const [pn, p] of POLS.slice(0, 5)) await vt(`witnessed ${wn} ${pn}`, S5w(ws), GPK, p);

// ---- head consistency, checkpoint chains ----
const vh = (n: string, a: unknown, b: unknown, p: unknown, pol: unknown = null) => o.run('verifyHeadConsistency', n, (x: never, y: never, z: never, g: never, q: unknown) => L.verifyHeadConsistency(x, y, z, g, (q ?? undefined) as never), [a, b, p, GPK, pol]);
const pr = (m: number, n: number) => led.consistencyProof(m, n);
for (const [m, n] of [[1, 2], [4, 5], [5, 6], [3, 9], [5, 5], [0, 4], [0, 0], [16, 17]] as [number, number][]) await vh(`${m}->${n}`, sthAt(m), sthAt(n), pr(m, n));
for (const [n, a, b, p] of [
  ['adjacent bad prev_root', sthAt(5), sthAt(6, { prev_root: root(4) }), pr(5, 6)], ['skip ahead bad prev_root', sthAt(5), sthAt(7, { prev_root: root(4) }), pr(5, 7)],
  ['instance differs', sthAt(5), sthAt(6, { instance_id: 'ins2' }), pr(5, 6)], ['principal differs', sthAt(5), sthAt(6, { principal: 'bob' }), pr(5, 6)],
  ['instance objects', sthAt(5, { instance_id: {} }), sthAt(6, { instance_id: {} }), pr(5, 6)], ['instance null both', sthAt(5, { instance_id: null }), sthAt(6, { instance_id: null }), pr(5, 6)],
  ['instance 1 vs 1', sthAt(5, { instance_id: 1 }), sthAt(6, { instance_id: 1 }), pr(5, 6)], ['prev_root object', sthAt(5, { root: root(5) }), sthAt(6, { prev_root: {} }), pr(5, 6)],
  ['proof sizes off', sthAt(5), sthAt(6), { ...pr(5, 6), oldSize: 4 }], ['proof newSize off', sthAt(5), sthAt(6), { ...pr(5, 6), newSize: 7 }], ['proof oldSize string', sthAt(5), sthAt(6), { ...pr(5, 6), oldSize: '5' }],
  ['proof null', sthAt(5), sthAt(6), null], ['proof array', sthAt(5), sthAt(6), []], ['proof false', sthAt(5), sthAt(6), false], ['newer forged', sthAt(5), { ...sthAt(6), root: root(2) }, pr(5, 6)],
  ['older not object', 'x', sthAt(6), pr(5, 6)], ['reversed', sthAt(6), sthAt(5), pr(5, 6)], ['proof path bad', sthAt(5), sthAt(9), { ...pr(5, 9), path: pr(5, 9).path.slice(1) }],
] as [string, unknown, unknown, unknown][]) await vh(n, a, b, p);
await vh('witnessed policy t1 both', S5w([C1]), withWitnesses(sthAt(6), [cosig(sthAt(6), W1)]), pr(5, 6), POL(1));
await vh('witnessed policy t1 newer bare', S5w([C1]), sthAt(6), pr(5, 6), POL(1));
const vcc = (n: string, chain: unknown, pol: unknown = null) => o.run('verifyCheckpointChain', n, (c: never, g: never, q: unknown) => {
  const r = L.verifyCheckpointChain(c, g, (q ?? undefined) as never);
  return r.ok ? { ok: true } : { ok: false, at: r.at };
}, [chain, GPK, pol]);
const cp = (n: number, proof?: unknown) => (proof === undefined ? { sth: sthAt(n) } : { sth: sthAt(n), proof });
await vcc('empty', []);
await vcc('not array', { sth: sthAt(1) });
await vcc('null', null);
await vcc('one', [cp(3)]);
await vcc('one with proof', [cp(3, pr(1, 3))]);
await vcc('three', [cp(1), cp(4, pr(1, 4)), cp(9, pr(4, 9))]);
await vcc('adjacent four', [cp(1), cp(2, pr(1, 2)), cp(3, pr(2, 3)), cp(4, pr(3, 4))]);
await vcc('missing proof', [cp(1), cp(4)]);
for (const bad of [null, false, 0, '', true, [], 'x']) await vcc(`proof ${ser(bad)}`, [cp(1), cp(4, bad)]);
await vcc('bad proof third', [cp(1), cp(4, pr(1, 4)), cp(9, pr(3, 9))]);
await vcc('bad head second', [cp(1), { sth: { ...sthAt(4), root: root(3) }, proof: pr(1, 4) }]);
await vcc('bad head first', [{ sth: { ...sthAt(1), root: root(3) } }, cp(4, pr(1, 4))]);
await vcc('entry null', [cp(1), null]);
await vcc('entry string', ['x']);
await vcc('rewritten history', [cp(4), { sth: reSth({ ...sthAt(9), root: led.rootAt(8) }), proof: pr(4, 9) }]);
await vcc('witnessed t1', [{ sth: S5w([C1]) }], POL(1));
await vcc('witnessed t2 short', [{ sth: S5w([C1]) }], POL(2));
o.write();
