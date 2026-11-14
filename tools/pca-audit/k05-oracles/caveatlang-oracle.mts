// k05 differential oracle: the caveat language v2 (packages/pca/src/caveat-lang.ts, track K1) and the K1 request headers
// (server/require-pca.ts presentedK1). Drives the TypeScript reference over a generated, boundary-heavy input space: every
// shape check under structural mutation (lib.variants), every limit at -1/0/+1, seeded random derive expressions (well-formed
// and broken), signed discharges / narrow blocks re-signed per variant so the post-signature branches are reached, and whole
// K1 evaluations over random chains. Writes out/k05-caveatlang.json.gz. Deterministic (Ed25519 keys from fixed seeds).
//
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/caveatlang-oracle.mts
import * as P from '../../../packages/pca/src/index.ts';
import * as RQ from '../../../packages/pca/src/server/require-pca.ts';
import * as IA from '../../../packages/pca/src/intent-artifacts.ts';
import { readFileSync } from 'node:fs';
import { Oracle, ROOT, clone, jsonOut, reparse, rng, seed, variants } from './lib.mjs';

const pca: any = (P as any).evaluateK1 ? P : (P as any).default;
const rq: any = (RQ as any).presentedK1 ? RQ : (RQ as any).default;
const O = new Oracle('caveatlang', 'tools/pca-audit/k05-oracles/caveatlang-oracle.mts',
  'TS-reference oracle for CaveatLang (caveat-lang.ts) + presentedK1 (server/require-pca.ts). Case = {fn, name, args, out}; see tools/pca-audit/k05-oracles/README.md for the native entry point per fn.');

// ---- keys, chains, artifacts (same seeds as packages/pca/scripts/gen-conformance-k1.mjs) -------------------------------
const NOW = 1_800_000_000_000;
const mk = (l: string) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent'), sub = mk('subagent'), rogue = mk('rogue');
const human = mk('k1/human'), org = mk('k1/org'), workload = mk('k1/workload'), model = mk('k1/model'), artifact = mk('k9/artifact');
const nonce = (n: number, len = 16) => pca.b64u(new Uint8Array(len).fill(n));
const dg = (c: string) => pca.b64u(new Uint8Array(32).fill(c.charCodeAt(0)));
const SPIFFE = 'spiffe://acme.test/ns/prod/runtime';
const pin = (label: string, cls: string, who: any, extra = {}) => ({ label, class: cls, pk: who.pub, ...extra });
const PINS = [pin('risk-team', 'human', human), pin('acme', 'org', org), pin('runtime', 'workload', workload, { spiffe_id: SPIFFE }), pin('screener', 'model', model), pin('provenance', 'artifact', artifact)];
const SIGNER: Record<string, any> = { 'risk-team': human, acme: org, runtime: workload, screener: model, provenance: artifact };
const root = (caveats: any[]) => pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });
const hop = (parent: any, signer: any, to: any, caveats: any[]) => pca.delegate(parent, to.pub, caveats, signer.sk);
const one = (c: any[]) => { const g = root(c); return { grant: g, chain: [g], leafSk: agent.sk }; };
const two = (rc: any[], a: any[]) => { const g = root(rc); const c = hop(g, agent, sub, a); return { grant: g, chain: [g, c], leafSk: sub.sk }; };
const three = (rc: any[], a1: any[], a2: any[]) => { const g = root(rc); const c1 = hop(g, agent, sub, a1); const c2 = hop(c1, sub, agent, a2); return { grant: g, chain: [g, c1, c2], leafSk: agent.sk }; };
const capN = (c: any, i: number) => pca.capHash(c.chain[i]);
const leafCap = (c: any) => capN(c, c.chain.length - 1);
const nd = (o: any = {}) => ({ type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 600_000, require: [{ claim: 'kyc_level', op: 'gte', value: 2 }], ...o });
const disBody = (cap: string, o: any = {}) => ({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', claims: { kyc_level: 3 }, iat: NOW - 1000, not_after: NOW + 300_000, nonce: nonce(7), ...o });
const dis = (cap: string, o: any = {}, who?: any) => { const b = disBody(cap, o); return pca.signDischarge(b, (who ?? SIGNER[b.issuer] ?? rogue).sk); };
const narBody = (c: any, caveats: any[], o: any = {}) => ({ v: 1, kind: 'pca-narrow', cap_hash: leafCap(c), holder: c.chain[c.chain.length - 1].holder, caveats, iat: NOW - 1000, not_after: NOW + 300_000, nonce: nonce(9), ...o });
const nar = (c: any, caveats: any[], o: any = {}, who?: any) => pca.signNarrow(narBody(c, caveats, o), who ?? c.leafSk);
/** Sign without the reference's own shape check (signArtifact), so a body the signer refuses still carries a VALID signature. */
const rawSign = (domain: string, body: any, sk: Uint8Array) => ((IA as any).signArtifact ?? (IA as any).default.signArtifact)(domain, body, sk);
const ACTION = (amount?: unknown, extra = {}) => ({ verb: 'refund', resource: 'orders/42', params: amount === undefined ? {} : { amount }, ...extra });
const ACT_DIGEST = dg('a');

/** Synchronous O.run (every reference here is sync); a repeated label gets a #n suffix, identical (fn, args) are dropped by O.add. */
function run(fn: string, name: string, ref: (...a: any[]) => unknown, args: unknown[]) {
  const a = reparse(args);
  let out: unknown;
  try { out = jsonOut(ref(...a)); } catch (e) { out = { $throws: e instanceof Error ? e.message : String(e) }; }
  let n = name;
  for (let i = 2; O.names.has(`${fn}/${n}`); i++) n = `${name} #${i}`;
  return O.add(fn, n, a, out);
}
const S = (n: number, ch = 'a') => ch.repeat(n);
const BIG_LENS = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257];

// =====================================================================================================================
// spiffeIdError
// =====================================================================================================================
const spiffe = (name: string, s: unknown) => run('spiffeIdError', name, pca.spiffeIdError, [s]);
{
  const fixed: [string, unknown][] = [
    ['ok', 'spiffe://acme.test'], ['ok path', SPIFFE], ['ok chars', 'spiffe://a-b_c.d/A-z_0.9'], ['trailing slash', 'spiffe://acme.test/'], ['td only slash', 'spiffe:///x'],
    ['empty', ''], ['number', 7], ['null', null], ['array', ['spiffe://a']], ['upper scheme', 'SPIFFE://a'], ['no scheme', 'acme.test'], ['http', 'https://a'],
    ['upper td', 'spiffe://Acme'], ['td percent', 'spiffe://a%20b'], ['td colon port', 'spiffe://a:443'], ['td at', 'spiffe://u@a'], ['query', 'spiffe://a/b?x'], ['fragment', 'spiffe://a/b#x'],
    ['dot seg', 'spiffe://a/./b'], ['dotdot seg', 'spiffe://a/../b'], ['dot end', 'spiffe://a/b/.'], ['dotdot end', 'spiffe://a/..'], ['empty seg', 'spiffe://a//b'], ['seg dots ok', 'spiffe://a/.../b'],
    ['seg space', 'spiffe://a/b c'], ['seg unicode', 'spiffe://a/é'], ['td unicode', 'spiffe://é'], ['lone surrogate', 'spiffe://a/\ud800'], ['td dot', 'spiffe://.'], ['td dotdot', 'spiffe://..'],
    ['scheme only', 'spiffe://'], ['scheme one slash', 'spiffe:/a'], ['nul', 'spiffe://a/\u0000'], ['seg plus', 'spiffe://a/b+c'], ['seg tilde', 'spiffe://a/~b'],
  ];
  for (const [n, s] of fixed) spiffe(n, s);
  for (const n of [253, 254, 255, 256]) spiffe(`td ${n}`, 'spiffe://' + S(n));
  for (const n of [2047, 2048, 2049]) { spiffe(`total ${n} ascii`, 'spiffe://a/' + S(n - 11)); }
  spiffe('total 2048 with multibyte crossing', 'spiffe://a/' + S(2048 - 11 - 1) + 'é');
  spiffe('total 2047 with multibyte fits', 'spiffe://a/' + S(2048 - 11 - 2) + 'é');
  spiffe('total 2048 lone surrogate (3 bytes)', 'spiffe://a/' + S(2048 - 11 - 2) + '\udc00');
  const r = rng(0xc0ffee01);
  const parts = ['spiffe://', 'a', 'z', 'A', '0', '.', '..', '/', '-', '_', '%', ':', '?', '#', 'é', ' ', 'acme.test', '//', '/.', '/..'];
  for (let i = 0; i < 600; i++) {
    let s = r.next() < 0.8 ? 'spiffe://' : '';
    for (let k = r.int(1, 7); k > 0; k--) s += r.pick(parts);
    spiffe(`rand ${i}`, s);
  }
}

// =====================================================================================================================
// needsDischargeError (requireError inside)
// =====================================================================================================================
const NDE = (name: string, c: unknown) => run('needsDischargeError', name, pca.needsDischargeError, [c]);
{
  const base = nd({ issuer_spiffe: SPIFFE, require: [{ claim: 'kyc_level', op: 'gte', value: 2 }, { claim: 'country', op: 'in', value: ['US', 'CA'] }, { claim: 'ok', op: 'eq', value: true }] });
  NDE('base', base);
  NDE('base no spiffe', nd());
  for (const [l, v] of variants(base, { lens: BIG_LENS })) NDE('var ' + l, v);
  for (const k of ['id', 'issuer']) for (const n of [63, 64, 65]) { NDE(`${k} ${n}`, nd({ [k]: S(n) })); NDE(`${k} ${n} dotted`, nd({ [k]: '0' + S(n - 1, '.') })); }
  for (const s of ['a', '0', '-a', '.a', '_a', 'a-b', 'a.b', 'a_b', 'A', 'a b', 'é']) { NDE(`id '${s}'`, nd({ id: s })); NDE(`issuer '${s}'`, nd({ issuer: s })); }
  for (const c of ['human', 'org', 'workload', 'model', 'artifact', 'Human', 'admin', '']) NDE(`class ${c}`, nd({ issuer_class: c }));
  for (const b of ['chain_hop', 'action', 'hop', '']) NDE(`bind ${b}`, nd({ bind: b }));
  for (const t of [0, 1, 2, 86_399_999, 86_400_000, 86_400_001, -1, 1.5, -0, 2 ** 53]) NDE(`ttl ${Object.is(t, -0) ? '-0' : t}`, nd({ ttl_ms: t }));
  const req = (r: any) => nd({ require: [r] });
  for (const n of [0, 1, 15, 16, 17]) NDE(`require ${n}`, nd({ require: Array.from({ length: n }, (_, i) => ({ claim: `c${i}`, op: 'eq', value: i })) }));
  NDE('require bad 17th', nd({ require: [...Array.from({ length: 16 }, (_, i) => ({ claim: `c${i}`, op: 'eq', value: i })), 5] }));
  for (const n of [63, 64, 65]) NDE(`claim name ${n}`, req({ claim: S(n), op: 'eq', value: 1 }));
  for (const s of ['a', '_a', '0a', 'a-b', 'A', 'a.b', '', 'aé']) NDE(`claim name '${s}'`, req({ claim: s, op: 'eq', value: 1 }));
  for (const op of ['eq', 'neq', 'gte', 'lte', 'in', 'lt', 'gt', 'EQ', '', null]) for (const value of [1, 'x', true, -1, 1.5, -0, 2 ** 53, null, [], ['x'], [1, 'x'], {}, S(256), S(257), '', 2 ** 53 - 1, -(2 ** 53 - 1)]) {
    NDE(`req ${op} ${JSON.stringify(value)?.slice(0, 20)}${Object.is(value, -0) ? '-0' : ''}`, req({ claim: 'k', op, value }));
  }
  for (const n of [0, 1, 16, 17]) NDE(`in ${n}`, req({ claim: 'k', op: 'in', value: Array.from({ length: n }, (_, i) => i) }));
  NDE('in with bad item', req({ claim: 'k', op: 'in', value: [1, 1.5] }));
  NDE('in with long string', req({ claim: 'k', op: 'in', value: ['a', S(257)] }));
  NDE('in with 256 string', req({ claim: 'k', op: 'in', value: ['a', S(256)] }));
  NDE('in with multibyte 256 crossing', req({ claim: 'k', op: 'in', value: [S(255) + 'é'] }));
  for (const [l, v] of variants({ claim: 'k', op: 'eq', value: 1 })) NDE('req var ' + l, req(v));
  for (const s of ['spiffe://a', 'spiffe://a/', '', 5, null]) NDE(`issuer_spiffe ${JSON.stringify(s)}`, nd({ issuer_spiffe: s }));
}

// =====================================================================================================================
// dischargeShapeError
// =====================================================================================================================
const DSE = (name: string, a: unknown) => run('dischargeShapeError', name, pca.dischargeShapeError, [a]);
const C1 = one([nd()]);
const CAP0 = capN(C1, 0);
{
  const d = dis(CAP0, { claims: { kyc_level: 3, country: 'US', ok: true } });
  const da = dis(CAP0, { bind: 'action', action_digest: ACT_DIGEST });
  DSE('base', d);
  DSE('base action', da);
  for (const [l, v] of variants(d, { lens: [15, 16, 21, 22, 42, 43, 44] })) DSE('var ' + l, v);
  for (const [l, v] of variants(da)) DSE('action var ' + l, v);
  for (const n of [0, 1, 16, 17]) DSE(`claims ${n}`, { ...d, claims: Object.fromEntries(Array.from({ length: n }, (_, i) => [`c${i}`, i])) });
  for (const [k, v] of [['A', 1], ['a-b', 1], ['_a', 1], [S(64), 1], [S(65), 1], ['k', 1.5], ['k', null], ['k', S(256)], ['k', S(257)], ['k', []], ['k', -0], ['k', 2 ** 53]] as [string, unknown][]) {
    DSE(`claim ${k.slice(0, 8)}(${k.length})=${JSON.stringify(v)?.slice(0, 12)}${Object.is(v, -0) ? '-0' : ''}`, { ...d, claims: { kyc_level: 3, [k]: v } });
  }
  for (const [iat, na] of [[0, 1], [0, 0], [1, 0], [0, 86_400_000], [0, 86_400_001], [5, 86_400_005], [5, 86_400_006], [-1, 5], [1.5, 5], [0, 2 ** 53], [2 ** 53 - 2, 2 ** 53 - 1], [-0, 5], [0, -0]]) {
    DSE(`window ${iat}..${na}${Object.is(iat, -0) || Object.is(na, -0) ? ' (-0)' : ''}`, { ...d, iat, not_after: na });
  }
  for (const n of [0, 8, 15, 16, 17, 32, 64]) DSE(`nonce ${n} bytes`, { ...d, nonce: nonce(1, n) });
  DSE('nonce padded', { ...d, nonce: nonce(1, 16) + '=' });
  DSE('nonce std alphabet', { ...d, nonce: '+/' + nonce(1, 16).slice(2) });
  DSE('nonce non-canonical tail', { ...d, nonce: nonce(1, 16).slice(0, -1) + 'B' });
  for (const alg of ['ed25519', 'ml-dsa-65', 'ed25519+ml-dsa-65', 'hybrid', 'rsa', 5, null, '']) {
    DSE(`alg ${alg}`, { ...d, alg });
    DSE(`alg ${alg} + pq_pk`, { ...d, alg, pq_pk: 'AAAA' });
    DSE(`alg ${alg} + pq_pk + pq_sig`, { ...d, alg, pq_pk: 'AAAA', pq_sig: 'AAAA' });
  }
  DSE('pq_pk number', { ...d, pq_pk: 5 });
  DSE('pq_sig only', { ...d, pq_sig: 'AA' });
  for (const n of [42, 43, 44]) DSE(`cap_hash ${n} chars`, { ...d, cap_hash: S(n, 'A') });
}

// =====================================================================================================================
// narrowShapeError
// =====================================================================================================================
const NSE = (name: string, a: unknown) => run('narrowShapeError', name, pca.narrowShapeError, [a]);
{
  const n = nar(C1, [{ type: 'max_amount', max: 10 }, { type: 'spiffe_bound', spiffe_id: SPIFFE }]);
  const na = nar(C1, [{ type: 'x' }], { action_digest: ACT_DIGEST });
  NSE('base', n);
  NSE('base action', na);
  for (const [l, v] of variants(n, { lens: [42, 43, 44, 63, 64, 65] })) NSE('var ' + l, v);
  for (const [l, v] of variants(na)) NSE('action var ' + l, v);
  for (const k of [0, 1, 15, 16, 17]) NSE(`caveats ${k}`, { ...n, caveats: Array.from({ length: k }, () => ({ type: 'x' })) });
  for (const t of ['envelope', 'sealed', 'budget_alloc', 'intent_session', 'narrow', 'needs_discharge', 'max_uses', 'Sealed', '']) NSE(`forbidden ${t}`, { ...n, caveats: [{ type: 'x' }, { type: t }] });
  for (const c of [null, 5, 'sealed', [], { type: 5 }, { type: null }, {}, { type: ['sealed'] }]) NSE(`caveat ${JSON.stringify(c)}`, { ...n, caveats: [{ type: 'x' }, c] });
  NSE('forbidden after bad', { ...n, caveats: [5, { type: 'sealed' }] });
  for (const h of [agent.pub + 'A', agent.pub.slice(0, -1), S(64, 'A'), S(65, 'A'), nonce(1, 31), nonce(1, 33), nonce(1, 48)]) NSE(`holder ${h.length}`, { ...n, holder: h });
  for (const [iat, na2] of [[0, 1], [0, 0], [0, 86_400_000], [0, 86_400_001], [1, 0], [-1, 1]]) NSE(`window ${iat}..${na2}`, { ...n, iat, not_after: na2 });
  for (const k of [15, 16, 17]) NSE(`nonce ${k}`, { ...n, nonce: nonce(2, k) });
  for (const alg of ['ed25519', 'ml-dsa-65', 'rsa']) NSE(`alg ${alg}`, { ...n, alg });
}

// =====================================================================================================================
// maxUsesError, maxUsesSlotKey, spiffeBoundError
// =====================================================================================================================
{
  const mu = { type: 'max_uses', id: 'budget', n: 3, until: NOW + 10 };
  const MU = (name: string, c: unknown) => run('maxUsesError', name, pca.maxUsesError, [c]);
  MU('base', mu);
  for (const [l, v] of variants(mu, { lens: [63, 64, 65] })) MU('var ' + l, v);
  for (const n of [0, 1, 2, 255, 256, 257, -1, 1.5]) MU(`n ${n}`, { ...mu, n });
  for (const u of [-1, 0, 1, 2 ** 53 - 1, 2 ** 53]) MU(`until ${u}`, { ...mu, until: u });
  for (const [cap, id, i] of [[dg('a'), 'budget', 0], [dg('a'), 'budget', 1], [dg('a'), 'budget', 255], [dg('b'), 'budget', 0], [dg('a'), 'b', 0], [dg('a'), 'a.b-c_d', 7], [dg('a'), S(64), 2]] as [string, string, number][]) {
    run('maxUsesSlotKey', `${cap.slice(0, 2)}/${id.slice(0, 8)}/${i}`, pca.maxUsesSlotKey, [cap, id, i]);
  }
  const SB = (name: string, c: unknown) => run('spiffeBoundError', name, pca.spiffeBoundError, [c]);
  const sbI = { type: 'spiffe_bound', spiffe_id: SPIFFE };
  const sbP = { type: 'spiffe_bound', spiffe_prefix: 'spiffe://acme.test/ns' };
  SB('id', sbI); SB('prefix', sbP);
  for (const [l, v] of variants(sbI)) SB('id var ' + l, v);
  for (const [l, v] of variants(sbP)) SB('prefix var ' + l, v);
  SB('both', { ...sbI, spiffe_prefix: 'spiffe://a' });
  SB('neither', { type: 'spiffe_bound' });
  SB('id undefined-like null', { type: 'spiffe_bound', spiffe_id: null });
  SB('prefix null', { type: 'spiffe_bound', spiffe_prefix: null });
  SB('id null + prefix', { type: 'spiffe_bound', spiffe_id: null, spiffe_prefix: 'spiffe://a' });
}

// =====================================================================================================================
// deriveError (exprError inside) and evaluateDerive
// =====================================================================================================================
const CONSTS: unknown[] = [0, 1, 2, 3, 5, 10, -1, 'refund', 'orders/42', 'a', '', true, false, 2 ** 53 - 1];
function genExpr(r: any, names: string[], depth: number, wild: boolean): any {
  const leaf = depth >= (wild ? 6 : 4) || r.next() < 0.3;
  if (leaf) {
    if (names.length && r.next() < 0.6) return { ref: wild && r.next() < 0.05 ? 'nope' : r.pick(names) };
    return { const: wild && r.next() < 0.05 ? r.pick([1.5, null, S(257), [], {}]) : r.pick(CONSTS) };
  }
  const k = r.int(0, 9);
  if (k <= 4) return { op: r.pick(['eq', 'neq', 'lt', 'lte', 'gt', 'gte']), a: genExpr(r, names, depth + 1, wild), b: genExpr(r, names, depth + 1, wild) };
  if (k <= 7) return { op: r.pick(['and', 'or']), args: Array.from({ length: wild && r.next() < 0.1 ? r.pick([0, 9]) : r.int(1, 3) }, () => genExpr(r, names, depth + 1, wild)) };
  if (k === 8) return { op: 'not', arg: genExpr(r, names, depth + 1, wild) };
  return wild ? r.pick([{ op: 'xor', args: [] }, { op: 'eq', a: { const: 1 } }, { ref: 'x', const: 1 }, { op: 'not', arg: { const: true }, x: 1 }]) : { op: 'not', arg: genExpr(r, names, depth + 1, wild) };
}
function genDefs(r: any, wild: boolean) {
  const defs: any[] = [];
  const names: string[] = [];
  for (let i = r.int(0, wild ? 9 : 5); i > 0; i--) {
    const name = wild && r.next() < 0.05 ? r.pick(['A', '1a', names[0] ?? 'x']) : `d${defs.length}`;
    const kind = r.pick(['count', 'param', 'action', 'claim', 'expr', 'expr']);
    let d: any;
    if (kind === 'count') {
      d = { name, kind, window_ms: r.pick([1, 1000, 60_000, 3_600_000, 30 * 86_400_000]) };
      if (r.next() < 0.5) d.verb = r.pick(['refund', 'read']);
      if (r.next() < 0.5) d.resource_prefix = r.pick(['orders/', 'orders/4', 'users/']);
    } else if (kind === 'param') d = { name, kind, path: r.pick(['amount', 'a.b', 'a.b.c.d', 'missing', 'obj', 'list']) };
    else if (kind === 'action') d = { name, kind, field: r.pick(['verb', 'resource']) };
    else if (kind === 'claim') d = { name, kind, caveat_id: r.pick(['kyc', 'other']), claim: r.pick(['kyc_level', 'country', 'missing']) };
    else d = { name, kind, expr: genExpr(r, names, 1, wild) };
    defs.push(d);
    names.push(name);
  }
  return { type: 'derive', id: 'd', defs, check: genExpr(r, names, 1, wild) };
}
const DER = (name: string, c: unknown) => run('deriveError', name, pca.deriveError, [c]);
const EVD = (name: string, c: unknown, inp: unknown) => run('evaluateDerive', name, pca.evaluateDerive, [c, inp]);
{
  const base = {
    type: 'derive', id: 'refund-guard',
    defs: [
      { name: 'recent', kind: 'count', window_ms: 3_600_000, verb: 'refund', resource_prefix: 'orders/' },
      { name: 'amt', kind: 'param', path: 'amount' },
      { name: 'verb', kind: 'action', field: 'verb' },
      { name: 'lvl', kind: 'claim', caveat_id: 'kyc', claim: 'kyc_level' },
      { name: 'ok', kind: 'expr', expr: { op: 'and', args: [{ op: 'lt', a: { ref: 'recent' }, b: { const: 3 } }, { op: 'not', arg: { op: 'gt', a: { ref: 'amt' }, b: { const: 100 } } }] } },
    ],
    check: { op: 'or', args: [{ ref: 'ok' }, { op: 'gte', a: { ref: 'lvl' }, b: { const: 3 } }] },
  };
  DER('base', base);
  for (const [l, v] of variants(base, { lens: [63, 64, 65, 256, 257], maxPaths: 400 })) DER('var ' + l, v);
  const defsN = (n: number) => Array.from({ length: n }, (_, i) => ({ name: `d${i}`, kind: 'action', field: 'verb' }));
  for (const n of [0, 1, 7, 8, 9]) DER(`defs ${n}`, { type: 'derive', id: 'd', defs: defsN(n), check: { const: true } });
  for (const w of [0, 1, 30 * 86_400_000, 30 * 86_400_000 + 1, 1.5, -1]) DER(`window ${w}`, { type: 'derive', id: 'd', defs: [{ name: 'c', kind: 'count', window_ms: w }], check: { const: true } });
  for (const p of ['a', 'a.b.c.d', 'a.b.c.d.e', 'a..b', '.a', 'a.', '', '__proto__', 'constructor', 'a.__proto__', 'a-b', 'a b', 'é', S(64), S(65), '0', 'A']) DER(`path '${p.slice(0, 12)}'(${p.length})`, { type: 'derive', id: 'd', defs: [{ name: 'p', kind: 'param', path: p }], check: { const: true } });
  // depth / node limits exactly
  const nestNot = (n: number): any => (n === 0 ? { const: true } : { op: 'not', arg: nestNot(n - 1) });
  for (const n of [2, 3, 4, 5]) DER(`not depth ${n + 1}`, { type: 'derive', id: 'd', defs: [], check: nestNot(n) });
  for (const n of [2, 3, 4]) DER(`expr def not depth ${n + 1}`, { type: 'derive', id: 'd', defs: [{ name: 'e', kind: 'expr', expr: nestNot(n) }], check: { ref: 'e' } });
  const wide = (k: number) => ({ op: 'and', args: Array.from({ length: k }, () => ({ const: true })) });
  for (const k of [0, 1, 8, 9]) DER(`and ${k} args`, { type: 'derive', id: 'd', defs: [], check: wide(k) });
  // node counting is shared across defs and the check: 32 vs 33 total nodes
  const and8 = () => ({ op: 'and', args: Array.from({ length: 7 }, () => ({ const: true })) }); // 8 nodes
  for (const [label, extra] of [['32', { const: true }], ['33', { op: 'not', arg: { const: true } }]] as const) {
    const defs = [0, 1, 2].map((i) => ({ name: `e${i}`, kind: 'expr', expr: and8() })); // 24 nodes
    const check = { op: 'and', args: [{ const: true }, { const: true }, { const: true }, { const: true }, { const: true }, { const: true }, extra] }; // 7 or 8 more
    DER(`nodes ${label}`, { type: 'derive', id: 'd', defs, check });
  }
  DER('dup def', { type: 'derive', id: 'd', defs: [...defsN(1), ...defsN(1)], check: { const: true } });
  DER('ref later def', { type: 'derive', id: 'd', defs: [{ name: 'a', kind: 'expr', expr: { ref: 'b' } }, { name: 'b', kind: 'action', field: 'verb' }], check: { const: true } });
  DER('ref self', { type: 'derive', id: 'd', defs: [{ name: 'a', kind: 'expr', expr: { ref: 'a' } }], check: { const: true } });
  DER('ref __proto__', { type: 'derive', id: 'd', defs: [], check: { ref: '__proto__' } });
  DER('ref + const', { type: 'derive', id: 'd', defs: defsN(1), check: { ref: 'd0', const: 1 } });
  DER('const + op', { type: 'derive', id: 'd', defs: [], check: { const: 1, op: 'eq' } });
  for (const op of ['eq', 'neq', 'lt', 'lte', 'gt', 'gte', 'and', 'or', 'not', 'xor', 'EQ', '', null, 5]) DER(`op ${op} bare`, { type: 'derive', id: 'd', defs: [], check: { op } });
  // seeded random: well-formed and wild
  const r = rng(0xde71e5);
  const histories = (now: number, w: number[]) => {
    const ts = [now, now - 1, now + 1, ...w.flatMap((x) => [now - x, now - x + 1, now - x - 1])];
    return ts.map((t, i) => ({ t, verb: ['refund', 'read'][i % 2], resource: ['orders/42', 'users/1', 'orders/7'][i % 3] }));
  };
  const inputs = (rr: any) => {
    const h = histories(NOW, [1000, 60_000, 3_600_000]);
    const amt = rr.pick([0, 50, 100, 101, -1, 1.5, 'x', true, null, { v: 1 }, [1], 2 ** 53 - 1]);
    return {
      now: NOW,
      action: rr.pick([ACTION(amt), ACTION(amt, { verb: 5 }), ACTION(amt, { resource: S(257) }), { verb: 'read', resource: 'orders/7', params: { a: { b: { c: { d: 4 } } }, obj: { x: 1 }, list: [1], amount: amt } }, {}, undefined]),
      history: rr.pick([h, h.slice(0, rr.int(0, h.length)), [], [...h, { t: 1.5, verb: 'refund', resource: 'orders/1' }], [...h, { t: NOW, verb: 1, resource: 'x' }], [5], 'x', undefined]),
      claims: rr.pick([{ kyc: { kyc_level: 3, country: 'US' } }, { kyc: { kyc_level: 1 } }, {}, { other: { kyc_level: 9 } }]),
    };
  };
  let wellFormed = 0;
  for (let i = 0; i < 2500; i++) {
    const wild = i % 3 === 0;
    const c = genDefs(r, wild);
    const err = pca.deriveError(reparse(c));
    DER(`rand ${wild ? 'wild' : 'ok'} ${i}`, c);
    if (err === null) {
      wellFormed++;
      for (let j = 0; j < 3; j++) EVD(`rand ${i}/${j}`, c, inputs(r));
    }
  }
  console.log(`derive: ${wellFormed} well-formed random caveats evaluated`);
  // evaluateDerive count-window boundaries exactly, every history-event refusal, and the DERIVE_MAX_HISTORY limit
  const cnt = (w: number, o: any = {}) => ({ type: 'derive', id: 'd', defs: [{ name: 'n', kind: 'count', window_ms: w, ...o }], check: { op: 'eq', a: { ref: 'n' }, b: { const: 1 } } });
  for (const w of [1, 1000]) for (const dt of [-1, 0, 1, w - 1, w, w + 1]) EVD(`window ${w} event at now-${dt}`, cnt(w), { now: NOW, history: [{ t: NOW - dt, verb: 'refund', resource: 'orders/42' }], claims: {} });
  for (const ev of [{ t: NOW }, { t: NOW, verb: 'refund' }, { t: 1.5, verb: 'refund', resource: 'r' }, { t: -0, verb: 'refund', resource: 'r' }, { t: '1', verb: 'refund', resource: 'r' }, { t: NOW, verb: 'refund', resource: 5 }, null, [], { t: NOW, verb: 'refund', resource: 'r', extra: 1 }]) {
    EVD(`bad event ${JSON.stringify(ev)}`, cnt(1000), { now: NOW, history: [ev], claims: {} });
  }
  for (const [v, rp, ev] of [['refund', undefined, ['refund', 'orders/42']], ['refund', undefined, ['read', 'orders/42']], [undefined, 'orders/', ['read', 'orders/42']], [undefined, 'orders/', ['read', 'order']], [undefined, 'orders/42', ['read', 'orders/42']], ['', undefined, ['', 'x']]] as any[]) {
    EVD(`filter verb=${v} prefix=${rp} ev=${ev}`, cnt(1000, { ...(v !== undefined ? { verb: v } : {}), ...(rp !== undefined ? { resource_prefix: rp } : {}) }), { now: NOW, history: [{ t: NOW, verb: ev[0], resource: ev[1] }], claims: {} });
  }
  const many = (n: number) => Array.from({ length: n }, () => ({ t: NOW, verb: 'refund', resource: 'orders/42' }));
  const cntN = { type: 'derive', id: 'd', defs: [{ name: 'n', kind: 'count', window_ms: 1000 }], check: { op: 'gte', a: { ref: 'n' }, b: { const: 0 } } };
  EVD('history 10000', cntN, { now: NOW, history: many(10_000), claims: {} });
  EVD('history 10001', cntN, { now: NOW, history: many(10_001), claims: {} });
  // three-valued logic table over const / unknown operands
  const vals = [{ const: true }, { const: false }, { ref: 'u' }, { const: 1 }, { const: 'x' }];
  const U = [{ name: 'u', kind: 'param', path: 'missing' }];
  for (const op of ['and', 'or']) for (const a of vals) for (const b of vals) EVD(`kleene ${op} ${JSON.stringify(a)} ${JSON.stringify(b)}`, { type: 'derive', id: 'd', defs: U, check: { op, args: [a, b] } }, { now: NOW, claims: {} });
  for (const a of vals) EVD(`kleene not ${JSON.stringify(a)}`, { type: 'derive', id: 'd', defs: U, check: { op: 'not', arg: a } }, { now: NOW, claims: {} });
  const cv = [{ const: 1 }, { const: 2 }, { const: '1' }, { const: true }, { ref: 'u' }, { const: -1 }, { const: 2 ** 53 - 1 }];
  for (const op of ['eq', 'neq', 'lt', 'lte', 'gt', 'gte']) for (const a of cv) for (const b of cv) EVD(`cmp ${op} ${JSON.stringify(a)} ${JSON.stringify(b)}`, { type: 'derive', id: 'd', defs: U, check: { op, a, b } }, { now: NOW, claims: {} });
  // param resolution through non-objects and prototype names; claim lookups through odd holders
  for (const params of [{ a: { b: 1 } }, { a: [1] }, { a: null }, { a: 'str' }, [1], null, 'x', { a: { b: 1.5 } }, { a: { b: S(257) } }, { a: { b: S(256) } }, { a: { b: false } }]) {
    EVD(`param a.b in ${JSON.stringify(params).slice(0, 30)}`, { type: 'derive', id: 'd', defs: [{ name: 'p', kind: 'param', path: 'a.b' }], check: { op: 'eq', a: { ref: 'p' }, b: { ref: 'p' } } }, { now: NOW, action: { params }, claims: {} });
  }
  for (const claims of [{ kyc: { kyc_level: 3 } }, { kyc: {} }, { kyc: null }, { kyc: 5 }, {}, { kyc: { kyc_level: null } }]) {
    EVD(`claim lookup ${JSON.stringify(claims)}`, { type: 'derive', id: 'd', defs: [{ name: 'c', kind: 'claim', caveat_id: 'kyc', claim: 'kyc_level' }], check: { op: 'eq', a: { ref: 'c' }, b: { const: 3 } } }, { now: NOW, claims });
  }
  for (const act of [{ verb: 'refund', resource: 'r' }, { verb: '' }, { verb: S(256) }, { verb: S(257) }, { verb: 5 }, null, undefined, { resource: S(255) + 'é' }]) {
    for (const field of ['verb', 'resource']) EVD(`action ${field} ${JSON.stringify(act)?.slice(0, 24)}`, { type: 'derive', id: 'd', defs: [{ name: 'f', kind: 'action', field }], check: { op: 'neq', a: { ref: 'f' }, b: { const: 'zz' } } }, { now: NOW, ...(act === undefined ? {} : { action: act }), claims: {} });
  }
}

// =====================================================================================================================
// verifyDischarge (claimHolds inside)
// =====================================================================================================================
const VD = (name: string, d: unknown, c: unknown, b: unknown) => run('verifyDischarge', name, pca.verifyDischarge, [d, c, b]);
const BIND = (o: any = {}) => ({ cap_hash: CAP0, pins: PINS, now: NOW, ...o });
{
  const conf = JSON.parse(readFileSync(ROOT + 'packages/pca/conformance/caveat-lang-vectors.json', 'utf8'));
  for (const v of conf.primitives.discharge_verify) VD('conf ' + v.name, v.input.discharge, v.input.caveat, { ...v.input.binding, cap_hash: v.input.binding.cap_hash ?? v.input.discharge?.cap_hash });
  const d = dis(CAP0);
  VD('base', d, nd(), BIND());
  for (const [l, v] of variants(d, { maxPaths: 60 })) VD('dis var ' + l, v, nd(), BIND());
  for (const [l, v] of variants(nd(), { maxPaths: 60 })) VD('cav var ' + l, d, v, BIND());
  // binding: clock, pins, revoked
  for (const now of [NOW - 1001, NOW - 1000, NOW - 999, NOW + 300_000, NOW + 300_001, 1.5, 2 ** 53, -1, 0]) VD(`now ${now}`, d, nd(), BIND({ now }));
  for (const [l, pins] of [['empty', []], ['not array', { a: 1 }], ['null', null], ['dup label', [...PINS, PINS[0]]], ['junk + right', [5, null, 'x', PINS[0]]], ['wrong class', [{ ...PINS[0], class: 'org' }]],
    ['other key', [{ ...PINS[0], pk: rogue.pub }]], ['label only other', PINS.slice(1)], ['pk missing', [{ label: 'risk-team', class: 'human' }]], ['pk number', [{ label: 'risk-team', class: 'human', pk: 5 }]]] as [string, unknown][]) {
    VD(`pins ${l}`, d, nd(), BIND({ pins }));
  }
  VD('revoked match', d, nd(), BIND({ revoked: [pca.dischargeDigest(d)] }));
  VD('revoked other', d, nd(), BIND({ revoked: [dg('z')] }));
  VD('revoked not array', d, nd(), BIND({ revoked: pca.dischargeDigest(d) }));
  VD('cap_hash other', d, nd(), BIND({ cap_hash: dg('q') }));
  // action binding
  const da = dis(CAP0, { bind: 'action', action_digest: ACT_DIGEST });
  VD('action ok', da, nd({ bind: 'action' }), BIND({ action_digest: ACT_DIGEST }));
  VD('action other', da, nd({ bind: 'action' }), BIND({ action_digest: dg('b') }));
  VD('action missing', da, nd({ bind: 'action' }), BIND());
  VD('bind mismatch hop vs action', d, nd({ bind: 'action' }), BIND({ action_digest: ACT_DIGEST }));
  VD('bind mismatch action vs hop', da, nd(), BIND({ action_digest: ACT_DIGEST }));
  // ttl vs lifetime
  for (const ttl of [301_000 - 1, 301_000, 301_001]) VD(`ttl ${ttl} vs life 301000`, d, nd({ ttl_ms: ttl }), BIND());
  // id / issuer / class / spiffe
  VD('caveat id other', d, nd({ id: 'other' }), BIND());
  VD('caveat issuer other', d, nd({ issuer: 'acme', issuer_class: 'org' }), BIND());
  const dw = dis(CAP0, { issuer: 'runtime' });
  VD('spiffe pinned ok', dw, nd({ issuer: 'runtime', issuer_class: 'workload', issuer_spiffe: SPIFFE }), BIND());
  VD('spiffe pinned other', dw, nd({ issuer: 'runtime', issuer_class: 'workload', issuer_spiffe: 'spiffe://acme.test/other' }), BIND());
  VD('spiffe on pin without', d, nd({ issuer_spiffe: SPIFFE }), BIND());
  VD('signed by rogue', dis(CAP0, {}, rogue), nd(), BIND());
  VD('signed by other pin', dis(CAP0, {}, org), nd(), BIND());
  // signature valid but body tampered post-signing: every member
  for (const k of ['claims', 'iat', 'not_after', 'nonce', 'cap_hash', 'caveat_id']) {
    const t = clone(d);
    if (k === 'claims') t.claims = { kyc_level: 4 }; else if (k === 'iat') t.iat -= 1; else if (k === 'not_after') t.not_after -= 1; else if (k === 'nonce') t.nonce = nonce(8); else if (k === 'cap_hash') t.cap_hash = dg('q'); else t.caveat_id = 'kyc2';
    VD(`tampered ${k}`, t, nd(k === 'caveat_id' ? { id: 'kyc2' } : {}), BIND(k === 'cap_hash' ? { cap_hash: dg('q') } : {}));
  }
  // claimHolds: every op x claim type x requirement value, each discharge freshly signed
  const claimVals: unknown[] = [0, 1, 2, 3, -1, 'US', 'CA', true, false, 2 ** 53 - 1, '2'];
  const reqs: any[] = [];
  for (const op of ['eq', 'neq']) for (const value of [2, '2', true, 'US', 0]) reqs.push({ claim: 'k', op, value });
  for (const op of ['gte', 'lte']) for (const value of [-1, 0, 2, 3, 2 ** 53 - 1]) reqs.push({ claim: 'k', op, value });
  for (const value of [['US', 'CA'], [2, '2'], [true], [0, 1, 2]]) reqs.push({ claim: 'k', op: 'in', value });
  for (const rqm of reqs) for (const cv of claimVals) {
    const dd = dis(CAP0, { claims: { k: cv } });
    VD(`claim ${rqm.op} ${JSON.stringify(rqm.value)} vs ${JSON.stringify(cv)}`, dd, nd({ require: [rqm] }), BIND());
  }
  const dd = dis(CAP0, { claims: { k: 1 } });
  VD('claim absent', dd, nd({ require: [{ claim: 'other', op: 'eq', value: 1 }] }), BIND());
  VD('claim __proto__ name', dd, nd({ require: [{ claim: 'constructor', op: 'neq', value: 1 }] }), BIND());
  VD('second requirement fails', dd, nd({ require: [{ claim: 'k', op: 'eq', value: 1 }, { claim: 'k', op: 'gte', value: 2 }] }), BIND());
  VD('empty require', dd, nd({ require: [] }), BIND());
  // a signature over a body the signer refuses (shape error must win)
  VD('signed but malformed (ttl too long)', rawSign(pca.DISCHARGE_DOMAIN, disBody(CAP0, { iat: 0, not_after: 86_400_001 }), human.sk), nd(), BIND());
}

// =====================================================================================================================
// verifyNarrow, boundCaveats, dischargeRequests
// =====================================================================================================================
const VN = (name: string, n: unknown, grant: unknown, chain: unknown, b: unknown) => run('verifyNarrow', name, pca.verifyNarrow, [n, grant, chain, b]);
// a trailing undefined argument is OMITTED (natives: absent = null), so TS never sees a null where it distinguishes undefined
const BC = (name: string, grant: unknown, chain: unknown) => run('boundCaveats', name, pca.boundCaveats, chain === undefined ? [grant] : [grant, chain]);
const DR = (name: string, grant: unknown, chain: unknown, ad: unknown) => run('dischargeRequests', name, pca.dischargeRequests, ad === undefined ? (chain === undefined ? [grant] : [grant, chain]) : [grant, chain ?? null, ad]);
{
  const C2 = two([{ type: 'max_amount', max: 100 }], [{ type: 'sealed' }]);
  const C3 = three([nd()], [nd({ id: 'b', bind: 'action' })], [{ type: 'x' }]);
  for (const [cn, c] of [['one', C1], ['two', C2], ['three', C3]] as [string, any][]) {
    const n = nar(c, [{ type: 'max_amount', max: 5 }]);
    const nb = { now: NOW };
    VN(`${cn} ok`, n, c.grant, c.chain, nb);
    VN(`${cn} chain absent (grant only)`, n, c.chain[c.chain.length - 1], null, nb);
    VN(`${cn} chain empty (grant only)`, n, c.chain[c.chain.length - 1], [], nb);
    for (const now of [NOW - 1001, NOW - 1000, NOW + 300_000, NOW + 300_001, 1.5, -1]) VN(`${cn} now ${now}`, n, c.grant, c.chain, { now });
    for (const [l, v] of variants(n, { maxPaths: cn === 'one' ? 40 : 8 })) VN(`${cn} var ${l}`, v, c.grant, c.chain, nb);
    const na = nar(c, [{ type: 'x' }], { action_digest: ACT_DIGEST });
    VN(`${cn} action ok`, na, c.grant, c.chain, { now: NOW, action_digest: ACT_DIGEST });
    VN(`${cn} action other`, na, c.grant, c.chain, { now: NOW, action_digest: dg('b') });
    VN(`${cn} action missing`, na, c.grant, c.chain, { now: NOW });
    VN(`${cn} bound to root hop`, nar(c, [{ type: 'x' }], { cap_hash: capN(c, 0) }), c.grant, c.chain, nb);
    VN(`${cn} signed by rogue`, nar(c, [{ type: 'x' }], {}, rogue.sk), c.grant, c.chain, nb);
    VN(`${cn} holder rogue self-signed`, nar(c, [{ type: 'x' }], { holder: rogue.pub }, rogue.sk), c.grant, c.chain, nb);
    VN(`${cn} pq_pk without holder_pq`, { ...n, pq_pk: 'AAAA' }, c.grant, c.chain, nb);
    BC(`${cn}`, c.grant, c.chain);
    BC(`${cn} leaf as grant, no chain`, c.chain[c.chain.length - 1], undefined);
    DR(`${cn}`, c.grant, c.chain, ACT_DIGEST);
    DR(`${cn} no action digest`, c.grant, c.chain, undefined);
  }
  // boundCaveats over hostile grant / chain shapes
  const g = C3.grant;
  for (const [l, gr, ch] of [['grant null', null, undefined], ['grant string', 'x', undefined], ['grant no caveats', { ...g, caveats: undefined }, undefined], ['grant caveats object', { ...g, caveats: {} }, undefined],
    ['chain object', g, { 0: g }], ['chain string', g, 'x'], ['chain [null]', g, [null]], ['chain [5]', g, [5]], ['chain leaf caveats null', g, [g, { ...C3.chain[1], caveats: null }]],
    ['chain shorter caveat lists', g, [C3.chain[2], C3.chain[0]]], ['chain mid malformed', g, [g, { x: 1 }, C3.chain[2]]], ['chain junk caveat entries', g, [{ ...g, caveats: [5, null, 'x', [], { type: 1 }] }]]] as [string, unknown, unknown][]) {
    BC(l, gr, ch);
    DR(l, gr, ch, ACT_DIGEST);
  }
  // dischargeRequests skips malformed needs_discharge
  const bad = one([nd(), nd({ id: 'b', ttl_ms: 0 }), { type: 'needs_discharge' }, nd({ id: 'c', bind: 'action' })]);
  DR('mixed well/malformed', bad.grant, bad.chain, ACT_DIGEST);
  DR('mixed well/malformed, no digest', bad.grant, bad.chain, undefined);
}

// =====================================================================================================================
// evaluateK1 and the combined decision evaluateCaveatsK1 (same replay as gen-conformance-k1.mjs k1_eval)
// =====================================================================================================================
const K1 = (name: string, grant: unknown, chain: unknown, k1: unknown, ctx: unknown) => run('evaluateK1', name, pca.evaluateK1, [grant, chain, k1, ctx]);
function caveatsK1(grant: any, chain: any, k1: any, context: any) {
  const k = pca.evaluateK1(grant, chain, k1, { now: context.now, action: context.action });
  const stock = [...pca.policyCaveats(grant, chain).filter((x: any) => !pca.isK1Caveat(x)), ...k.plain];
  const s = pca.evaluateAgentCaveats(stock, { now: context.now, delegationDepth: context.delegation_depth, ...(context.recent_action_times ? { recentActionTimes: context.recent_action_times } : {}) }, { action: context.action });
  const failed = [...s.failed, ...k.failed].sort();
  return { allow: failed.length === 0, failed };
}
const CK = (name: string, grant: unknown, chain: unknown, k1: unknown, context: unknown) => run('evaluateCaveatsK1', name, caveatsK1, [grant, chain, k1, context]);
{
  const conf = JSON.parse(readFileSync(ROOT + 'packages/pca/conformance/caveat-lang-vectors.json', 'utf8'));
  for (const v of [...conf.primitives.k1_eval, ...conf.primitives.k1_unconfigured]) {
    const { grant, chain, k1, context } = v.input;
    K1('conf ' + v.name, grant, chain, k1, { now: context.now, ...(context.action !== undefined ? { action: context.action } : {}) });
    CK('conf ' + v.name, grant, chain, k1, context);
  }
  // seeded random chains of K1 + stock caveats, with discharges / narrow blocks / spiffe / history drawn per case
  const r = rng(0x4b31e7a1);
  const pool = (rr: any): any => rr.pick([
    nd(), nd({ id: 'b', issuer: 'acme', issuer_class: 'org', require: [] }), nd({ bind: 'action' }), nd({ ttl_ms: 0 }), nd({ issuer: 'runtime', issuer_class: 'workload', issuer_spiffe: SPIFFE, id: 'w', require: [] }),
    { type: 'sealed' }, { type: 'sealed', x: 1 },
    { type: 'max_uses', id: 'u', n: 2, until: NOW + 10 }, { type: 'max_uses', id: 'u', n: 2, until: NOW }, { type: 'max_uses', id: 'u', n: 0, until: NOW + 10 },
    { type: 'derive', id: 'g', defs: [{ name: 'a', kind: 'param', path: 'amount' }], check: { op: 'lte', a: { ref: 'a' }, b: { const: 50 } } },
    { type: 'derive', id: 'h', defs: [{ name: 'l', kind: 'claim', caveat_id: 'kyc', claim: 'kyc_level' }], check: { op: 'gte', a: { ref: 'l' }, b: { const: 3 } } },
    { type: 'derive', id: 'c', defs: [{ name: 'n', kind: 'count', window_ms: 60_000, verb: 'refund' }], check: { op: 'lt', a: { ref: 'n' }, b: { const: 2 } } },
    { type: 'derive', id: 'bad', defs: [], check: { op: 'nope' } },
    { type: 'spiffe_bound', spiffe_id: SPIFFE }, { type: 'spiffe_bound', spiffe_prefix: 'spiffe://acme.test/ns' }, { type: 'spiffe_bound' },
    { type: 'max_amount', max: 100 }, { type: 'expires_at', at: NOW + 10 },
  ]);
  for (let i = 0; i < 700; i++) {
    const nh = r.int(1, 3);
    const lists = Array.from({ length: nh }, (_, h) => Array.from({ length: r.int(h === 0 ? 0 : 0, 3) }, () => pool(r)));
    let c: any;
    try {
      c = nh === 1 ? one(lists[0]) : nh === 2 ? two(lists[0], lists[1]) : three(lists[0], lists[1], lists[2]);
    } catch { continue; }
    const k1: any = { pins: PINS };
    const ad = r.pick([ACT_DIGEST, dg('b'), undefined]);
    if (ad !== undefined) k1.action_digest = ad;
    const ds: any[] = [];
    for (let h = 0; h < nh; h++) if (r.next() < 0.5) ds.push(dis(capN(c, h), r.pick([{}, { bind: 'action', action_digest: ACT_DIGEST }, { caveat_id: 'b', issuer: 'acme', claims: {} }, { caveat_id: 'w', issuer: 'runtime', claims: {} }, { claims: { kyc_level: 1 } }, { iat: NOW - 600_000, not_after: NOW - 1 }])));
    if (ds.length || r.next() < 0.2) k1.discharges = r.next() < 0.1 ? [5, null, ...ds] : ds;
    if (r.next() < 0.3) k1.narrow = r.next() < 0.85 ? nar(c, Array.from({ length: r.int(1, 3) }, () => pool(r)).filter((x) => !['sealed'].includes(x.type)).concat([{ type: 'max_amount', max: 10 }])) : r.pick([null, 5, {}, nar(c, [{ type: 'x' }], {}, rogue.sk)]);
    if (r.next() < 0.4) k1.spiffe_id = r.pick([SPIFFE, 'spiffe://acme.test/ns', 'spiffe://acme.test/nsx', 'spiffe://acme.test/ns/a', 'spiffe://other']);
    if (r.next() < 0.4) k1.history = r.pick([[], [{ t: NOW - 1, verb: 'refund', resource: 'orders/42' }], [{ t: NOW - 1, verb: 'refund', resource: 'a' }, { t: NOW - 2, verb: 'refund', resource: 'b' }]]);
    if (r.next() < 0.1) k1.revoked_discharges = ds.map((x) => pca.dischargeDigest(x));
    const kin = r.next() < 0.07 ? undefined : k1;
    const action = ACTION(r.pick([10, 50, 51, 'x', undefined]));
    const now = r.pick([NOW, NOW, NOW, NOW + 10, NOW + 9, 2 ** 53]);
    K1(`rand ${i}`, c.grant, c.chain, kin, { now, action });
    if (Number.isSafeInteger(now)) CK(`rand ${i}`, c.grant, c.chain, kin, { now, delegation_depth: nh - 1, action });
  }
  // ids unique per type across chain + narrow; sealed placement
  const dupU = one([{ type: 'max_uses', id: 'u', n: 2, until: NOW + 10 }]);
  K1('max_uses id dup via narrow', dupU.grant, dupU.chain, { pins: PINS, narrow: nar(dupU, [{ type: 'max_uses', id: 'u', n: 1, until: NOW + 10 }]) }, { now: NOW });
  K1('max_uses same id other type', dupU.grant, dupU.chain, { pins: PINS, narrow: nar(dupU, [{ type: 'derive', id: 'u', defs: [], check: { const: true } }]) }, { now: NOW });
  for (const now of [NOW + 9, NOW + 10, NOW + 11]) K1(`max_uses until boundary ${now - NOW}`, dupU.grant, dupU.chain, { pins: PINS }, { now });
  const sealedMid = three([], [{ type: 'sealed' }], []);
  K1('sealed mid chain', sealedMid.grant, sealedMid.chain, {}, { now: NOW });
  const sealedLeaf = two([], [{ type: 'sealed' }]);
  K1('sealed leaf', sealedLeaf.grant, sealedLeaf.chain, {}, { now: NOW });
  K1('sealed leaf, chain omitted', sealedLeaf.chain[1], undefined, {}, { now: NOW });
  for (const [l, k1] of [['k1 null', null], ['k1 array', []], ['k1 string', 'x'], ['k1 {}', {}]] as [string, unknown][]) K1(l, sealedMid.grant, sealedMid.chain, k1, { now: NOW });
  // 0.5: only a plain object configures the caveat language. An empty array (PHP decodes {} and [] alike) is NOT `{}`:
  // under it a constant-true derive must still be refused (configured-empty would let it pass, widening authority).
  const constDerive = two([], [{ type: 'derive', id: 'g', defs: [], check: { const: true } }]);
  for (const [l, k1] of [['k1 array', []], ['k1 [{}]', [{}]], ['k1 null', null], ['k1 {}', {}]] as [string, unknown][]) {
    K1(`const derive, ${l}`, constDerive.grant, constDerive.chain, k1, { now: NOW });
    CK(`const derive, ${l}`, constDerive.grant, constDerive.chain, k1, { now: NOW, delegation_depth: 1 });
  }
  for (const [l, ctx] of [['ctx null', null], ['now missing', {}], ['now 1.5', { now: 1.5 }], ['now string', { now: '1' }], ['now 2^53', { now: 2 ** 53 }], ['now negative', { now: -5 }]] as [string, unknown][]) K1(l, C1.grant, C1.chain, { pins: PINS }, ctx);
  K1('malformed chain', { x: 1 }, undefined, {}, { now: NOW });
}

// =====================================================================================================================
// presentedK1 (request headers PCA-Discharges / PCA-Narrow)
// =====================================================================================================================
{
  const b = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
  const ref = (headers: unknown) => { try { return { ok: true, value: rq.presentedK1({ headers }) }; } catch { return { ok: false }; } };
  const KH = (name: string, headers: unknown) => run('presentedK1', name, ref, [headers]);
  const d1 = dis(CAP0);
  const vals: [string, string][] = [
    ['array', b([d1])], ['empty array', b([])], ['object', b({ a: 1 })], ['number', b('5')], ['null', b('null')], ['string', b('"x"')], ['empty', ''], ['bad b64', '!!!!'], ['padded', b([1]) + '=='],
    ['std alphabet', Buffer.from('[[[[?>>>]').toString('base64')], ['not json', b('not json')], ['dup keys', b('{"a":1,"a":2}')], ['float spelling', b('{"a":1.0}')], ['exp spelling', b('[1e2]')],
    ['neg zero', b('[-0]')], ['big int', b('[9007199254740993]')], ['lone surrogate escape', b('["\\ud800"]')], ['bad utf8', Buffer.from([0x5b, 0x22, 0xff, 0x22, 0x5d]).toString('base64url')], ['bom', b('﻿[1]')],
    ['trailing comma', b('[1,]')], ['whitespace', b(' [ 1 ] ')], ['nested deep', b('['.repeat(64) + ']'.repeat(64))], ['non-canonical b64 tail', b([1]).slice(0, -1) + (b([1]).endsWith('A') ? 'B' : 'A')],
  ];
  KH('none', {});
  for (const [l, v] of vals) { KH(`discharges ${l}`, { 'pca-discharges': v }); KH(`narrow ${l}`, { 'pca-narrow': v }); }
  KH('both', { 'pca-discharges': b([d1]), 'pca-narrow': b({ a: 1 }) });
  KH('case-insensitive', { 'PCA-Discharges': b([d1]), 'Pca-Narrow': b([1]) });
  KH('two spellings same value', { 'PCA-Discharges': b([1]), 'pca-discharges': b([1]) });
  KH('two spellings differ', { 'PCA-Discharges': b([1]), 'pca-discharges': b([2]) });
  KH('two spellings one empty', { 'PCA-Discharges': '', 'pca-discharges': b([2]) });
  KH('discharges bad, narrow ok', { 'pca-discharges': '!!', 'pca-narrow': b({ a: 1 }) });
  KH('other headers only', { 'x-pca-discharges': b([1]), 'pca-discharge': b([1]) });
}

O.write();
