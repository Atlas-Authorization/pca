// k05 oracle: leases and break-glass grants (Java Lease / BreakGlass and every native port). TS reference:
// packages/pca-grants/src/lease.ts, packages/pca-grants/src/breakglass.ts. Extends conformance/lease-vectors.json and
// break-glass-vectors.json with: every record member retyped / deleted / bounded, both UNSIGNED (the signature fails) and RE-SIGNED by
// the authority (so the shape check alone decides), separation-of-duties over policy x chain x approver lists, and registry walks
// (hand-written scenarios plus seeded random walks over a record pool) replayed on a fresh registry.
// Writes tools/pca-audit/k05-oracles/out/k05-grants.json.gz. Deterministic.
// PORTING (fn -> Java). Compare by JSON value.
//   verifyLease(rec) / verifyLeaseRevocation(rec)           Lease.verify / Lease.verifyRevocation
//   verifyBreakGlass(rec) / verifyBreakGlassReview(rec)     BreakGlass.verify / BreakGlass.verifyReview
//   sodError(lease, policy, chain)                          Lease.sodError(lease, policy{minApprovals, eligibleApprovers}, chain)
//   leaseWalk(policy, steps) -> list                        a fresh Lease.Registry(policy{authorities, minApprovals?, eligibleApprovers?,
//                                                           freshJustification?}); each step {op: accept, rec, chain} -> {ok, replaced, seq} |
//                                                           {ok:false, code}; {op: revoke, rec} -> {ok, revoked} | {ok:false, code};
//                                                           {op: check, rec, now} -> {decision, lease_id?, expires_at?, code?}
//   bgWalk(policy, steps) -> list                           a fresh BreakGlass.Registry(authorities, reviewers); steps accept(rec, now) /
//                                                           use(id, holder, action_digest, now, notified) / review(rec, holder, now) /
//                                                           frozen(holder, now) -> the registry's result map (frozen: a boolean)
import * as GL from '../../../packages/pca-grants/src/lease.ts';
import * as GB from '../../../packages/pca-grants/src/breakglass.ts';
import { signBody as signDomainBody } from '../../../packages/pca-grants/src/sig.ts';
const G = { ...GL, ...GB };
import { b64u } from '../../../packages/pca/src/hash.ts';
import { publicKeyOf } from '../../../packages/pca/src/keys.ts';
import { Oracle, variants, rng, ser } from './lib.mjs';

const o = new Oracle('grants', 'tools/pca-audit/k05-oracles/grants-oracle.mts', 'TS-reference oracle for leases and break-glass grants: record shapes (unsigned and re-signed), separation of duties, registry walks.');
const pk = (s: Uint8Array) => b64u(publicKeyOf(s));
const AUTH = new Uint8Array(32).fill(81);
const ROGUE = new Uint8Array(32).fill(82);
const REV = new Uint8Array(32).fill(83);
const AK = pk(AUTH), RK = pk(ROGUE), VK = pk(REV);
const T0 = 1_800_000_000_000;
const isPlain = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);

// ---- lease shapes ----
const LBODY = ['v', 'lease_id', 'path', 'grant_ref', 'holder', 'requester', 'approvers', 'justification_digest', 'seq', 'issued_at', 'renewed_at', 'expires_at', 'max_ttl', 'authority'];
const resign = (dom: string, keys: string[], r: unknown, sk = AUTH): unknown => {
  if (!isPlain(r)) return r;
  const body = Object.fromEntries(keys.map((k) => [k, r[k]]));
  try { return { ...r, sig: signDomainBody(dom, body, sk) }; } catch { return r; }
};
const BASE_L = { lease_id: 'L1', path: 'db/prod/ro', grant_ref: 'g1', holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 600, max_ttl: 1000 };
const L0 = G.signLease(AUTH, BASE_L);
const vl = (n: string, r: unknown) => o.run('verifyLease', n, G.verifyLease, [r]);
await vl('base', L0);
const LENS = [1, 64, 65, 127, 128, 129, 255, 256, 257];
for (const [n, v] of variants(L0, { lens: LENS })) {
  await vl('unsigned' + n, v);
  if (!n.startsWith('/sig')) await vl('re-signed' + n, resign(G.LEASE_DOMAIN, LBODY, v));
}
const lpatch = (n: string, patch: Record<string, unknown>) => vl('patch ' + n, resign(G.LEASE_DOMAIN, LBODY, { ...L0, ...patch }));
for (const p of ['a', 'db', 'db/prod', 'a/b/c/d/e/f/g/h', 'a/b/c/d/e/f/g/h/i', 'x'.repeat(64), 'x'.repeat(65), 'db//x', '/db', 'db/', 'DB', 'db prod', 'a.b-c_d', ''])
  await lpatch(`path ${ser(p)}`, { path: p });
for (const [n, p] of [
  ['seq 2 renewed later', { seq: 2, renewed_at: T0 + 1 }], ['seq 2 renewed = issued', { seq: 2 }], ['seq 1 renewed later', { renewed_at: T0 + 1 }],
  ['seq 0', { seq: 0 }], ['renewed before issue', { seq: 2, renewed_at: T0 - 1 }], ['expires = renewed', { expires_at: T0 }], ['expires = renewed + 1', { expires_at: T0 + 1 }],
  ['max_ttl 0', { max_ttl: 0 }], ['max_ttl 1', { max_ttl: 1 }], ['over cap still verifies', { expires_at: T0 + 5000 }], ['issued 0', { issued_at: 0, renewed_at: 0, expires_at: 1 }],
  ['approvers 16', { approvers: Array.from({ length: 16 }, (_, i) => `a${i}`) }], ['approvers 17', { approvers: Array.from({ length: 17 }, (_, i) => `a${i}`) }], ['approvers empty', { approvers: [] }],
  ['approver empty string', { approvers: [''] }], ['approver 128', { approvers: ['a'.repeat(128)] }], ['approver 129', { approvers: ['a'.repeat(129)] }], ['approver number', { approvers: [1] }],
  ['v 2', { v: 2 }], ['v 1.0 string', { v: '1' }], ['extra member', { extra: 1 }],
] as [string, Record<string, unknown>][]) await lpatch(n, p);
await vl('signed by another key, authority claims AUTH', resign(G.LEASE_DOMAIN, LBODY, L0, ROGUE));
await vl('signed under the revoke domain', resign(G.LEASE_REVOKE_DOMAIN, LBODY, L0));

const RVBODY = ['v', 'target', 'value', 'revoked_at', 'authority'];
const R0 = G.signLeaseRevocation(AUTH, { target: 'prefix', value: 'db/prod', revoked_at: T0 });
const vr = (n: string, r: unknown) => o.run('verifyLeaseRevocation', n, G.verifyLeaseRevocation, [r]);
await vr('base', R0);
for (const base of [R0, G.signLeaseRevocation(AUTH, { target: 'lease', value: 'L1', revoked_at: T0 }), G.signLeaseRevocation(AUTH, { target: 'grant', value: 'g1', revoked_at: T0 })])
  for (const [n, v] of variants(base, { lens: LENS })) {
    await vr(`${base.target} unsigned${n}`, v);
    if (!n.startsWith('/sig')) await vr(`${base.target} re-signed${n}`, resign(G.LEASE_REVOKE_DOMAIN, RVBODY, v));
  }
for (const t of ['lease', 'prefix', 'grant', 'Lease', 'path', ''])
  for (const v of ['L1', 'db/prod', 'db//x', 'UP', 'x'.repeat(256), 'x'.repeat(257)])
    await vr(`target ${t} value ${v.length > 20 ? v.length : v}`, resign(G.LEASE_REVOKE_DOMAIN, RVBODY, { ...R0, target: t, value: v }));

// ---- separation of duties ----
const sod = (n: string, l: unknown, p: unknown, chain: unknown) => o.run('sodError', n, (a: never, b: never, c: never) => G.sodError(a, b, c), [l, p, chain]);
const APPS: string[][] = [[], ['bob'], ['bob', 'carol'], ['bob', 'bob'], ['alice'], ['agent'], ['bob', 'alice'], ['carol', 'agent'], ['dave'], ['bob', 'dave', 'carol']];
const POLS: Record<string, unknown>[] = [{}, { minApprovals: 1 }, { minApprovals: 2 }, { minApprovals: 3 }, { minApprovals: 0 }, { minApprovals: -1 }, { minApprovals: 2 ** 53 - 1 }, { minApprovals: 2 ** 53 }, { eligibleApprovers: ['bob', 'carol'] }, { eligibleApprovers: [] }, { minApprovals: 2, eligibleApprovers: ['bob', 'carol', 'dave'] }];
const CHAINS: string[][] = [[], ['carol'], ['dave', 'bob'], ['x']];
for (const a of APPS) for (const [i, p] of POLS.entries()) for (const c of CHAINS)
  await sod(`approvers ${ser(a)} policy ${i} chain ${ser(c)}`, { ...BASE_L, approvers: a }, p, c);

// ---- lease registry walks ----
type Step = Record<string, unknown>;
const lstrip = (r: Record<string, unknown>) => { const { reason: _r, ...rest } = r; return rest; };
async function leaseWalk(policy: Record<string, unknown>, steps: Step[]) {
  const reg = new G.LeaseRegistry({ authorities: policy.authorities as string[], ...(policy.minApprovals !== undefined ? { minApprovals: policy.minApprovals as number } : {}), ...(policy.eligibleApprovers !== undefined ? { eligibleApprovers: policy.eligibleApprovers as string[] } : {}), ...(policy.freshJustification !== undefined ? { freshJustification: policy.freshJustification as boolean } : {}) }, G.memoryLeaseKv());
  const out: unknown[] = [];
  for (const s of steps) {
    if (s.op === 'accept') out.push(lstrip(await reg.accept(s.rec, (s.chain as string[]) ?? [])));
    else if (s.op === 'revoke') out.push(await reg.revoke(s.rec));
    else out.push(await G.checkLease(s.rec, reg, s.now as number));
  }
  return out;
}
const lw = (n: string, policy: Record<string, unknown>, steps: Step[]) => o.run('leaseWalk', n, leaseWalk, [policy, steps]);
const L = (over: Record<string, unknown> = {}, sk = AUTH) => G.signLeaseUnsafeOverCap(sk, { ...BASE_L, ...over } as never);
const renew = (seq: number, at: number, exp: number, j: string, over: Record<string, unknown> = {}) => L({ seq, renewed_at: at, expires_at: exp, justification_digest: j, ...over });
const RV = (target: 'lease' | 'prefix' | 'grant', value: string, at: number, sk = AUTH) => G.signLeaseRevocation(sk, { target, value, revoked_at: at });
const POOL_L = [
  L(), renew(2, T0 + 300, T0 + 900, 'j2'), renew(2, T0 + 300, T0 + 900, 'j1'), renew(3, T0 + 899, T0 + 1000, 'j3'), renew(2, T0 + 300, T0 + 950, 'j9'),
  renew(2, T0 + 300, T0 + 900, 'j2', { holder: 'other' }), renew(2, T0 + 300, T0 + 900, 'j2', { path: 'db/prod' }), renew(2, T0 + 300, T0 + 900, 'j2', { grant_ref: 'g2' }),
  renew(2, T0 + 300, T0 + 900, 'j2', { requester: 'zed' }), renew(2, T0 + 300, T0 + 900, 'j2', { max_ttl: 2000 }), renew(2, T0 + 300, T0 + 900, 'j2', { issued_at: T0 - 1, renewed_at: T0 + 300 }),
  renew(2, T0 + 600, T0 + 900, 'j2'), renew(2, T0 + 599, T0 + 900, 'j2'), renew(2, T0 + 300, T0 + 600, 'j2'), renew(2, T0 + 300, T0 + 601, 'j2'), renew(2, T0 - 0, T0 + 700, 'j2'),
  renew(3, T0 + 300, T0 + 900, 'j3'), renew(4, T0 + 300, T0 + 900, 'j4'), renew(2, T0 + 300, T0 + 1001, 'j2'), renew(2, T0 + 300, T0 + 1000, 'j2'),
  L({}, ROGUE), L({ lease_id: 'L2', path: 'db/prod' }), L({ lease_id: 'L3', path: 'db/production' }), L({ lease_id: 'L4', grant_ref: 'g2', path: 'kv/a' }), L({ lease_id: 'L5', issued_at: T0 + 10, renewed_at: T0 + 10, expires_at: T0 + 500 }),
  L({ approvers: ['alice'] }), L({ approvers: [] }), L({ lease_id: 'L6', seq: 2, renewed_at: T0 + 1 }), { ...L(), expires_at: T0 + 700 }, L({ approvers: ['bob', 'carol'] }), L({ expires_at: T0 + 1000 }), L({ expires_at: T0 + 1001 }),
];
const POOL_R = [RV('lease', 'L1', T0 + 10), RV('prefix', 'db/prod', T0), RV('prefix', 'db', T0 - 1), RV('grant', 'g1', T0), RV('grant', 'g2', T0 + 20), RV('prefix', 'db/prod/ro/x', T0 + 50), RV('lease', 'L1', T0 + 10, ROGUE), RV('prefix', 'kv', T0 + 9), RV('lease', 'L5', T0 + 9), RV('lease', 'L5', T0 + 10)];
const NOWS = [T0 - 1, T0, T0 + 9, T0 + 10, T0 + 299, T0 + 300, T0 + 599, T0 + 600, T0 + 601, T0 + 899, T0 + 900, T0 + 999, T0 + 1000, T0 + 1001, -1, 1.5];
const POL_L = [{ authorities: [AK] }, { authorities: [AK], minApprovals: 2 }, { authorities: [AK], freshJustification: false }, { authorities: [AK], eligibleApprovers: ['bob'] }, { authorities: [AK, RK] }, { authorities: [] }];
// hand-written walks
const acc = (i: number, chain?: string[]) => ({ op: 'accept', rec: POOL_L[i], ...(chain ? { chain } : {}) });
const chk = (i: number, now: number) => ({ op: 'check', rec: POOL_L[i], now });
const rvk = (i: number) => ({ op: 'revoke', rec: POOL_R[i] });
for (const [pi, pol] of POL_L.entries()) {
  for (let i = 0; i < POOL_L.length; i++) await lw(`pol ${pi} issue+renew ${i}`, pol, [acc(0), acc(i), acc(i), chk(0, T0 + 100), chk(i, T0 + 350), chk(i, T0 + 950)]);
  for (let r = 0; r < POOL_R.length; r++) await lw(`pol ${pi} revoke ${r}`, pol, [acc(0), acc(21), acc(22), acc(23), acc(24), rvk(r), rvk(r), chk(0, T0 + 100), chk(21, T0 + 100), chk(22, T0 + 100), chk(23, T0 + 100), chk(24, T0 + 100), acc(1), acc(24)]);
  for (const now of NOWS) await lw(`pol ${pi} check at ${now - T0}`, pol, [acc(0), chk(0, now), acc(1), chk(1, now), chk(0, now), acc(3), chk(3, now)]);
}
await lw('chain blocks an approver', POL_L[0], [acc(0, ['bob']), acc(0, ['carol']), acc(29, ['carol'])]);
await lw('unknown lease and bad inputs', POL_L[0], [chk(0, T0), { op: 'check', rec: null, now: T0 }, { op: 'check', rec: POOL_L[28], now: T0 }, { op: 'accept', rec: 'x' }, { op: 'revoke', rec: { ...POOL_R[0], value: 'L2' } }]);
// seeded random walks over the pools
const rnd = rng(0x1ea5e);
for (let w = 0; w < 400; w++) {
  const steps: Step[] = [];
  for (let k = 0; k < 10; k++) {
    const x = rnd.next();
    if (x < 0.5) steps.push(acc(rnd.int(0, POOL_L.length - 1), rnd.next() < 0.2 ? [rnd.pick(['bob', 'carol', 'x'])] : undefined));
    else if (x < 0.65) steps.push(rvk(rnd.int(0, POOL_R.length - 1)));
    else steps.push(chk(rnd.int(0, POOL_L.length - 1), rnd.pick(NOWS)));
  }
  await lw(`walk ${w}`, rnd.pick(POL_L), steps);
}

// ---- break-glass shapes ----
const BGBODY = ['v', 'id', 'holder', 'grant_ref', 'reason_digest', 'max_uses', 'issued_at', 'expires_at', 'review_within', 'notify_to', 'authority'];
const RWBODY = ['v', 'id', 'outcome', 'notes_digest', 'at', 'reviewer'];
// holders whose shards (of 16) differ, so a holder's state never shares a shard with another's (the Java registry keys by holder)
const HOLDERS: string[] = [];
for (let i = 0; HOLDERS.length < 3; i++) { const h = `holder-${i}`; if (!HOLDERS.some((x) => G.shardOf(x, 16) === G.shardOf(h, 16))) HOLDERS.push(h); }
const [H1, H2, H3] = HOLDERS as [string, string, string];
const BASE_B = { id: 'bg1', holder: H1, grant_ref: 'g1', reason_digest: 'r1', max_uses: 2, issued_at: T0, expires_at: T0 + 1000, review_within: 500, notify_to: 'oncall' };
const B0 = G.signBreakGlass(AUTH, BASE_B);
const vb = (n: string, r: unknown) => o.run('verifyBreakGlass', n, G.verifyBreakGlass, [r]);
await vb('base', B0);
for (const [n, v] of variants(B0, { lens: LENS })) {
  await vb('unsigned' + n, v);
  if (!n.startsWith('/sig')) await vb('re-signed' + n, resign(G.BREAK_GLASS_DOMAIN, BGBODY, v));
}
for (const [n, p] of [
  ['max_uses 0', { max_uses: 0 }], ['max_uses 1', { max_uses: 1 }], ['max_uses 16', { max_uses: 16 }], ['max_uses 17', { max_uses: 17 }],
  ['window 0', { expires_at: T0 }], ['window 1', { expires_at: T0 + 1 }], ['window 24h', { expires_at: T0 + 86_400_000 }], ['window 24h+1', { expires_at: T0 + 86_400_001 }], ['expires before issue', { expires_at: T0 - 1 }],
  ['review 0', { review_within: 0 }], ['review 1', { review_within: 1 }], ['review 30d', { review_within: 30 * 86_400_000 }], ['review 30d+1', { review_within: 30 * 86_400_000 + 1 }],
  ['issued 0', { issued_at: 0, expires_at: 5 }], ['notify 256', { notify_to: 'n'.repeat(256) }], ['notify 257', { notify_to: 'n'.repeat(257) }], ['grant_ref 256', { grant_ref: 'g'.repeat(256) }], ['grant_ref 257', { grant_ref: 'g'.repeat(257) }],
  ['v 2', { v: 2 }], ['extra', { extra: true }],
] as [string, Record<string, unknown>][]) await vb('patch ' + n, resign(G.BREAK_GLASS_DOMAIN, BGBODY, { ...B0, ...p }));
await vb('signed by another key', resign(G.BREAK_GLASS_DOMAIN, BGBODY, B0, ROGUE));
await vb('review domain', resign(G.BREAK_GLASS_REVIEW_DOMAIN, BGBODY, B0));
const W0 = G.signBreakGlassReview(REV, { id: 'bg1', outcome: 'justified', notes_digest: 'n1', at: T0 + 10 });
const vw = (n: string, r: unknown) => o.run('verifyBreakGlassReview', n, G.verifyBreakGlassReview, [r]);
await vw('base', W0);
for (const [n, v] of variants(W0, { lens: LENS })) {
  await vw('unsigned' + n, v);
  if (!n.startsWith('/sig')) await vw('re-signed' + n, resign(G.BREAK_GLASS_REVIEW_DOMAIN, RWBODY, v, REV));
}
for (const oc of ['justified', 'unjustified', 'Justified', '', 'ok']) await vw(`outcome ${oc}`, resign(G.BREAK_GLASS_REVIEW_DOMAIN, RWBODY, { ...W0, outcome: oc }, REV));

// ---- break-glass registry walks ----
async function bgWalk(policy: Record<string, unknown>, steps: Step[]) {
  const reg = new G.BreakGlassRegistry({ authorities: policy.authorities as string[], reviewers: policy.reviewers as string[] }, G.memoryLeaseKv());
  const out: unknown[] = [];
  for (const s of steps) {
    if (s.op === 'accept') out.push(await reg.accept(s.rec, s.now as number));
    else if (s.op === 'use') out.push(await reg.use({ id: s.id, holder: s.holder, action_digest: s.action_digest, now: s.now, notified: s.notified } as never));
    else if (s.op === 'review') out.push(await reg.review(s.rec, s.holder as string, s.now as number));
    else out.push(await reg.frozen(s.holder as string, s.now as number));
  }
  return out;
}
const bw = (n: string, policy: Record<string, unknown>, steps: Step[]) => o.run('bgWalk', n, bgWalk, [policy, steps]);
const B = (over: Record<string, unknown> = {}, sk = AUTH) => G.signBreakGlass(sk, { ...BASE_B, ...over } as never);
const W = (over: Record<string, unknown> = {}, sk = REV) => G.signBreakGlassReview(sk, { id: 'bg1', outcome: 'justified', notes_digest: 'n1', at: T0 + 10, ...over } as never);
const POOL_B = [B(), B({ id: 'bg2' }), B({ id: 'bg1', reason_digest: 'other' }), B({ holder: H2 }), B({ id: 'bg3', holder: H2, max_uses: 1 }), B({}, ROGUE), B({ id: 'bg4', issued_at: T0 + 100, expires_at: T0 + 200 }), B({ id: 'bg5', max_uses: 16, review_within: 1 }), B({ id: 'bg6', holder: H3 })];
const POOL_W = [W(), W({ outcome: 'unjustified' }), W({ at: T0 - 1 }), W({ at: T0 + 2000 }), W({ id: 'bg2' }), W({ id: 'bg3', at: T0 + 20 }), W({}, AUTH), W({ notes_digest: 'n2' }), W({ id: 'bg5', outcome: 'unjustified', at: T0 + 30 })];
const POL_B = [{ authorities: [AK], reviewers: [VK] }, { authorities: [AK], reviewers: [VK, AK] }, { authorities: [], reviewers: [VK] }, { authorities: [AK], reviewers: [] }];
const bacc = (i: number, now = T0) => ({ op: 'accept', rec: POOL_B[i], now });
const buse = (id: string, holder: string, now: number, notified: unknown = true, ad: unknown = 'act') => ({ op: 'use', id, holder, action_digest: ad, now, notified });
const brev = (i: number, holder: string, now: number) => ({ op: 'review', rec: POOL_W[i], holder, now });
const bfz = (holder: unknown, now: unknown) => ({ op: 'frozen', holder, now });
const BNOWS = [T0 - 1, T0, T0 + 10, T0 + 99, T0 + 100, T0 + 199, T0 + 200, T0 + 509, T0 + 510, T0 + 511, T0 + 999, T0 + 1000, T0 + 2000];
for (const [pi, pol] of POL_B.entries()) {
  for (let i = 0; i < POOL_B.length; i++) await bw(`pol ${pi} accept ${i}`, pol, [bacc(0), bacc(i), bacc(i, T0 + 600), bfz(H1, T0), bfz(H2, T0)]);
  for (const now of BNOWS) await bw(`pol ${pi} use at ${now - T0}`, pol, [bacc(0), bacc(6), buse('bg1', H1, now), buse('bg4', H1, now), buse('bg1', H1, now), buse('bg1', H1, now), bfz(H1, now), bfz(H1, now + 500)]);
  for (let w = 0; w < POOL_W.length; w++) for (const now of [T0 + 10, T0 + 20, T0 + 30, T0 + 600, T0 + 2000])
    await bw(`pol ${pi} review ${w} at ${now - T0}`, pol, [bacc(0), bacc(1), bacc(7), buse('bg1', H1, T0 + 10), buse('bg5', H1, T0 + 10), brev(w, H1, now), brev(w, H1, now), brev(w, H2, now), bfz(H1, now), buse('bg1', H1, now), buse('bg2', H1, now), bacc(4, now), bfz(H1, T0 + 10)]);
}
for (const [n, s] of [
  ['use not notified', buse('bg1', H1, T0 + 10, false)], ['use notified string', buse('bg1', H1, T0 + 10, 'true')], ['use id empty', buse('', H1, T0)], ['use id 129', buse('x'.repeat(129), H1, T0)],
  ['use holder 129', buse('bg1', 'h'.repeat(129), T0)], ['use action empty', buse('bg1', H1, T0, true, '')], ['use action 129', buse('bg1', H1, T0, true, 'a'.repeat(129))], ['use now -1', buse('bg1', H1, -1)],
  ['use now 1.5', buse('bg1', H1, 1.5)], ['use other holder', buse('bg1', H2, T0 + 10)], ['frozen bad holder', bfz('', T0)], ['frozen bad now', bfz(H1, -1)], ['frozen holder 129', bfz('h'.repeat(129), T0)],
  ['review holder empty', { op: 'review', rec: POOL_W[0], holder: '', now: T0 + 20 }], ['review now -1', { op: 'review', rec: POOL_W[0], holder: H1, now: -1 }], ['accept now -1', { op: 'accept', rec: POOL_B[0], now: -1 }],
  ['accept junk', { op: 'accept', rec: { ...POOL_B[0], max_uses: 3 }, now: T0 }], ['review junk', { op: 'review', rec: { ...POOL_W[0], at: T0 + 11 }, holder: H1, now: T0 + 20 }],
] as [string, Step][]) await bw('edge ' + n, POL_B[0], [bacc(0), buse('bg1', H1, T0 + 5), s, bfz(H1, T0 + 5)]);
// the holder freeze: an overdue review blocks every grant of the holder (not others'), a late review lifts it, unjustified is for good
await bw('freeze across grants', POL_B[0], [bacc(0), bacc(1), bacc(8), buse('bg1', H1, T0 + 10), buse('bg2', H1, T0 + 509), buse('bg2', H1, T0 + 510), buse('bg6', H3, T0 + 510), bacc(4, T0 + 510), bfz(H1, T0 + 509), bfz(H1, T0 + 510), bfz(H3, T0 + 510),
  brev(0, H1, T0 + 520), bfz(H1, T0 + 520), buse('bg2', H1, T0 + 520), brev(1, H1, T0 + 530), buse('bg2', H1, T0 + 530)]);
await bw('unjustified freezes for good', POL_B[0], [bacc(0), bacc(1), buse('bg1', H1, T0 + 10), brev(1, H1, T0 + 20), bfz(H1, T0 + 20), buse('bg1', H1, T0 + 20), buse('bg2', H1, T0 + 20), bacc(4, T0 + 20)]);
const rnd2 = rng(0xb9a55);
for (let w = 0; w < 400; w++) {
  const steps: Step[] = [];
  for (let k = 0; k < 10; k++) {
    const x = rnd2.next();
    const h = rnd2.pick([H1, H1, H2, H3]);
    const now = rnd2.pick(BNOWS);
    if (x < 0.3) steps.push(bacc(rnd2.int(0, POOL_B.length - 1), now));
    else if (x < 0.65) steps.push(buse(rnd2.pick(['bg1', 'bg2', 'bg3', 'bg4', 'bg5', 'bg6']), h, now, rnd2.next() < 0.9));
    else if (x < 0.85) steps.push(brev(rnd2.int(0, POOL_W.length - 1), h, now));
    else steps.push(bfz(h, now));
  }
  await bw(`walk ${w}`, rnd2.pick(POL_B), steps);
}
o.write();
