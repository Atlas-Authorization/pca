// Oracle: @atlasauth/pca-intent intent statements (statement.ts over the core ext/intent): signIntent, verifyIntent, intentRef, intentGoal, parseIntentGoal. Ed25519 only;
// keys derive from fixed seeds; no clocks. A reason "malformed intent statement: ..." (the strict-canonical error text of the core encoder) is dropped from the corpus.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   signIntent(s, seedB64u)             IntentStatement.signIntent(s, seed bytes) -> signed statement (a throw requires a throw)
//   verifyIntent(s, opts)               IntentStatement.verifyIntent(s, opts.expectedSigner, opts.pqPins) -> {ok, reason?}
//   intentRef(s)                        IntentStatement.intentRef(s)
//   intentGoal(ref, mapDigest?)         IntentStatement.intentGoal(ref, mapDigest or null)
//   parseIntentGoal(goal)               IntentStatement.parseIntentGoal(goal) -> {intentRef, mapDigest?} or null
import * as S0 from '../../../packages/pca-intent/src/statement';
import { Oracle, refWrite, seed } from './lib.mjs';
import { sha256 } from '@noble/hashes/sha2';

const S: any = (S0 as any).default ?? S0;
const o = new Oracle('intent-statement', 'tools/pca-audit/oracles/intent-statement.mts', 'TS-reference oracle for intent statements.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const runKeep = async (fn: string, f: any, args: any[]) => { try { const r = f(...JSON.parse(JSON.stringify(args))); if (JSON.stringify(r)?.includes('malformed intent statement')) return; } catch {} await run(fn, f, args); };
const SEED_A = Buffer.from(seed('intent-statement/a')).toString('base64url');
const SEED_B = Buffer.from(seed('intent-statement/b')).toString('base64url');
const unseed = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const dig = (x: string) => Buffer.from(sha256(new TextEncoder().encode(x))).toString('base64url');
const signAs = (s: any, sd: string) => S.signIntent(s, unseed(sd));

const slots = { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', op: 'lte', value: 100 }] };
const base = { v: 1, text: 'refund up to 100 to bob', slots, sources: [{ kind: 'conversation', digest: dig('t1'), uri: 'https://x/1' }], created_at: 1_800_000_000_000, nonce: 'n-1' };
const stmts: any[] = [base, { ...base, sources: [] }, { ...base, text: 'é中😀' }, { ...base, created_at: 0 }, { ...base, created_at: 9007199254740991 },
  { ...base, sources: [{ kind: 'ticket', digest: dig('a') }, { kind: 'document', digest: dig('b') }, { kind: 'form', digest: dig('c') }, { kind: 'other', digest: dig('d') }] },
  { ...base, slots: {} }, { ...base, slots: { verbs: [], constraints: [], nested: { a: [1, 2, { b: null }] } } }, { ...base, nonce: 'x'.repeat(200) }];
const bads: any[] = [{ ...base, v: 2 }, { ...base, v: '1' }, { ...base, text: '' }, { ...base, text: 5 }, { ...base, slots: [] }, { ...base, slots: null }, { ...base, sources: 'x' }, { ...base, sources: [5] },
  { ...base, sources: [{ kind: 'weird', digest: dig('x') }] }, { ...base, sources: [{ kind: 'form', digest: 'short' }] }, { ...base, sources: [{ kind: 'form', digest: dig('x'), uri: 5 }] }, { ...base, sources: [{ kind: 'form', digest: dig('x'), uri: null }] },
  { ...base, created_at: -1 }, { ...base, created_at: 1.5 }, { ...base, created_at: '5' }, { ...base, created_at: 9007199254740992 }, { ...base, nonce: '' }, { ...base, nonce: 5 }, { ...base, slots: { x: 1.5 } },
  { ...base, principal: 'AAAA' }, { ...base, principal: dig('other') }, { ...base, principal: null }, { text: 'x' }, {}];
for (const sd of [SEED_A, SEED_B]) for (const s of [...stmts, ...bads]) await runKeep('signIntent', (st: any, k: string) => signAs(st, k), [s, sd]);
const pubA = signAs(base, SEED_A).principal;
await runKeep('signIntent', (st: any, k: string) => signAs(st, k), [{ ...base, principal: pubA }, SEED_A]);
await runKeep('signIntent', (st: any, k: string) => signAs(st, k), [{ ...base, principal: pubA }, SEED_B]);
await runKeep('signIntent', (st: any, k: string) => signAs(st, k), [{ ...base, extra: 'ignored', alg: 'x', sig: 'y' }, SEED_A]);

// ---- verify ----
const sig = signAs(base, SEED_A);
const sigB = signAs(base, SEED_B);
const vcases: any[] = [sig, sigB, ...stmts.map((s) => signAs(s, SEED_A)), { ...sig, sig: sigB.sig }, { ...sig, sig: 5 }, { ...sig, sig: 'AAAA' }, { ...sig, sig: undefined }, { ...sig, text: 'tampered' }, { ...sig, nonce: 'n-2' }, { ...sig, slots: {} },
  { ...sig, principal: sigB.principal }, { ...sig, alg: 'ed25519' }, { ...sig, alg: 'ml-dsa-65' }, { ...sig, alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'AAAA', pq_sig: 'AAAA' }, { ...sig, alg: 'nope' }, { ...sig, alg: 5 }, { ...sig, alg: null },
  { ...sig, pq_pk: 'x' }, { ...sig, pq_sig: 'x' }, { ...sig, alg: 'ed25519', pq_sig: 'x' }, { ...sig, extra: 1 }, null, 5, 'x', [], {}, ...bads];
for (const c of vcases) {
  await runKeep('verifyIntent', S.verifyIntent, [c, {}]);
  await runKeep('verifyIntent', S.verifyIntent, [c, { expectedSigner: pubA }]);
}
await runKeep('verifyIntent', S.verifyIntent, [sigB, { expectedSigner: pubA }]);
await runKeep('verifyIntent', S.verifyIntent, [{ ...sig, alg: 'ml-dsa-65', pq_pk: 'AAAA' }, { pqPins: { [pubA]: 'AAAA' } }]);
await runKeep('verifyIntent', S.verifyIntent, [{ ...sig, alg: 'ml-dsa-65', pq_pk: 'AAAA', pq_sig: 'AAAA' }, { pqPins: {} }]);

// ---- ref / goal ----
for (const s of [sig, sigB, ...stmts.map((x) => signAs(x, SEED_A)), base, { ...sig, sig: 'zzz', alg: 'a' }, { ...sig, extra: 1 }, { ...sig, slots: { x: 1.5 } }]) await runKeep('intentRef', S.intentRef, [s]);
const refA = S.intentRef(sig);
for (const [r, m] of [[refA, undefined], [refA, dig('m')], [refA, ''], ['', undefined], ['a:b', 'c'], [refA, 'x:y']] as any[]) await run('intentGoal', S.intentGoal, m === undefined ? [r] : [r, m]);
for (const g of [S.intentGoal(refA), S.intentGoal(refA, dig('m')), 'pca-intent:v1:', 'pca-intent:v1::x', 'pca-intent:v1:a:b:c', 'pca-intent:v1:a:', 'pca-intent:v1:a::', 'pca-intent:v1:a:b:', 'pca-intent:v2:a', 'x', '', 5, null, undefined, 'pca-intent:v1:a:b']) await run('parseIntentGoal', S.parseIntentGoal, [g]);
refWrite(o, 'intent-statement');
