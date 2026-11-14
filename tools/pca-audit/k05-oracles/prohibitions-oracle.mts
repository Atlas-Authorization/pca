// k05 oracle: the prohibition engine (Kotlin Prohibitions and every native port). TS reference: packages/pca/src/prohibitions.ts.
// Extends conformance/prohibition-vectors.json with generated, boundary-heavy inputs: every invariant kind x every limit (ids, keys,
// ledger sizes, windows, thresholds), every state / action / constitution member retyped or deleted, the cap / rate / never_after /
// require_prior / require_approval_over grids around their exact boundaries (window edges, max, threshold), descriptions of every JSON
// type, advance transitions (pruning, latches, ledger merge / overflow, hash chain), evidence + signed evidence (forged, re-bound,
// retyped), check-and-advance guards.
// Writes tools/pca-audit/k05-oracles/out/k05-prohibitions.json.gz. Deterministic (Ed25519 is deterministic).
// Cases whose name starts with `x:` hold a value the canonical hash refuses (-0, |n| > 2^53-1, lone surrogates): natives replay them
// in a separate test so a divergence there stays visible on its own.
// PORTING (fn -> Kotlin; other natives use their twin). Secrets are args as base64url of the 32-byte Ed25519 seed.
//   validateInvariant(inv) / validateConstitution(c)      exact string[]
//   stateProblem(s) / stateDigest(s) / canonicalState(s)  exact string|null / digest / canonical JSON; {$throws} -> must throw
//   tickState(s, now)                                      canonical JSON ({ok, state} | {ok:false, reason})
//   checkProhibitions(action, c, s)                        canonical JSON of {ok, violated, reasons, evaluated}
//   advanceStateStrict(action, c, s [, now])               canonical JSON ({ok, state} | {ok:false, reason}); the 4th arg is absent, or present (null included: a clock regression)
//   proveSafety(action, c, s)                              canonical JSON of the evidence
//   verifySafetyEvidence(ev, action, c, s)                 null (ok) or the exact reason
//   safetyBindingId(ev, signer) / signSafetyEvidence(ev, sk, signerPublic)   exact id / canonical JSON; {$throws} -> must throw
//   verifySignedSafetyEvidence(signed, expected)           null (ok) or the exact reason
//   checkAndAdvance(permitted, action, c, s [, opts])      canonical JSON; opts.expectedSeq is absent or present (null included: a stale head); expectedStateDigest is absent or a string
//   verifyConstitution(sc [, principal])                   null (ok) or the exact reason (principal absent or a string)
//   constitutionId(c) (objects only) / emptyState(now) / whenAffirmative(w, ctx) (ctx an object)
import * as P from '../../../packages/pca/src/index.ts';
import * as PR from '../../../packages/pca/src/prohibitions.ts';
import { Oracle, variants, rng, seed, ser, HOSTILE } from './lib.mjs';

const pca: any = (P as any).publicKeyOf ? P : (P as any).default;
const o = new Oracle('prohibitions', 'tools/pca-audit/k05-oracles/prohibitions-oracle.mts', 'TS-reference oracle for the prohibition engine: constitution / state validation, the monitor, advance, evidence, signed evidence, check-and-advance.');
const fromB64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const SK = pca.b64u(seed('k05-prohibitions/principal'));
const PK = pca.b64u(pca.publicKeyOf(fromB64u(SK)));
const SK2 = pca.b64u(seed('k05-prohibitions/other'));
const PK2 = pca.b64u(pca.publicKeyOf(fromB64u(SK2)));
const r = rng(0x9a0b);
const NOW = 1_700_000_000_000;

/** A value the canonical hash refuses: -0, an integer beyond 2^53-1, a non-integer below 1e-6, a lone surrogate. */
const exotic = (v: unknown): boolean => {
  if (typeof v === 'number') return Object.is(v, -0) || (Number.isInteger(v) ? !Number.isSafeInteger(v) : Math.abs(v) < 1e-6 || !Number.isFinite(v));
  if (typeof v === 'string') return /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(v);
  if (Array.isArray(v)) return v.some(exotic);
  if (v !== null && typeof v === 'object') return Object.entries(v).some(([k, x]) => exotic(k) || exotic(x));
  return false;
};
const HASHES = new Set(['canonicalState', 'stateDigest', 'advanceStateStrict', 'proveSafety', 'verifySafetyEvidence', 'safetyBindingId', 'signSafetyEvidence', 'verifySignedSafetyEvidence', 'checkAndAdvance', 'verifyConstitution', 'constitutionId']);
let nameN = 0;
const used = new Map<string, number>();
/** Record one case; hash-hostile inputs get the `x:` prefix. */
const run = async (fn: string, name: string, ref: (...a: any[]) => unknown, args: unknown[]) => {
  let s: string;
  try { s = ser(args); } catch { return false; }
  let nm = (HASHES.has(fn) && exotic(JSON.parse(s)) ? 'x:' : '') + name;
  const key = fn + '/' + nm;
  const k = (used.get(key) ?? 0) + 1;
  used.set(key, k);
  if (k > 1) nm += ` #${k}`;
  return o.run(fn, nm, ref, args);
};
const SMALL = [null, true, 0, 1, -1, 1.5, '', 'x', [], {}, { x: 1 }, ['x']];

// ---- seeds -----------------------------------------------------------------------------------------------------------
const act = (verb: unknown, resource: unknown = '/r', params?: unknown, extra: Record<string, unknown> = {}) => ({ action: { verb, resource, ...(params !== undefined ? { params } : {}), ...extra } });
const APPROVED = { field: 'action.params.approved', op: 'eq', value: true };
const INV: Record<string, any> = {
  never: { id: 'n', kind: 'never', when: { verb: 'delete', resource: '/prod/db' }, description: 'no deletes' },
  never_unless: { id: 'nu', kind: 'never_unless', when: { verb: ['wire', 'pay'], where: [{ field: 'action.params.amount', op: 'gt', value: 1000 }] }, unless: [APPROVED] },
  cap: { id: 'c', kind: 'cap', when: { verb: 'pay' }, amount: 'action.params.amount', max: 100, window_secs: 60 },
  rate: { id: 'r', kind: 'rate', when: { verb: 'call', resource: 're:/api/.*' }, max: 3, window_secs: 10, description: 'slow down' },
  never_after: { id: 'na', kind: 'never_after', after: { verb: 'export' }, forbid: { verb: 'delete' } },
  require_prior: { id: 'rp', kind: 'require_prior', when: { verb: 'deploy' }, prior: { verb: 'review' } },
  require_approval_over: { id: 'ra', kind: 'require_approval_over', when: { verb: 'refund' }, amount: 'action.params.amount', threshold: 50, approved: [APPROVED] },
};
const KINDS = Object.keys(INV);
const con = (invariants: unknown[], extra: Record<string, unknown> = {}) => ({ version: 1, principal: PK, invariants, ...extra });
const CS = con(KINDS.map((k) => INV[k]));
const only = (k: string, patch: Record<string, unknown> = {}) => con([{ ...INV[k], ...patch }]);
const baseState = (over: Record<string, unknown> = {}) => ({ now: NOW, seq: 0, parent: null, ledger: {}, latched: {}, ...over });
const PARENT = 'p'.repeat(43);
const chained = (over: Record<string, unknown> = {}) => baseState({ seq: 3, parent: PARENT, ...over });
const E = (dt: number, amount: number) => ({ t: NOW - dt, amount });
const A0 = act('pay', '/r', { amount: 10 });

// ---- validateInvariant ------------------------------------------------------------------------------------------------
const vi = (n: string, inv: unknown) => run('validateInvariant', n, PR.validateInvariant, [inv]);
for (const k of KINDS) {
  await vi(`${k} base`, INV[k]);
  for (const [n, v] of variants(INV[k], { hostile: HOSTILE, lens: [0, 127, 128, 129, 200, 201] })) await vi(`${k} ${n}`, v);
}
for (const bad of [null, 1, 'x', [], true, [INV.never], undefined as any]) await vi(`not an object ${ser(bad ?? null)}`, bad ?? null);
for (const id of ['', 'a'.repeat(127), 'a'.repeat(128), 'a'.repeat(129), 'é'.repeat(128), 'é'.repeat(129), '__proto__', 'constructor', 'prototype', 'toString', 'a b', 5, null, ['n'], {}])
  for (const k of KINDS) await vi(`${k} id ${ser(id)}`, { ...INV[k], id });
for (const kind of [undefined, 'Never', 'NEVER', 'x', '', 5, null, true, ['never'], [], {}, { a: 1 }, 'never ', 'rate_limit', 'cap2'])
  await vi(`kind ${ser(kind ?? 'undef')}`, { id: 'k', ...(kind === undefined ? {} : { kind }) });
await vi('no kind, description', { id: 'k', description: 'd' });
const WHENS: unknown[] = [
  { verb: 'v' }, { verb: ['a', 'b'] }, { verb: '' }, { verb: [] }, { verb: ['a', ''] }, { verb: ['a', 1] }, { verb: 5 }, {}, { resource: '/x' }, null, 'x', [], undefined,
  { verb: 'v', resource: '' }, { verb: 'v', resource: 5 }, { verb: 'v', resource: null }, { verb: 'v', resource: 're:' }, { verb: 'v', resource: 're:a+' },
  { verb: 'v', resource: 're:(' }, { verb: 'v', resource: 're:' + 'a'.repeat(200) }, { verb: 'v', resource: 're:' + 'a'.repeat(201) }, { verb: 'v', resource: 're:(a+)+$' },
  { verb: 'v', resource: 're:[' }, { verb: 'v', where: [] }, { verb: 'v', where: {} }, { verb: 'v', where: null }, { verb: 'v', where: [APPROVED] },
  { verb: 'v', where: [APPROVED, { field: 'x', op: 'bogus' }] }, { verb: 'v', where: [{}] }, { verb: 'v', where: [{ field: '', op: 'eq' }] }, { verb: 'v', where: [{ not: APPROVED }] },
];
const WHEN_FIELDS: Record<string, string[]> = { never: ['when'], never_unless: ['when'], cap: ['when'], rate: ['when'], never_after: ['after', 'forbid'], require_prior: ['when', 'prior'], require_approval_over: ['when'] };
for (const k of KINDS) for (const f of WHEN_FIELDS[k]!) for (const [i, w] of WHENS.entries()) await vi(`${k}.${f} when#${i}`, { ...INV[k], [f]: w });
const NUMS: unknown[] = [-1, -0, 0, 0.001, 1, 1.5, 10, 10_000, 10_001, 2 ** 31, 2 ** 53, 1e21, '1', null, true, [], {}, 'Infinity'];
for (const x of NUMS) {
  await vi(`cap max ${ser(x)}`, { ...INV.cap, max: x });
  await vi(`cap window ${ser(x)}`, { ...INV.cap, window_secs: x });
  await vi(`rate max ${ser(x)}`, { ...INV.rate, max: x });
  await vi(`rate window ${ser(x)}`, { ...INV.rate, window_secs: x });
  await vi(`approval threshold ${ser(x)}`, { ...INV.require_approval_over, threshold: x });
}
{ const { window_secs: _w, ...nw } = INV.cap; await vi('cap no window', nw); const { window_secs: _x, ...nr } = INV.rate; await vi('rate no window', nr); const { max: _m, ...nm } = INV.rate; await vi('rate no max', nm); }
for (const a of ['action.', 'action.x', 'action.params.amount', 'Action.x', 'x', '', 5, null, 'action', ' action.x', ['action.x']]) {
  await vi(`cap amount ${ser(a)}`, { ...INV.cap, amount: a });
  await vi(`approval amount ${ser(a)}`, { ...INV.require_approval_over, amount: a });
}
const CONDS: unknown[] = [[], [APPROVED], [APPROVED, APPROVED], [APPROVED, { field: 'x', op: 'bogus' }], [{ field: 'x', op: 'bogus' }, 5], {}, null, 'x', 5, [null], [[APPROVED]], [{ all_of: [] }], [{ any_of: [APPROVED] }], [{ not: APPROVED }]];
for (const [i, c] of CONDS.entries()) { await vi(`unless#${i}`, { ...INV.never_unless, unless: c }); await vi(`approved#${i}`, { ...INV.require_approval_over, approved: c }); }
{ const { unless: _u, ...nu } = INV.never_unless; await vi('unless missing', nu); const { approved: _a, ...na } = INV.require_approval_over; await vi('approved missing', na); }

// ---- validateConstitution ---------------------------------------------------------------------------------------------
const vc = (n: string, c: unknown) => run('validateConstitution', n, PR.validateConstitution, [c]);
await vc('base', CS);
for (const [n, v] of variants(CS, { hostile: HOSTILE, depth: 3 })) await vc(n, v);
for (const bad of [null, 1, 'x', [], true]) await vc(`not an object ${ser(bad)}`, bad);
for (const ver of [1, 2, 0, -1, '1', null, 1.5, true, [1], {}, 1e21]) await vc(`version ${ser(ver)}`, con([], { version: ver }));
await vc('version missing', { principal: PK, invariants: [] });
await vc('principal missing', { version: 1, invariants: [] });
await vc('principal empty', con([], { principal: '' }));
await vc('principal number', con([], { principal: 5 }));
await vc('version and principal bad, invariants not array', { version: 2, principal: '', invariants: 'x' });
await vc('version bad, invariants bad item', { version: 2, principal: PK, invariants: [5] });
const nev = (i: number) => ({ id: 'i' + i, kind: 'never', when: { verb: 'v' } });
for (const n of [255, 256, 257, 258]) await vc(`${n} invariants`, con(Array.from({ length: n }, (_, i) => nev(i))));
await vc('257 invariants with a duplicate and a bad one', con([...Array.from({ length: 255 }, (_, i) => nev(i)), nev(0), { id: 'bad', kind: 'nope' }]));
await vc('duplicate id', con([nev(1), nev(1)]));
await vc('duplicate id thrice', con([nev(1), nev(1), nev(1)]));
await vc('duplicate id non adjacent', con([nev(1), nev(2), nev(1)]));
await vc('two different duplicates', con([nev(1), nev(2), nev(1), nev(2)]));
await vc('duplicate and bad', con([nev(1), { id: 'i1', kind: 'nope' }, { kind: 'never' }, 5]));
await vc('id-less items never duplicate', con([{ kind: 'never' }, { kind: 'never' }, null, null]));
await vc('non-string ids never duplicate', con([{ id: 5, kind: 'never' }, { id: 5, kind: 'never' }]));
await vc('empty-id duplicates', con([{ id: '', kind: 'never' }, { id: '', kind: 'never' }]));
await vc('invariants object', con({} as any));
await vc('extra constitution members ok', { ...CS, id: 'x', sig: 'y', extra: 1 });

// ---- state ------------------------------------------------------------------------------------------------------------
const sp = (n: string, s: unknown) => run('stateProblem', n, PR.stateProblem, [s]);
const SEEDS: Record<string, any> = {
  genesis: baseState(),
  full: chained({ ledger: { c: [E(1000, 40), E(500, 20)], r: [E(100, 1)] }, latched: { na: NOW - 5 }, deadlines: { d1: 5 } }),
};
await sp('genesis', SEEDS.genesis);
for (const [k, s] of Object.entries(SEEDS)) for (const [n, v] of variants(s, { hostile: HOSTILE, lens: [0, 127, 128, 129] })) await sp(`${k} ${n}`, v);
for (const bad of [null, 1, 'x', [], true]) await sp(`not an object ${ser(bad)}`, bad);
for (const seq of [0, 1, 2, -1, -0, 1.5, 2 ** 53, '0', null, true]) for (const parent of [null, PARENT, '', 5, undefined, true, [], {}])
  await sp(`seq ${ser(seq)} parent ${ser(parent ?? 'undef')}`, { now: NOW, seq, ...(parent === undefined ? {} : { parent }), ledger: {}, latched: {} });
for (const now of [NOW, 0, -1, -0, 1.5, '1', null, true, 2 ** 53, 1e21]) await sp(`now ${ser(now)}`, baseState({ now }));
for (const t of [NOW, NOW + 1, NOW - 1, 0, -1, -0, '1', null, 1e21]) await sp(`ledger t ${ser(t)}`, baseState({ ledger: { c: [{ t, amount: 1 }] } }));
for (const amount of [0, -0, 1, -1, 1.5, '1', null, 1e21, true]) await sp(`ledger amount ${ser(amount)}`, baseState({ ledger: { c: [{ t: NOW, amount }] } }));
for (const t of [NOW, NOW + 1, NOW - 1, 0, -1, -0, '1', null, 1e21]) await sp(`latch ${ser(t)}`, baseState({ latched: { na: t } }));
for (const k of ['', 'a', 'a'.repeat(127), 'a'.repeat(128), 'a'.repeat(129), 'é'.repeat(128), 'é'.repeat(129), '__proto__', 'constructor', 'prototype']) {
  await sp(`ledger key ${ser(k).slice(0, 12)} ${k.length}`, baseState({ ledger: { [k]: [] } }));
  await sp(`latch key ${ser(k).slice(0, 12)} ${k.length}`, baseState({ latched: { [k]: NOW } }));
  await sp(`deadline key ${ser(k).slice(0, 12)} ${k.length}`, baseState({ deadlines: { [k]: 1 } }));
}
for (const d of [1, 2, 1_000_000, 1_000_001, 0, -1, -0, 1.5, '1', null, true, 2 ** 53]) await sp(`deadline ${ser(d)}`, baseState({ deadlines: { d: d } }));
for (const dl of [{}, [], null, 'x', 5, true, { a: 1, b: 2 }]) await sp(`deadlines ${ser(dl)}`, baseState({ deadlines: dl }));
for (const bad of [null, [], 'x', 5, true, undefined]) { await sp(`ledger ${ser(bad ?? 'undef')}`, { ...baseState(), ...(bad === undefined ? {} : { ledger: bad }) } as any); await sp(`latched ${ser(bad ?? 'undef')}`, { ...baseState(), ...(bad === undefined ? {} : { latched: bad }) } as any); }
for (const v of [null, {}, 'x', 5, [null], [5], [[]], [{}], [{ t: NOW }], [{ amount: 1 }], [{ t: NOW, amount: 1 }, null]]) await sp(`ledger value ${ser(v)}`, baseState({ ledger: { c: v } }));
const many = (n: number, mk: (i: number) => unknown) => Object.fromEntries(Array.from({ length: n }, (_, i) => ['k' + i, mk(i)]));
for (const n of [1023, 1024, 1025]) {
  await sp(`${n} ledger keys`, baseState({ ledger: many(n, () => []) }));
  await sp(`${n} latch keys`, baseState({ latched: many(n, () => NOW) }));
  await sp(`${n} deadline keys`, baseState({ deadlines: many(n, () => 1) }));
  await sp(`${n} ledger keys, 1025 latch keys`, baseState({ ledger: many(n, () => []), latched: many(1025, () => NOW) }));
}
const ents = (n: number, amount = 1) => Array.from({ length: n }, (_, i) => ({ t: NOW - 20_000 + i, amount }));
for (const n of [9999, 10_000, 10_001]) await sp(`${n} ledger entries`, baseState({ ledger: { c: ents(n) } }));
await sp('total 100000 entries', baseState({ ledger: many(10, () => ents(10_000)) }));
await sp('total 100001 entries', baseState({ ledger: { ...many(10, () => ents(10_000)), z: ents(1) } }));
await sp('bad entry after the size limit', baseState({ ledger: { c: [...ents(10_000), 5] } }));
await sp('too many keys beats a bad key', baseState({ ledger: { ...many(1025, () => []), __proto__x: [] } }));
await sp('forbidden ledger key beats entry problems', baseState({ ledger: { constructor: 5 } }));
await sp('latch problem after ledger ok', baseState({ ledger: { c: [E(1, 1)] }, latched: { na: NOW + 1 } }));
await sp('ledger problem before latch problem', baseState({ ledger: { c: [E(1, -1)] }, latched: { na: NOW + 1 } }));
await sp('deadline problem after latch ok', baseState({ latched: { na: NOW }, deadlines: { d: 0 } }));

// ---- canonicalState / stateDigest / tickState --------------------------------------------------------------------------
const cst = (n: string, s: unknown) => run('canonicalState', n, PR.canonicalState as any, [s]);
const sdg = (n: string, s: unknown) => run('stateDigest', n, PR.stateDigest as any, [s]);
const CANON: Array<[string, unknown]> = [
  ['genesis', baseState()],
  ['chained full', SEEDS.full],
  ['unsorted ledger', chained({ ledger: { c: [E(10, 5), E(1000, 9), E(10, 2), E(500, 1), E(1000, 3)], r: [] } })],
  ['empty arrays dropped', chained({ ledger: { c: [], r: [], z: [E(5, 1)] } })],
  ['unknown fields dropped', { ...chained({ ledger: { c: [{ t: NOW, amount: 1, extra: 'x' }] } }), junk: 1 }],
  ['deadlines empty', baseState({ deadlines: {} })],
  ['deadlines kept', baseState({ deadlines: { b: 2, a: 1 } })],
  ['latched many', chained({ latched: { z: NOW, a: NOW - 1, m: 5 } })],
  ['same t different amount', chained({ ledger: { c: [{ t: NOW, amount: 5 }, { t: NOW, amount: 1 }, { t: NOW, amount: 3 }] } })],
  ['float amounts', chained({ ledger: { c: [{ t: NOW, amount: 0.1 }, { t: NOW, amount: 0.2 }, { t: NOW - 1, amount: 0.30000000000000004 }] } })],
  ['negative t', chained({ now: 5, ledger: { c: [{ t: -5, amount: 1 }, { t: -10, amount: 1 }] } })],
  ['t zero and negative zero', chained({ now: 5, ledger: { c: [{ t: 0, amount: 5 }, { t: -0, amount: 7 }, { t: 0, amount: 1 }, { t: -0, amount: 0 }] } })],
  ['amount zero and negative zero', chained({ ledger: { c: [{ t: NOW, amount: 0 }, { t: NOW, amount: -0 }, { t: NOW, amount: 3 }] } })],
  ['malformed', 5],
  ['malformed seq', baseState({ seq: -1 })],
];
for (const [n, s] of CANON) { await cst(n, s); await sdg(n, s); }
for (const [n, v] of variants(SEEDS.full, { hostile: SMALL, lens: [] })) { await cst(n, v); await sdg(n, v); }
const tk = (n: string, s: unknown, now: unknown) => run('tickState', n, PR.tickState as any, [s, now]);
for (const [sn, s] of [['genesis', baseState()], ['full', SEEDS.full], ['bad', baseState({ seq: -1 })], ['null', null]] as const)
  for (const now of [NOW, NOW + 1, NOW - 1, NOW + 1e9, 0, -1, -0, 1.5, '1', null, true, 2 ** 53, 1e21, [], {}]) await tk(`${sn} now ${ser(now)}`, s, now);
await tk('state with deadlines', baseState({ deadlines: { d: 3 } }), NOW + 5);
await tk('state with unknown field', { ...baseState(), junk: 1 }, NOW + 5);
for (const now of [0, NOW, -1, 1.5, '1', null, 1e21, -0]) await run('emptyState', `now ${ser(now)}`, PR.emptyState as any, [now]);

// ---- the monitor: check grids ------------------------------------------------------------------------------------------
const chk = (n: string, a: unknown, c: unknown, s: unknown) => run('checkProhibitions', n, PR.checkProhibitions as any, [a, c, s]);
const ACTIONS: Array<[string, unknown]> = [
  ['pay 10', act('pay', '/r', { amount: 10 })], ['pay 0', act('pay', '/r', { amount: 0 })], ['pay 60', act('pay', '/r', { amount: 60 })], ['pay 100', act('pay', '/r', { amount: 100 })],
  ['pay 100.5', act('pay', '/r', { amount: 100.5 })], ['pay 101', act('pay', '/r', { amount: 101 })], ['pay 0.1', act('pay', '/r', { amount: 0.1 })], ['pay 0.2', act('pay', '/r', { amount: 0.2 })],
  ['pay -1', act('pay', '/r', { amount: -1 })], ['pay -0', act('pay', '/r', { amount: -0 })], ['pay str', act('pay', '/r', { amount: '5' })], ['pay null', act('pay', '/r', { amount: null })],
  ['pay missing', act('pay', '/r')], ['pay 1e21', act('pay', '/r', { amount: 1e21 })], ['pay big', act('pay', '/r', { amount: 2 ** 53 })], ['pay obj', act('pay', '/r', { amount: {} })],
  ['wire 1000', act('wire', '/r', { amount: 1000 })], ['wire 1001', act('wire', '/r', { amount: 1001 })], ['wire 1001 approved', act('wire', '/r', { amount: 1001, approved: true })],
  ['wire 1001 not approved', act('wire', '/r', { amount: 1001, approved: false })], ['wire 1001 approved str', act('wire', '/r', { amount: 1001, approved: 'true' })], ['wire noamount', act('wire', '/r')],
  ['call api', act('call', '/api/x')], ['call other', act('call', '/other')], ['call api nested', act('call', '/api/a/b/c')],
  ['delete db', act('delete', '/prod/db')], ['delete other', act('delete', '/x')], ['export', act('export')], ['deploy', act('deploy')], ['review', act('review')], ['read', act('read')],
  ['refund 49', act('refund', '/r', { amount: 49 })], ['refund 50', act('refund', '/r', { amount: 50 })], ['refund 51', act('refund', '/r', { amount: 51 })], ['refund -1', act('refund', '/r', { amount: -1 })],
  ['refund missing', act('refund')], ['refund str', act('refund', '/r', { amount: 'x' })], ['refund 51 approved', act('refund', '/r', { amount: 51, approved: true })],
  ['refund 51 not approved', act('refund', '/r', { amount: 51, approved: false })], ['refund missing approved', act('refund', '/r', { approved: true })], ['refund 50.5', act('refund', '/r', { amount: 50.5 })],
  ['refund 0.5 approved', act('refund', '/r', { amount: 0.5, approved: true })],
  ['verb number', act(5)], ['verb missing', { action: { resource: '/r' } }], ['resource missing', { action: { verb: 'pay' } }], ['resource number', act('pay', 5)], ['verb array', act(['pay'])],
  ['no action', {}], ['action null', { action: null }], ['action string', { action: 'x' }], ['action array', { action: [] }], ['null', null], ['number', 5],
];
const STATES: Array<[string, unknown]> = [
  ['genesis', baseState()], ['chained', chained()], ['bad', baseState({ seq: -1 })], ['latched na', chained({ latched: { na: NOW - 1 } })], ['latched rp', chained({ latched: { rp: NOW } })],
  ['latched both', chained({ latched: { na: NOW - 1, rp: NOW, other: NOW } })], ['latched other', chained({ latched: { zz: NOW } })],
];
// every kind alone, every action, every plain state; then everything together
for (const k of KINDS) for (const [an, a] of ACTIONS) for (const [sn, s] of STATES) await chk(`${k} / ${an} / ${sn}`, a, only(k), s);
for (const [an, a] of ACTIONS) for (const [sn, s] of STATES) await chk(`all / ${an} / ${sn}`, a, CS, s);
// cap and rate windows
const capLedgers: Array<[string, unknown[]]> = [
  ['empty', []], ['40 recent', [E(1000, 40)]], ['edge excluded', [E(60_000, 50)]], ['edge+1 included', [E(59_999, 50)]], ['now included', [E(0, 50)]], ['old', [E(120_000, 90)]],
  ['mixed unordered', [E(5, 30), E(70_000, 99), E(1, 10), E(59_000, 20)]], ['floats', [E(5, 0.1), E(6, 0.2)]], ['floats reversed', [E(6, 0.2), E(5, 0.1)]], ['zero amounts', [E(5, 0), E(6, 0)]],
  ['sum exactly 90', [E(5, 40), E(6, 50)]], ['big', [E(5, 1e20)]], ['same t', [{ t: NOW - 5, amount: 3 }, { t: NOW - 5, amount: 1 }, { t: NOW - 5, amount: 2 }]],
];
for (const window_secs of [undefined, 60, 0.5]) for (const max of [0, 100, 100.5]) for (const [ln, led] of capLedgers) for (const [an, a] of ACTIONS.slice(0, 16).filter((_, i) => [0, 1, 3, 4, 5, 6, 8, 12].includes(i)))
  await chk(`cap w${window_secs} max${max} / ${ln} / ${an}`, a, only('cap', { max, window_secs }), chained({ ledger: { c: led } }));
const rateLedgers: Array<[string, unknown[]]> = [['0', []], ['1', [E(1000, 1)]], ['2', [E(1000, 1), E(2000, 1)]], ['3', [E(1000, 1), E(2000, 1), E(3000, 1)]], ['4', [E(1000, 1), E(2000, 1), E(3000, 1), E(4000, 1)]],
  ['edge', [E(10_000, 1), E(1000, 1)]], ['edge+1', [E(9_999, 1), E(1000, 1)]], ['old', [E(50_000, 1), E(60_000, 1), E(70_000, 1)]], ['now', [E(0, 1)]]];
for (const max of [0, 1, 2, 3, 4]) for (const window_secs of [10, 0.5, 1e6]) for (const [ln, led] of rateLedgers) for (const [an, a] of ACTIONS.filter((_, i) => [22, 23].includes(i)))
  await chk(`rate max${max} w${window_secs} / ${ln} / ${an}`, a, only('rate', { max, window_secs }), chained({ ledger: { r: led } }));
// the ledger of one id never feeds another invariant
await chk('ledger of another id ignored', act('pay', '/r', { amount: 99 }), only('cap'), chained({ ledger: { zz: [E(5, 99)] } }));
await chk('ledger key proto-like', act('pay', '/r', { amount: 99 }), only('cap', { id: 'toString' }), chained({ ledger: { toString: [E(5, 2)] } }));
// descriptions of every type, on every reason-bearing kind
const DESCS: unknown[] = [undefined, null, '', 'why', 0, 1, -0, 5.5, false, true, [], ['a'], ['a', ['b']], [null, 'a'], {}, { a: 1 }, 'é', '0'];
const VIOL: Record<string, [unknown, unknown]> = {
  never: [act('delete', '/prod/db'), baseState()], never_unless: [act('wire', '/r', { amount: 2000 }), baseState()], never_after: [act('delete'), chained({ latched: { na: NOW } })],
  require_prior: [act('deploy'), chained()], require_approval_over: [act('refund', '/r', { amount: 99 }), baseState()], cap: [act('pay', '/r', { amount: 101 }), baseState()], rate: [act('call', '/api/x'), chained({ ledger: { r: [E(1, 1), E(2, 1), E(3, 1)] } })],
};
for (const k of KINDS) for (const [i, d] of DESCS.entries()) await chk(`${k} description#${i}`, VIOL[k]![0], con([{ ...INV[k], description: d }]), VIOL[k]![1]);
await chk('two violations listed in order', act('delete', '/prod/db'), con([INV.never, { ...INV.never, id: 'n2', description: 'second' }, { ...INV.never, id: 'n3', when: { verb: 'x' } }]), baseState());
await chk('every invariant evaluated, mixed', act('pay', '/r', { amount: 101 }), CS, chained({ latched: { na: NOW } }));
// structural refusals: ordering of the three checks and each reason
await chk('bad constitution beats bad action beats bad state', null, { version: 2 }, 5);
await chk('bad action beats bad state', null, CS, 5);
await chk('bad state', act('pay'), CS, 5);
await chk('bad constitution only', act('pay'), { version: 1, principal: PK, invariants: [{ id: 'x' }] }, baseState());
await chk('first problem of many', act('pay'), { version: 2, principal: '', invariants: 'x' }, baseState());
await chk('invariant order kept', act('pay', '/r', { amount: 1 }), con([INV.cap, INV.never, INV.rate]), baseState());
for (const [n, v] of variants(CS, { hostile: SMALL, depth: 3 })) await chk(`CS ${n}`, act('pay', '/r', { amount: 10 }), v, chained({ ledger: { c: [E(1000, 40)], r: [E(1, 1)] }, latched: { na: NOW } }));
for (const [n, v] of variants(act('pay', '/r', { amount: 10 }), { hostile: SMALL })) await chk(`A ${n}`, v, CS, chained());
for (const [n, v] of variants(SEEDS.full, { hostile: SMALL })) await chk(`S ${n}`, A0, CS, v);
// where / matching through the veto
for (const [i, w] of WHENS.entries()) await chk(`when#${i}`, act('v', '/x', { approved: true }), con([{ id: 'n', kind: 'never', when: w }]), baseState());
// limits inside the monitor
await chk('10000 entries in a cap ledger', act('pay', '/r', { amount: 1 }), only('cap', { max: 1e9 }), baseState({ ledger: { c: ents(10_000) } }));
await chk('10001 entries rejected', act('pay', '/r', { amount: 1 }), only('cap', { max: 1e9 }), baseState({ ledger: { c: ents(10_001) } }));
await chk('rate over 10000 entries', act('call', '/api/x'), only('rate', { max: 10_000, window_secs: 100 }), baseState({ ledger: { r: ents(10_000) } }));

// ---- advance ----------------------------------------------------------------------------------------------------------
const adv = (n: string, a: unknown, c: unknown, s: unknown, ...now: unknown[]) => run('advanceStateStrict', n, PR.advanceStateStrict as any, [a, c, s, ...now]);
for (const k of KINDS) for (const [an, a] of ACTIONS) for (const [sn, s] of STATES.slice(0, 5)) await adv(`${k} / ${an} / ${sn}`, a, only(k), s);
for (const [an, a] of ACTIONS) for (const [sn, s] of STATES) await adv(`all / ${an} / ${sn}`, a, CS, s);
for (const now of [NOW, NOW + 1, NOW + 61_000, NOW - 1, NOW + 1e9, 0, -1, 1.5, '1', true, 2 ** 53, [], {}, NOW + 0.5, null])
  for (const [sn, s] of STATES.slice(0, 3)) await adv(`now ${ser(now)} / ${sn}`, A0, CS, s, now);
for (const now of [NOW + 5, NOW + 10_000, NOW + 59_999, NOW + 60_000, NOW + 60_001]) for (const [ln, led] of capLedgers) for (const window_secs of [undefined, 60])
  await adv(`cap w${window_secs} now+${now - NOW} / ${ln}`, A0, only('cap', { window_secs }), chained({ ledger: { c: led } }), now);
for (const now of [NOW, NOW + 9_999, NOW + 10_000, NOW + 10_001]) for (const [ln, led] of rateLedgers)
  await adv(`rate now+${now - NOW} / ${ln}`, act('call', '/api/x'), only('rate'), chained({ ledger: { r: led } }), now);
for (const [ln, led] of capLedgers) await adv(`cap non-matching action prunes / ${ln}`, act('read'), only('cap'), chained({ ledger: { c: led } }), NOW + 30_000);
for (const [ln, led] of rateLedgers) await adv(`rate non-matching prunes / ${ln}`, act('read'), only('rate'), chained({ ledger: { r: led } }), NOW + 5_000);
await adv('latch earliest kept', act('export'), only('never_after'), chained({ latched: { na: NOW - 100 } }), NOW + 5);
await adv('latch recorded at now', act('export'), only('never_after'), chained(), NOW + 5);
await adv('latch not recorded when no match', act('read'), only('never_after'), chained(), NOW + 5);
await adv('prior recorded', act('review'), only('require_prior'), chained(), NOW + 5);
await adv('prior kept earliest', act('review'), only('require_prior'), chained({ latched: { rp: NOW - 7 } }), NOW + 5);
await adv('prior ambiguous not recorded', act('review', '/r'), con([{ ...INV.require_prior, prior: { verb: 'review', where: [{ field: 'action.params.ok', op: 'eq', value: true }] } }]), chained(), NOW + 5);
await adv('prior where holds recorded', act('review', '/r', { ok: true }), con([{ ...INV.require_prior, prior: { verb: 'review', where: [{ field: 'action.params.ok', op: 'eq', value: true }] } }]), chained(), NOW + 5);
await adv('after ambiguous latches', act('export', '/r'), con([{ ...INV.never_after, after: { verb: 'export', where: [{ field: 'action.params.ok', op: 'eq', value: true }] } }]), chained(), NOW + 5);
await adv('after where false not latched', act('export', '/r', { ok: false }), con([{ ...INV.never_after, after: { verb: 'export', where: [{ field: 'action.params.ok', op: 'eq', value: true }] } }]), chained(), NOW + 5);
await adv('empty ledger entry removed', act('read'), only('cap'), chained({ ledger: { c: [E(100_000, 5)] } }), NOW + 5);
await adv('other ledger ids survive', act('read'), only('cap'), chained({ ledger: { zz: [E(100_000, 5)], c: [E(5, 1)] } }), NOW + 5);
await adv('deadlines are dropped', act('pay', '/r', { amount: 1 }), only('cap'), chained({ deadlines: { d: 3 } }), NOW + 5);
await adv('unknown fields dropped', act('pay', '/r', { amount: 1 }), only('cap'), { ...chained(), junk: 1 }, NOW + 5);
await adv('window-less cap keeps everything', act('pay', '/r', { amount: 1 }), only('cap', { window_secs: undefined }), chained({ ledger: { c: [E(1e9, 5)] } }), NOW + 5);
await adv('unsorted ledger sorted', act('pay', '/r', { amount: 3 }), only('cap', { max: 1e9 }), chained({ ledger: { c: [E(1, 1), E(100, 2), E(50, 3)] } }), NOW + 5);
await adv('same t sorted by amount', act('pay', '/r', { amount: 2 }), only('cap', { max: 1e9 }), chained({ ledger: { c: [{ t: NOW + 5, amount: 9 }, { t: NOW + 5, amount: 1 }] }, now: NOW + 5 }), NOW + 5);
await adv('amount is the new entry', act('pay', '/r', { amount: 0.1 }), only('cap'), chained({ ledger: { c: [E(1, 0.2)] } }), NOW + 5);
await adv('window_secs float', act('pay', '/r', { amount: 1 }), only('cap', { window_secs: 0.001 }), chained({ ledger: { c: [E(0, 1), E(1, 1), E(2, 1)] } }), NOW + 1);
// ledger merge and overflow
const bigE = (n: number, f: (i: number) => number = (i) => i + 1) => Array.from({ length: n }, (_, i) => ({ t: NOW - 20_000 + i, amount: f(i) }));
for (const n of [9998, 9999, 10_000]) {
  await adv(`cap ledger ${n} + 1`, act('pay', '/r', { amount: 7 }), only('cap', { max: 1e12, window_secs: undefined }), baseState({ ledger: { c: bigE(n) } }));
  await adv(`cap windowed ledger ${n} + 1`, act('pay', '/r', { amount: 7 }), only('cap', { max: 1e12, window_secs: 100 }), baseState({ ledger: { c: bigE(n) } }));
  await adv(`rate ledger ${n} + 1`, act('call', '/api/x'), only('rate', { max: 10_000, window_secs: 100 }), baseState({ ledger: { r: bigE(n, () => 1) } }));
  await adv(`cap non-matching ${n}`, act('read'), only('cap', { max: 1e12, window_secs: undefined }), baseState({ ledger: { c: bigE(n) } }));
}
await adv('cap merge floats', act('pay', '/r', { amount: 0.3 }), only('cap', { max: 1e12, window_secs: undefined }), baseState({ ledger: { c: bigE(10_000, (i) => (i % 2 ? 0.1 : 0.2)) } }));
await adv('cap merge new entry is oldest', act('pay', '/r', { amount: 4 }), only('cap', { max: 1e12, window_secs: undefined }), baseState({ now: NOW, ledger: { c: bigE(10_000, () => 2) } }), NOW);
await adv('cap merge ties', act('pay', '/r', { amount: 1 }), only('cap', { max: 1e12, window_secs: undefined }), baseState({ ledger: { c: Array.from({ length: 10_000 }, () => ({ t: NOW - 1, amount: 1 })) } }));
await adv('two ledgers one overflows', act('pay', '/r', { amount: 1 }), con([{ ...INV.cap, window_secs: undefined, max: 1e12 }, { ...INV.cap, id: 'c2', window_secs: undefined, max: 1e12 }]), baseState({ ledger: { c: bigE(10_000), c2: bigE(3) } }));
await adv('rate overflow with a cap before it', act('call', '/api/x'), con([{ ...INV.cap, when: { verb: 'call' }, max: 1e12, window_secs: undefined, amount: 'action.params.n' }, { ...INV.rate, max: 10_000, window_secs: 100 }]), baseState({ ledger: { r: bigE(10_000, () => 1) } }));
// error order inside advance
await adv('bad constitution first', 5, { version: 2 }, 5, 1);
await adv('bad state before clock', 5, CS, 5, 1);
await adv('clock before action', null, CS, baseState(), NOW - 1);
await adv('action last', null, CS, baseState(), NOW);
await adv('unresolvable cap amount', act('pay', '/r', {}), only('cap'), baseState());
await adv('unresolvable cap amount after a good one', act('pay', '/r', { amount: -1 }), con([{ ...INV.never, id: 'z', when: { verb: 'q' } }, INV.cap]), baseState());
await adv('second invariant state invalid', act('pay', '/r', { amount: 1 }), only('cap'), chained({ ledger: { c: [E(1, 1)] } }), NOW + 1e9);
for (const [n, v] of variants(CS, { hostile: SMALL, depth: 3 })) await adv(`CS ${n}`, A0, v, chained({ ledger: { c: [E(1000, 40)] }, latched: { na: NOW } }), NOW + 1);
for (const [n, v] of variants(A0, { hostile: SMALL })) await adv(`A ${n}`, v, CS, chained(), NOW + 1);
for (const [n, v] of variants(SEEDS.full, { hostile: SMALL })) await adv(`S ${n}`, A0, CS, v, NOW + 1);
// a chain of advances: feed each next state into the following step
{
  let s: any = baseState();
  const steps: unknown[] = [act('export'), act('pay', '/r', { amount: 40 }), act('review'), act('call', '/api/a'), act('pay', '/r', { amount: 50 }), act('call', '/api/b'), act('deploy'), act('pay', '/r', { amount: 20 }), act('call', '/api/c'), act('call', '/api/d')];
  for (const [i, a] of steps.entries()) {
    const now = NOW + (i + 1) * 3000;
    await adv(`chain step ${i}`, a, CS, s, now);
    const res: any = PR.advanceStateStrict(a as any, CS as any, s, now);
    if (res.ok) s = JSON.parse(ser(res.state));
  }
}

// a window-less cap counts every entry up to now, however old (t at or below 1, negative)
{
  const oldLed = [{ t: 0, amount: 60 }, { t: -500, amount: 30 }, { t: 1, amount: 5 }, { t: 2, amount: 4 }];
  for (const [i, led] of [oldLed, oldLed.slice(0, 1), oldLed.slice(1, 2), oldLed.slice(2, 3), oldLed.slice(3), [{ t: -2, amount: 100 }]].entries())
    for (const max of [0, 50, 99, 100, 150]) for (const amount of [0, 1, 10]) {
      const st = { now: 1000, seq: 3, parent: PARENT, ledger: { c: led }, latched: {} };
      await chk(`cap no window old entries#${i} max${max} amount${amount}`, act('pay', '/r', { amount }), only('cap', { max, window_secs: undefined }), st);
      await adv(`cap no window old entries#${i} max${max} amount${amount}`, act('pay', '/r', { amount }), only('cap', { max, window_secs: undefined }), st);
    }
  await adv('cap windowed old entries', act('pay', '/r', { amount: 1 }), only('cap', { window_secs: 5000 }), { now: 1000, seq: 3, parent: PARENT, ledger: { c: oldLed }, latched: {} });
}
for (const [an, a] of [['refund 0', act('refund', '/r', { amount: 0 })], ['refund 0.5', act('refund', '/r', { amount: 0.5 })], ['refund 1', act('refund', '/r', { amount: 1 })], ['refund 50 unapproved', act('refund', '/r', { amount: 50, approved: false })]] as const)
  for (const th of [0, 0.5, 1, 50]) await chk(`approval ${an} threshold ${th}`, a, only('require_approval_over', { threshold: th }), baseState());
for (const [an, a] of [['pay 0', act('pay', '/r', { amount: 0 })], ['pay 0.5', act('pay', '/r', { amount: 0.5 })], ['pay 1', act('pay', '/r', { amount: 1 })]] as const) { await adv(`amount ${an}`, a, only('cap'), baseState()); await chk(`amount ${an}`, a, only('cap', { max: 0 }), baseState()); }
// nesting depth of a condition list: 32 is the last depth accepted
{
  const chain = (n: number): any => (n === 0 ? APPROVED : { not: chain(n - 1) });
  const wide = (n: number): any => (n === 0 ? APPROVED : { all_of: [chain(0), wide(n - 1)] });
  for (const n of [0, 1, 31, 32, 33, 34]) {
    await vi(`unless chain ${n}`, { ...INV.never_unless, unless: [chain(n)] });
    await vi(`approved chain ${n}`, { ...INV.require_approval_over, approved: [chain(n)] });
    await vi(`unless second chain ${n}`, { ...INV.never_unless, unless: [APPROVED, chain(n)] });
    await vi(`unless wide ${n}`, { ...INV.never_unless, unless: [wide(n)] });
    await vi(`where chain ${n}`, { ...INV.never, when: { verb: 'v', where: [chain(n)] } });
  }
}

// ---- evidence -----------------------------------------------------------------------------------------------------------
const prove = (n: string, a: unknown, c: unknown, s: unknown) => run('proveSafety', n, PR.proveSafety as any, [a, c, s]);
for (const [an, a] of ACTIONS.filter((_, i) => [0, 5, 12, 17, 18, 22, 25, 26, 30, 31, 32, 37, 38, 42, 43, 44, 50, 52, 53, 56, 57, 58].includes(i))) for (const [sn, s] of STATES) {
  await prove(`${an} / ${sn}`, a, CS, s);
  await prove(`${an} / ${sn} / no invariants`, a, con([]), s);
}
await prove('bad constitution', A0, { version: 2 }, baseState());
await prove('bad constitution null', A0, null, baseState());
await prove('bad action', null, CS, baseState());
await prove('unhashable action', act('pay', '/r', { amount: -0 }), CS, baseState());
await prove('unhashable constitution', A0, con([{ ...INV.cap, max: -0 }]), baseState());
await prove('bad state', A0, CS, 5);
await prove('unhashable state', A0, CS, baseState({ ledger: { c: [{ t: -0, amount: 1 }] } }));
await prove('unhashable action and state', act('pay', '/r', { amount: -0 }), CS, baseState({ ledger: { c: [{ t: -0, amount: 1 }] } }));
await prove('state now missing', A0, CS, { seq: 0 });
await prove('state now string', A0, CS, baseState({ now: '5' }));
await prove('state now negative', A0, CS, baseState({ now: -5 }));
await prove('state null', A0, CS, null);
const FRESH = pca.proveSafety ? pca.proveSafety(A0, CS, chained({ ledger: { c: [E(1000, 40)] } })) : (PR as any).proveSafety(A0, CS, chained({ ledger: { c: [E(1000, 40)] } }));
const FRESHV = (PR as any).proveSafety(act('pay', '/r', { amount: 101 }), CS, chained({ ledger: { c: [E(1000, 40)] } }));
const ST1 = chained({ ledger: { c: [E(1000, 40)] } });
const vse = (n: string, ev: unknown, a: unknown, c: unknown, s: unknown) => run('verifySafetyEvidence', n, PR.verifySafetyEvidence as any, [ev, a, c, s]);
await vse('fresh', FRESH, A0, CS, ST1);
await vse('fresh violated', FRESHV, act('pay', '/r', { amount: 101 }), CS, ST1);
await vse('fresh violated tampered', { ...FRESHV, ok: true }, act('pay', '/r', { amount: 101 }), CS, ST1);
for (const [n, v] of variants(FRESH, { hostile: SMALL, lens: [] })) await vse(`ev ${n}`, v, A0, CS, ST1);
for (const [n, v] of variants(FRESHV, { hostile: SMALL, lens: [] })) await vse(`evV ${n}`, v, act('pay', '/r', { amount: 101 }), CS, ST1);
for (const ev of [null, 5, 'x', [], true, {}, { v: 1 }, { v: 2 }, { v: '1' }, { v: 1.5 }, { v: -0 }]) await vse(`ev ${ser(ev)}`, ev, A0, CS, ST1);
await vse('other action', FRESH, act('pay', '/r', { amount: 11 }), CS, ST1);
await vse('other constitution', FRESH, A0, only('cap'), ST1);
await vse('other state', FRESH, A0, CS, chained({ ledger: { c: [E(1000, 41)] } }));
await vse('malformed action', FRESH, null, CS, ST1);
await vse('malformed constitution', FRESH, A0, { version: 2 }, ST1);
await vse('malformed state', FRESH, A0, CS, 5);
await vse('extra evidence member', { ...FRESH, extra: 1 }, A0, CS, ST1);
await vse('rows reordered', { ...FRESH, evaluated: [...FRESH.evaluated].reverse() }, A0, CS, ST1);
await vse('violated list tampered', { ...FRESH, violated: ['x'] }, A0, CS, ST1);
await vse('violated multiple', (PR as any).proveSafety(act('delete', '/prod/db'), con([INV.never, { ...INV.never, id: 'n2' }]), baseState()), act('delete', '/prod/db'), con([INV.never, { ...INV.never, id: 'n2' }]), baseState());
await vse('violated multiple ev', (PR as any).proveSafety(act('delete', '/prod/db'), con([INV.never, { ...INV.never, id: 'n2' }]), baseState()), act('delete', '/prod/db'), con([INV.never, { ...INV.never, id: 'n2' }]), baseState());
await vse('unhashable constitution recompute', FRESH, A0, con([{ ...INV.cap, max: -0 }]), ST1);
await vse('unhashable action recompute', FRESH, act('pay', '/r', { amount: -0 }), CS, ST1);

// ---- signing and signed evidence ---------------------------------------------------------------------------------------
const sse = (n: string, ev: unknown, sk: unknown, pub: unknown) => run('signSafetyEvidence', n, (e: any, k: string, p: any) => (PR as any).signSafetyEvidence(e, fromB64u(k), p), [ev, sk, pub]);
await sse('fresh', FRESH, SK, PK);
await sse('violated evidence signs', FRESHV, SK, PK);
await sse('other key', FRESH, SK2, PK2);
await sse('mismatched pair', FRESH, SK2, PK);
for (const pub of ['', null, 5, [], {}, undefined as any]) await sse(`signer ${ser(pub ?? null)}`, FRESH, SK, pub ?? null);
for (const k of ['constitution', 'action_digest', 'state_digest']) for (const d of ['', '<unhashable>', null, 5, [], undefined as any, 'x']) await sse(`${k} ${ser(d ?? null)}`, { ...FRESH, [k]: d }, SK, PK);
for (const ev of [null, 5, {}, { v: 2 }, { v: '1' }, { ...FRESH, v: 1.5 }]) await sse(`ev ${ser(ev)}`, ev, SK, PK);
const sbi = (n: string, ev: unknown, signer: unknown) => run('safetyBindingId', n, PR.safetyBindingId as any, [ev, signer]);
await sbi('fresh', FRESH, PK);
await sbi('other signer', FRESH, PK2);
await sbi('violated', FRESHV, PK);
for (const [n, v] of variants(FRESH, { hostile: SMALL, lens: [] })) await sbi(n, v, PK);

const sign = (ev: any, sk = SK, pk = PK) => { try { return JSON.parse(ser((PR as any).signSafetyEvidence(JSON.parse(ser(ev)), fromB64u(sk), pk))); } catch { return null; } };
const SIGNED = sign(FRESH);
const SIGNEDV = sign(FRESHV);
const AV = act('pay', '/r', { amount: 101 });
const FULL = { signer: PK, action: A0, constitution: CS, state: ST1 };
const SIGNED_CS = JSON.parse(ser((PR as any).signConstitution(CS, fromB64u(SK))));
const vss = (n: string, sg: unknown, ex: unknown) => run('verifySignedSafetyEvidence', n, PR.verifySignedSafetyEvidence as any, [sg, ex]);
await vss('full', SIGNED, FULL);
await vss('violated, default', SIGNEDV, { ...FULL, action: AV });
await vss('violated, requireOk false', SIGNEDV, { ...FULL, action: AV, requireOk: false });
await vss('violated, requireOk true', SIGNEDV, { ...FULL, action: AV, requireOk: true });
await vss('ok evidence, requireOk false', SIGNED, { ...FULL, requireOk: false });
await vss('ok evidence, requireOk null', SIGNED, { ...FULL, requireOk: null });
await vss('ok evidence, requireOk 0', SIGNED, { ...FULL, requireOk: 0 });
await vss('digests only', SIGNED, { signer: PK, actionDigest: FRESH.action_digest, constitutionId: FRESH.constitution, stateDigest: FRESH.state_digest });
await vss('digests plus constitution (coverage)', SIGNED, { signer: PK, actionDigest: FRESH.action_digest, constitution: CS, stateDigest: FRESH.state_digest });
await vss('action + constitution only', SIGNED, { signer: PK, action: A0, constitution: CS, stateDigest: FRESH.state_digest });
await vss('action + state only', SIGNED, { signer: PK, action: A0, constitutionId: FRESH.constitution, state: ST1 });
await vss('constitution + state only', SIGNED, { signer: PK, actionDigest: FRESH.action_digest, constitution: CS, state: ST1 });
await vss('signers list', SIGNED, { ...FULL, signer: [PK2, PK] });
await vss('signers list without', SIGNED, { ...FULL, signer: [PK2] });
for (const sg of [[], [''], [PK, ''], [PK, 5], '', 5, null, undefined as any, {}, [null]]) await vss(`signer ${ser(sg ?? null)}`, SIGNED, { ...FULL, ...(sg === undefined ? { signer: undefined } : { signer: sg }) });
for (const [k] of Object.entries(FULL)) await vss(`expected ${k} deleted`, SIGNED, Object.fromEntries(Object.entries(FULL).filter(([x]) => x !== k)));
await vss('action not specified', SIGNED, { signer: PK, constitution: CS, state: ST1 });
await vss('constitution not specified', SIGNED, { signer: PK, action: A0, state: ST1 });
await vss('state not specified', SIGNED, { signer: PK, action: A0, constitution: CS });
for (const [k, v] of [['action', null], ['constitution', null], ['state', null], ['actionDigest', null], ['constitutionId', null], ['stateDigest', null]] as const) await vss(`expected ${k} null`, SIGNED, { ...FULL, [k]: v });
await vss('action and digest agree', SIGNED, { ...FULL, actionDigest: FRESH.action_digest });
await vss('action and digest disagree', SIGNED, { ...FULL, actionDigest: 'zzz' });
await vss('constitution and id agree', SIGNED, { ...FULL, constitutionId: FRESH.constitution });
await vss('constitution and id disagree', SIGNED, { ...FULL, constitutionId: 'zzz' });
await vss('state and digest agree', SIGNED, { ...FULL, stateDigest: FRESH.state_digest });
await vss('state and digest disagree', SIGNED, { ...FULL, stateDigest: 'zzz' });
await vss('other action', SIGNED, { ...FULL, action: act('pay', '/r', { amount: 11 }) });
await vss('other action digest', SIGNED, { ...FULL, action: undefined, actionDigest: 'zzz' });
await vss('other constitution', SIGNED, { ...FULL, constitution: only('cap') });
await vss('other constitution id', SIGNED, { ...FULL, constitution: undefined, constitutionId: 'zzz' });
await vss('other state', SIGNED, { ...FULL, state: chained() });
await vss('other state digest', SIGNED, { ...FULL, state: undefined, stateDigest: 'zzz' });
await vss('malformed expected constitution with its id', SIGNED, { ...FULL, constitution: { version: 2, principal: PK, invariants: [] } });
await vss('expected constitution null', SIGNED, { ...FULL, constitution: null });
await vss('expected action null', SIGNED, { ...FULL, action: null });
await vss('expected state null', SIGNED, { ...FULL, state: null });
await vss('expected state bad', SIGNED, { ...FULL, state: 5 });
await vss('expected state malformed object', SIGNED, { ...FULL, state: baseState({ seq: -1 }) });
// principal pins
await vss('principal ok', sign(FRESH), { ...FULL, constitution: SIGNED_CS, principal: PK });
await vss('principal pinned, signed constitution tampered', sign(FRESH), { ...FULL, constitution: { ...SIGNED_CS, principal: PK2 }, principal: PK2 });
await vss('principal other', sign(FRESH), { ...FULL, constitution: SIGNED_CS, principal: PK2 });
await vss('principal, unsigned constitution', sign(FRESH), { ...FULL, principal: PK });
await vss('principal, no constitution', SIGNED, { signer: PK, action: A0, constitutionId: FRESH.constitution, state: ST1, principal: PK });
await vss('principal null', sign(FRESH), { ...FULL, constitution: SIGNED_CS, principal: null });
await vss('principal number', sign(FRESH), { ...FULL, constitution: SIGNED_CS, principal: 5 });
await vss('principal empty', sign(FRESH), { ...FULL, constitution: SIGNED_CS, principal: '' });
await vss('principal, sig number', sign(FRESH), { ...FULL, constitution: { ...SIGNED_CS, sig: 5 }, principal: PK });
await vss('principal, bad sig', sign(FRESH), { ...FULL, constitution: { ...SIGNED_CS, sig: SIGNED_CS.sig.slice(0, -2) + 'AA' }, principal: PK });
await vss('principal, wrong id', sign(FRESH), { ...FULL, constitution: { ...SIGNED_CS, id: 'x' }, principal: PK });
await vss('principal, malformed constitution', sign(FRESH), { ...FULL, constitution: { ...SIGNED_CS, version: 2 }, principal: PK });
await vss('principal, constitution array', sign(FRESH), { ...FULL, constitution: [], principal: PK });
await vss('principal pin on the signed constitution, digests only', SIGNED, { signer: PK, actionDigest: FRESH.action_digest, constitution: SIGNED_CS, stateDigest: FRESH.state_digest, principal: PK });
// the signed object, retyped
for (const [n, v] of variants(SIGNED, { hostile: SMALL, lens: [] })) await vss(`signed ${n}`, v, FULL);
for (const [n, v] of variants(SIGNEDV, { hostile: SMALL, lens: [] })) await vss(`signedV ${n}`, v, { ...FULL, action: AV, requireOk: false });
for (const [n, v] of variants(FULL, { hostile: SMALL, lens: [], depth: 3 })) { const c = (v as any)?.constitution; if (c !== undefined && c !== null && (typeof c !== 'object' || Array.isArray(c))) continue; await vss(`expected ${n}`, SIGNED, v); }
for (const sg of [null, 5, 'x', [], true, {}, { evidence: null }, { evidence: [] }, { evidence: 'x' }, { evidence: {} }]) await vss(`signed ${ser(sg)}`, sg, FULL);
for (const ex of [null, 5, 'x', [], true, {}]) await vss(`expected ${ser(ex)}`, SIGNED, ex);
// forged evidence, re-signed so only the internal checks stand in the way
const forge = (patch: Record<string, unknown>, base = FRESH) => sign({ ...base, ...patch });
const rows = FRESH.evaluated;
const forgeCases: Array<[string, Record<string, unknown>, Record<string, unknown>?]> = [
  ['ok false, no violations', { ok: false }], ['ok true, a violation listed', { violated: ['x'] }], ['ok true, a violated row', { evaluated: [{ ...rows[0], result: 'violated' }, ...rows.slice(1)] }],
  ['ok true, row result missing', { evaluated: [{ id: rows[0].id, kind: rows[0].kind }, ...rows.slice(1)] }], ['ok true, row null', { evaluated: [null, ...rows.slice(1)] }], ['ok true, row string', { evaluated: ['x', ...rows.slice(1)] }],
  ['ok true, row id number', { evaluated: [{ ...rows[0], id: 5 }, ...rows.slice(1)] }], ['ok true, row id null', { evaluated: [{ ...rows[0], id: null }, ...rows.slice(1)] }], ['ok true, row id missing', { evaluated: [{ result: 'pass', kind: 'never' }, ...rows.slice(1)] }],
  ['ok true, evaluated empty', { evaluated: [] }], ['ok true, evaluated object', { evaluated: {} }], ['ok true, violated object', { violated: {} }], ['ok true, violated string', { violated: 'x' }], ['evaluated missing', { evaluated: undefined }], ['violated missing', { violated: undefined }],
  ['ok missing', { ok: undefined }], ['ok string', { ok: 'true' }], ['ok 1', { ok: 1 }], ['ok null', { ok: null }], ['ok number 0 with rows violated', { ok: 0, evaluated: [{ ...rows[0], result: 'violated' }] }],
  ['one row too many', { evaluated: [...rows, rows[0]] }], ['one row too few', { evaluated: rows.slice(1) }], ['rows reordered', { evaluated: [...rows].reverse() }], ['row id swapped', { evaluated: [{ ...rows[0], id: 'zz' }, ...rows.slice(1)] }],
  ['ids ok, kinds changed', { evaluated: rows.map((r: any) => ({ ...r, kind: 'never' })) }], ['extra row member', { evaluated: rows.map((r: any) => ({ ...r, extra: 1 })) }], ['now changed', { now: 5 }], ['version 2', { v: 2 }], ['now missing', { now: undefined }],
];
for (const [n, patch] of forgeCases) {
  for (const [exn, ex] of [['full', FULL], ['digests+constitution', { signer: PK, actionDigest: FRESH.action_digest, constitution: CS, stateDigest: FRESH.state_digest }], ['digests', { signer: PK, actionDigest: FRESH.action_digest, constitutionId: FRESH.constitution, stateDigest: FRESH.state_digest }]] as const) {
    if (forge(patch) === null) continue;
    await vss(`forged ${n} / ${exn}`, forge(patch), ex);
    await vss(`forged ${n} / ${exn} / requireOk false`, forge(patch), { ...ex, requireOk: false });
  }
}
// forged violation evidence
const rowsV = FRESHV.evaluated;
for (const [n, patch] of [['ok true', { ok: true }], ['violated emptied', { violated: [] }], ['rows all pass', { evaluated: rowsV.map((r: any) => ({ ...r, result: 'pass' })) }], ['reason changed', { evaluated: rowsV.map((r: any) => ({ ...r, reason: 'other' })) }], ['rows dropped', { evaluated: [] }], ['now changed', { now: 1 }]] as Array<[string, Record<string, unknown>]>)
  for (const rq of [undefined, false, true]) await vss(`forged violation ${n} / requireOk ${rq}`, forge(patch, FRESHV), { ...FULL, action: AV, ...(rq === undefined ? {} : { requireOk: rq }) });
// coverage branch: ids of the constitution vs rows, null rows
const C2 = con([INV.never, INV.cap]);
const E2 = (PR as any).proveSafety(A0, C2, baseState());
const D2 = { signer: PK, actionDigest: E2.action_digest, constitution: C2, stateDigest: E2.state_digest };
await vss('coverage ok', sign(E2), D2);
await vss('coverage rows swapped', sign({ ...E2, evaluated: [...E2.evaluated].reverse() }), D2);
await vss('coverage extra row', sign({ ...E2, evaluated: [...E2.evaluated, E2.evaluated[0]] }), D2);
await vss('coverage missing row', sign({ ...E2, evaluated: E2.evaluated.slice(1) }), D2);
await vss('coverage null row', sign({ ...E2, evaluated: [null, E2.evaluated[1]] }), D2);
await vss('coverage string row', sign({ ...E2, evaluated: ['x', E2.evaluated[1]] }), D2);
await vss('coverage number row', sign({ ...E2, evaluated: [5, E2.evaluated[1]] }), D2);
await vss('coverage id-less row', sign({ ...E2, evaluated: [{ result: 'pass' }, E2.evaluated[1]] }), D2);
await vss('coverage second row wrong', sign({ ...E2, evaluated: [E2.evaluated[0], { ...E2.evaluated[1], id: 'zz' }] }), D2);
await vss('coverage first row wrong', sign({ ...E2, evaluated: [{ ...E2.evaluated[0], id: 'zz' }, E2.evaluated[1]] }), D2);
await vss('coverage requireOk false', sign({ ...E2, evaluated: E2.evaluated.slice(1) }), { ...D2, requireOk: false });
await vss('coverage skipped when not ok', sign({ ...E2, ok: false, violated: ['n'], evaluated: [{ ...E2.evaluated[0], result: 'violated' }] }), D2);
await vss('coverage skipped when not ok, requireOk false', sign({ ...E2, ok: false, violated: ['n'], evaluated: [{ ...E2.evaluated[0], result: 'violated' }] }), { ...D2, requireOk: false });
await vss('coverage without constitution', sign({ ...E2, evaluated: [] }), { signer: PK, actionDigest: E2.action_digest, constitutionId: E2.constitution, stateDigest: E2.state_digest });
// signer / id / signature tampering
await vss('other signer signed', sign(FRESH, SK2, PK2), FULL);
await vss('other signer pinned', sign(FRESH, SK2, PK2), { ...FULL, signer: PK2 });
await vss('signer swapped', { ...SIGNED, signer: PK2 }, { ...FULL, signer: PK2 });
await vss('id changed', { ...SIGNED, id: SIGNED.id.slice(0, -1) + (SIGNED.id.endsWith('A') ? 'B' : 'A') }, FULL);
await vss('sig changed', { ...SIGNED, sig: SIGNED.sig.slice(0, -2) + (SIGNED.sig.endsWith('AA') ? 'BB' : 'AA') }, FULL);
for (let i = 0; i < 64; i += 9) { const b = fromB64u(SIGNED.sig); b[i] ^= 1; await vss(`sig byte ${i}`, { ...SIGNED, sig: pca.b64u(b) }, FULL); }
await vss('sig truncated', { ...SIGNED, sig: SIGNED.sig.slice(0, 40) }, FULL);
await vss('sig padded', { ...SIGNED, sig: SIGNED.sig + '=' }, FULL);
await vss('evidence changed after signing', { ...SIGNED, evidence: { ...SIGNED.evidence, now: 5 } }, FULL);
await vss('signed with the wrong domain id', { ...SIGNED, id: (PR as any).safetyBindingId(SIGNED.evidence, PK2) }, FULL);
await vss('signed extra members', { ...SIGNED, extra: 1 }, FULL);
await vss('constitution ok but evidence for the other', sign((PR as any).proveSafety(A0, only('cap'), ST1)), FULL);

// ---- check-and-advance --------------------------------------------------------------------------------------------------
const caa = (n: string, p: unknown, a: unknown, c: unknown, s: unknown, opts?: unknown) => run('checkAndAdvance', n, PR.checkAndAdvance as any, opts === undefined ? [p, a, c, s] : [p, a, c, s, opts]);
const S2 = chained({ ledger: { c: [E(1000, 40)] }, latched: { na: NOW - 3 } });
for (const permitted of [true, false]) for (const [an, a] of ACTIONS.filter((_, i) => [0, 3, 5, 12, 17, 18, 22, 25, 26, 28, 30, 31, 33, 34, 37, 38, 44, 50, 55].includes(i))) for (const [sn, s] of [STATES[0]!, STATES[1]!, STATES[2]!, STATES[3]!, ['S2', S2] as [string, unknown]])
  await caa(`permitted ${permitted} / ${an} / ${sn}`, permitted, a, CS, s);
for (const permitted of [true, false]) for (const k of KINDS) for (const [an, a] of ACTIONS.filter((_, i) => [0, 5, 18, 22, 25, 26, 28, 30, 31, 33, 34].includes(i))) await caa(`permitted ${permitted} / ${k} / ${an}`, permitted, a, only(k), S2);
const SD = (PR as any).stateDigest(S2);
for (const seq of [3, 2, 4, 0, -0, 3.5, '3', true, [], {}, null]) { await caa(`expectedSeq ${ser(seq)}`, true, A0, CS, S2, { expectedSeq: seq }); await caa(`expectedSeq ${ser(seq)} not permitted`, false, A0, CS, S2, { expectedSeq: seq }); }
for (const dg of [SD, 'zzz', '', SD + 'x']) { await caa(`expectedStateDigest ${dg.slice(0, 6)}${dg.length}`, true, A0, CS, S2, { expectedStateDigest: dg }); await caa(`expectedStateDigest ${dg.slice(0, 6)}${dg.length} not permitted`, false, A0, CS, S2, { expectedStateDigest: dg }); }
await caa('both guards ok', true, A0, CS, S2, { expectedSeq: 3, expectedStateDigest: SD });
await caa('seq ok digest bad', true, A0, CS, S2, { expectedSeq: 3, expectedStateDigest: 'zzz' });
await caa('seq bad digest ok', true, A0, CS, S2, { expectedSeq: 2, expectedStateDigest: SD });
await caa('seq guard with bad state', true, A0, CS, 5, { expectedSeq: 3 });
await caa('digest guard with bad state', true, A0, CS, 5, { expectedStateDigest: 'zzz' });
await caa('digest guard with unhashable state', true, A0, CS, baseState({ ledger: { c: [{ t: -0, amount: 1 }] } }), { expectedStateDigest: 'zzz' });
await caa('seq guard on null state', true, A0, CS, null, { expectedSeq: 0 });
await caa('opts empty', true, A0, CS, S2, {});
await caa('opts with undefined guards', true, A0, CS, S2, { expectedSeq: undefined, expectedStateDigest: undefined });
await caa('unhashable action, permitted', true, act('pay', '/r', { amount: -0 }), CS, S2);
await caa('unhashable constitution, permitted', true, A0, con([{ ...INV.cap, max: -0 }]), S2);
await caa('advance fails after allow (unresolvable cap amount handled by monitor)', true, act('pay', '/r', {}), CS, S2);
await caa('advance fails: ledger overflow on rate', true, act('call', '/api/x'), con([{ ...INV.rate, max: 10_000, window_secs: 100 }]), baseState({ ledger: { r: bigE(10_000, () => 1) } }));
await caa('merge overflow allowed', true, act('pay', '/r', { amount: 1 }), con([{ ...INV.cap, max: 1e12, window_secs: undefined }]), baseState({ ledger: { c: bigE(10_000) } }));
await caa('advance invalid result: now regression is impossible, deadline state', true, A0, CS, baseState({ deadlines: { d: 3 } }));
// a primitive constitution digests as its object rest in the reference (`{...5}` is `{}`): not part of the shared contract
for (const [n, v] of variants(CS, { hostile: SMALL, depth: 3 })) if (!n.startsWith('/ =')) await caa(`CS ${n}`, true, A0, v, S2);
for (const [n, v] of variants(S2, { hostile: SMALL })) await caa(`S ${n}`, true, A0, CS, v);

// ---- constitutions: id, signature, whenAffirmative -------------------------------------------------------------------------
const cid = (n: string, c: unknown) => (c !== null && typeof c === 'object' && !Array.isArray(c) ? run('constitutionId', n, PR.constitutionId as any, [c]) : false);
await cid('base', CS);
await cid('signed ignores id and sig', SIGNED_CS);
await cid('id and sig changed', { ...SIGNED_CS, id: 'x', sig: 'y' });
await cid('key order', { invariants: CS.invariants, principal: PK, version: 1 });
for (const [n, v] of variants(CS, { hostile: SMALL, depth: 3 })) await cid(n, v);
const vcs = (n: string, sc: unknown, p?: unknown) => run('verifyConstitution', n, PR.verifyConstitution as any, p === undefined ? [sc] : [sc, p]);
await vcs('signed', SIGNED_CS);
await vcs('signed, principal', SIGNED_CS, PK);
await vcs('signed, other principal', SIGNED_CS, PK2);
await vcs('signed, principal empty', SIGNED_CS, '');
await vcs('unsigned', CS);
await vcs('unsigned, principal', CS, PK);
await vcs('signed by another key', JSON.parse(ser((PR as any).signConstitution(CS, fromB64u(SK2)))));
await vcs('principal is the other key, signed by it', JSON.parse(ser((PR as any).signConstitution({ ...CS, principal: PK2 }, fromB64u(SK2)))));
await vcs('principal is the other key, signed by the first', JSON.parse(ser((PR as any).signConstitution({ ...CS, principal: PK2 }, fromB64u(SK)))));
for (const [n, v] of variants(SIGNED_CS, { hostile: SMALL, lens: [], depth: 3 })) await vcs(n, v);
for (const [n, v] of variants(SIGNED_CS, { hostile: SMALL, lens: [], depth: 1 })) await vcs(`pinned ${n}`, v, PK);
for (const sc of [null, 5, 'x', [], true, {}]) await vcs(`not a constitution ${ser(sc)}`, sc);
for (let i = 0; i < 64; i += 9) { const b = fromB64u(SIGNED_CS.sig); b[i] ^= 1; await vcs(`sig byte ${i}`, { ...SIGNED_CS, sig: pca.b64u(b) }); }
await vcs('sig truncated', { ...SIGNED_CS, sig: SIGNED_CS.sig.slice(0, 40) });
await vcs('sig padded', { ...SIGNED_CS, sig: SIGNED_CS.sig + '=' });
await vcs('id wrong', { ...SIGNED_CS, id: 'x' });
await vcs('id number', { ...SIGNED_CS, id: 5 });
await vcs('sig number', { ...SIGNED_CS, sig: 5 });
await vcs('principal not a key', JSON.parse(ser((PR as any).signConstitution({ ...CS, principal: 'abc' }, fromB64u(SK)))));
const wa = (n: string, w: unknown, ctx: unknown) => (ctx !== null && typeof ctx === 'object' && !Array.isArray(ctx) ? run('whenAffirmative', n, PR.whenAffirmative as any, [w, ctx]) : false);
const WACTS = [act('review'), act('review', '/x', { ok: true }), act('review', '/x', { ok: false }), act('deploy', '/prod/db'), act('call', '/api/x'), act('call', '/other'), {}, { action: null }, act(5)];
for (const [i, w] of WHENS.entries()) for (const [j, a] of WACTS.entries()) await wa(`when#${i} act#${j}`, w, a);
for (const w of [{ verb: 'review', where: [{ field: 'action.params.ok', op: 'eq', value: true }] }, { verb: ['review', 'deploy'] }, { verb: 'review', resource: '/x' }, { verb: 'review', resource: 're:/x.*' }, { verb: 'review', where: [{ field: 'action.params.ok', op: 'exists' }] }])
  for (const [j, a] of WACTS.entries()) await wa(`where ${ser(w).slice(0, 40)} act#${j}`, w, a);
// several problems: the first one is the reason
for (const bad of [{ version: 2, principal: '', invariants: [] }, { version: 2, principal: '', invariants: 'x' }, { version: 2, principal: PK, invariants: [{ id: 'a', kind: 'x' }, { id: 'b', kind: 'y' }] }]) {
  await vcs(`two problems ${ser(bad).slice(0, 40)}`, bad);
  await adv(`two problems ${ser(bad).slice(0, 40)}`, A0, bad, baseState(), NOW);
  await chk(`two problems ${ser(bad).slice(0, 40)}`, A0, bad, baseState());
}
// signed evidence of several violations: the verdict joins every id
{
  const cMany = con([INV.never, { ...INV.never, id: 'n2' }, { ...INV.never, id: 'n3', description: 'third' }]);
  const aMany = act('delete', '/prod/db');
  const eMany = (PR as any).proveSafety(aMany, cMany, baseState());
  const sMany = sign(eMany);
  await vss('several violations, full', sMany, { signer: PK, action: aMany, constitution: cMany, state: baseState() });
  await vss('several violations, digests', sMany, { signer: PK, actionDigest: eMany.action_digest, constitutionId: eMany.constitution, stateDigest: eMany.state_digest });
  await vss('several violations, requireOk false', sMany, { signer: PK, actionDigest: eMany.action_digest, constitutionId: eMany.constitution, stateDigest: eMany.state_digest, requireOk: false });
  await vse('several violations, recomputed', eMany, aMany, cMany, baseState());
  for (const violated of [[null, 'a'], ['a', null], [['b', 'c'], 'd'], [5, 'a', true], [{}, 'x'], ['a'], ['a', 'b'], [[], 'z'], ['é', '']]) {
    const forged = sign({ ...eMany, violated });
    await vss(`violated list ${ser(violated)}`, forged, { signer: PK, actionDigest: eMany.action_digest, constitutionId: eMany.constitution, stateDigest: eMany.state_digest });
  }
  // the constitution of the expectation malformed in several ways, bound by id
  for (const bad of [{ version: 2, principal: '', invariants: [] }, { version: 1, principal: PK, invariants: [{ id: 'a', kind: 'x' }, { id: 'a', kind: 'y' }] }]) {
    const ev = sign({ ...FRESH, constitution: (PR as any).constitutionId(bad) });
    await vss(`expected constitution malformed in several ways ${ser(bad).slice(0, 30)}`, ev, { ...FULL, constitution: bad });
  }
}
// a constitution the canonical hash refuses: verification fails closed
{
  const exo = { ...SIGNED_CS, invariants: [{ ...INV.cap, max: -0 }] };
  await vcs('exotic invariant', exo);
  await vcs('exotic invariant, principal', exo, PK);
  await vcs('exotic principal', { ...SIGNED_CS, principal: 'p', extra: -0 });
  // the advance itself pushes the state over the 100000-entry limit: the resulting state is refused
  const full = { ...many(9, () => ents(10_000)), c: ents(9999), z: ents(1) };
  const capOnly = only('cap', { max: 1e12, window_secs: undefined });
  await adv('resulting state over the entry limit', act('pay', '/r', { amount: 1 }), capOnly, baseState({ ledger: full }));
  await caa('resulting state over the entry limit', true, act('pay', '/r', { amount: 1 }), capOnly, baseState({ ledger: full }));
}
void r;
void nameN;

o.write();
