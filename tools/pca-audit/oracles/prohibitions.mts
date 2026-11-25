// Oracle: the prohibitions.ts surface that neither prohibition-vectors.json nor oracles-base/prohibitions-oracle.mts (base-prohibitions) exercises:
// the constants, validateWhen, whenMatches, signConstitution, advanceState (the non-strict wrapper), evidenceDigest and composeAuthority.
// Together with those two corpora every exported name of prohibitions.ts is replayed (see the coverage table in the foundation notes).
// Deterministic (Ed25519 is deterministic). Secrets appear only as {"$seed": "<label>"}: the native derives the 32-byte Ed25519 seed as
// sha256("atlas-pca-conformance/" + label). A refusal is {"$throws": ...}: the native must throw (the message is not compared).
// PORTING (fn(args) -> native entry point; compared by JSON value):
//   constants() -> {CONSTITUTION_VERSION, CONSTITUTION_SIG_DOMAIN, EVIDENCE_VERSION, SAFETY_EVIDENCE_SIG_DOMAIN, STATE_DIGEST_DOMAIN, STATE_CHAIN_DOMAIN, MAX_LEDGER, MAX_INVARIANTS, MAX_DEADLINE}
//   validateWhen(w, label) -> string | null       the exact message, label as prefix
//   whenMatches(w, ctx) -> bool                    conservative match (unresolvable => true); ctx is an action context {action: {verb, resource, params?, ...}}
//   signConstitution(c, {$seed}) -> SignedConstitution (id, sig included)   throws on a malformed constitution
//   advanceState(action, c, state [, now]) -> state    the input state unchanged when the strict advance refuses; the 4th arg is absent or present
//   evidenceDigest(ev) -> string                   hashCanonical of the evidence (throws on a value the canonical hash refuses)
//   composeAuthority(permitted, action, c, state) -> {allow, decidedBy, permitted, prohibition}   permitted is ANDed only when === true
import * as PR0 from '../../../packages/pca/src/prohibitions.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, seed, ser, HOSTILE } from './lib.mjs';

const PR: any = (PR0 as any).default ?? PR0;
const P: any = (P0 as any).publicKeyOf ? P0 : (P0 as any).default;
const o = new Oracle('prohibitions', 'tools/pca-audit/oracles/prohibitions.mts', 'TS-reference oracle for the prohibitions.ts names the shared vectors and base-prohibitions do not reach.');
const uniq = (fn: string, name: string) => { let nm = name; for (let i = 2; o.names.has(`${fn}/${nm}`); i++) nm = `${name} #${i}`; return nm; };
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$seed === 'string' && Object.keys(v).length === 1) return seed(v.$seed);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const S = (l: string) => ({ $seed: 'prohibitions/' + l });
const PK = P.b64u(P.publicKeyOf(seed('prohibitions/principal')));
const NOW = 1_700_000_000_000;
let n = 0;
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => {
  try { ser(args); } catch { return Promise.resolve(false); }
  return o.run(fn, uniq(fn, name), (...a: any[]) => f(...un(a)), args);
};

const act = (verb: unknown, resource: unknown = '/r', params?: unknown, extra: Record<string, unknown> = {}) => ({ action: { verb, resource, ...(params !== undefined ? { params } : {}), ...extra } });
const APPROVED = { field: 'action.params.approved', op: 'eq', value: true };
const INV: Record<string, any> = {
  never: { id: 'n', kind: 'never', when: { verb: 'delete', resource: '/prod/db' } },
  never_unless: { id: 'nu', kind: 'never_unless', when: { verb: ['wire', 'pay'], where: [{ field: 'action.params.amount', op: 'gt', value: 1000 }] }, unless: [APPROVED] },
  cap: { id: 'c', kind: 'cap', when: { verb: 'pay' }, amount: 'action.params.amount', max: 100, window_secs: 60 },
  rate: { id: 'r', kind: 'rate', when: { verb: 'call', resource: 're:/api/.*' }, max: 3, window_secs: 10 },
  never_after: { id: 'na', kind: 'never_after', after: { verb: 'export' }, forbid: { verb: 'delete' } },
  require_prior: { id: 'rp', kind: 'require_prior', when: { verb: 'deploy' }, prior: { verb: 'review' } },
  require_approval_over: { id: 'ra', kind: 'require_approval_over', when: { verb: 'refund' }, amount: 'action.params.amount', threshold: 50, approved: [APPROVED] },
};
const KINDS = Object.keys(INV);
const con = (invariants: unknown[], extra: Record<string, unknown> = {}) => ({ version: 1, principal: PK, invariants, ...extra });
const CS = con(KINDS.map((k) => INV[k]));
const st = (over: Record<string, unknown> = {}) => ({ now: NOW, seq: 0, parent: null, ledger: {}, latched: {}, ...over });
const PARENT = 'p'.repeat(43);

// ---- constants
await run('constants', 'all', () => ({
  CONSTITUTION_VERSION: PR.CONSTITUTION_VERSION, CONSTITUTION_SIG_DOMAIN: PR.CONSTITUTION_SIG_DOMAIN, EVIDENCE_VERSION: PR.EVIDENCE_VERSION,
  SAFETY_EVIDENCE_SIG_DOMAIN: PR.SAFETY_EVIDENCE_SIG_DOMAIN, STATE_DIGEST_DOMAIN: PR.STATE_DIGEST_DOMAIN, STATE_CHAIN_DOMAIN: PR.STATE_CHAIN_DOMAIN,
  MAX_LEDGER: PR.MAX_LEDGER, MAX_INVARIANTS: PR.MAX_INVARIANTS, MAX_DEADLINE: PR.MAX_DEADLINE,
}), []);

// ---- validateWhen / whenMatches
const WHENS: unknown[] = [
  { verb: 'v' }, { verb: ['a', 'b'] }, { verb: '' }, { verb: [] }, { verb: ['a', ''] }, { verb: ['a', 1] }, { verb: 5 }, {}, { resource: '/x' }, null, 'x', [], 7, true,
  { verb: 'v', resource: '' }, { verb: 'v', resource: 5 }, { verb: 'v', resource: null }, { verb: 'v', resource: 're:' }, { verb: 'v', resource: 're:a+' }, { verb: 'v', resource: 're:/api/.*' },
  { verb: 'v', resource: 're:(' }, { verb: 'v', resource: 're:' + 'a'.repeat(200) }, { verb: 'v', resource: 're:' + 'a'.repeat(201) }, { verb: 'v', resource: 're:(a+)+$' },
  { verb: 'v', resource: 're:[' }, { verb: 'v', resource: '/prod/' }, { verb: 'v', where: [] }, { verb: 'v', where: {} }, { verb: 'v', where: null }, { verb: 'v', where: [APPROVED] },
  { verb: 'v', where: [APPROVED, { field: 'x', op: 'bogus' }] }, { verb: 'v', where: [{}] }, { verb: 'v', where: [{ field: '', op: 'eq' }] },
  { verb: 'v', where: [{ not: APPROVED }] }, { verb: 'v', where: [{ all_of: [] }] }, { verb: 'v', where: [{ any_of: [APPROVED, { field: 'q', op: 'exists' }] }] },
  { verb: 'v', where: [{ field: 'a', op: 'eq', ref: '' }] }, { verb: 'v', where: [{ field: 'a', op: 'member_of', collection: '' }] }, { verb: 'v', where: [{ field: 'a', op: 'member_of', collection: 'c' }] },
  { verb: 'v', where: [{ field: 'action.params.amount', op: 'gt', value: 1000 }] }, { verb: 'v', where: [{ field: 'action.params.amount', op: 'lte', value: 5 }] },
  { verb: 'v', where: [{ field: 'action.params.name', op: 'prefix', value: 'ab' }] }, { verb: 'v', where: [{ field: 'action.params.name', op: 'matches', value: 'a+b' }] },
  { verb: 'v', where: [{ field: 'action.params.name', op: 'matches', value: '(' }] }, { verb: 'v', where: [{ field: 'action.params.tags', op: 'in', value: ['x'] }] },
  { verb: 'v', where: [{ field: 'action.params.missing', op: 'eq', value: 1 }] }, { verb: 'v', where: [{ field: 'action.params.amount', op: 'eq', ref: 'action.params.limit' }] },
  { verb: 'v', where: [{ field: 'action.params.amount', op: 'eq', ref: 'action.params.gone' }] }, { verb: 'v', where: [{ field: 'action.params.amount', op: 'lt', value: 'ten' }] },
  { verb: 'v', where: [{ not: { field: 'action.params.amount', op: 'gt', value: 5 } }] },
  { verb: ['pay', 'wire'], resource: '/a/b', where: [{ field: 'action.params.amount', op: 'gt', value: 10 }] },
  { verb: 'v', extra_member: 1 }, { verb: 'v', where: [{ all_of: [{ not: { not: { field: 'x', op: 'exists' } } }] }] },
];
let deep: any = { field: 'x', op: 'exists' };
for (let i = 0; i < 33; i++) deep = { not: deep };
WHENS.push({ verb: 'v', where: [deep] });
let deep32: any = { field: 'x', op: 'exists' };
for (let i = 0; i < 32; i++) deep32 = { not: deep32 };
WHENS.push({ verb: 'v', where: [deep32] });
for (const [i, w] of WHENS.entries()) for (const label of ['when', 'p', 'q', 'after', '']) await run('validateWhen', `when#${i} ${label || 'empty'}`, PR.validateWhen, [w, label]);
for (const label of [null, 5]) await run('validateWhen', `label ${ser(label ?? null)}`, PR.validateWhen, [{ verb: '' }, label]);

const CTXS: unknown[] = [
  act('v'), act('v', '/prod/db'), act('v', '/api/x', { amount: 2000, name: 'ab', tags: ['x'], limit: 2000, approved: true }), act('v', '/api/x', { amount: 5 }),
  act('pay', '/a/b', { amount: 11 }), act('wire', '/a/b', { amount: 9 }), act('v', '/x/y', { amount: '12', name: 'aab', approved: false }), act('v', '', {}),
  act('v', '/p', { amount: 1e21, name: 5 }), act('v', 'é'), act('v', '/' + 'a'.repeat(5000)), act('v', '/api/' + 'a'.repeat(5000)),
  { action: { verb: 5, resource: '/r' } }, { action: { verb: 'v', resource: 5 } }, { action: { verb: 'v' } }, { action: null }, { action: [] }, {}, null, 'x', 5, [],
  act('v', '/r', null), act('v', '/r', [1]), act('v', '/r', { amount: null }), act('v', '/r', { amount: -0 }),
  { action: { verb: 'v', resource: '/r', params: { amount: 7 } }, principal: 'p', context: { limit: 7 } },
  act('v', '/r', { name: 'a'.repeat(200) }), act('v', '/r', { name: '(' }),
];
for (const [i, w] of WHENS.entries()) for (const [j, ctx] of CTXS.entries()) {
  // sample the grid: every when against the first 8 contexts, every context against a spread of whens
  if (j < 8 || (i + j) % 5 === 0) await run('whenMatches', `when#${i} ctx#${j}`, PR.whenMatches, [w, ctx]);
}

// ---- signConstitution
const sc = (name: string, c: unknown, key: unknown = S('principal')) => run('signConstitution', name, PR.signConstitution, [c, key]);
await sc('all kinds', CS);
for (const k of KINDS) await sc(`only ${k}`, con([INV[k]]));
await sc('empty invariants', con([]));
await sc('issued_at', con([INV.never], { issued_at: NOW }));
await sc('other key', CS, S('other'));
await sc('description', con([{ ...INV.never, description: 'no deletes' }]));
await sc('unknown member', con([INV.never], { extra: [1, { a: null }] }));
for (const [nm, c] of [
  ['not an object', null], ['array', []], ['version 2', { ...CS, version: 2 }], ['no version', { principal: PK, invariants: [] }], ['no principal', { version: 1, invariants: [] }], ['empty principal', con([], { principal: '' })],
  ['invariants not array', con([]) && { version: 1, principal: PK, invariants: {} }], ['dup ids', con([INV.never, INV.never])], ['bad invariant', con([{ id: 'x', kind: 'nope' }])],
  ['forbidden id', con([{ ...INV.never, id: '__proto__' }])], ['too many', con(Array.from({ length: 257 }, (_, i) => ({ ...INV.never, id: 'n' + i })))],
  ['256 ok', con(Array.from({ length: 256 }, (_, i) => ({ ...INV.never, id: 'n' + i })))],
  ['unhashable', con([{ ...INV.never, description: '\ud800' }])], ['negative zero issued_at', con([INV.never], { issued_at: -0 })], ['id given is replaced', { ...CS, id: 'forged', sig: 'forged' }],
] as [string, any][]) await sc(nm, c);
for (const [nm, k] of [['null key', null], ['string key', 'abc'], ['number key', 5]] as [string, any][]) await sc('key ' + nm, CS, k);

// ---- advanceState (the non-strict wrapper) and composeAuthority
const A_OK = act('pay', '/r', { amount: 10 });
const ACTIONS: Array<[string, unknown]> = [
  ['pay 10', A_OK], ['pay over cap', act('pay', '/r', { amount: 500 })], ['delete prod', act('delete', '/prod/db')], ['delete other', act('delete', '/other')], ['export', act('export')],
  ['deploy', act('deploy')], ['review', act('review')], ['refund 80', act('refund', '/r', { amount: 80 })], ['refund 80 approved', act('refund', '/r', { amount: 80, approved: true })], ['refund 20', act('refund', '/r', { amount: 20 })],
  ['wire big', act('wire', '/r', { amount: 5000 })], ['wire big approved', act('wire', '/r', { amount: 5000, approved: true })], ['call api', act('call', '/api/x')], ['pay no amount', act('pay', '/r', {})],
  ['malformed verb', { action: { verb: 5, resource: '/r' } }], ['no action', {}], ['null', null], ['string', 'x'], ['no params pay', act('pay')],
];
const STATES: Array<[string, unknown]> = [
  ['genesis', st()], ['chained', st({ seq: 3, parent: PARENT })], ['spent', st({ seq: 1, parent: PARENT, ledger: { c: [{ t: NOW - 1000, amount: 95 }] } })], ['rate full', st({ seq: 3, parent: PARENT, ledger: { r: [{ t: NOW - 100, amount: 1 }, { t: NOW - 50, amount: 1 }, { t: NOW - 10, amount: 1 }] } })],
  ['latched export', st({ seq: 1, parent: PARENT, latched: { na: NOW - 5 } })], ['latched review', st({ seq: 1, parent: PARENT, latched: { rp: NOW - 5 } })], ['malformed', { now: 'x' }], ['null', null], ['seq neg', st({ seq: -1 })], ['future ledger', st({ ledger: { c: [{ t: NOW + 5, amount: 1 }] } })],
];
const CONS: Array<[string, unknown]> = [['all kinds', CS], ['none', con([])], ['cap only', con([INV.cap])], ['invalid', con([{ id: 'x', kind: 'zz' }])], ['not object', null], ['no-op version', { ...CS, version: 9 }]];
for (const [an, a] of ACTIONS) for (const [sn, s] of STATES) {
  await run('composeAuthority', `true ${an} | ${sn} | all kinds`, PR.composeAuthority, [true, a, CS, s]);
  await run('advanceState', `${an} | ${sn} | all kinds`, PR.advanceState, [a, CS, s]);
}
for (const [cn, c] of CONS) for (const p of [true, false]) {
  for (const [an, a] of ACTIONS.slice(0, 8)) await run('composeAuthority', `${p} ${an} | genesis | ${cn}`, PR.composeAuthority, [p, a, c, st()]);
  for (const [an, a] of ACTIONS.slice(0, 4)) await run('advanceState', `${an} | spent | ${cn}`, PR.advanceState, [a, c, STATES[2]![1]]);
}
for (const p of [1, 0, 'true', 'false', null, {}, [], [true], 2, -1, NaN as any, undefined as any]) {
  const pj = (() => { try { return ser(p ?? null); } catch { return 'nan'; } })();
  if (pj === 'nan') continue;
  for (const [an, a] of [ACTIONS[0]!, ACTIONS[2]!]) await run('composeAuthority', `permitted ${pj} ${an}`, PR.composeAuthority, [p ?? null, a, CS, st()]);
}
for (const now of [NOW, NOW + 1, NOW + 1e9, NOW - 1, 0, -1, 1.5, '1', null, 1e21, -0, 2 ** 53]) for (const [an, a] of [ACTIONS[0]!, ACTIONS[7]!, ACTIONS[2]!]) {
  await run('advanceState', `now ${ser(now)} ${an}`, PR.advanceState, [a, CS, STATES[1]![1], now]);
}
// window pruning and ledger bound through the wrapper
await run('advanceState', 'prune expired cap entry', PR.advanceState, [A_OK, CS, st({ seq: 1, parent: PARENT, ledger: { c: [{ t: NOW - 61_000, amount: 99 }, { t: NOW - 1000, amount: 1 }] } }), NOW + 5000]);
await run('advanceState', 'tick forward 70s drops the window', PR.advanceState, [A_OK, CS, st({ seq: 1, parent: PARENT, ledger: { c: [{ t: NOW - 1000, amount: 99 }] } }), NOW + 70_000]);
await run('advanceState', 'rate overflow refuses (state returned)', PR.advanceState, [act('call', '/api/y'), con([{ ...INV.rate, max: 1_000_000, window_secs: undefined }]), st({ seq: 1, parent: PARENT, ledger: { r: Array.from({ length: PR.MAX_LEDGER }, (_, i) => ({ t: NOW - 20_000 + i, amount: 1 })) } })]);

// ---- evidenceDigest
const evOf = (a: unknown, c: unknown, s: unknown) => PR.proveSafety(a, c, s);
for (const [an, a] of ACTIONS.slice(0, 14)) for (const [sn, s] of STATES.slice(0, 5)) await run('evidenceDigest', `${an} | ${sn}`, PR.evidenceDigest, [evOf(a, CS, s)]);
const EV = evOf(A_OK, CS, st());
await run('evidenceDigest', 'member order is irrelevant', PR.evidenceDigest, [{ ok: EV.ok, violated: EV.violated, evaluated: EV.evaluated, now: EV.now, state_digest: EV.state_digest, action_digest: EV.action_digest, constitution: EV.constitution, v: EV.v }]);
for (const [nm, v] of [['null', null], ['string', 'x'], ['number', 5], ['array', [EV]], ['empty', {}], ['extra member', { ...EV, x: 1 }], ['ok flipped', { ...EV, ok: !EV.ok }], ['now -0', { ...EV, now: -0 }], ['now 2^53', { ...EV, now: 2 ** 53 }], ['now 1.5', { ...EV, now: 1.5 }],
  ['now tiny', { ...EV, now: 1e-7 }], ['lone surrogate', { ...EV, constitution: '\ud800' }], ['unicode', { ...EV, constitution: 'é\u{1F600}' }], ['evaluated emptied', { ...EV, evaluated: [] }], ['nested -0', { ...EV, evaluated: [{ id: 'n', kind: 'never', result: 'pass', reason: -0 }] }],
] as [string, any][]) await run('evidenceDigest', nm, PR.evidenceDigest, [v]);
for (const h of HOSTILE) await run('evidenceDigest', `field v ${ser(h)}`, PR.evidenceDigest, [{ ...EV, v: h }]);

refWrite(o, 'prohibitions');
void n;
