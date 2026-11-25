// Oracle: the whole contracts.ts surface (bounded safety-LTL behavioural contracts), generated over a clause x action x state space, to sit beside
// conformance/contracts-vectors.json (validate, check, advance, verify, enforcer rows). This corpus adds the names the vectors never call
// directly: validateClause, contractId, signContract, embeddedConstitution, contractFromConstitution, checkAndAdvanceContract, the constants, and a
// wider checkContract / advanceContract grid (every clause kind, nesting, deadlines, CAS guards, malformed inputs).
// Deterministic (Ed25519 is deterministic). Secrets appear only as {"$seed": "<label>"}: the native derives the 32-byte Ed25519 seed as
// sha256("atlas-pca-conformance/" + label). A refusal is {"$throws": ...}: the native must throw (the message is not compared).
// PORTING (fn(args) -> native entry point; compared by JSON value):
//   constants() -> {CONTRACT_VERSION, CONTRACT_SIG_DOMAIN, MAX_CLAUSES, MAX_CLAUSE_DEPTH}
//   validateClause(clause, seenIds, depth) -> string[]     seenIds is an array of ids already taken (the native builds a set from it); the output is the exact problem list
//   contractId(c) -> string                                 hashCanonical of the body without id/sig (throws on an unhashable value)
//   signContract(c, {$seed}) -> SignedContract              throws on a malformed contract
//   embeddedConstitution(c) -> {version: 1, principal, invariants}    invariants is c.invariants when an array, else []
//   contractFromConstitution(c) -> {version: 1, principal, invariants, clauses: []}
//   checkContract(action, contract, state) -> {ok, violated, reasons, evaluated}
//   advanceContract(state, action, contract [, opts]) -> {ok, violated, reasons, evaluated, next, decidedBy}   opts: {expectedSeq?, expectedStateDigest?, now?}
//   checkAndAdvanceContract(permitted, state, action, contract [, opts]) -> advanceContract's result + {allow, permitted}   permitted is ANDed only when === true
import * as C0 from '../../../packages/pca/src/contracts.ts';
import * as PR0 from '../../../packages/pca/src/prohibitions.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, seed, ser } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const PR: any = (PR0 as any).default ?? PR0;
const P: any = (P0 as any).publicKeyOf ? P0 : (P0 as any).default;
const o = new Oracle('contracts', 'tools/pca-audit/oracles/contracts.mts', 'TS-reference oracle for the contracts.ts surface (clauses, contract id / signature, check, advance, check-and-advance).');
const uniq = (fn: string, name: string) => { let nm = name; for (let i = 2; o.names.has(`${fn}/${nm}`); i++) nm = `${name} #${i}`; return nm; };
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$seed === 'string' && Object.keys(v).length === 1) return seed(v.$seed);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const S = (l: string) => ({ $seed: 'contracts/' + l });
const PK = P.b64u(P.publicKeyOf(seed('contracts/principal')));
const NOW = 1_700_000_000_000;
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => {
  try { ser(args); } catch { return Promise.resolve(false); }
  return o.run(fn, uniq(fn, name), (...a: any[]) => f(...un(a)), args);
};

const act = (verb: unknown, resource: unknown = '/r', params?: unknown) => ({ action: { verb, resource, ...(params !== undefined ? { params } : {}) } });
const W = (verb: unknown, extra: Record<string, unknown> = {}) => ({ verb, ...extra });
const st = (over: Record<string, unknown> = {}) => ({ now: NOW, seq: 0, parent: null, ledger: {}, latched: {}, ...over });
const PARENT = 'p'.repeat(43);
const INV_CAP = { id: 'cap', kind: 'cap', when: W('pay'), amount: 'action.params.amount', max: 100, window_secs: 60 };
const INV_NEVER = { id: 'nodel', kind: 'never', when: W('delete', { resource: '/prod/db' }) };
const CL: Record<string, any> = {
  always: { id: 'al', kind: 'always', p: W(['read', 'list', 'write', 'noop', 'open', 'close', 'review', 'deploy', 'approve', 'ship', 'pay', 'x1', 'y0', 'y1']) },
  never: { id: 'nv', kind: 'never', p: W('drop') },
  precedes: { id: 'pc', kind: 'precedes', p: W('review'), q: W('deploy') },
  requires_prior: { id: 'rq', kind: 'requires_prior', q: W('ship'), p: W('approve') },
  responds_within: { id: 'rw', kind: 'responds_within', p: W('open'), q: W('close'), within: 3 },
  and: { id: 'an', kind: 'and', clauses: [{ id: 'an1', kind: 'never', p: W('x1') }, { id: 'an2', kind: 'precedes', p: W('y0'), q: W('y1') }] },
};
const KINDS = Object.keys(CL);
const con = (clauses: unknown[] | undefined, invariants: unknown[] | undefined = undefined, extra: Record<string, unknown> = {}) => ({
  version: 1, principal: PK, ...(invariants !== undefined ? { invariants } : {}), ...(clauses !== undefined ? { clauses } : {}), ...extra,
});
const ALL = con(KINDS.map((k) => CL[k]), [INV_CAP, INV_NEVER]);

await run('constants', 'all', () => ({ CONTRACT_VERSION: C.CONTRACT_VERSION, CONTRACT_SIG_DOMAIN: C.CONTRACT_SIG_DOMAIN, MAX_CLAUSES: C.MAX_CLAUSES, MAX_CLAUSE_DEPTH: C.MAX_CLAUSE_DEPTH }), []);

// ---- validateClause(clause, seen[], depth)
const vcl = (name: string, cl: unknown, seen: string[] = [], depth = 1) => run('validateClause', name, (c: any, s: string[], d: number) => C.validateClause(c, new Set(s), d), [cl, seen, depth]);
for (const k of KINDS) await vcl(`${k} ok`, CL[k]);
const nest = (d: number): any => (d === 0 ? { id: 'leaf', kind: 'never', p: W('z') } : { id: 'and' + d, kind: 'and', clauses: [nest(d - 1)] });
for (const d of [1, 14, 15, 16, 17, 40]) await vcl(`and nest ${d}`, nest(d));
for (const dep of [0, 1, 15, 16, 17, 100, -1, 1.5]) await vcl(`depth ${dep}`, CL.never, [], dep);
for (const [nm, cl] of [
  ['null', null], ['string', 'x'], ['array', []], ['number', 5], ['no id', { kind: 'never', p: W('x') }], ['empty id', { id: '', kind: 'never', p: W('x') }], ['id number', { id: 5, kind: 'never', p: W('x') }],
  ['id 128', { id: 'a'.repeat(128), kind: 'never', p: W('x') }], ['id 129', { id: 'a'.repeat(129), kind: 'never', p: W('x') }], ['id multibyte 128', { id: 'é'.repeat(128), kind: 'never', p: W('x') }],
  ['__proto__', { id: '__proto__', kind: 'never', p: W('x') }], ['constructor', { id: 'constructor', kind: 'never', p: W('x') }], ['prototype', { id: 'prototype', kind: 'never', p: W('x') }],
  ['no kind', { id: 'k', p: W('x') }], ['unknown kind', { id: 'k', kind: 'sometimes', p: W('x') }], ['kind upper', { id: 'k', kind: 'NEVER', p: W('x') }], ['kind number', { id: 'k', kind: 5, p: W('x') }],
  ['always bad p', { id: 'k', kind: 'always', p: { verb: '' } }], ['always no p', { id: 'k', kind: 'always' }], ['never bad regex', { id: 'k', kind: 'never', p: W('v', { resource: 're:(' }) }],
  ['precedes no q', { id: 'k', kind: 'precedes', p: W('a') }], ['precedes no p', { id: 'k', kind: 'precedes', q: W('a') }], ['precedes bad q', { id: 'k', kind: 'precedes', p: W('a'), q: { verb: 5 } }],
  ['rw within 0', { ...CL.responds_within, within: 0 }], ['rw within 1', { ...CL.responds_within, within: 1 }], ['rw within max', { ...CL.responds_within, within: 1_000_000 }], ['rw within max+1', { ...CL.responds_within, within: 1_000_001 }],
  ['rw within 1.5', { ...CL.responds_within, within: 1.5 }], ['rw within -1', { ...CL.responds_within, within: -1 }], ['rw within str', { ...CL.responds_within, within: '3' }], ['rw within null', { ...CL.responds_within, within: null }],
  ['rw no within', { id: 'k', kind: 'responds_within', p: W('a'), q: W('b') }], ['rw within -0', { ...CL.responds_within, within: -0 }], ['rw bad q', { ...CL.responds_within, q: null }],
  ['and empty', { id: 'k', kind: 'and', clauses: [] }], ['and not array', { id: 'k', kind: 'and', clauses: {} }], ['and no clauses', { id: 'k', kind: 'and' }], ['and bad child', { id: 'k', kind: 'and', clauses: [{ id: 'c', kind: 'x' }, 5] }],
  ['and dup child ids', { id: 'k', kind: 'and', clauses: [{ id: 'c', kind: 'never', p: W('a') }, { id: 'c', kind: 'never', p: W('b') }] }], ['and child equals parent id', { id: 'k', kind: 'and', clauses: [{ id: 'k', kind: 'never', p: W('a') }] }],
  ['with description', { ...CL.never, description: 'no drops' }], ['unknown member', { ...CL.never, extra: 1 }],
] as [string, any][]) await vcl(nm, cl);
await vcl('id already seen', CL.never, ['nv']);
await vcl('other id seen', CL.never, ['zz']);
await vcl('and child already seen', CL.and, ['an2']);
await vcl('forbidden id seen irrelevant', { id: 'constructor', kind: 'never', p: W('x') }, ['constructor']);

// ---- validateContract is covered by the vectors; contractId / signContract / embeddedConstitution / contractFromConstitution here
const cid = (name: string, c: unknown) => run('contractId', name, C.contractId, [c]);
await cid('all', ALL);
await cid('empty', con(undefined));
await cid('clauses only', con([CL.never]));
await cid('invariants only', con(undefined, [INV_CAP]));
await cid('issued_at', con([CL.never], undefined, { issued_at: NOW }));
await cid('id and sig ignored', { ...ALL, id: 'x', sig: 'y' });
await cid('member order irrelevant', { clauses: ALL.clauses, invariants: ALL.invariants, principal: PK, version: 1 });
await cid('version 7 (not validated)', { ...ALL, version: 7 });
await cid('malformed is still hashed', { clauses: 'nope' });
for (const [nm, v] of [['null', null], ['string', 'x'], ['array', []], ['-0', { a: -0 }], ['2^53', { a: 2 ** 53 }], ['lone surrogate', { a: '\ud800' }], ['nested unicode', { a: ['é', '\u{1F600}'] }]] as [string, any][]) await cid(nm, v);

const sct = (name: string, c: unknown, key: unknown = S('principal')) => run('signContract', name, C.signContract, [c, key]);
await sct('all kinds', ALL);
for (const k of KINDS) await sct(`only ${k}`, con([CL[k]]));
await sct('invariants only', con(undefined, [INV_CAP]));
await sct('empty', con(undefined));
await sct('empty arrays', con([], []));
await sct('issued_at', con([CL.never], undefined, { issued_at: NOW }));
await sct('other key', ALL, S('other'));
await sct('given id and sig replaced', { ...ALL, id: 'forged', sig: 'forged' });
for (const [nm, c] of [
  ['null', null], ['version 2', { ...ALL, version: 2 }], ['no principal', { version: 1, clauses: [] }], ['clauses not array', { version: 1, principal: PK, clauses: {} }], ['invariants not array', { version: 1, principal: PK, invariants: 'x' }],
  ['bad clause', con([{ id: 'x', kind: 'zz' }])], ['dup clause ids', con([CL.never, CL.never])], ['clause id equals invariant id', con([{ ...CL.never, id: 'cap' }], [INV_CAP])],
  ['256 clauses ok', con(Array.from({ length: 256 }, (_, i) => ({ id: 'c' + i, kind: 'never', p: W('x') })))], ['257 clauses', con(Array.from({ length: 257 }, (_, i) => ({ id: 'c' + i, kind: 'never', p: W('x') })))],
  ['256 counting nested', con([{ id: 'a0', kind: 'and', clauses: Array.from({ length: 255 }, (_, i) => ({ id: 'c' + i, kind: 'never', p: W('x') })) }])],
  ['257 counting nested', con([{ id: 'a0', kind: 'and', clauses: Array.from({ length: 256 }, (_, i) => ({ id: 'c' + i, kind: 'never', p: W('x') })) }])],
  ['257 invariants', con(undefined, Array.from({ length: 257 }, (_, i) => ({ ...INV_NEVER, id: 'n' + i })))], ['nest 16', con([nest(15)])], ['nest 17', con([nest(16)])],
  ['unhashable', con([{ ...CL.never, description: '\ud800' }])],
] as [string, any][]) await sct(nm, c);
for (const [nm, k] of [['null key', null], ['string key', 'abc']] as [string, any][]) await sct('key ' + nm, ALL, k);

const emb = (name: string, c: unknown) => run('embeddedConstitution', name, C.embeddedConstitution, [c]);
await emb('all', ALL);
await emb('no invariants', con([CL.never]));
await emb('invariants not array', { version: 1, principal: PK, invariants: 'x' });
await emb('empty invariants', con([], []));
await emb('principal only', { principal: PK });
await emb('no principal', { invariants: [INV_CAP] });
await emb('version ignored', { version: 9, principal: PK, invariants: [INV_CAP] });
await emb('null', null);
await emb('string', 'x');
const cfc = (name: string, c: unknown) => run('contractFromConstitution', name, C.contractFromConstitution, [c]);
await cfc('constitution', { version: 1, principal: PK, invariants: [INV_CAP, INV_NEVER] });
await cfc('empty', { version: 1, principal: PK, invariants: [] });
await cfc('issued_at dropped', { version: 1, principal: PK, invariants: [INV_NEVER], issued_at: NOW });
await cfc('version replaced', { version: 5, principal: PK, invariants: [INV_NEVER] });
await cfc('no invariants', { version: 1, principal: PK });
await cfc('principal missing', { invariants: [] });
await cfc('null', null);
await cfc('number', 5);

// ---- checkContract / advanceContract / checkAndAdvanceContract
const ACTIONS: Array<[string, unknown]> = [
  ['read', act('read')], ['list', act('list')], ['write', act('write')], ['drop', act('drop')], ['review', act('review')], ['deploy', act('deploy')], ['approve', act('approve')], ['ship', act('ship')],
  ['open', act('open')], ['close', act('close')], ['noop', act('noop')], ['x1', act('x1')], ['y0', act('y0')], ['y1', act('y1')], ['pay 10', act('pay', '/r', { amount: 10 })], ['pay 500', act('pay', '/r', { amount: 500 })],
  ['pay no amount', act('pay', '/r', {})], ['delete prod', act('delete', '/prod/db')], ['delete other', act('delete', '/o')], ['malformed verb', { action: { verb: 5, resource: '/r' } }], ['no action', {}], ['null', null],
];
const STATES: Array<[string, unknown]> = [
  ['genesis', st()], ['chained', st({ seq: 3, parent: PARENT })], ['reviewed', st({ seq: 1, parent: PARENT, latched: { pc: NOW - 5 } })], ['approved', st({ seq: 1, parent: PARENT, latched: { rq: NOW - 5 } })],
  ['open 3', st({ seq: 1, parent: PARENT, deadlines: { rw: 3 } })], ['open 1', st({ seq: 1, parent: PARENT, deadlines: { rw: 1 } })], ['open 2', st({ seq: 1, parent: PARENT, deadlines: { rw: 2 } })],
  ['and latched', st({ seq: 1, parent: PARENT, latched: { an2: NOW - 5 } })], ['spent cap', st({ seq: 1, parent: PARENT, ledger: { cap: [{ t: NOW - 1000, amount: 95 }] } })],
  ['malformed', { now: 'x' }], ['null', null], ['deadline 0', st({ seq: 1, parent: PARENT, deadlines: { rw: 0 } })], ['deadline unknown id', st({ seq: 1, parent: PARENT, deadlines: { zz: 2 } })],
];
for (const [an, a] of ACTIONS) for (const [sn, s] of STATES) {
  if (sn === 'genesis' || sn === 'malformed' || (an.length + sn.length) % 3 === 0 || ['open 1', 'open 2', 'reviewed', 'approved'].includes(sn)) {
    await run('checkContract', `${an} | ${sn} | all`, C.checkContract, [a, ALL, s]);
    await run('advanceContract', `${an} | ${sn} | all`, C.advanceContract, [s, a, ALL]);
  }
}
for (const k of KINDS) for (const [an, a] of ACTIONS.slice(0, 15)) for (const [sn, s] of STATES.slice(0, 8)) {
  if ((an.length * 7 + sn.length + k.length) % 4 === 0 || sn === 'genesis') {
    await run('checkContract', `${an} | ${sn} | only ${k}`, C.checkContract, [a, con([CL[k]]), s]);
    await run('advanceContract', `${an} | ${sn} | only ${k}`, C.advanceContract, [s, a, con([CL[k]])]);
  }
}
// scripted multi-step histories through advanceContract: each step is its own case from the state the reference reached
{
  const path = (name: string, contract: any, verbs: Array<[string, any?]>, now0 = NOW, dt = 1000) => {
    let s: any = st({ now: now0 });
    return (async () => {
      for (const [i, [v, p]] of verbs.entries()) {
        const a = act(v, '/r', p);
        const nowi = now0 + (i + 1) * dt;
        const args = [s, a, contract, { now: nowi }];
        await run('advanceContract', `${name} #${i} ${v}`, C.advanceContract, args);
        const r = C.advanceContract(s, a, contract, { now: nowi });
        s = r.next;
      }
    })();
  };
  await path('review-then-deploy', ALL, [['deploy'], ['review'], ['deploy'], ['deploy']]);
  await path('open-close', ALL, [['open'], ['noop'], ['close'], ['noop'], ['noop']]);
  await path('open-timeout', ALL, [['open'], ['noop'], ['noop'], ['noop'], ['noop']]);
  await path('open-open-close', ALL, [['open'], ['open'], ['noop'], ['close'], ['noop']]);
  await path('approve-ship', ALL, [['ship'], ['approve'], ['ship'], ['ship']]);
  await path('and-order', ALL, [['y1'], ['y0'], ['y1'], ['x1']]);
  await path('cap-window', ALL, [['pay', { amount: 60 }], ['pay', { amount: 30 }], ['pay', { amount: 20 }], ['pay', { amount: 5 }]], NOW, 20_000);
  await path('mixed', ALL, [['read'], ['review'], ['pay', { amount: 5 }], ['open'], ['deploy'], ['close'], ['ship'], ['approve'], ['ship']]);
  await path('deadline within 1', con([{ ...CL.responds_within, within: 1 }]), [['open'], ['noop'], ['close']]);
  await path('deadline within 2 respond', con([{ ...CL.responds_within, within: 2 }]), [['open'], ['close'], ['noop']]);
}
// CAS guards, now, options
const S1 = st({ seq: 3, parent: PARENT });
const SD = PR.stateDigest(S1);
for (const [nm, opts] of [
  ['none', {}], ['seq ok', { expectedSeq: 3 }], ['seq stale', { expectedSeq: 2 }], ['seq null', { expectedSeq: null }], ['seq str', { expectedSeq: '3' }], ['digest ok', { expectedStateDigest: SD }],
  ['digest stale', { expectedStateDigest: 'x' }], ['digest null', { expectedStateDigest: null }], ['both ok', { expectedSeq: 3, expectedStateDigest: SD }], ['seq ok digest bad', { expectedSeq: 3, expectedStateDigest: 'x' }],
  ['now later', { now: NOW + 5000 }], ['now same', { now: NOW }], ['now before', { now: NOW - 1 }], ['now null', { now: null }], ['now str', { now: '1' }], ['now 1.5', { now: NOW + 0.5 }], ['now huge', { now: 1e21 }], ['now -0', { now: -0 }],
  ['unknown opt', { zz: 1 }],
] as [string, any][]) {
  for (const [an, a] of [['review', act('review')], ['pay 10', act('pay', '/r', { amount: 10 })], ['drop', act('drop')]] as [string, any][]) {
    await run('advanceContract', `opts ${nm} ${an}`, C.advanceContract, [S1, a, ALL, opts]);
    await run('checkAndAdvanceContract', `true opts ${nm} ${an}`, C.checkAndAdvanceContract, [true, S1, a, ALL, opts]);
  }
}
await run('advanceContract', 'opts null', C.advanceContract, [S1, act('review'), ALL, null]);
await run('advanceContract', 'opts absent', C.advanceContract, [S1, act('review'), ALL]);
for (const p of [true, false, 1, 0, 'true', null, {}, [true]]) for (const [an, a] of [['review', act('review')], ['drop', act('drop')], ['deploy', act('deploy')], ['pay 10', act('pay', '/r', { amount: 10 })], ['noop', act('noop')]] as [string, any][]) {
  await run('checkAndAdvanceContract', `permitted ${ser(p)} ${an}`, C.checkAndAdvanceContract, [p, STATES[1]![1], a, ALL]);
}
for (const [sn, s] of STATES) for (const p of [true, false]) await run('checkAndAdvanceContract', `${p} ${sn} noop`, C.checkAndAdvanceContract, [p, s, act('noop'), ALL]);
for (const [cn, c] of [['null', null], ['empty', con(undefined)], ['version 2', { ...ALL, version: 2 }], ['bad clause', con([{ id: 'x', kind: 'q' }])], ['invariants only', con(undefined, [INV_CAP, INV_NEVER])], ['principal only', { version: 1, principal: PK }]] as [string, any][]) {
  for (const p of [true, false]) {
    await run('checkAndAdvanceContract', `${p} contract ${cn}`, C.checkAndAdvanceContract, [p, st(), act('pay', '/r', { amount: 10 }), c]);
    await run('checkContract', `contract ${cn} ${p}`, C.checkContract, [act('pay', '/r', { amount: 10 }), c, st()]);
  }
  await run('advanceContract', `contract ${cn}`, C.advanceContract, [st(), act('pay', '/r', { amount: 10 }), c]);
}
// the contract with embedded invariants only is the prohibition monitor
for (const [an, a] of ACTIONS.slice(14, 19)) for (const [sn, s] of STATES.slice(0, 3).concat([STATES[8]!])) {
  await run('checkContract', `invariants only ${an} | ${sn}`, C.checkContract, [a, con(undefined, [INV_CAP, INV_NEVER]), s]);
  await run('advanceContract', `invariants only ${an} | ${sn}`, C.advanceContract, [s, a, con(undefined, [INV_CAP, INV_NEVER])]);
}

refWrite(o, 'contracts');
