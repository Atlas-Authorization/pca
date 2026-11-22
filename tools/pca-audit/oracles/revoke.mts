// Oracle: @atlasauth/pca-revoke (revocation registry, the chain check, verifyWithRevocation, CAEP bridge). Deterministic: fixed
// clocks (T0); an entry whose revokedAt is within two minutes of the wall clock is printed "<now>" on both sides.
// Stateful objects are driven by a scenario script: scenario(spec) with spec = {store: 'mem'|'failGet'|'failAll', ops: [step...]}.
// A step is {op, ...}: revoke{input} revokeSubtree{target,opts} unrevoke{key} list lookup{kind,value} prefixes clear
// killAgent{holder,opts} killSubtree{root,opts} check{p,opts} verify{p,core,opts} ingest{event}; its result is the JSON of the
// returned entry / list / bool / result, or {"$err": true} when the call threw (only the refusal is compared, not the message).
// A failGet store throws from get(), a failAll store from all(); both with new Error('boom').
// PORTING (fn(args) -> native entry point, comparison rule):
//   scenario(spec)         run the steps over a Revoke registry (InMemoryRevocationStore or a throwing store); compare the result list by JSON value
//   isActiveAt(entry, now) Revoke.isActiveAt(RevocationEntry, now); boolean exact (a non-number now / notBefore counts as non-finite)
//   caepEventTypes()       Revoke.SESSION_REVOKED / GRANT_REVOKED / KILL_SWITCH; JSON equal to {sessionRevoked, grantRevoked, killSwitch}
// Revoke inputs with a non-string kind are not generated (the Java port refuses them where the reference stores them).
import * as M0 from '@atlasauth/pca-revoke';
import { Oracle, refWrite, variants } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('revoke', 'tools/pca-audit/oracles/revoke.mts', 'TS-reference oracle for the revocation registry, chain check and CAEP bridge.');
const T0 = 1_800_000_000_000;

function norm(v: any): any {
  if (Array.isArray(v)) return v.map(norm);
  if (v !== null && typeof v === 'object') {
    const out: any = {};
    for (const k of Object.keys(v)) out[k] = k === 'revokedAt' && typeof v[k] === 'number' && Math.abs(v[k] - Date.now()) < 120_000 ? '<now>' : norm(v[k]);
    return out;
  }
  return v;
}

async function scenario(spec: any) {
  const base = new M.InMemoryRevocationStore();
  const boom = async () => { throw new Error('boom'); };
  const store = spec.store === 'failGet' ? { add: (e: any) => base.add(e), remove: (k: any, v: any) => base.remove(k, v), get: boom, all: () => base.all(), clear: () => base.clear() }
    : spec.store === 'failAll' ? { add: (e: any) => base.add(e), remove: (k: any, v: any) => base.remove(k, v), get: (k: any, v: any) => base.get(k, v), all: boom, clear: () => base.clear() }
    : base;
  const reg = new M.RevocationRegistry(store);
  const out: any[] = [];
  for (const s of spec.ops) {
    try {
      let r: any;
      switch (s.op) {
        case 'revoke': r = await reg.revoke(s.input); break;
        case 'revokeSubtree': r = await reg.revokeSubtree(s.target, s.opts); break;
        case 'unrevoke': r = await reg.unrevoke(s.key); break;
        case 'list': r = await reg.list(); break;
        case 'lookup': r = (await reg.lookup(s.kind, s.value)) ?? null; break;
        case 'prefixes': r = await reg.prefixes(); break;
        case 'clear': r = (await reg.clear(), null); break;
        case 'killAgent': r = await reg.killAgent(s.holder, s.opts); break;
        case 'killSubtree': r = await reg.killSubtree(s.root, s.opts); break;
        case 'check': r = await M.checkRevocation(s.p, reg, s.opts); break;
        case 'verify': r = await M.verifyWithRevocation(s.p, s.core, reg, s.opts); break;
        case 'ingest': r = await M.ingestCaepEvent(s.event, reg); break;
        default: throw new Error('bad op');
      }
      out.push(norm(JSON.parse(JSON.stringify(r === undefined ? null : r))));
    } catch {
      out.push({ $err: true });
    }
  }
  return out;
}
let n = 0;
const sc = (name: string, spec: any) => o.run('scenario', `${name}#${n++}`, scenario, [spec]);

// ---- revoke inputs -----------------------------------------------------------------------------------------------------
const rv = (input: any) => ({ ops: [{ op: 'revoke', input }, { op: 'list' }] });
const R = (extra: any) => ({ revokedAt: T0, ...extra });
const inputs: any[] = [
  R({ kind: 'cap', value: 'c1' }), R({ kind: 'holder', value: 'h1', reason: 'because' }), R({ kind: 'issuer', value: 'i1', notBefore: T0 + 5 }),
  R({ kind: 'prefix', prefix: ['a', 'b'] }), R({ kind: 'prefix', prefix: ['a'], reason: 'r', notBefore: 0 }), { kind: 'cap', value: 'now' },
  R({ kind: 'cap', value: '' }), R({ kind: 'cap' }), R({ kind: 'cap', value: 5 }), R({ kind: 'cap', value: null }), R({ kind: 'cap', value: ['x'] }),
  R({ kind: 'prefix', prefix: [] }), R({ kind: 'prefix' }), R({ kind: 'prefix', prefix: 'a,b' }), R({ kind: 'prefix', prefix: ['a,b'] }),
  R({ kind: 'prefix', prefix: ['a', ''] }), R({ kind: 'prefix', prefix: ['a', 1] }), R({ kind: 'prefix', prefix: ['a', null] }), R({ kind: 'prefix', value: 'a' }),
  R({ kind: 'cap', value: 'c', revokedAt: '5' }), R({ kind: 'cap', value: 'c', revokedAt: null }), R({ kind: 'cap', value: 'c', revokedAt: -0 }),
  R({ kind: 'cap', value: 'c', revokedAt: 1.5 }), R({ kind: 'cap', value: 'c', revokedAt: 2 ** 53 }), R({ kind: 'cap', value: 'c', revokedAt: true }),
  R({ kind: 'cap', value: 'c', notBefore: null }), R({ kind: 'cap', value: 'c', notBefore: '5' }), R({ kind: 'cap', value: 'c', notBefore: -0 }),
  R({ kind: 'cap', value: 'c', notBefore: 1.25 }), R({ kind: 'cap', value: 'c', reason: 5 }), R({ kind: 'cap', value: 'c', reason: null }),
  R({ kind: 'cap', value: 'c', reason: '' }), R({ kind: 'cap', value: 'c', reason: 'é\u0000' }), R({ kind: 'bogus', value: 'v' }), R({ value: 'v' }), R({ kind: '', value: 'v' }),
  null, {}, R({ kind: 'prefix', prefix: ['a', 'b'], value: 'ignored' }), R({ kind: 'cap', value: 'a,b' }), R({ kind: 'cap', value: 'c', prefix: ['x'] }),
];
for (const [i, inp] of inputs.entries()) await sc(`revoke/${i}`, rv(inp));
// same value under different kinds / replace / order
await sc('replace', { ops: [{ op: 'revoke', input: R({ kind: 'cap', value: 'x', reason: 'one' }) }, { op: 'revoke', input: R({ kind: 'holder', value: 'x' }) }, { op: 'revoke', input: R({ kind: 'cap', value: 'x', reason: 'two' }) }, { op: 'list' }, { op: 'lookup', kind: 'cap', value: 'x' }, { op: 'lookup', kind: 'issuer', value: 'x' }] });
await sc('prefix-alias', { ops: [{ op: 'revoke', input: R({ kind: 'prefix', prefix: ['a', 'b'] }) }, { op: 'revoke', input: R({ kind: 'prefix', prefix: ['a'] }) }, { op: 'prefixes' }, { op: 'list' }, { op: 'clear' }, { op: 'list' }, { op: 'prefixes' }] });

// ---- revokeSubtree / kill-switch / unrevoke --------------------------------------------------------------------------------
const targets: any[] = ['root1', '', ['a', 'b'], [], ['a,b'], ['a', ''], 5, null, ['x', 1], 'a,b'];
const sopts: any[] = [undefined, {}, { reason: 'why', revokedAt: T0 }, { revokedAt: T0, notBefore: T0 + 10 }, { revokedAt: 'x' }, { reason: 7, revokedAt: T0 }, { revokedAt: T0, notBefore: null }];
for (const [i, t] of targets.entries()) for (const [j, op] of sopts.entries()) await sc(`subtree/${i}/${j}`, { ops: [{ op: 'revokeSubtree', target: t, opts: op?.revokedAt === undefined && op !== undefined && !('reason' in op) ? { revokedAt: T0, ...op } : (op === undefined ? { revokedAt: T0 } : op) }, { op: 'list' }] });
const killers: any[] = ['agent1', '', 5, null, ['a']];
for (const [i, h] of killers.entries()) for (const [j, op] of [{ revokedAt: T0 }, { reason: 'x', revokedAt: T0 }, { reason: 3, revokedAt: T0 }, { revokedAt: 'x' }, { revokedAt: null }].entries()) {
  await sc(`killAgent/${i}/${j}`, { ops: [{ op: 'killAgent', holder: h, opts: op }, { op: 'list' }] });
  await sc(`killSubtree/${i}/${j}`, { ops: [{ op: 'killSubtree', root: h, opts: op }, { op: 'list' }] });
}
const keys: any[] = [{ kind: 'cap', value: 'c1' }, { kind: 'holder', value: 'h1' }, { kind: 'issuer', value: 'i1' }, { kind: 'prefix', prefix: ['a', 'b'] }, { kind: 'prefix', prefix: ['a'] },
  { kind: 'prefix', prefix: [] }, { kind: 'prefix' }, { kind: 'prefix', prefix: 'a,b' }, { kind: 'cap' }, { kind: 'cap', value: 5 }, { kind: 'bogus', value: 'c1' }, { value: 'c1' }, {}, null,
  { kind: 'prefix', prefix: [1, null, 'b'] }, { kind: 'cap', value: null }];
for (const [i, k] of keys.entries()) await sc(`unrevoke/${i}`, { ops: [
  { op: 'revoke', input: R({ kind: 'cap', value: 'c1' }) }, { op: 'revoke', input: R({ kind: 'holder', value: 'h1' }) }, { op: 'revoke', input: R({ kind: 'issuer', value: 'i1' }) },
  { op: 'revoke', input: R({ kind: 'prefix', prefix: ['a', 'b'] }) }, { op: 'revoke', input: R({ kind: 'prefix', prefix: ['a'] }) }, { op: 'revoke', input: R({ kind: 'prefix', prefix: [',', 'b'].slice(1) }) },
  { op: 'unrevoke', key: k }, { op: 'unrevoke', key: k }, { op: 'list' }] });

// ---- the chain check ------------------------------------------------------------------------------------------------------
const hop = (id: string, issuer: string, holder: string) => ({ id, issuer, holder, verb: 'files.read' });
const CHAIN = [hop('cap_a', 'iss_root', 'hold_1'), hop('cap_b', 'hold_1', 'hold_2'), hop('cap_c', 'hold_2', 'hold_3')];
const P = { v: 2, cap_chain: CHAIN, action: { verb: 'files.read' } };
const regs: any[] = [
  [], [R({ kind: 'cap', value: 'cap_b' })], [R({ kind: 'cap', value: 'cap_z' })], [R({ kind: 'holder', value: 'hold_3' })], [R({ kind: 'holder', value: 'hold_1' })], [R({ kind: 'issuer', value: 'iss_root' })],
  [R({ kind: 'issuer', value: 'hold_2' })], [R({ kind: 'prefix', prefix: ['cap_a', 'cap_b'] })], [R({ kind: 'prefix', prefix: ['cap_b'] })], [R({ kind: 'prefix', prefix: ['cap_a', 'cap_b', 'cap_c', 'cap_d'] })],
  [R({ kind: 'prefix', prefix: ['cap_a', 'cap_b', 'cap_c'] })], [R({ kind: 'cap', value: 'cap_c', reason: 'stolen' })], [R({ kind: 'cap', value: 'cap_c', notBefore: T0 + 1000 })],
  [R({ kind: 'prefix', prefix: ['cap_a'], notBefore: T0 + 1000 })], [R({ kind: 'cap', value: 'cap_b' }), R({ kind: 'holder', value: 'hold_1' }), R({ kind: 'issuer', value: 'iss_root' })],
  [R({ kind: 'holder', value: 'hold_2' }), R({ kind: 'cap', value: 'cap_a' })], [R({ kind: 'cap', value: 'cap_a', notBefore: 5e12 })], [R({ kind: 'cap', value: 'cap_a', notBefore: 1 })],
];
const nows: any[] = [{ now: T0 }, { now: T0 + 999 }, { now: T0 + 1000 }, { now: T0 + 1001 }, { now: -0 }, { now: 0 }, { now: '5' }, { now: null }, { now: true }, { now: [] }, {}, undefined];
for (const [i, rs] of regs.entries()) for (const [j, op] of nows.entries()) {
  await sc(`check/${i}/${j}`, { ops: [...rs.map((input: any) => ({ op: 'revoke', input })), { op: 'check', p: P, opts: op }] });
}
for (const [i, rs] of [regs[0], regs[1], regs[3], regs[7]].entries()) for (const [name, v] of variants(P, { hostile: [null, 0, 1, '', 'x', [], {}, true] })) {
  await sc(`checkp/${i}/${name}`, { ops: [...rs.map((input: any) => ({ op: 'revoke', input })), { op: 'check', p: v, opts: { now: T0 } }] });
}
const badPs: any[] = [null, 'str', 5, [], {}, { cap_chain: null }, { cap_chain: 'x' }, { cap_chain: {} }, { cap_chain: [] }, { cap_chain: [null] }, { cap_chain: ['x'] }, { cap_chain: [[]] },
  { cap_chain: [hop('', 'i', 'h')] }, { cap_chain: [hop('c', '', 'h')] }, { cap_chain: [hop('c', 'i', '')] }, { cap_chain: [{ id: 5, issuer: 'i', holder: 'h' }] }, { cap_chain: [{ id: 'c', holder: 'h' }] },
  { cap_chain: [{ id: 'c', issuer: 'i' }] }, { cap_chain: [hop('ok', 'i', 'h'), null] }, { cap_chain: [hop('ok', 'i', 'h'), hop('ok2', 'i2', '')] }];
for (const [i, p] of badPs.entries()) {
  await sc(`badp/${i}`, { ops: [{ op: 'revoke', input: R({ kind: 'cap', value: 'ok' }) }, { op: 'check', p, opts: { now: T0 } }] });
  await sc(`badp-verify/${i}`, { ops: [{ op: 'verify', p, core: { allow: true }, opts: { now: T0 } }] });
}
for (const st of ['failGet', 'failAll']) for (const [i, rs] of [regs[0], regs[1], regs[7], regs[5]].entries()) await sc(`${st}/${i}`, { store: st, ops: [...rs.map((input: any) => ({ op: 'revoke', input })), { op: 'check', p: P, opts: { now: T0 } }, { op: 'verify', p: P, core: { allow: true }, opts: { now: T0 } }, { op: 'list' }, { op: 'lookup', kind: 'cap', value: 'cap_b' }, { op: 'prefixes' }] });

// ---- verifyWithRevocation -----------------------------------------------------------------------------------------------------
const cores: any[] = [{ allow: true }, { allow: false, reason: 'bad sig' }, { allow: false }, { allow: 'true' }, { allow: 1 }, null, 'str', 5, [], {}, { allow: true, reason: 5 }, { allow: false, reason: 5 }, { allow: false, reason: null }, { allow: false, reason: '' }, { allow: true, reason: 'x' }];
for (const [i, rs] of [regs[0], regs[1], regs[11], regs[12]].entries()) for (const [j, c] of cores.entries()) {
  await sc(`verify/${i}/${j}`, { ops: [...rs.map((input: any) => ({ op: 'revoke', input })), { op: 'verify', p: P, core: c, opts: { now: T0 } }] });
}

// ---- CAEP bridge -----------------------------------------------------------------------------------------------------------------
const ET = M.CAEP_EVENT_TYPES;
const evs: any[] = [
  { type: ET.grantRevoked, payload: { grant_ref: 'cap_a', reason: 'gone', event_timestamp: 1_800_000_000 } },
  { type: ET.grantRevoked, payload: { grant_ref: 'cap_a', event_timestamp: 1_800_000_000.0005 } },
  { type: ET.killSwitch, payload: { agent: 'hold_2', grant_ref: 'cap_b', reason: 'kill', event_timestamp: 1_800_000_001 } },
  { type: ET.killSwitch, payload: { agent: 'hold_2', event_timestamp: 1_800_000_001 } },
  { type: ET.killSwitch, payload: { grant_ref: 'cap_b', event_timestamp: 1_800_000_001 } },
  { type: ET.sessionRevoked, payload: { subject: { format: 'opaque', id: 'hold_3' }, event_timestamp: 1_800_000_002, reason_admin: 'adm', reason_user: 'usr' } },
  { type: ET.sessionRevoked, payload: { subject: { format: 'opaque', holder: 'h1', agent: 'a1', id: 'i1' }, event_timestamp: 1_800_000_002, reason_user: 'usr' } },
  { type: ET.sessionRevoked, payload: { subject: { format: 'opaque', agent: 'a1' }, event_timestamp: 1_800_000_002 } },
  { type: ET.sessionRevoked, payload: { subject: { format: 'email', email: 'a@b.c' }, event_timestamp: 1_800_000_002 } },
  { type: ET.sessionRevoked, payload: { event_timestamp: 1_800_000_002 } },
  { type: ET.sessionRevoked, payload: { subject: null, event_timestamp: 1_800_000_002 } },
  { type: ET.sessionRevoked, payload: { subject: 'str', event_timestamp: 1_800_000_002 } },
  { type: 'https://example.test/other', payload: { subject: { format: 'opaque', id: 'x' }, event_timestamp: 5 } },
  { type: ET.grantRevoked, payload: null }, { type: ET.killSwitch, payload: null }, { type: ET.sessionRevoked, payload: null }, { type: ET.grantRevoked }, { type: ET.sessionRevoked },
  { type: ET.grantRevoked, payload: 'str' }, { type: ET.killSwitch, payload: 5 }, { type: ET.sessionRevoked, payload: [] }, null, {}, 'str', { payload: { grant_ref: 'c' } },
  { type: ET.grantRevoked, payload: { grant_ref: '' } }, { type: ET.grantRevoked, payload: { grant_ref: 5, event_timestamp: 1 } }, { type: ET.killSwitch, payload: { agent: '', grant_ref: '' } },
];
for (const [i, e] of evs.entries()) await sc(`ingest/${i}`, { ops: [{ op: 'ingest', event: e }, { op: 'list' }, { op: 'check', p: P, opts: { now: 1_900_000_000_000 } }] });
for (const [name, v] of variants(evs[2], { hostile: [null, 0, -0, 1.5, 2 ** 53, 1e21, '', 'x', [], {}, true] })) await sc(`ingestv/${name}`, { ops: [{ op: 'ingest', event: v }, { op: 'list' }] });
for (const [name, v] of variants(evs[5], { hostile: [null, 0, -0, 1.5, '', 'x', [], {}, true] })) await sc(`ingestv5/${name}`, { ops: [{ op: 'ingest', event: v }, { op: 'list' }] });
for (const [name, v] of variants(evs[0], { hostile: [null, -0, 1.5, 2 ** 53, 1e21, '', 'x', [], {}] })) await sc(`ingestv0/${name}`, { ops: [{ op: 'ingest', event: v }, { op: 'list' }] });
// the ingest then check path: an ingested kill-switch makes a held PCActn deny
await sc('kill-then-verify', { ops: [{ op: 'ingest', event: evs[3] }, { op: 'verify', p: P, core: { allow: true }, opts: { now: T0 } }] });
await sc('subtree-then-verify', { ops: [{ op: 'revokeSubtree', target: 'cap_b', opts: { revokedAt: T0, reason: 'tree' } }, { op: 'verify', p: P, core: { allow: true }, opts: { now: T0 } }] });

// ---- isActiveAt / constants ------------------------------------------------------------------------------------------------------
const nbs: any[] = [undefined, null, 0, -0, 5, 1.5, T0, 2 ** 53, 'x', '5', true, [], {}];
const clocks: any[] = [0, -0, 4, 5, 6, T0, T0 - 1, 1e21, -1, 1.5, null, 'x', true, []];
for (const [i, nb] of nbs.entries()) for (const [j, c] of clocks.entries()) await o.run('isActiveAt', `${i}/${j}`, M.isActiveAt, [{ kind: 'cap', value: 'v', reason: '', revokedAt: 1, ...(nb === undefined ? {} : { notBefore: nb }) }, c]);
await o.run('caepEventTypes', 'all', () => M.CAEP_EVENT_TYPES, []);

refWrite(o, 'revoke');
