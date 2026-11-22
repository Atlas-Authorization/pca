// Oracle: @atlasauth/pca-rotate (agent / principal key rotation, compromised-subtree re-issue, applyRotation). Deterministic:
// Ed25519 signatures, fixed clocks (T0; an entry / record whose revokedAt is within two minutes of the wall clock prints "<now>").
// Keys cross the oracle as base64url Ed25519 SEEDS ("seed"): the wrapper builds {secretKey: seed, publicKey} for the reference.
// PORTING (fn(args) -> native entry point, comparison rule; all compared by JSON value, a throw requires the native to refuse):
//   rotateAgentKey(chain, {oldSeed, newSeed, reason?, now?})            Rotate.rotateAgentKey(chain, edFromSeed(oldSeed), edFromSeed(newSeed), reason, now) -> {chain, revocation: record.toMap()}
//   rotatePrincipalKey({chain?, oldRoot?, oldSeed, newSeed, holderSeeds?, reason?, now?})   Rotate.rotatePrincipalKey(chain, oldRoot, edFromSeed(oldSeed), edFromSeed(newSeed), holderSeeds as keys, reason, now)
//   revokeAndReissueSubtree(chain, holder, {newSeed, ancestorSeed, reason?, now?})          Rotate.revokeAndReissueSubtree(chain, holder, edFromSeed(newSeed), edFromSeed(ancestorSeed), reason, now) -> {chain, revocation}
//   compromisedKeyFlow(chain, holder, {newSeed, ancestorSeed, reason?, now?})               Rotate.compromisedKeyFlow(...) -> {revocations: [record.toMap()], reissued}
//   applyRotationScenario({pre, records, reissued?, failAt?, failUnrevoke?})                a registry (pre = cap ids revoked first at T0) behind a sink that throws from its failAt-th revoke
//                                                    call and, with failUnrevoke, from every unrevoke; Rotate.applyRotation(sink, records, reissued) -> {result: ids | {$err}, list: registry entries}
// Not generated (the Java port refuses them where the reference passes them through): hops without a string id / issuer / holder or
// without a caveats array; a non-string reason; a string capIds (the reference iterates its characters).
import * as M0 from '@atlasauth/pca-rotate';
import * as P from '@atlasauth/pca';
import * as R0 from '@atlasauth/pca-revoke';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const RevocationRegistry: any = ((R0 as any).default ?? R0).RevocationRegistry;
const pca: any = (P as any).mintRoot ? P : (P as any).default;
const o = new Oracle('rotate', 'tools/pca-audit/oracles/rotate.mts', 'TS-reference oracle for key rotation and subtree revocation.');
const T0 = 1_800_000_000_000;
const SEED: Record<string, string> = {};
for (const k of ['P', 'A', 'B', 'C', 'D', 'N', 'M']) SEED[k] = pca.b64u(seed(`ref-rotate/${k}`));
const bytes = (s: any) => (typeof s === 'string' ? new Uint8Array(Buffer.from(s, 'base64url')) : s);
const kp = (s: any) => (typeof s === 'string' ? { secretKey: bytes(s), publicKey: pca.publicKeyOf(bytes(s)) } : s);
const pubOf = (k: string) => pca.b64u(pca.publicKeyOf(bytes(SEED[k])));

const root = pca.mintRoot({ principalSecret: bytes(SEED.P), principalPublic: pubOf('P'), holder: pubOf('A'), caveats: [{ type: 'ttl', secs: 3600 }, { type: 'resource', prefix: '/acct' }] });
const leafA = pca.attenuate(root, [{ type: 'resource', prefix: '/acct/x' }], bytes(SEED.A));
const d1 = pca.delegate(root, pubOf('B'), [{ type: 'scope', v: 'read' }], bytes(SEED.A));
const d2 = pca.delegate(d1, pubOf('C'), [{ type: 'budget', n: 5 }, { type: 'x', y: [1, 2.5, null, true] }], bytes(SEED.B));
const d3 = pca.attenuate(d2, [{ type: 'resource', prefix: '/acct/x/y' }], bytes(SEED.C));
const noop = pca.attenuate(d3, [], bytes(SEED.C));
const CH: Record<string, any[]> = { root: [root], c2: [root, leafA], c3: [root, d1, d2], c4: [root, d1, d2, d3], c5: [root, d1, d2, d3, noop] };

const shapeOk = (h: any) => Array.isArray(h) && h.length > 0 && h.every((c) => c && typeof c === 'object' && typeof c.id === 'string' && c.id.length > 0 && typeof c.issuer === 'string' && typeof c.holder === 'string' && Array.isArray(c.caveats));
function norm(v: any): any {
  if (Array.isArray(v)) return v.map(norm);
  if (v !== null && typeof v === 'object') {
    const out: any = {};
    for (const k of Object.keys(v)) out[k] = k === 'revokedAt' && typeof v[k] === 'number' && Math.abs(v[k] - Date.now()) < 120_000 ? '<now>' : norm(v[k]);
    return out;
  }
  return v;
}
const run = async (name: string, ref: Function, args: any[], hops?: any, fn = 'x') => {
  // run through the capture path, but drop a success whose chain is out of the supported shape
  const { capture, reparse } = await import('./lib.mjs');
  const a = reparse(args);
  const out: any = await capture((...x: any[]) => norm(JSON.parse(JSON.stringify(ref(...x)))), a);
  if (hops !== undefined && !out.$throws && !shapeOk(typeof hops === 'function' ? hops(a) : hops)) return;
  o.add(fn, name, a, out);
};
const optsOf = (x: any) => (x === undefined || x === null ? x : { ...x });

// wrappers: seeds -> keys
const rotateAgentKey = (chain: any, op: any) => M.rotateAgentKey(chain, op === null || op === undefined ? op : { ...op, oldHolderSecret: bytes(op.oldSeed), newKeyPair: kp(op.newSeed), oldSeed: undefined, newSeed: undefined });
const rotatePrincipalKey = (a: any) => M.rotatePrincipalKey({ ...a, oldPrincipalSecret: bytes(a.oldSeed), newPrincipalKeyPair: kp(a.newSeed), holderSecrets: a.holderSeeds === undefined ? undefined : a.holderSeeds === null ? null : a.holderSeeds.map(bytes), oldSeed: undefined, newSeed: undefined, holderSeeds: undefined });
const reissue = (fn: string) => (chain: any, holder: any, op: any) => M[fn](chain, holder, { ...op, newKeyPair: kp(op.newSeed), ancestorSecret: bytes(op.ancestorSeed), newSeed: undefined, ancestorSeed: undefined });
const revokeAndReissueSubtree = reissue('revokeAndReissueSubtree');
const compromisedKeyFlow = reissue('compromisedKeyFlow');

const nowOpts: any[] = [{ now: T0 }, {}, { now: -0 }, { now: null }, { now: '5' }, { reason: 'because', now: 1.5 }, { reason: '', now: T0 }];
let n = 0;
const nm = (s: string) => `${s}#${n++}`;

// ---- rotateAgentKey ------------------------------------------------------------------------------------------------------
const aKey: Record<string, [string, string]> = { root: ['P', 'N'], c2: ['A', 'N'], c3: ['B', 'N'], c4: ['C', 'N'], c5: ['C', 'N'] };
for (const [cn, [old, nw]] of Object.entries(aKey)) {
  const chain = CH[cn];
  for (const [j, no] of nowOpts.entries()) await run(nm(`agent/${cn}/now${j}`), rotateAgentKey, [chain, { oldSeed: SEED[old], newSeed: SEED[nw], ...no }], chain, 'rotateAgentKey');
  // wrong / missing / same keys
  for (const [w, op] of Object.entries({ wrongOld: { oldSeed: SEED.D, newSeed: SEED[nw], now: T0 }, sameNew: { oldSeed: SEED[old], newSeed: SEED[cn === 'c2' ? 'A' : cn === 'c3' ? 'C' : 'C'], now: T0 }, nullOld: { oldSeed: null, newSeed: SEED[nw], now: T0 }, nullNew: { oldSeed: SEED[old], newSeed: null, now: T0 }, shortOld: { oldSeed: 'AAAA', newSeed: SEED[nw], now: T0 }, oldIsNew: { oldSeed: SEED[old], newSeed: SEED[old], now: T0 } }))
    await run(nm(`agent/${cn}/${w}`), rotateAgentKey, [chain, op], chain, 'rotateAgentKey');
}
for (const [w, c] of Object.entries({ empty: [], nul: null, str: 'x', obj: {}, num: 5, hopNull: [null], hopStr: ['x'] }))
  await run(nm(`agent/bad/${w}`), rotateAgentKey, [c, { oldSeed: SEED.C, newSeed: SEED.N, now: T0 }], c, 'rotateAgentKey');
for (const [name, v] of variants(CH.c3, { hostile: [null, 0, '', [], {}], maxPaths: 25 }))
  await run(nm(`agent/var/${name}`), rotateAgentKey, [v, { oldSeed: SEED.B, newSeed: SEED.N, now: T0 }], v, 'rotateAgentKey');

// ---- rotatePrincipalKey -----------------------------------------------------------------------------------------------------------
const hs: Record<string, string[]> = { root: [], c2: ['A'], c3: ['A', 'B'], c4: ['A', 'B', 'C'], c5: ['A', 'B', 'C', 'C'] };
for (const cn of ['root', 'c2', 'c4']) {
  const chain = CH[cn];
  const holderSeeds = hs[cn].map((k) => SEED[k]);
  const base = { chain, oldSeed: SEED.P, newSeed: SEED.N, holderSeeds };
  for (const [j, no] of nowOpts.entries()) await run(nm(`principal/${cn}/now${j}`), rotatePrincipalKey, [{ ...base, ...no }], chain, 'rotatePrincipalKey');
  const variantsOf: Record<string, any> = {
    wrongOld: { ...base, oldSeed: SEED.D }, sameNew: { ...base, newSeed: SEED.P }, nullOld: { ...base, oldSeed: null }, nullNew: { ...base, newSeed: null },
    fewSecrets: { ...base, holderSeeds: holderSeeds.slice(1) }, manySecrets: { ...base, holderSeeds: [...holderSeeds, SEED.A] }, noSecrets: { ...base, holderSeeds: undefined },
    nullSecrets: { ...base, holderSeeds: null }, wrongSecret: { ...base, holderSeeds: holderSeeds.map(() => SEED.D) }, reversed: { ...base, holderSeeds: [...holderSeeds].reverse() },
    nullSecretElem: { ...base, holderSeeds: holderSeeds.map(() => null) },
  };
  for (const [w, a] of Object.entries(variantsOf)) await run(nm(`principal/${cn}/${w}`), rotatePrincipalKey, [{ ...a, now: T0 }], chain, 'rotatePrincipalKey');
}
// root-only through oldRoot; chain null / absent / ignored
await run(nm('principal/oldRoot'), rotatePrincipalKey, [{ oldRoot: root, oldSeed: SEED.P, newSeed: SEED.N, now: T0 }], [root], 'rotatePrincipalKey');
await run(nm('principal/oldRoot-null-chain'), rotatePrincipalKey, [{ chain: null, oldRoot: root, oldSeed: SEED.P, newSeed: SEED.N, holderSeeds: [], now: T0 }], [root], 'rotatePrincipalKey');
await run(nm('principal/oldRoot-ignored'), rotatePrincipalKey, [{ chain: CH.c2, oldRoot: d1, oldSeed: SEED.P, newSeed: SEED.N, holderSeeds: [SEED.A], now: T0 }], CH.c2, 'rotatePrincipalKey');
await run(nm('principal/oldRoot-child'), rotatePrincipalKey, [{ oldRoot: d1, oldSeed: SEED.A, newSeed: SEED.N, holderSeeds: [], now: T0 }], [d1], 'rotatePrincipalKey');
await run(nm('principal/chain-child'), rotatePrincipalKey, [{ chain: [d1, d2], oldSeed: SEED.A, newSeed: SEED.N, holderSeeds: [SEED.B], now: T0 }], [d1, d2], 'rotatePrincipalKey');
for (const [w, a] of Object.entries({ none: {}, emptyChain: { chain: [] }, falsy: { oldRoot: 0 }, nullRoot: { oldRoot: null }, str: { oldRoot: 'x' }, strChain: { chain: 'x' } }))
  await run(nm(`principal/bad/${w}`), rotatePrincipalKey, [{ ...a, oldSeed: SEED.P, newSeed: SEED.N, holderSeeds: [], now: T0 }], undefined, 'rotatePrincipalKey');
for (const [name, v] of variants(CH.c3, { hostile: [null, 0, '', [], {}], maxPaths: 25 }))
  await run(nm(`principal/var/${name}`), rotatePrincipalKey, [{ chain: v, oldSeed: SEED.P, newSeed: SEED.N, holderSeeds: [SEED.A, SEED.B], now: T0 }], v, 'rotatePrincipalKey');

// ---- compromised subtree ----------------------------------------------------------------------------------------------------------------
const holders: Record<string, string> = { A: pubOf('A'), B: pubOf('B'), C: pubOf('C'), D: pubOf('D'), N: pubOf('N') };
const anc: Record<string, string> = { B: 'A', C: 'B' }; // the compromised holder -> the safe ancestor's secret
for (const fn of ['revokeAndReissueSubtree', 'compromisedKeyFlow'] as const) {
  const ref = fn === 'revokeAndReissueSubtree' ? revokeAndReissueSubtree : compromisedKeyFlow;
  for (const cn of fn === 'compromisedKeyFlow' ? ['c2', 'c4'] : ['root', 'c4', 'c5']) {
    const chain = CH[cn];
    for (const [hk, hv] of Object.entries(holders)) {
      const ancSeed = SEED[anc[hk] ?? 'A'];
      for (const [j, no] of [{ now: T0 }, { now: null }, {}, { reason: 'bad', now: 1.5 }].entries())
        await run(nm(`${fn}/${cn}/${hk}/o${j}`), ref, [chain, hv, { newSeed: SEED.M, ancestorSeed: ancSeed, ...no }], chain, fn);
      await run(nm(`${fn}/${cn}/${hk}/wrongAnc`), ref, [chain, hv, { newSeed: SEED.M, ancestorSeed: SEED.D, now: T0 }], chain, fn);
      await run(nm(`${fn}/${cn}/${hk}/newInside`), ref, [chain, hv, { newSeed: SEED.C, ancestorSeed: ancSeed, now: T0 }], chain, fn);
      await run(nm(`${fn}/${cn}/${hk}/newIsHolder`), ref, [chain, hv, { newSeed: SEED[hk] ?? SEED.M, ancestorSeed: ancSeed, now: T0 }], chain, fn);
      await run(nm(`${fn}/${cn}/${hk}/nullKeys`), ref, [chain, hv, { newSeed: null, ancestorSeed: null, now: T0 }], chain, fn);
    }
    for (const hv of [null, 5, '', [], {}]) await run(nm(`${fn}/${cn}/badholder`), ref, [chain, hv, { newSeed: SEED.M, ancestorSeed: SEED.A, now: T0 }], chain, fn);
  }
  for (const [w, c] of Object.entries({ empty: [], nul: null, str: 'x', obj: {}, hopNull: [null] })) await run(nm(`${fn}/bad/${w}`), ref, [c, holders.B, { newSeed: SEED.M, ancestorSeed: SEED.A, now: T0 }], c, fn);
  for (const [name, v] of fn === 'compromisedKeyFlow' ? [] : variants(CH.c4, { hostile: [null, 0, '', [], {}], maxPaths: 25 }))
    await run(nm(`${fn}/var/${name}`), ref, [v, holders.C, { newSeed: SEED.M, ancestorSeed: SEED.B, now: T0 }], v, fn);
}

// ---- applyRotation --------------------------------------------------------------------------------------------------------------------------
async function applyRotationScenario(spec: any) {
  const reg = new RevocationRegistry();
  for (const id of spec.pre ?? []) await reg.revoke({ kind: 'cap', value: id, reason: 'pre', revokedAt: T0 });
  let calls = 0;
  const sink = {
    revoke: async (i: any) => { calls++; if (spec.failAt === calls) throw new Error('sink down'); await reg.revoke(i); },
    unrevoke: async (k: any) => { if (spec.failUnrevoke) throw new Error('unrevoke down'); return reg.unrevoke(k); },
    lookup: (k: any, v: any) => reg.lookup(k, v),
  };
  let result: any;
  try { result = await M.applyRotation(sink, spec.records, spec.reissued); } catch { result = { $err: true }; }
  return { result, list: norm(JSON.parse(JSON.stringify(await reg.list()))) };
}
const ids = CH.c4.map((c) => c.id);
const rec = (capIds: any, extra: any = {}) => ({ capIds, reason: 'why', revokedAt: T0, ...extra });
const recs: any[] = [
  rec([ids[0]]), rec(ids), rec(ids.slice(1)), rec([ids[1], ids[1], ids[2]]), { capId: ids[1], reason: 'one', revokedAt: T0 }, { capId: ids[1] }, { capIds: [ids[2]] }, { capIds: [] }, { capIds: [], capId: ids[0] }, { capIds: null, capId: ids[0] },
  {}, null, 5, 'str', [], [rec([ids[0]]), rec([ids[1]])], [rec([ids[0]], { reason: 'first' }), rec([ids[0], ids[1]], { reason: 'second' })], [rec([ids[0]]), null], [rec([ids[0]]), {}], [{}],
  rec(['']), rec([5]), rec([null]), rec([ids[0], '']), rec([ids[0], 5]), rec({}), rec(5), { capId: '' }, { capId: 5 }, { capId: null },
  rec([ids[0]], { revokedAt: 'x' }), rec([ids[0]], { revokedAt: null }), rec([ids[0]], { revokedAt: undefined }), rec([ids[0]], { reason: undefined }), rec([ids[0]], { reason: null }), rec([ids[0]], { reason: '' }),
  rec([ids[0]], { revokedAt: 1.5 }), rec([ids[0]], { revokedAt: -0 }),
];
const specs: any[] = [];
for (const [i, r] of recs.entries()) {
  specs.push({ pre: [], records: r });
  specs.push({ pre: [ids[0]], records: r });
  specs.push({ pre: [], records: r, failAt: 1 });
  specs.push({ pre: [ids[1]], records: r, failAt: 2 });
  specs.push({ pre: [], records: r, failAt: 2, failUnrevoke: true });
  specs.push({ pre: [], records: r, reissued: CH.c2 });
  specs.push({ pre: [], records: r, reissued: [d3] });
  specs.push({ pre: [], records: r, reissued: [] });
}
for (const rs of [null, 'x', {}, [null], [{}], [{ id: 5 }], [d3, null]]) specs.push({ pre: [], records: rec([ids[0]]), reissued: rs });
for (const [i, s] of specs.entries()) await o.run('applyRotationScenario', `s${i}`, applyRotationScenario, [s]);

{ const by: any = {}; for (const c of o.cases) by[c.fn] = (by[c.fn] ?? 0) + JSON.stringify(c).length; console.log(by); }
refWrite(o, 'rotate');
