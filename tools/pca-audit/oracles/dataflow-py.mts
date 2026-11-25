// Oracle: the @atlasauth/pca-dataflow CaMeL data-flow model (tag, derive, combineCaps, classifyFlow, checkAction, dualContext,
// levelOf), the detector receipts (digest, shape, sign) and the three vendor adapters. The trace rules have their own corpus
// (dataflow-rs.mts). Writes out/ref-dataflow-py.json.gz. Tagged values are built from JSON specs on both sides:
//   {k:'trusted'|'tool'|'source'|'tag'|'derive'|'raw'|'fake', ...}; a tagged result is returned as
//   {tagged, value, sources(sorted), isTrusted, readers?(sorted)}; sinks use snake_case members (external, require_trusted,
//   allowed_sources, denied_sources); a null entry in the checkAction argument list is a sparse-array hole.
// Ed25519 receipts are deterministic: compared byte for byte. ctx = {detector, version, content, seed (number n -> 32 x n), now, ...}.
import { Oracle, refWrite } from './lib.mjs';

const D: any = await import('../../../packages/pca-dataflow/src/index.ts');
const PC: any = await import('@atlasauth/pca');
const P: any = PC.default ?? PC;
const o = new Oracle('dataflow-py', 'tools/pca-audit/oracles/dataflow-py.mts', 'TS-reference oracle for the CaMeL data-flow model and the detector adapters.');
let n = 0;
const run = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, `${name}#${n++}`, ref, args);

const set = (a: any) => (Array.isArray(a) ? new Set(a) : a);
const ro = (s: any) => (s.readers === undefined ? {} : { readers: s.readers });
const OPS: Record<string, (...a: any[]) => any> = { concat: (...a) => a.join('|'), first: (a) => a, count: (...a) => a.length };
function build(s: any): any {
  switch (s.k) {
    case 'trusted': return D.fromTrustedQuery(s.value, ro(s));
    case 'tool': return D.fromToolOutput(s.name, s.value, ro(s));
    case 'source': return D.fromSource(s.source, s.value, { ...(s.trusted !== undefined ? { isTrusted: s.trusted } : {}), ...ro(s) });
    case 'tag': {
      const c = s.cap;
      return D.tag(s.value, c === null || typeof c !== 'object' ? c : { sources: set(c.sources), isTrusted: c.isTrusted, ...(c.readers !== undefined ? { readers: set(c.readers) } : {}) });
    }
    case 'derive': return D.derive(s.inputs.map(build), OPS[s.op]);
    case 'raw': return s.value;
    case 'fake': return { value: s.value, cap: { sources: new Set(['trusted-query']), isTrusted: true } };
  }
  throw new Error('bad spec');
}
const capOf = (c: any) => ({ sources: [...c.sources].sort(), isTrusted: c.isTrusted, ...(c.readers !== undefined ? { readers: [...c.readers].sort() } : {}) });
const outT = (t: any) => (D.isTagged(t) ? { tagged: true, value: t.value, ...capOf(t.cap) } : { tagged: false });
const sinkOf = (s: any) => {
  if (s === null || typeof s !== 'object') return s;
  const a = s.accepts;
  if (a === null || typeof a !== 'object') return { id: s.id, accepts: a };
  return { id: s.id, accepts: { external: a.external, requireTrusted: a.require_trusted, allowedSources: set(a.allowed_sources), deniedSources: set(a.denied_sources) } };
};
const governor = (g: any) => ({
  sinkFor: (act: any) => {
    if (g.kind === 'throw') throw new Error('no sink');
    return sinkOf(g.kind === 'byVerb' ? (g.map[act.verb] ?? g.default) : g.sink);
  },
});

// ---- tagging ------------------------------------------------------------------------------------------------------------------
const T = (v: any) => ({ k: 'trusted', value: v });
const L = (name: string, v: any, readers?: string[]) => ({ k: 'tool', name, value: v, ...(readers ? { readers } : {}) });
const specs: any[] = [
  T('q'), { ...T('q'), readers: ['mail', 'slack'] }, { ...T(5), readers: [] }, L('web', 'x'), L('web', { a: 1 }, ['log']),
  { k: 'source', source: 'user', value: 1 }, { k: 'source', source: 'user', value: 1, trusted: true }, { k: 'source', source: 'user', value: 1, trusted: 1 },
  { k: 'source', source: 'tool:x', value: 1, trusted: true }, { k: 'source', source: 'agent', value: null, trusted: true, readers: ['a'] },
  { k: 'tag', value: 1, cap: { sources: ['a'], isTrusted: false } }, { k: 'tag', value: 1, cap: { sources: ['user'], isTrusted: true, readers: ['x', 'y'] } },
  { k: 'tag', value: 1, cap: { sources: [], isTrusted: true } }, { k: 'tag', value: 1, cap: { sources: [], isTrusted: false } },
  { k: 'tag', value: 1, cap: { sources: ['tool:z'], isTrusted: true } }, { k: 'tag', value: 1, cap: { sources: 'abc', isTrusted: false } },
  { k: 'tag', value: 1, cap: { sources: ['a'], isTrusted: 'yes' } }, { k: 'tag', value: 1, cap: { sources: ['a'], isTrusted: false, readers: 'abc' } },
  { k: 'tag', value: 1, cap: null }, { k: 'tag', value: 1, cap: 5 }, { k: 'tag', value: 1, cap: { sources: ['é', 'z', 'a', '😀', '￿'], isTrusted: false } },
  { k: 'derive', op: 'concat', inputs: [T('a'), T('b')] }, { k: 'derive', op: 'concat', inputs: [T('a'), L('w', 'b')] },
  { k: 'derive', op: 'concat', inputs: [{ ...T('a'), readers: ['x', 'y'] }, { ...T('b'), readers: ['y', 'z'] }] },
  { k: 'derive', op: 'concat', inputs: [{ ...T('a'), readers: ['x'] }, T('b')] }, { k: 'derive', op: 'concat', inputs: [{ ...T('a'), readers: ['x'] }, { ...T('b'), readers: ['y'] }] },
  { k: 'derive', op: 'count', inputs: [] }, { k: 'derive', op: 'first', inputs: [L('a', 1)] },
  { k: 'derive', op: 'concat', inputs: [T('a'), { k: 'raw', value: 'x' }] }, { k: 'derive', op: 'concat', inputs: [T('a'), { k: 'fake', value: 'x' }] },
  { k: 'derive', op: 'first', inputs: [{ k: 'derive', op: 'concat', inputs: [T('a'), L('t', 'b')] }] },
];
for (const [i, s] of specs.entries()) await run('build', `s${i}`, (x: any) => outT(build(x)), [s]);
for (const [i, s] of [T('a'), L('t', 'x'), { k: 'source', source: 'u', value: 1 }, { k: 'raw', value: { value: 1, cap: {} } }, { k: 'fake', value: 1 }, { k: 'derive', op: 'concat', inputs: [T('a'), L('t', 'b')] }].entries()) await run('levelOf', `l${i}`, (x: any) => D.levelOf(build(x)), [s]);
await run('levelOf', 'null', () => D.levelOf(null), [1]);
await run('levelOf', 'string', () => D.levelOf('trusted'), [2]);
await run('levelOf', 'mixed tool+user', (x: any) => D.levelOf(D.derive([D.fromToolOutput('a', 1), D.fromSource('user', 2)], (a: any, b: any) => a + b)), [0]);
await run('levelOf', 'empty derive', () => D.levelOf(D.derive([], () => 1)), [3]);
await run('toolProvenance', 'name', D.toolProvenance, ['web']);
await run('toolProvenance', 'empty', D.toolProvenance, ['']);
await run('combineCaps', 'empty', () => capOf(D.combineCaps([])), [4]);
await run('combineCaps', 'three', () => capOf(D.combineCaps([build(T('a')).cap, build({ ...T('b'), readers: ['x', 'y'] }).cap, build({ ...T('c'), readers: ['y'] }).cap])), [5]);
await run('combineCaps', 'untrusted', () => capOf(D.combineCaps([build(T('a')).cap, build(L('w', 'b')).cap])), [6]);
await run('unionSources', 'two', () => [...D.unionSources([build(T('a')).cap, build(L('w', 'b')).cap])].sort(), [7]);

// ---- classifyFlow / canFlow ---------------------------------------------------------------------------------------------------
const S = (id: any, accepts: any) => ({ id, accepts });
const sinks: any[] = [
  S('mail', { external: true }), S('db', { require_trusted: true }), S('log', {}), S('x', { denied_sources: ['tool:web'] }), S('x', { allowed_sources: ['trusted-query', 'user'] }),
  S('x', { allowed_sources: [] }), S('x', { denied_sources: [], allowed_sources: ['trusted-query'], external: true, require_trusted: true }),
  S('mail', { external: 1, require_trusted: 'true' }), S('', {}), S(5, {}), S('x', null), S('x', 5), null, 'sink', S('slack', { external: true, require_trusted: true }),
  S('x', { denied_sources: ['tool:web'], external: true }),
];
const vals: any[] = [T('q'), { ...T('q'), readers: ['mail'] }, { ...T('q'), readers: [] }, L('web', 1), L('web', 1, ['db', 'log']), { k: 'source', source: 'user', value: 1 },
  { k: 'derive', op: 'concat', inputs: [T('a'), L('web', 'b')] }, { k: 'raw', value: 5 }, { k: 'fake', value: 1 }, { k: 'raw', value: null }];
for (const [i, v] of vals.entries()) for (const [j, s] of sinks.entries()) {
  await run('classifyFlow', `v${i}/s${j}`, (a: any, b: any) => D.classifyFlow(build(a), sinkOf(b)), [v, s]);
  if (j % 3 === 0) await run('canFlow', `v${i}/s${j}`, (a: any, b: any) => D.canFlow(build(a), sinkOf(b)), [v, s]);
}
await run('externalSendSink', 'id', (id: any) => ({ id: D.externalSendSink(id).id, accepts: D.externalSendSink(id).accepts }), ['mail']);
await run('sensitiveSink', 'id', (id: any) => ({ id: D.sensitiveSink(id).id, accepts: D.sensitiveSink(id).accepts }), ['db']);

// ---- checkAction --------------------------------------------------------------------------------------------------------------
const act = (verb: string) => ({ verb, resource: 'r' });
const gov = (sink: any) => ({ kind: 'fixed', sink });
const govs: any[] = [gov(S('mail', { external: true })), gov(S('db', { require_trusted: true })), gov(S('log', {})), { kind: 'throw' }, gov(null), gov(S('', {})), gov(S(5, {})),
  { kind: 'byVerb', map: { send: S('mail', { external: true }), write: S('db', { require_trusted: true }) }, default: S('log', {}) }];
const argLists: any[] = [[], [T('a')], [T('a'), L('web', 'b')], [L('web', 'b'), T('a')], [T('a'), null], [null], [T('a'), { k: 'raw', value: 1 }], [T('a'), { k: 'fake', value: 1 }],
  [{ ...T('a'), readers: ['db'] }, L('web', 'x', ['db'])], [L('w1', 1), L('w2', 2)], 'not a list', 5];
const mk = (args: any) => (Array.isArray(args) ? (() => { const a: any[] = new Array(args.length); args.forEach((s: any, i: number) => { if (s !== null) a[i] = build(s); }); return a; })() : args);
for (const [i, g] of govs.entries()) for (const [j, a] of argLists.entries()) {
  for (const verb of i === 7 ? ['send', 'write', 'read'] : ['send']) await run('checkAction', `g${i}/a${j}/${verb}`, (ac: any, ar: any, gv: any) => D.checkAction(ac, mk(ar), governor(gv)), [act(verb), a, g]);
}
for (const [i, e] of [0, 1, 2, 3, 2.0].entries()) await run('checkAction', `expected ${i}`, (ac: any, ar: any, gv: any, ex: any) => D.checkAction(ac, mk(ar), governor(gv), { expectedArgs: ex }), [act('send'), [T('a'), T('b')], govs[2], e]);

// ---- dualContext --------------------------------------------------------------------------------------------------------------
const Q: Record<string, (p: any) => any> = { tool: (p) => D.fromToolOutput('q', 'r:' + p), trusted: (p) => D.fromTrustedQuery(p), raw: (p) => p, fake: (p) => ({ value: p, cap: {} }) };
for (const [i, q] of [T('hello'), L('w', 'x'), { k: 'raw', value: 'x' }, { k: 'fake', value: 'x' }, { k: 'source', source: 'user', value: 'u' }, { k: 'source', source: 'user', value: 'u', trusted: true }].entries())
  for (const qop of Object.keys(Q)) await run('dualContext', `q${i}/${qop}`, (qs: any, op: any) => { const r = D.dualContext({ query: build(qs), plan: (x: any) => 'plan:' + x, quarantine: Q[op]! }); return { plan: r.plan, result: outT(r.result) }; }, [q, qop]);

// ---- detectors ----------------------------------------------------------------------------------------------------------------
const key = (n: number) => new Uint8Array(32).fill(n);
const SESSION = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');
const ctxOf = (c: any) => ({ detector: c.detector, version: c.version, content: c.content, secretKey: key(c.seed), now: c.now, ...(c.session !== undefined ? { session: c.session } : {}), ...(c.calibration_ref !== undefined ? { calibration_ref: c.calibration_ref } : {}) });
const ctxs: any[] = [
  { detector: 'lakera', version: 'v2', content: 'hello', seed: 1, now: 1_800_000_000_000 },
  { detector: 'ps', version: '1.0', content: { a: [1, 2], b: 'é' }, seed: 2, now: 0, session: SESSION, calibration_ref: 'bench-2026' },
  { detector: 'g', version: 'x'.repeat(64), content: [], seed: 3, now: 5 },
  { detector: 'g', version: 'x'.repeat(65), content: 'a', seed: 3, now: 5 },
  { detector: 'G', version: 'v', content: 'a', seed: 3, now: 5 },
  { detector: 'g', version: '', content: 'a', seed: 3, now: 5 },
  { detector: 'g', version: 'v', content: 'a', seed: 3, now: -1 },
  { detector: 'g', version: 'v', content: 'a', seed: 3, now: 1.5 },
  { detector: 'g', version: 'v', content: 'a', seed: 3, now: 1, session: 'short' },
  { detector: 'g', version: 'v', content: 'a', seed: 3, now: 1, calibration_ref: '' },
];
const lakera: any[] = [{ flagged: false }, { flagged: true }, { flagged: false, breakdown: [] }, { flagged: false, breakdown: [{ detector_type: 'prompt_attack', detected: false }] },
  { flagged: false, breakdown: [{ detector_type: 'prompt_attack', detected: true }] }, { flagged: true, breakdown: [{ detector_type: 'pii/email', detected: true }, { detector_type: 'moderated_content/hate', detected: true }, { detector_type: 'x', detected: false }] },
  { flagged: false, breakdown: [{ detector_type: 5, detected: true }] }, { flagged: false, breakdown: [{ detector_type: 'a' }] }, { flagged: false, breakdown: 'x' }, { flagged: false, breakdown: null },
  { flagged: 'false' }, { flagged: 1 }, {}, [], null, 'x', 5, { flagged: true, breakdown: [null] },
  { flagged: true, breakdown: Array.from({ length: 12 }, (_, i) => ({ detector_type: `cat${String(i).padStart(2, '0')}`, detected: true })) }];
const ps: any[] = [{ result: { action: 'log' } }, { result: { action: 'block' } }, { result: { action: 'modify' } }, { result: { prompt: { action: 'log' } } }, { result: { prompt: { action: 'block', violations: ['Prompt Injection'] } } },
  { result: { prompt: { action: 'log', violations: [] } } }, { result: { prompt: { action: 'log', violations: ['jailbreak', 5] } } }, { result: { action: 'log', prompt: { action: 'modify' } } },
  { result: { action: 'log', prompt: { violations: ['x'] } } }, { result: { prompt: { violations: [] } } }, { result: {} }, { result: { action: 5 } }, { result: { action: null } }, { result: { prompt: 'x', action: 'log' } },
  { result: { prompt: null, action: 'log' } }, { result: { prompt: { action: 'log', violations: 'x' } } }, { result: { prompt: { action: 'log', violations: null } } }, { result: [] }, { result: null }, {}, null, 'x', { result: { action: ['block'] } }];
const gen: any[] = [{ flagged: false }, { flagged: true }, { flagged: true, categories: ['PII', 'prompt injection'] }, { flagged: false, categories: [] }, { flagged: false, categories: ['x'] }, { flagged: true, categories: [] },
  { flagged: true, categories: 'x' }, { flagged: true, categories: null }, { flagged: 'yes' }, {}, null, [], 5, { flagged: true, categories: [5, null, 'é'] }, { flagged: true, categories: ['b', 'a', 'b', '9x'] }];
for (const [fn, resp] of [['lakeraReceipt', lakera], ['promptSecurityReceipt', ps], ['genericReceipt', gen]] as const)
  for (const [i, r] of resp.entries()) for (const [j, c] of (i < 8 ? ctxs : ctxs.slice(0, 2)).entries())
    await run(fn, `r${i}/c${j}`, (a: any, b: any) => D[fn](a, ctxOf(b)), [r, c]);
for (const [i, c] of [{ a: 1 }, 'text', '', [1, 'a'], null, 5, true, { z: { y: [] } }, 'é\u0000'].entries()) await run('detectorInputDigest', `d${i}`, P.detectorInputDigest, [c]);
const goodBody = (x: any = {}) => ({ v: 1, kind: 'pca-detector-receipt', detector: 'g', version: 'v', input_digest: P.detectorInputDigest('a'), verdict: 'suspicious', categories: ['a', 'b'], iat: 5, ...x });
const bodies: any[] = [goodBody(), goodBody({ verdict: 'no_finding', categories: [] }), goodBody({ verdict: 'no_finding' }), goodBody({ categories: ['b', 'a'] }), goodBody({ categories: ['a', 'a'] }), goodBody({ categories: Array.from({ length: 9 }, (_, i) => `c${i}`) }),
  goodBody({ categories: ['A'] }), goodBody({ categories: 'a' }), goodBody({ v: 2 }), goodBody({ kind: 'x' }), goodBody({ detector: '1a' }), goodBody({ version: 5 }), goodBody({ input_digest: 'abc' }), goodBody({ verdict: 'maybe' }), goodBody({ iat: -1 }),
  goodBody({ iat: 1.5 }), goodBody({ iat: 9007199254740992 }), goodBody({ session: 'x' }), goodBody({ session: Buffer.from(key(9)).toString('base64url') }), goodBody({ calibration_ref: 'c'.repeat(256) }), goodBody({ calibration_ref: 'c'.repeat(257) }),
  goodBody({ extra: 1 }), goodBody({ alg: 'ed25519' }), goodBody({ alg: 5 }), goodBody({ alg: 'bogus' }), goodBody({ pq_pk: 'x' }), goodBody({ sig: 'x' }), { ...goodBody(), v: undefined }, [], null, 'x'];
for (const [i, b] of bodies.entries()) {
  await run('signDetectorReceipt', `b${i}`, (x: any, s: any) => P.signDetectorReceipt(x, key(s)), [b, 4]);
}
const signed = P.signDetectorReceipt(goodBody(), key(4));
for (const [i, r] of ([signed, { ...signed, sig: 5 }, { ...signed, extra: 1 }, { ...signed, session: 'bad' }, { ...signed, pq_sig: 'x' }, (({ sig, ...r }) => r)(signed), null, [], 'x', { ...signed, v: 1.0 }, { ...signed, verdict: 'no_finding' }] as any[]).entries()) {
  await run('detectorReceiptShapeError', `r${i}`, P.detectorReceiptShapeError, [r]);
  await run('detectorReceiptRef', `r${i}`, P.detectorReceiptRef, [r]);
}

refWrite(o, 'dataflow-py');
