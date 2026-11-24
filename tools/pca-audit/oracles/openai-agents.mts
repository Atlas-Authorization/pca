// Oracle: the policy / step-up logic of @atlasauth/pca-openai-agents. The tool and run context are driven with declarative descriptors
// (a stub verifier named by tag, call logs for execute / verify / onDeny / onVerified / recorder), so a native replays the same flows.
// Writes out/ref-openai-agents.json.gz.
//   proofFromRunContext({input, runContext})        string | null
//   provenanceFromRunContext({runContext})          any | null
//   proofFromInputHeaders({field?, header?, input}) string | null
//   guardrailProofFromContext({args})               string | null
//   pendingStepUps(reviews)                         [{tool, request}]
//   withPcaTool({tool, options, input, runContext?, noRunContext?}) {ok, out, calls, ...} | {err, kind?, verb?, message, checks?, calls}
//   pcaTools({tools, options, input, runContext})   {name: withPcaTool-result + {same}}
//   guardrail({kind: 'input'|'tool', options, args}) {name, result}
//   needsApproval({tool, opts, input, via: 'direct'|'withApproval'}) {value, calls, tool?}
//   reviewToolCall({tool, input, opts})             intent-null (auto) path only; the rest needs reviewAction, which has no native twin
import { Oracle, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-openai-agents/src/index.ts');
const o = new Oracle('openai-agents', 'tools/pca-audit/oracles/openai-agents.mts', 'TS-reference oracle for the proof sources, guard pipeline, guardrails and step-up logic of the OpenAI Agents adapter.');

const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const P = (verb = 'stripe.refund', extra: any = {}) => ({ action: { verb, resource: 'stripe:ch_1' }, ...extra });
const J = (p: any) => JSON.stringify(p);
const H = (p: any) => b64u(JSON.stringify(p));
const norm = (m: string) => String(m).replace(/proof could not be decoded: [\s\S]*$/, 'proof could not be decoded: ').replace(/withPcaTool/g, 'with_pca_tool');

// ---- proof sources ------------------------------------------------------------------------------------------------------
const bags: any[] = [
  { context: { pca: 'A' } }, { context: { pcaProof: 'B' } }, { context: { pca: 'A', pcaProof: 'B' } }, { context: { pca: 5, pcaProof: 'B' } },
  { context: { pca: null, pcaProof: 'B' } }, { context: { pca: '' } }, { pca: 'C' }, { pcaProof: 'D' }, { context: { pca: 'A' }, pca: 'C' },
  { context: { pca: 5 }, pca: 'C' }, { context: 'str', pca: 'C' }, { context: null, pcaProof: 'D' }, { context: [], pca: 'C' }, { context: {} },
  {}, { context: { pca: { nested: 1 } } }, { context: { pca: true } }, { context: [ 'x' ] }, { context: { pca: ['x'] }, pcaProof: 'D' },
];
for (const [i, rc] of bags.entries()) await o.run('proofFromRunContext', `b${i}`, (a: any) => M.proofFromRunContext(a.input, a.runContext), [{ input: { x: 1 }, runContext: rc }]);
for (const [i, rc] of bags.entries()) await o.run('guardrailProofFromContext', `b${i}`, (a: any) => M.guardrailProofFromContext(a.args), [{ args: { context: rc } }]);
for (const [i, a] of [{}, { context: null }, { context: 'x' }, { input: 'x' }, { context: { context: { pca: 'in' }, pca: 'out' } }, { context: { context: { pca: 5 }, pca: 'out' } }, { context: { context: {}, pcaProof: 'out' } }].entries()) {
  await o.run('guardrailProofFromContext', `g${i}`, (x: any) => M.guardrailProofFromContext(x.args), [{ args: a }]);
}
const provs: any[] = [
  { context: { pcaProvenance: 'a' } }, { context: { pca_provenance: 'b' } }, { context: { 'PCA-Provenance': 'c' } }, { context: { pcaProvenance: null, pca_provenance: 'b' } },
  { context: { pcaProvenance: 0 } }, { context: { pcaProvenance: '' } }, { context: { pcaProvenance: { s: 1 } } }, { pcaProvenance: 'o' }, { 'PCA-Provenance': 'o2' },
  { context: { pcaProvenance: false }, pcaProvenance: 'o' }, { context: { pcaProvenance: null }, pcaProvenance: 'o' }, { context: 'str', pca_provenance: 'o3' },
  { context: null }, {}, { context: { other: 1 } }, { context: [] },
];
for (const [i, rc] of provs.entries()) await o.run('provenanceFromRunContext', `p${i}`, (a: any) => M.provenanceFromRunContext(undefined, a.runContext), [{ runContext: rc }]);
const hdrIn: any[] = [
  { field: undefined, header: undefined, input: { headers: { 'PCA-Action': 'h' } } }, { input: { headers: { 'PCA-Action': 5 } } }, { input: { headers: {} } }, { input: { headers: null } },
  { input: { headers: 'x' } }, { input: null }, { input: 'str' }, { input: [] }, { input: { hdr: { 'x-pca': 'v' } }, field: 'hdr', header: 'x-pca' },
  { input: { hdr: { 'x-pca': 'v' } }, field: 'hdr' }, { input: { headers: { 'x-pca': 'v' } }, header: 'x-pca' }, { input: { headers: { 'pca-action': 'v' } } },
  { input: { headers: ['a'] } }, { input: { headers: { 'PCA-Action': '' } } },
];
for (const [i, a] of hdrIn.entries()) await o.run('proofFromInputHeaders', `h${i}`, (x: any) => M.proofFromInputHeaders(x.field, x.header)(x.input, {}), [a]);

// ---- pendingStepUps -----------------------------------------------------------------------------------------------------
const req = (id: string) => ({ id, verb: 'v', resource: 'r', tier: 2, reason: 'x', goalCommit: '', lineage: { chain: [], because: '' }, r: 0.5, requestedAt: 1 });
const revs: any[][] = [
  [], [{ tool: 'a', review: { kind: 'auto' } }], [{ tool: 'a', review: { kind: 'deny', reason: 'no' } }],
  [{ tool: 'a', review: { kind: 'step_up', request: req('1') } }],
  [{ tool: 'a', review: { kind: 'auto' } }, { tool: 'b', review: { kind: 'step_up', request: req('2') } }, { tool: 'c', review: { kind: 'deny', reason: 'x' } }, { tool: 'd', review: { kind: 'step_up', request: req('3') } }],
  [{ tool: 'a', review: { kind: 'step_up', request: req('1') } }, { tool: 'a', review: { kind: 'step_up', request: req('1') } }],
];
for (const [i, r] of revs.entries()) await o.run('pendingStepUps', `r${i}`, M.pendingStepUps, [r]);

// ---- withPcaTool / pcaTools ---------------------------------------------------------------------------------------------
type Calls = any[];
const stub = (d: any, calls: Calls) => (p: any) => {
  calls.push(['verify', d.stub, p?.action?.verb ?? null]);
  if (d.throws) throw new Error(d.throws);
  return { allow: d.allow, checks: { sig: d.allow ? 'pass' : 'fail' }, ...(d.reason !== undefined ? { reason: d.reason } : {}) };
};
const has = (x: any, k: string) => Object.prototype.hasOwnProperty.call(x, k);
const buildOpts = (d: any, calls: Calls): any => {
  const out: any = {};
  for (const k of ['mode', 'verb', 'audience', 'name']) if (has(d, k)) out[k] = d[k];
  if (d.verify) out.verify = stub(d.verify, calls);
  if (d.authorize) out.authorize = d.authorize;
  if (d.require) out.require = d.require.headers ? M.proofFromInputHeaders(...d.require.headers) : () => d.require.const;
  if (d.onDeny) out.onDeny = (e: any, input: any) => calls.push(['onDeny', e.kind, input]);
  if (d.onVerified) out.onVerified = (r: any, p: any, input: any) => calls.push(['onVerified', r.allow, p?.action?.verb ?? null, input]);
  if (d.recorder) out.recorder = { tool: (name: string, output: any) => calls.push(['recorded', name, output]) };
  if (d.per) out.per = Object.fromEntries(Object.entries(d.per).map(([k, v]) => [k, buildOpts(v, calls)]));
  if (d.only) out.only = d.only;
  return out;
};
const buildTool = (td: any, calls: Calls): any => ({
  name: td.name, description: 'd', parameters: { type: 'object' }, ...(td.extra ?? {}),
  ...(td.noExecute ? {} : { execute: async (input: any) => { calls.push(['exec', td.name ?? null, input]); if (td.throws) throw new Error(td.throws); return { echo: input, tool: td.name ?? null }; } }),
});
const outcome = async (t: any, input: any, rc: any, noRc: boolean, calls: Calls) => {
  try {
    const out = await t.execute(input, noRc ? undefined : rc);
    return { ok: true, out, calls, name: t.name ?? null, extra: t.extra ?? null, hasNeedsApproval: 'needsApproval' in t };
  } catch (e: any) {
    const kind = e instanceof M.PcaToolDenied ? { kind: e.kind, verb: e.verb, ...(e.checks !== undefined ? { checks: e.checks } : {}) } : {};
    return { err: e instanceof M.PcaToolDenied ? 'PcaToolDenied' : e instanceof TypeError ? 'TypeError' : 'Error', message: norm(e.message), ...kind, calls };
  }
};
const runTool = async (a: any) => {
  const calls: Calls = [];
  let t: any;
  try { t = M.withPcaTool(buildTool(a.tool, calls), buildOpts(a.options, calls)); } catch (e: any) { return { err: e instanceof TypeError ? 'TypeError' : 'Error', message: norm(e.message), calls, build: true }; }
  return outcome(t, a.input, a.runContext, !!a.noRunContext, calls);
};
const runTools = async (a: any) => {
  const calls: Calls = [];
  const tools = Object.fromEntries(Object.entries(a.tools).map(([k, v]) => [k, buildTool(v, calls)]));
  let g: any;
  try { g = M.pcaTools(tools, buildOpts(a.options, calls)); } catch (e: any) { return { err: e instanceof TypeError ? 'TypeError' : 'Error', message: norm(e.message), calls, build: true }; }
  const res: any = {};
  for (const k of Object.keys(g)) { const r: any = await outcome(g[k], a.input, a.runContext, false, calls); r.same = g[k] === tools[k]; res[k] = r; }
  return res;
};
const ok = (tag: string, extra: any = {}) => ({ stub: tag, allow: true, ...extra });
const no = (tag: string, reason?: string) => ({ stub: tag, allow: false, ...(reason !== undefined ? { reason } : {}) });
const SO = { mode: 'signature-only', verify: ok('v'), audience: 'rs' };
const rc = (p: any) => ({ context: { pca: p } });
const T = { name: 'refund' };
let n = 0;
const wt = (name: string, a: any) => o.run('withPcaTool', name, runTool, [a]);

// happy paths and proof forms
await wt('json proof', { tool: T, options: { ...SO, onDeny: 1, onVerified: 1, recorder: 1 }, input: { amount: 5 }, runContext: rc(J(P())) });
await wt('header proof', { tool: T, options: { ...SO, onVerified: 1 }, input: { amount: 5 }, runContext: rc(H(P())) });
await wt('pcaProof key', { tool: T, options: SO, input: {}, runContext: { context: { pcaProof: J(P()) } } });
await wt('proof on runContext', { tool: T, options: SO, input: {}, runContext: { pca: J(P()) } });
await wt('extra fields kept', { tool: { name: 'refund', extra: { k: 1, strict: true } }, options: SO, input: {}, runContext: rc(J(P())) });
await wt('tool without name', { tool: {}, options: SO, input: {}, runContext: rc(J(P())) });
await wt('verb bound ok', { tool: T, options: { ...SO, verb: 'stripe.refund' }, input: {}, runContext: rc(J(P())) });
await wt('input headers source', { tool: T, options: { ...SO, require: { headers: [] } }, input: { headers: { 'PCA-Action': J(P()) } }, runContext: {} });
await wt('input headers source custom', { tool: T, options: { ...SO, require: { headers: ['h', 'x'] } }, input: { h: { x: H(P()) } }, runContext: {} });
await wt('input headers missing', { tool: T, options: { ...SO, require: { headers: [] }, onDeny: 1 }, input: {}, runContext: rc(J(P())) });
await wt('audience null', { tool: T, options: { ...SO, audience: null }, input: {}, runContext: rc(J(P())) });
await wt('audience omitted', { tool: T, options: { mode: 'signature-only', verify: ok('v') }, input: {}, runContext: rc(J(P())) });
await wt('no run context', { tool: T, options: { ...SO, onDeny: 1 }, input: {}, noRunContext: true });
await wt('execute throws', { tool: { name: 'refund', throws: 'boom' }, options: { ...SO, recorder: 1 }, input: {}, runContext: rc(J(P())) });
await wt('no execute', { tool: { name: 'refund', noExecute: true }, options: { ...SO, onVerified: 1 }, input: {}, runContext: rc(J(P())) });
await wt('recorder verb', { tool: { name: 'refund' }, options: { ...SO, recorder: 1 }, input: { a: 1 }, runContext: rc(J(P('x.y'))) });
await wt('recorder no action verb', { tool: { name: 'refund' }, options: { ...SO, recorder: 1 }, input: { a: 1 }, runContext: rc(J({ ok: true })) });
await wt('recorder label verb option', { tool: { name: 'refund' }, options: { ...SO, recorder: 1, verb: 'a.b' }, input: { a: 1 }, runContext: rc(J(P('a.b'))) });

// refusals: missing / malformed / binding / verify
for (const [i, v] of [undefined, null].entries()) await wt(`missing ${i}`, { tool: T, options: { ...SO, onDeny: 1 }, input: {}, runContext: v === null ? { context: { pca: null } } : { context: {} } });
await wt('missing with verb label', { tool: T, options: { ...SO, verb: 'stripe.refund' }, input: {}, runContext: {} });
await wt('missing tool label', { tool: T, options: SO, input: {}, runContext: {} });
await wt('missing no label', { tool: {}, options: SO, input: {}, runContext: {} });
await wt('non-string proof', { tool: T, options: SO, input: {}, runContext: { context: { pca: 5 } } });
for (const [i, raw] of ['garbage', '', '[]', '5', '"s"', 'null', '{"a":1,"a":2}', '{"action":', 'e30', 'e2E6MX0', '!!!', J(P()) + ' ', ' ' + J(P()), 'W10', 'bnVsbA'].entries()) {
  await wt(`malformed ${i}`, { tool: T, options: { ...SO, onDeny: 1 }, input: {}, runContext: rc(raw) });
}
await wt('verb mismatch', { tool: T, options: { ...SO, verb: 'stripe.refund', onDeny: 1 }, input: { a: 1 }, runContext: rc(J(P('other.verb'))) });
await wt('verb mismatch checked before verify', { tool: T, options: { ...SO, verb: 'x', onDeny: 1 }, input: {}, runContext: rc(J(P('y'))) });
await wt('verify deny reason', { tool: T, options: { mode: 'signature-only', verify: no('v', 'bad sig'), audience: 'rs', onDeny: 1 }, input: {}, runContext: rc(J(P())) });
await wt('verify deny no reason', { tool: T, options: { mode: 'signature-only', verify: no('v'), audience: 'rs' }, input: {}, runContext: rc(J(P())) });
await wt('verify deny empty reason', { tool: T, options: { mode: 'signature-only', verify: no('v', ''), audience: 'rs' }, input: {}, runContext: rc(J(P())) });
await wt('verifier throws', { tool: T, options: { mode: 'signature-only', verify: { stub: 'v', allow: true, throws: 'verifier boom' }, audience: 'rs', onDeny: 1 }, input: {}, runContext: rc(J(P())) });

// configuration errors (thrown when the tool is wrapped)
await wt('cfg full without authorize', { tool: T, options: { audience: 'rs' }, input: {}, runContext: rc(J(P())) });
await wt('cfg full with verify', { tool: T, options: { audience: 'rs', verify: ok('v') }, input: {}, runContext: rc(J(P())) });
await wt('cfg full explicit with verify', { tool: T, options: { mode: 'full', audience: 'rs', verify: ok('v'), authorize: {} }, input: {}, runContext: rc(J(P())) });
await wt('cfg so with authorize', { tool: T, options: { mode: 'signature-only', verify: ok('v'), authorize: {} }, input: {}, runContext: rc(J(P())) });
await wt('cfg so without verify', { tool: T, options: { mode: 'signature-only' }, input: {}, runContext: rc(J(P())) });
await wt('cfg unknown mode', { tool: T, options: { mode: 'strict', verify: ok('v') }, input: {}, runContext: rc(J(P())) });
await wt('cfg unknown mode null', { tool: T, options: { mode: null, verify: ok('v') }, input: {}, runContext: rc(J(P())) });
await wt('cfg full missing parts', { tool: T, options: { authorize: {}, audience: 'rs', verb: 'v' }, input: {}, runContext: rc(J(P())) });
await wt('cfg full no audience', { tool: T, options: { authorize: {}, verb: 'v' }, input: {}, runContext: rc(J(P())) });
await wt('cfg full audience null', { tool: T, options: { authorize: {}, audience: null, verb: 'v' }, input: {}, runContext: rc(J(P())) });

// pcaTools: shared options, per-tool overrides, `only`, pass-through by reference
const A = { name: 'a' }, B = { name: 'b' }, Cc = { name: 'c', extra: { keep: 1 } };
const pt = (name: string, a: any) => o.run('pcaTools', name, runTools, [a]);
await pt('all guarded', { tools: { a: A, b: B }, options: { ...SO, onDeny: 1, onVerified: 1 }, input: { q: 1 }, runContext: rc(J(P())) });
await pt('all denied', { tools: { a: A, b: B }, options: { ...SO, onDeny: 1 }, input: {}, runContext: {} });
await pt('only subset', { tools: { a: A, b: B, c: Cc }, options: { ...SO, only: ['b'] }, input: {}, runContext: {} });
await pt('only empty', { tools: { a: A, b: B }, options: { ...SO, only: [] }, input: {}, runContext: {} });
await pt('only unknown name', { tools: { a: A }, options: { ...SO, only: ['zzz'] }, input: {}, runContext: {} });
await pt('per verb binds', { tools: { a: A, b: B }, options: { ...SO }, input: {}, runContext: rc(J(P('verb.a'))) });
await pt('per verb a', { tools: { a: A, b: B }, options: { ...SO, per: { a: { verb: 'verb.a' } } }, input: {}, runContext: rc(J(P('verb.a'))) });
await pt('per verb both', { tools: { a: A, b: B }, options: { ...SO, per: { a: { verb: 'verb.a' }, b: { verb: 'verb.b' } } }, input: {}, runContext: rc(J(P('verb.a'))) });
await pt('per verify replaces', { tools: { a: A, b: B }, options: { ...SO, per: { b: { verify: no('w', 'b denied') } } }, input: {}, runContext: rc(J(P())) });
await pt('per verify keeps shared mode', { tools: { a: A }, options: { ...SO, per: { a: { verify: ok('w') } } }, input: {}, runContext: rc(J(P())) });
await pt('per authorize replaces verify', { tools: { a: A, b: B }, options: { ...SO, per: { b: { authorize: {}, mode: 'full' } } }, input: {}, runContext: rc(J(P())) });
await pt('per audience null', { tools: { a: A, b: B }, options: { ...SO, audience: 'other', per: { b: { audience: null } } }, input: {}, runContext: rc(J(P())) });
await pt('per audience inherits', { tools: { a: A, b: B }, options: { ...SO, per: { b: { verb: 'verb.a' } } }, input: {}, runContext: rc(J(P('verb.a'))) });
await pt('per mode only', { tools: { a: A }, options: { ...SO, per: { a: { mode: 'signature-only' } } }, input: {}, runContext: rc(J(P())) });
await pt('per hooks override', { tools: { a: A, b: B }, options: { ...SO, onDeny: 1, per: { b: { onDeny: 1, onVerified: 1 } } }, input: {}, runContext: {} });
await pt('per recorder', { tools: { a: A, b: B }, options: { ...SO, per: { a: { recorder: 1 } } }, input: {}, runContext: rc(J(P())) });
await pt('per require', { tools: { a: A, b: B }, options: { ...SO, per: { b: { require: { headers: [] } } } }, input: { headers: { 'PCA-Action': J(P()) } }, runContext: {} });
await pt('per for unknown tool', { tools: { a: A }, options: { ...SO, per: { zzz: { verb: 'x' } } }, input: {}, runContext: rc(J(P())) });
await pt('only + per', { tools: { a: A, b: B }, options: { ...SO, only: ['a'], per: { a: { verify: no('w', 'nope') }, b: { verb: 'x' } } }, input: {}, runContext: rc(J(P())) });
await pt('no per, no mode config error', { tools: { a: A }, options: { audience: 'rs' }, input: {}, runContext: {} });

// ---- guardrails ---------------------------------------------------------------------------------------------------------
const runGuard = async (a: any) => {
  const calls: Calls = [];
  const opts: any = buildOpts(a.options, calls);
  if (a.options.verify) opts.verify = stub(a.options.verify, calls);
  const g = a.kind === 'input' ? M.pcaInputGuardrail(opts) : M.pcaToolGuard(opts);
  try { return { name: g.name, result: await g.execute(a.args), calls }; } catch (e: any) { return { err: e.name, message: norm(e.message), calls }; }
};
const gr = (name: string, a: any) => o.run('guardrail', name, runGuard, [a]);
for (const kind of ['input', 'tool']) {
  const base = { kind, options: { verify: ok('v'), audience: 'rs' } };
  await gr(`${kind} ok`, { ...base, args: { context: rc(J(P())) } });
  await gr(`${kind} ok header`, { ...base, args: { context: rc(H(P())) } });
  await gr(`${kind} ok bare context`, { ...base, args: { context: { pca: J(P()) } } });
  await gr(`${kind} missing`, { ...base, args: { context: {} } });
  await gr(`${kind} no context`, { ...base, args: {} });
  await gr(`${kind} malformed`, { ...base, args: { context: rc('nope') } });
  await gr(`${kind} verb mismatch`, { kind, options: { verify: ok('v'), audience: 'rs', verb: 'a.b' }, args: { context: rc(J(P('c.d'))) } });
  await gr(`${kind} verify deny`, { kind, options: { verify: no('v', 'bad sig'), audience: 'rs' }, args: { context: rc(J(P())) } });
  await gr(`${kind} verify deny no reason`, { kind, options: { verify: no('v'), audience: 'rs' }, args: { context: rc(J(P())) } });
  await gr(`${kind} named`, { kind, options: { verify: ok('v'), name: 'custom' }, args: { context: rc(J(P())) } });
  await gr(`${kind} verifier throws`, { kind, options: { verify: { stub: 'v', allow: true, throws: 'verifier boom' } }, args: { context: rc(J(P())) } });
  await gr(`${kind} require const`, { kind, options: { verify: ok('v'), require: { const: J(P()) } }, args: { context: {} } });
  await gr(`${kind} require none`, { kind, options: { verify: ok('v'), require: { const: null } }, args: { context: rc(J(P())) } });
  await gr(`${kind} require headers`, { kind, options: { verify: ok('v'), require: { headers: [] } }, args: { input: { headers: { 'PCA-Action': J(P()) } } } });
}

// ---- step-up (the intent-null path never reaches reviewAction) ---------------------------------------------------------------
const NOAGENT: any = {};
const runReview = (a: any) => {
  const calls: Calls = [];
  const r = M.reviewToolCall(NOAGENT, a.tool, a.input, { intent: (t: string, i: any) => { calls.push(['intent', t, i ?? null]); return null; } });
  return { r, calls };
};
for (const [i, a] of [{ tool: 'refund', input: { a: 1 } }, { tool: '', input: undefined }, { tool: 'x', input: {} }].entries()) await o.run('reviewToolCall', `auto ${i}`, runReview, [a]);
const runNeeds = async (a: any) => {
  const calls: Calls = [];
  const opts: any = { intent: (t: string, i: any) => { calls.push(['intent', t, i ?? null]); return null; }, ...(a.toolName !== undefined ? { toolName: a.toolName } : {}) };
  if (a.via === 'direct') {
    const f = M.pcaNeedsApproval(NOAGENT, opts);
    return { value: await f({}, a.input, 'c1'), calls };
  }
  const t = M.withApproval({ name: a.tool?.name, description: 'd', ...(a.tool?.extra ?? {}), execute: async () => 1 }, NOAGENT, opts);
  return { value: await t.needsApproval({}, a.input, 'c1'), calls, name: t.name ?? null, extra: t.extra ?? null, hasExecute: typeof t.execute === 'function' };
};
await o.run('needsApproval', 'direct default name', runNeeds, [{ via: 'direct', input: { a: 1 } }]);
await o.run('needsApproval', 'direct named', runNeeds, [{ via: 'direct', toolName: 'refund', input: { a: 1 } }]);
await o.run('needsApproval', 'withApproval name', runNeeds, [{ via: 'with', tool: { name: 'refund', extra: { k: 1 } }, input: { a: 1 } }]);
await o.run('needsApproval', 'withApproval no name', runNeeds, [{ via: 'with', tool: {}, input: { a: 1 } }]);
await o.run('needsApproval', 'withApproval toolName wins', runNeeds, [{ via: 'with', toolName: 'other', tool: { name: 'refund' }, input: {} }]);

refWrite(o, 'openai-agents');
