// k05 differential oracle: the authorize pipeline's 0.5 additions and its pure pieces
// (packages/pca/src/server/authorize.ts + server/require-pca.ts, agent-native.ts tool_schema, risk.ts, envelope.ts, attestation.ts).
// Natives: Java Authorize.java (and every port). See README.md for the per-fn porting note.
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/authorize-oracle.mts
// Deterministic: seeded keys, fixed clock, a fresh atomic memory store per scenario.
import * as P from '../../../packages/pca/src/index.ts';
import { requiresAttestation } from '../../../packages/pca/src/attestation.ts';
import { Oracle, variants, rng, seed, reparse, clone, HOSTILE } from './lib.mjs';

const p: any = (P as any).createAuthorizer ? P : (P as any).default;
const an: any = p.agentNative;
const O = new Oracle('authorize', 'tools/pca-audit/k05-oracles/authorize-oracle.mts', 'TS-reference oracle for Authorize: tool_schema validation and evaluation, risk policy, envelope reading, requiresAttestation, and authorize() scenarios over provenance by default, fresh_at escalation, escalation answers and undo admission.');
const used = new Map<string, number>();
const run = (fn: string, n: string, ref: any, a: any[]) => { const k = `${fn}/${n}`; const c = used.get(k) ?? 0; used.set(k, c + 1); return O.run(fn, c ? `${n} #${c}` : n, ref, a); };
const R = rng(0xa07);

// ================================================================ tool_schema: validateArgSchema
const S = (props: any, required?: any) => (required === undefined ? { props } : { props, required });
const BASE_SCHEMA = S({ amount: { type: 'number', min: 0, max: 100 }, currency: { type: 'string', enum: ['usd', 'eur'] }, memo: { type: 'string', maxLength: 16, minLength: 1, prefix: 'm' },
  n: { type: 'integer', const: 3 }, ok: { type: 'boolean', enum: [true] }, tags: { type: 'array', items: { type: 'string', maxLength: 4 }, minItems: 1, maxItems: 3 },
  to: { type: 'object', props: { iban: { type: 'string' }, bic: { type: 'string' } }, required: ['iban'] } }, ['amount']);
for (const [l, v] of variants(BASE_SCHEMA, { depth: 5 })) await run('validateArgSchema', l, an.validateArgSchema, [v]);
const nest = (d: number): any => (d === 0 ? { type: 'string' } : { type: 'object', props: { a: nest(d - 1) } });
const nestArr = (d: number): any => (d === 0 ? { type: 'string' } : { type: 'array', items: nestArr(d - 1) });
for (const d of [5, 6, 7, 8, 9]) { await run('validateArgSchema', `object depth ${d}`, an.validateArgSchema, [S({ x: nest(d) })]); await run('validateArgSchema', `array depth ${d}`, an.validateArgSchema, [S({ x: nestArr(d) })]); }
const flat = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`p${i}`, { type: 'boolean' }]));
for (const n of [63, 64, 65]) await run('validateArgSchema', `props ${n}`, an.validateArgSchema, [S(flat(n))]);
// node budget: 256 total (objects count once). 4 objects x 63 leaves + root ~ 256 boundary
for (const [o, l] of [[4, 62], [4, 63], [4, 64], [3, 64], [5, 50], [5, 51]] as const)
  await run('validateArgSchema', `nodes ${o}x${l}`, an.validateArgSchema, [S(Object.fromEntries(Array.from({ length: o }, (_, i) => [`o${i}`, { type: 'object', props: flat(l) }])))]);
for (const n of [0, 1, 256, 257]) await run('validateArgSchema', `enum ${n}`, an.validateArgSchema, [S({ e: { type: 'integer', enum: Array.from({ length: n }, (_, i) => i) } })]);
for (const n of [1023, 1024, 1025]) await run('validateArgSchema', `const len ${n}`, an.validateArgSchema, [S({ e: { type: 'string', const: 'a'.repeat(n) } })]);
for (const n of [511, 512, 513]) await run('validateArgSchema', `prefix len ${n}`, an.validateArgSchema, [S({ e: { type: 'string', prefix: 'a'.repeat(n) } })]);
for (const [k, lim] of [['minLength', 1_048_576], ['maxLength', 1_048_576], ['minItems', 4096], ['maxItems', 4096]] as const) {
  const t = k.endsWith('Items') ? { type: 'array', items: { type: 'string' } } : { type: 'string' };
  for (const v of [0, 1, lim - 1, lim, lim + 1, -1, 1.5, '1', null, -0, 1e21]) await run('validateArgSchema', `${k} ${JSON.stringify(v)}`, an.validateArgSchema, [S({ e: { ...t, [k]: v } })]);
}
for (const [a, b] of [[1, 2], [2, 2], [3, 2], [0, 0]]) {
  await run('validateArgSchema', `minLength ${a} maxLength ${b}`, an.validateArgSchema, [S({ e: { type: 'string', minLength: a, maxLength: b } })]);
  await run('validateArgSchema', `minItems ${a} maxItems ${b}`, an.validateArgSchema, [S({ e: { type: 'array', items: { type: 'string' }, minItems: a, maxItems: b } })]);
  await run('validateArgSchema', `min ${a} max ${b}`, an.validateArgSchema, [S({ e: { type: 'number', min: a, max: b } })]);
}
for (const t of ['string', 'number', 'integer', 'boolean']) for (const c of [1, 1.5, 'x', true, null, -0, 2 ** 53, [], {}]) {
  await run('validateArgSchema', `${t} const ${JSON.stringify(c)}`, an.validateArgSchema, [S({ e: { type: t, const: c } })]);
  await run('validateArgSchema', `${t} enum [${JSON.stringify(c)}]`, an.validateArgSchema, [S({ e: { type: t, enum: [c] } })]);
}
for (const [l, n] of [['bad name dash', 'a-b'], ['bad name empty', ''], ['name 64', 'a'.repeat(64)], ['name 65', 'a'.repeat(65)], ['name unicode', 'é'], ['name long bad', '-'.repeat(40)], ['name digits', '123'], ['name underscore', '_']] as const)
  await run('validateArgSchema', l, an.validateArgSchema, [S({ [n]: { type: 'string' } })]);
for (const [l, r] of [['required undeclared', ['zz']], ['required non-string', [1]], ['required dup', ['amount', 'amount']], ['required 65', Array.from({ length: 65 }, () => 'amount')], ['required 64', Array.from({ length: 64 }, () => 'amount')], ['required obj', {}], ['required null', null]] as const)
  await run('validateArgSchema', l, an.validateArgSchema, [S({ amount: { type: 'number' } }, r)]);
for (const t of ['String', 'float', 'null', '', 'object', 'array']) await run('validateArgSchema', `type ${t}`, an.validateArgSchema, [S({ e: { type: t } })]);
for (const v of [null, [], 'x', 1, { props: {}, extra: 1 }, { props: [] }, { props: null }, {}, { props: {} }]) await run('validateArgSchema', `top ${JSON.stringify(v)}`, an.validateArgSchema, [v]);

// a seeded generator of valid-ish schemas (and conforming values for them)
function genSpec(d: number): any {
  const t = d >= 3 ? R.pick(['string', 'number', 'integer', 'boolean']) : R.pick(['string', 'number', 'integer', 'boolean', 'object', 'array']);
  if (t === 'object') { const n = R.int(0, 3); const props = Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, genSpec(d + 1)])); const s: any = { type: 'object', props }; if (n && R.next() < 0.5) s.required = R.sub(Object.keys(props)); return s; }
  if (t === 'array') { const s: any = { type: 'array', items: genSpec(d + 1) }; if (R.next() < 0.4) s.minItems = R.int(0, 2); if (R.next() < 0.5) s.maxItems = R.int(s.minItems ?? 0, 4); return s; }
  if (t === 'string') { const s: any = { type: 'string' }; const k = R.int(0, 4); if (k === 1) s.enum = R.sub(['a', 'bb', 'ccc', '']).concat(['a']); if (k === 2) s.const = 'x'; if (k === 3) s.prefix = 'p'; if (k === 4) { s.minLength = R.int(0, 2); s.maxLength = R.int(s.minLength, 5); } return s; }
  if (t === 'boolean') { const s: any = { type: 'boolean' }; if (R.next() < 0.3) s.const = R.pick([true, false]); return s; }
  const s: any = { type: t }; const k = R.int(0, 3); if (k === 1) s.enum = [0, 1, t === 'number' ? 2.5 : 2]; if (k === 2) s.const = 7; if (k === 3) { s.min = R.int(-3, 0); s.max = R.int(0, 9); } return s;
}
function genVal(s: any): any {
  switch (s.type) {
    case 'object': { const o: any = {}; for (const [k, v] of Object.entries(s.props)) if ((s.required ?? []).includes(k) || R.next() < 0.6) o[k] = genVal(v); return o; }
    case 'array': return Array.from({ length: R.int(s.minItems ?? 0, Math.max(s.minItems ?? 0, s.maxItems ?? 3)) }, () => genVal(s.items));
    case 'string': return s.const ?? (s.enum ? R.pick(s.enum) : (s.prefix ?? '') + 'abcde'.slice(0, R.int(s.minLength ?? 0, s.maxLength ?? 4)));
    case 'boolean': return s.const ?? R.pick([true, false]);
    default: return s.const ?? (s.enum ? R.pick(s.enum) : s.min !== undefined ? R.int(s.min, s.max) : R.int(-2, 50));
  }
}
const schemas: any[] = [BASE_SCHEMA];
for (let i = 0; i < 160; i++) {
  const n = R.int(1, 4);
  const props = Object.fromEntries(Array.from({ length: n }, (_, j) => [`a${j}`, genSpec(1)]));
  const sc: any = { props };
  if (R.next() < 0.5) sc.required = R.sub(Object.keys(props));
  await run('validateArgSchema', `gen ${i}`, an.validateArgSchema, [sc]);
  if (an.validateArgSchema(sc) === null) schemas.push(sc);
}

// ================================================================ tool_schema: evaluateToolSchema
const SIG = { name: 'payments.send', params: ['amount', 'currency'] };
const ev = an.evaluateToolSchema;
const longKey = 'k'.repeat(60);
for (const [si, sc] of schemas.entries()) {
  const cav = an.toolSchemaCaveat(SIG, sc);
  const nCalls = si === 0 ? 40 : 12;
  for (let j = 0; j < nCalls; j++) {
    const args = genVal({ type: 'object', props: sc.props, required: sc.required });
    await run('evaluateToolSchema', `s${si} conforming ${j}`, ev, [cav, { tool: SIG.name, args }]);
    // structural mutants of the conforming args
    const vs = [...variants(args, { depth: 4, maxPaths: 6, hostile: R.sub(HOSTILE, 6) })];
    for (let k = 0; k < Math.min(vs.length, si === 0 ? 30 : 6); k++) { const [l, v] = vs[R.int(0, vs.length - 1)]!; await run('evaluateToolSchema', `s${si} ${j} mut ${l}`, ev, [cav, { tool: SIG.name, args: v }]); }
  }
}
{
  const cav = an.toolSchemaCaveat(SIG, BASE_SCHEMA);
  const ok = { amount: 50, currency: 'usd' };
  const calls: [string, any][] = [
    ['ok', { tool: SIG.name, args: ok }], ['other tool', { tool: 'payments.refund', args: ok }], ['tool long', { tool: 't'.repeat(60), args: ok }], ['tool quote', { tool: 'a"b\\c\n\u0001', args: ok }],
    ['tool lone surrogate', { tool: 'x\ud800y', args: ok }], ['tool surrogate cut at 48', { tool: 'a'.repeat(47) + '😀' + 'zz', args: ok }], ['tool 48', { tool: 'a'.repeat(48), args: ok }], ['tool 49', { tool: 'a'.repeat(49), args: ok }],
    ['unexpected key long', { tool: SIG.name, args: { ...ok, [longKey]: 1 } }], ['unexpected key control', { tool: SIG.name, args: { ...ok, 'a\tb\u0007': 1 } }], ['unexpected key lone low', { tool: SIG.name, args: { ...ok, '\udc00x': 1 } }],
    ['unexpected key del', { tool: SIG.name, args: { ...ok, '\u007f': 1 } }], ['unexpected key b f', { tool: SIG.name, args: { ...ok, '\b\f\r': 1 } }],
    ['missing required', { tool: SIG.name, args: { currency: 'usd' } }], ['args array', { tool: SIG.name, args: [] }], ['args null', { tool: SIG.name, args: null }], ['tool number', { tool: 5, args: ok }], ['call null', null], ['call array', []],
    ['signature same', { tool: SIG.name, args: ok, toolSignature: SIG }], ['signature other', { tool: SIG.name, args: ok, toolSignature: { name: SIG.name } }], ['signature digest same', { tool: SIG.name, args: ok, toolSignatureDigest: cav.signature_digest }],
    ['signature digest other', { tool: SIG.name, args: ok, toolSignatureDigest: cav.binding_digest }], ['signature digest null', { tool: SIG.name, args: ok, toolSignatureDigest: null }], ['signature null', { tool: SIG.name, args: ok, toolSignature: null }],
    ['amount -0', { tool: SIG.name, args: { amount: -0, currency: 'usd' } }], ['amount 100', { tool: SIG.name, args: { amount: 100 } }], ['amount 100.5', { tool: SIG.name, args: { amount: 100.5 } }], ['amount 1e21', { tool: SIG.name, args: { amount: 1e21 } }],
    ['n 3.0', { tool: SIG.name, args: { amount: 1, n: 3.0 } }], ['n 3.5', { tool: SIG.name, args: { amount: 1, n: 3.5 } }], ['memo prefix', { tool: SIG.name, args: { amount: 1, memo: 'mx' } }], ['memo no prefix', { tool: SIG.name, args: { amount: 1, memo: 'x' } }],
    ['memo 16', { tool: SIG.name, args: { amount: 1, memo: 'm'.repeat(16) } }], ['memo 17', { tool: SIG.name, args: { amount: 1, memo: 'm'.repeat(17) } }], ['memo empty', { tool: SIG.name, args: { amount: 1, memo: '' } }], ['memo astral 16 units', { tool: SIG.name, args: { amount: 1, memo: 'm' + '😀'.repeat(7) + 'x' } }],
    ['tags 0', { tool: SIG.name, args: { amount: 1, tags: [] } }], ['tags 4', { tool: SIG.name, args: { amount: 1, tags: ['a', 'b', 'c', 'd'] } }], ['tags item long', { tool: SIG.name, args: { amount: 1, tags: ['abcde'] } }], ['tags null item', { tool: SIG.name, args: { amount: 1, tags: [null] } }],
    ['to missing iban', { tool: SIG.name, args: { amount: 1, to: { bic: 'x' } } }], ['to extra', { tool: SIG.name, args: { amount: 1, to: { iban: 'x', zz: 1 } } }], ['to array', { tool: SIG.name, args: { amount: 1, to: [] } }],
    ['ok true', { tool: SIG.name, args: { amount: 1, ok: true } }], ['ok false', { tool: SIG.name, args: { amount: 1, ok: false } }], ['currency EUR', { tool: SIG.name, args: { amount: 1, currency: 'EUR' } }],
  ];
  for (const [l, c] of calls) await run('evaluateToolSchema', `base ${l}`, ev, [cav, c]);
  const cavs: [string, any][] = [['schema edited', { ...cav, schema: { ...cav.schema, required: [] } }], ['schema digest edited', { ...cav, schema_digest: cav.binding_digest }], ['binding edited', { ...cav, binding_digest: cav.schema_digest }],
    ['sig digest edited', { ...cav, signature_digest: cav.schema_digest }], ['type other', { ...cav, type: 'predicates' }], ['tool empty', { ...cav, tool: '' }], ['schema invalid', { ...cav, schema: { props: { a: { type: 'x' } } } }], ['null', null], ['array', []], ['sig digest number', { ...cav, signature_digest: 5 }]];
  for (const [l, c] of cavs) await run('evaluateToolSchema', `caveat ${l}`, ev, [c, { tool: SIG.name, args: ok }]);
  // value budget: MAX_VALUE_NODES = 10000
  const big = an.toolSchemaCaveat(SIG, S({ xs: { type: 'array', items: { type: 'array', items: { type: 'integer' }, maxItems: 4096 }, maxItems: 4096 } }));
  for (const [l, outer, inner] of [['9999 nodes', 9, 1109], ['10000 nodes', 1, 9998], ['10001 nodes', 1, 9999], ['inner 4096', 1, 4096], ['inner 4097', 1, 4097], ['default 256', 1, 256]] as const)
    await run('evaluateToolSchema', `budget ${l}`, ev, [big, { tool: SIG.name, args: { xs: Array.from({ length: outer }, () => Array.from({ length: inner }, () => 1)) } }]);
  const dflt = an.toolSchemaCaveat(SIG, S({ s: { type: 'string' }, a: { type: 'array', items: { type: 'boolean' } } }));
  for (const n of [256, 257]) await run('evaluateToolSchema', `default maxItems ${n}`, ev, [dflt, { tool: SIG.name, args: { a: Array.from({ length: n }, () => true) } }]);
  for (const n of [65_536, 65_537]) await run('evaluateToolSchema', `default maxLength ${n}`, ev, [dflt, { tool: SIG.name, args: { s: 'a'.repeat(n) } }]);
  const maxD = [8, 7, 6, 5].find((d) => an.validateArgSchema(S({ x: nest(d) })) === null)!;
  const deep8 = an.toolSchemaCaveat(SIG, S({ x: nest(maxD) }));
  const deepVal = (d: number): any => (d === 0 ? 'v' : { a: deepVal(d - 1) });
  for (const d of [maxD - 1, maxD, maxD + 1, maxD + 2]) await run('evaluateToolSchema', `deep value ${d}`, ev, [deep8, { tool: SIG.name, args: { x: deepVal(d) } }]);
}

// ================================================================ risk policy, envelope, attestation requirement
const ZERO = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1000 };
for (const [l, v] of variants(ZERO)) await run('validateRiskPolicy', l, p.validateRiskPolicy, [v]);
for (const [l, o] of [['theta1=theta2', { theta1: 0.5, theta2: 0.5 }], ['theta1>theta2', { theta1: 0.6, theta2: 0.5 }], ['theta1<0', { theta1: -0.1 }], ['theta1 -0', { theta1: -0 }], ['kappa 0', { kappa: 0 }], ['kappa -0', { kappa: -0 }], ['kappa tiny', { kappa: 1e-300 }],
  ['lambda -1', { lambda: -1 }], ['rho -1', { rho: -1 }], ['bMax -1', { bMax: -1 }], ['bMax 0', { bMax: 0 }], ['weights array', { weights: [] }], ['weights null', { weights: null }], ['weight -0', { weights: { ...ZERO.weights, beta: -0 } }]] as const)
  await run('validateRiskPolicy', l, p.validateRiskPolicy, [{ ...ZERO, ...o }]);
for (const v of [null, [], 'x', 5, {}]) await run('validateRiskPolicy', `top ${JSON.stringify(v)}`, p.validateRiskPolicy, [v]);

const ENV = { type: 'envelope', goal_commit: 'gc', predicates: [], caveats: [], agent_binding: {}, risk_policy: ZERO };
const grantOf = (caveats: any) => ({ id: 'g', issuer: 'i', holder: 'h', caveats, body_digest: 'g', sig: 's' });
await run('readEnvelope', 'base', p.readEnvelope, [grantOf([ENV])]);
for (const [l, v] of variants(ENV, { depth: 2 })) await run('readEnvelope', `env ${l}`, p.readEnvelope, [grantOf([v])]);
for (const [l, cs] of [['second envelope ignored', [ENV, { ...ENV, goal_commit: 1 }]], ['first malformed, second ok', [{ ...ENV, goal_commit: 1 }, ENV]], ['after other caveat', [{ type: 'max_spend', usd: 1 }, ENV]], ['null caveat first', [null, ENV]], ['none', []],
  ['agent_binding array', [{ ...ENV, agent_binding: [] }]], ['with provenance', [{ ...ENV, provenance: { mode: 'insecure_off' } }]], ['caveats object', {}], ['caveats null', null]] as const)
  await run('readEnvelope', l, p.readEnvelope, [grantOf(cs)]);
for (const g of [null, [], 'x', {}, { caveats: 'x' }]) await run('readEnvelope', `grant ${JSON.stringify(g)}`, p.readEnvelope, [g]);

const bindings: any[] = [undefined, null, {}, [], { operator: '' }, { operator: 'acme' }, { operator: 5 }, { min_measurement: '' }, { min_measurement: 'm' }, { min_measurement: null }, { min_measurement: 0 },
  { model_allowlist: [] }, { model_allowlist: ['m'] }, { model_allowlist: 'm' }, { weights_allowlist: ['w'] }, { weights_allowlist: [] }, { system_prompt_allowlist: ['s'] }, { tool_manifest_allowlist: ['t'] }, { tool_manifest_allowlist: [] },
  { require_hardware: true }, { require_hardware: false }, { require_hardware: 'true' }, { require_measured_weights: true }, { require_measured_weights: 1 }, { unknown: 1 }, { model_allowlist: [null] }];
for (const [i, b] of bindings.entries()) await run('requiresAttestation', `binding ${i} ${JSON.stringify(b) ?? 'undefined'}`, (x: any) => requiresAttestation(x ?? undefined), [b]);

// ================================================================ authorize() scenarios
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments/acme';
const prSk = seed('k05az/principal');
const agSk = seed('k05az/agent');
const pPub = p.b64u(p.publicKeyOf(prSk));
const aPub = p.b64u(p.publicKeyOf(agSk));
const SALT = p.b64u(seed('k05az/salt').slice(0, 16));
const recOf = (l: string, o: any = {}) => p.createProvenanceRecorder({ mediator: o.mediator ?? 'harness', kid: 'k1', secretKey: seed(`k05az/med/${l}`), session: p.b64u(seed(`k05az/session/${l}`)), now: () => NOW });
const PIN = recOf('main').pin;
const PIN_OTHER = recOf('other').pin;
const BAD_PIN = { ...PIN, pk: 'x' };

function envGrant(o: any = {}) {
  const envelope: any = { predicates: o.predicates ?? [{ verb: [VERB, 'payments.refund'], resource: 'payments/*' }], caveats: o.caveats ?? [], agent_binding: o.agentBinding ?? {}, risk_policy: ZERO };
  if (o.provenance !== undefined && p.provEnvelopeError(o.provenance) === null) envelope.provenance = o.provenance;
  let g = p.mintGrant({ principalSecret: prSk, principalPublic: pPub, holder: aPub, goal: 'pay invoices', salt: SALT, envelope }).grant;
  if (o.provenance !== undefined && p.provEnvelopeError(o.provenance) !== null) {
    // a malformed provenance member cannot be minted through mintGrant: re-sign the root with the raw envelope caveat
    const cv = g.caveats.map((c: any) => (c.type === 'envelope' ? { ...c, provenance: o.provenance } : c));
    g = p.mintRoot({ principalSecret: prSk, principalPublic: pPub, holder: aPub, caveats: cv });
  }
  return g;
}
const pay = (amount: number, extra: any = {}) => ({ amount, currency: 'usd', ...extra });
function signP(grant: any, params: any, counter: number, o: any = {}) {
  const node = { id: 'n1', verb: o.verb ?? VERB, resource: o.resource ?? RES, params_digest: p.paramsDigest(params), reversibility_class: o.rev ?? 'irreversible' };
  return p.buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter, signerSecret: agSk, aud: o.aud ?? AUD, now: NOW });
}
const FRESH = { signer: pPub, scope: 'payments', local: { revocation_epoch: 0, ledger_tree_size: 0, budget_version: 0, policy_revision: 0, policy_digest: p.b64u(seed('k05az/pd')) }, require: true };
const ADM = (verb = 'payments.refund') => ({ id: 'undo-1', window_end: NOW + 600_000, compensation: { verb, resource: RES } });
const RENDER = p.b64u(seed('k05az/render'));

// one scenario = {grant, config, steps}; the reference result per step is the projection below
const KEY = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'plan_root_authorized', 'leaf_signature', 'counter_format', 'fresh_at', 'attestation', 'revocation', 'grant_ref', 'operation', 'params_digest', 'delegated_caveats', 'policy', 'replay', 'provenance_flow', 'undo_window', 'escalation'];
const OWN = ['provenance_flow: ', 'undo_window: ', 'escalation: ', 'fresh_at: '];
async function scenario(sc: any) {
  let revoked = false;
  const cfg = sc.config;
  const opts: any = {
    audience: cfg.audience, resolveGrant: async (ref: string) => (ref === sc.grant.id ? sc.grant : null), budgetStore: p.atomicMemoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: !revoked }) }, plan: 'single-step', now: () => cfg.now,
    provenance: { mediators: cfg.mediators, ...(cfg.actions ? { actions: (op: any) => cfg.actions[op.verb] } : {}), ...(cfg.observed ? { observed: () => cfg.observed } : {}) },
  };
  if (cfg.freshAt) opts.freshAt = cfg.freshAt;
  if (cfg.undo) opts.undo = { admit: async (a: any) => (a.converted && cfg.undo[a.operation.verb] !== undefined ? clone(cfg.undo[a.operation.verb]) : { refused: 'not eligible' }), open: async (adm: any) => adm };
  if (cfg.escalation) opts.escalation = { principals: cfg.escalation.principals, ...(cfg.escalation.render_digest ? { render: () => cfg.escalation.render_digest } : {}), ...(cfg.escalation.insecureUnboundApproval ? { insecureUnboundApproval: true } : {}) };
  const az = p.createAuthorizer(opts);
  const out: any[] = [];
  for (const s of sc.steps) {
    revoked = s.revoked === true;
    const r = await az({ pcactn: s.pcactn, operation: s.operation, ...(s.provenance !== undefined ? { provenance: s.provenance } : {}), ...(s.escalationAnswer !== undefined ? { escalationAnswer: s.escalationAnswer } : {}) });
    const checks = r.verdict?.checks ?? {};
    const reasons: string[] = r.verdict?.reasons ?? [];
    out.push({
      allow: r.allow, decision: r.decision, status: r.status,
      checks: Object.fromEntries(KEY.filter((k) => checks[k] !== undefined).map((k) => [k, checks[k]])),
      failed: KEY.filter((k) => checks[k] === 'fail'),
      reasons: reasons.filter((x) => OWN.some((o) => x.startsWith(o))),
      escalation: r.escalation === undefined ? null : r.allow ? r.escalation : { request: true },
      undo: r.undo ?? null,
    });
  }
  return out;
}
const opOf = (params: any, o: any = {}) => ({ verb: o.verb ?? VERB, resource: o.resource ?? RES, params });
const direct = (l: string, op: any) => p.principalDirectProvenance(recOf(l), op);
function tainted(l: string, op: any, src = 'crm.lookup') {
  const r = recOf(l);
  r.principal('pay the invoice');
  r.tool(src, 'payee acme 50');
  return r.forAction(op);
}
function forged(op: any) {
  const b = direct('main', op);
  return { ...b, receipts: [b.receipts[0], { ...b.receipts[1], sig: b.receipts[0].sig }] };
}
function answer(grant: any, pcactn: any, decision: string, o: any = {}) {
  const body: any = { v: 1, kind: 'pca-escalation-answer', principal: o.principal ?? pPub, policy_digest: p.escalationPolicyDigest(grant), action_digest: p.escalationActionDigest(pcactn), history_head: p.escalationHistoryHead(o.last),
    decision, iat: NOW - 1000, expires_at: NOW + (o.ttl ?? 60_000), nonce: p.b64u(seed(`k05az/nonce/${o.nonce ?? 0}`).slice(0, 16)) };
  if (o.render !== undefined) body.render_digest = o.render;
  return p.signEscalationAnswer(body, o.sk ?? prSk);
}
const az = (name: string, sc: any) => run('authorize', name, scenario, [sc]);

// ---- the grid: grant provenance member x verifier pins x bundle x action facts x observations x fresh_at x undo
const envP: [string, any][] = [['none', undefined], ['enforce', { mode: 'enforce' }], ['insecure_off', { mode: 'insecure_off' }], ['grant names harness', { mediators: [PIN] }], ['malformed mode', { mode: 'off' }], ['malformed pin', { mediators: [BAD_PIN] }]];
const pinsL: [string, any][] = [['none', []], ['harness', [PIN]], ['other', [PIN_OTHER]]];
const bundleL: [string, (op: any) => any][] = [['direct', (op) => direct('main', op)], ['tainted', (op) => tainted('main', op)], ['none', () => null], ['forged', (op) => forged(op)], ['unpinned', (op) => direct('other', op)], ['other op', (op) => direct('main', { ...op, params: pay(1) })]];
const factsL: [string, any][] = [['unknown', undefined], ['read', { [VERB]: { effects: ['read'] } }], ['write', { [VERB]: { effects: ['write'] } }], ['write floors agent', { [VERB]: { effects: ['write'], params: { amount: 'agent', currency: 'agent' } } }]];
const obsL: [string, any][] = [['none', undefined], ['tool', [{ origin: 'tool', source: 'gw' }]]];
const grants = new Map<string, any>();
const grantFor = (l: string, prov: any) => { if (!grants.has(l)) grants.set(l, envGrant({ provenance: prov })); return grants.get(l); };
let gi = 0;
for (const [el, prov] of envP)
  for (const [pl, pins] of pinsL)
    for (const [bl, mk] of bundleL)
      for (const [fl, facts] of factsL)
        for (const [ol, obs] of obsL)
          for (const fresh of [false, true])
            for (const undo of [false, true]) {
              // full grid for the provenance dimensions without fresh_at/undo; a seeded sample of the rest
              if ((fresh || undo || ol !== 'none') && R.next() > 0.12) continue;
              const g = grantFor(el, prov);
              const params = pay(50);
              const op = opOf(params);
              const pc = signP(g, params, 1);
              const config: any = { audience: AUD, now: NOW, mediators: pins, ...(facts ? { actions: facts } : {}), ...(obs ? { observed: obs } : {}), ...(fresh ? { freshAt: FRESH } : {}), ...(undo ? { undo: { [VERB]: ADM() } } : {}) };
              await az(`grid ${gi++} [env ${el}|pins ${pl}|bundle ${bl}|facts ${fl}|obs ${ol}|fresh ${fresh}|undo ${undo}]`, { grant: g, config, steps: [{ pcactn: pc, operation: op, provenance: mk(op) }] });
            }

// ---- escalation answers (fresh_at escalate-class failure; provenance passes with a pinned principal-direct bundle)
{
  const g = grantFor('none', undefined);
  const params = pay(50);
  const op = opOf(params);
  const pc = signP(g, params, 1);
  const base = { audience: AUD, now: NOW, mediators: [PIN], freshAt: FRESH };
  const prov = direct('main', op);
  const esc = (l: string, escCfg: any, ans: any, extra: any = {}) => az(`escalation ${l}`, { grant: g, config: { ...base, escalation: escCfg, ...extra }, steps: [{ pcactn: pc, operation: op, provenance: prov, ...(ans !== undefined ? { escalationAnswer: ans } : {}) }] });
  const E = { principals: [pPub], render_digest: RENDER };
  await esc('no answer', E, undefined);
  await esc('allow bound to render', E, answer(g, pc, 'allow', { render: RENDER }));
  await esc('deny', E, answer(g, pc, 'deny', { render: RENDER }));
  await esc('allow, render differs', E, answer(g, pc, 'allow', { render: p.b64u(seed('x')) }));
  await esc('allow, no render in answer', E, answer(g, pc, 'allow'));
  await esc('allow, verifier has no render (K7 default)', { principals: [pPub] }, answer(g, pc, 'allow'));
  await esc('allow, insecureUnboundApproval', { principals: [pPub], insecureUnboundApproval: true }, answer(g, pc, 'allow'));
  await esc('allow, unpinned principal', { principals: [aPub], render_digest: RENDER }, answer(g, pc, 'allow', { render: RENDER }));
  await esc('allow signed by agent key', E, answer(g, pc, 'allow', { render: RENDER, principal: aPub, sk: agSk }));
  await esc('allow, other action', E, answer(g, signP(g, pay(51), 1), 'allow', { render: RENDER }));
  await esc('allow, wrong history head', E, answer(g, pc, 'allow', { render: RENDER, last: 7 }));
  await esc('allow, expires at now', { ...E }, answer(g, pc, 'allow', { render: RENDER, ttl: 0 }));
  await esc('answer malformed', E, { v: 1 });
  await esc('answer null', E, null);
  await esc('no principals configured', { principals: [], render_digest: RENDER }, answer(g, pc, 'allow', { render: RENDER }));
  // the undo window is never offered when an answer is presented, and never for a provenance escalation
  await esc('deny answer + undo', E, answer(g, pc, 'deny', { render: RENDER }), { undo: { [VERB]: ADM() } });
  await esc('no answer + undo', E, undefined, { undo: { [VERB]: ADM() } });
  await esc('no answer + undo for other verb', E, undefined, { undo: { 'payments.refund': ADM() } });
  await az('undo + provenance escalation', { grant: g, config: { ...base, undo: { [VERB]: ADM() } }, steps: [{ pcactn: pc, operation: op, provenance: tainted('main', op) }] });
  await az('undo + allowed action (no escalation)', { grant: g, config: { audience: AUD, now: NOW, mediators: [PIN], undo: { [VERB]: ADM() } }, steps: [{ pcactn: pc, operation: op, provenance: prov }] });
  for (const [l, adm] of [['window_end 0', { ...ADM(), window_end: 0 }], ['compensation with resource', ADM('payments.refund')], ['id 128', { ...ADM(), id: 'i'.repeat(128) }],
    // a malformed admission is no admission: the escalation stands (0.5; before, any truthy admission turned it into an allow)
    ['id empty', { ...ADM(), id: '' }], ['id 129', { ...ADM(), id: 'i'.repeat(129) }], ['id number', { ...ADM(), id: 7 }], ['window_end -5', { ...ADM(), window_end: -5 }],
    ['window_end 1.5', { ...ADM(), window_end: 1.5 }], ['window_end string', { ...ADM(), window_end: '5' }], ['window_end 2^53', { ...ADM(), window_end: 2 ** 53 }],
    ['compensation verb empty', { ...ADM(), compensation: { verb: '', resource: 'r' } }], ['compensation missing', (() => { const { compensation: _c, ...a } = ADM() as any; return a; })()],
    ['compensation array', { ...ADM(), compensation: [] }], ['admission array', []]] as const)
    await az(`undo admission ${l}`, { grant: g, config: { ...base, undo: { [VERB]: adm } }, steps: [{ pcactn: pc, operation: op, provenance: prov }] });
  // replay after an undo admission / an answered escalation consumes the counter
  await az('undo then replay', { grant: g, config: { ...base, undo: { [VERB]: ADM() } }, steps: [{ pcactn: pc, operation: op, provenance: prov }, { pcactn: pc, operation: op, provenance: prov }] });
}

// ---- the pipeline around the gate (binding, replay, revocation, caveats, audience, attestation), provenance passing
{
  const gEnvCav = envGrant({ caveats: [{ type: 'max_spend', usd: 100 }] });
  const gPred = envGrant({ predicates: [{ verb: VERB, resource: 'payments/*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }] });
  const gAtt = envGrant({ agentBinding: { operator: 'acme-ops' } });
  const cfg = { audience: AUD, now: NOW, mediators: [PIN] };
  const one = (l: string, g: any, signParams: any, op: any, o: any = {}) => az(`pipeline ${l}`, { grant: g, config: { ...cfg, ...(o.config ?? {}) }, steps: [{ pcactn: signP(g, signParams, o.counter ?? 1, o.sign ?? {}), operation: op, provenance: direct('main', op), ...(o.revoked ? { revoked: true } : {}) }] });
  await one('within', gEnvCav, pay(50), opOf(pay(50)));
  await one('over max_spend', gEnvCav, pay(400), opOf(pay(400)));
  await one('signed 50 executes 400', gEnvCav, pay(50), opOf(pay(400)));
  await one('predicate over', gPred, pay(101), opOf(pay(101)));
  await one('predicate at limit', gPred, pay(100), opOf(pay(100)));
  await one('other verb', gEnvCav, pay(50), opOf(pay(50), { verb: 'payments.refund' }));
  await one('other resource', gEnvCav, pay(50), opOf(pay(50), { resource: 'payments/x' }));
  await one('revoked', gEnvCav, pay(50), opOf(pay(50)), { revoked: true });
  await one('wrong audience', gEnvCav, pay(50), opOf(pay(50)), { sign: { aud: 'other' } });
  await one('attestation bound', gAtt, pay(50), opOf(pay(50)));
  await one('counter 0', gEnvCav, pay(50), opOf(pay(50)), { counter: 0 });
  await one('reversible class', gEnvCav, pay(50), opOf(pay(50)), { sign: { rev: 'reversible' } });
  for (const [l, prov] of [['insecure_off + tainted', { mode: 'insecure_off' }], ['enforce + tainted', { mode: 'enforce' }]] as const) {
    const g = envGrant({ provenance: prov });
    const op = opOf(pay(50));
    await az(`pipeline ${l}`, { grant: g, config: cfg, steps: [{ pcactn: signP(g, pay(50), 1), operation: op, provenance: tainted('main', op) }] });
  }
  const op = opOf(pay(50));
  const p1 = signP(gEnvCav, pay(50), 1);
  const p2 = signP(gEnvCav, pay(50), 2);
  await az('pipeline replay', { grant: gEnvCav, config: cfg, steps: [{ pcactn: p1, operation: op, provenance: direct('main', op) }, { pcactn: p1, operation: op, provenance: direct('main', op) }, { pcactn: p2, operation: op, provenance: direct('main', op) }] });
  await az('pipeline escalate does not consume', { grant: gEnvCav, config: cfg, steps: [{ pcactn: p1, operation: op, provenance: tainted('main', op) }, { pcactn: p1, operation: op, provenance: direct('main', op) }] });
  await az('pipeline deny (forged) does not consume', { grant: gEnvCav, config: cfg, steps: [{ pcactn: p1, operation: op, provenance: forged(op) }, { pcactn: p1, operation: op, provenance: direct('main', op) }] });
}

O.write();
