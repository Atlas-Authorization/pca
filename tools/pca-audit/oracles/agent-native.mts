// Oracle: every export of packages/pca/src/agent-native.ts (caution claims, rationale commitments, tool-schema firewall, capability
// introspection, authority leases), TS reference. Writes out/ref-agent-native.json.gz. Deterministic: keys from seed(label), no clock (every
// time is an argument). Case shape (as every sibling): {fn, name, args, out}; `out` is what the reference returned, or {"$throws": message}.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw = the native refuses)
//   args conventions (corpus -> reference call):
//     {"$num":"NaN"|"Infinity"|"-Infinity"}  anywhere in args = that non-finite double (plain JSON cannot carry them)
//     {"$bytes": {"$seed": label}}            the 32-byte secret key (signCaution / signHeartbeat 2nd arg): sha256("atlas-pca-conformance/" + label), b64u; (the generator writes the key bytes, the strip tool rewrites them to the label,
//                                             so the committed corpus never carries a key)
//     null in an OPTIONAL position (named below) = argument not given. Required positions pass null through as a real null.
//     verifyRationale 3rd arg (action): array length decides (2 args = not given; a given null is a real null).
//   judge (auditRationale 4th arg) is a spec: "true" | "false" | "throw" | "truthy" (returns the string "yes": not === true) | "contains:<s>"
//     (rationale includes s) | "action-verb:<v>" (action.verb === v).
//   signCaution [body, secret]                         -> claim (throws on an invalid body)
//   verifyCaution [claim, digest|null, holder|null]    -> bool
//   combineCaution [declared|null, serverRisk]         -> number          (null = undefined declared)
//   combineSignedCaution [claim|null, digest, serverRisk, holder|null] -> {effectiveRisk, honoured, escalated}
//   checkCautionMonotone [grid]                        -> {ok, counterexample?}
//   isStrongSalt [salt]                                -> bool
//   bindRationale [action, text, salt]                 -> {commitment, reveal} (a throw is a refusal; no case omits the salt: the default is random)
//   verifyRationale [commitment, reveal, action?]      -> bool
//   auditRationale [commitment, action, reveal|null, judge] -> {verdict, slashable, evidence}
//   validateArgSchema [schema]                         -> string | null
//   toolSchemaCaveat [toolSignature, argSchema]        -> caveat (throws on a bad tool name / schema)
//   evaluateToolSchema [caveat, call]                  -> {ok, reason?}   (call: {tool, args, toolSignature?, toolSignatureDigest?})
//   toolSchemaEvaluator [caveat, ctx]                  -> bool
//   predicatesCaveat [allow]                           -> {type:'predicates', allow: canonical clone}
//   actionSpendUsd [action]                            -> number | null   (the reference's undefined is null on the wire)
//   agentNativeCaveatEvaluator [caveat, ctx]           -> bool
//   describeEnvelope [chain, now|null, expectedRootIssuer|null, policy|null] -> AuthorityEnvelope (chain carries real signatures)
//   envelopePermits [env, verb, resource, now|null, params|null] -> bool   (env = a describeEnvelope result or a hand-built one)
//   envelopePermitsToolCall [env, call]                -> {ok, reason?}
//   grantLease [args] -> lease (throws) ; leaseState [lease, now] -> {live, expiresIn, reason?} ; signHeartbeat [body, secret] -> heartbeat
//   renewLease [lease, hb, now]                        -> {ok:true, lease} | {ok:false, reason}
//   constants []                                       -> {NAME: value} for every exported constant
import { Oracle, refWrite, seed } from './lib.mjs';

const P: any = await import('../../../packages/pca/src/index.ts');
const AN: any = await import('../../../packages/pca/src/agent-native.ts');
const { b64u } = await import('../../../packages/pca/src/hash.ts') as any;
const { publicKeyOf, encodeKey, mintRoot, delegate, hashCanonical } = P.default ?? P;

const o = new Oracle('agent-native', 'tools/pca-audit/oracles/agent-native.mts', 'TS-reference oracle for packages/pca/src/agent-native.ts (caution, rationale, tool-schema firewall, envelope introspection, leases).');
const key = (l: string) => { const sk = seed('an/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const H = key('holder'), H2 = key('holder2'), PR = key('principal'), AG = key('agent'), SUB = key('sub');
const J = (x: any) => JSON.parse(JSON.stringify(x));

// $num revival (args only)
const NUM: any = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity };
const revive = (v: any): any => Array.isArray(v) ? v.map(revive)
  : v && typeof v === 'object' ? ('$bytes' in v && Object.keys(v).length === 1 ? new Uint8Array(Buffer.from(v.$bytes, 'base64url')) : '$num' in v && Object.keys(v).length === 1 ? NUM[v.$num] : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, revive(x)]))) : v;
const nul = (x: any) => (x === null ? undefined : x);
const judgeOf = (s: string) => (r: string, a: any) => {
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'throw') throw new Error('judge boom');
  if (s === 'truthy') return 'yes' as any;
  if (s.startsWith('contains:')) return r.includes(s.slice(9));
  if (s.startsWith('action-verb:')) return a?.verb === s.slice(12);
  throw new Error('bad judge spec');
};
const REF: Record<string, (...a: any[]) => any> = {
  signCaution: (b, s) => AN.signCaution(b, s),
  verifyCaution: (c, d, h) => AN.verifyCaution(c, nul(d), nul(h)),
  combineCaution: (d, s) => AN.combineCaution(nul(d), s),
  combineSignedCaution: (c, d, s, h) => AN.combineSignedCaution(nul(c), d, s, nul(h)),
  checkCautionMonotone: (g) => AN.checkCautionMonotone(g),
  isStrongSalt: (s) => AN.isStrongSalt(s),
  bindRationale: (...a) => AN.bindRationale(...a),
  verifyRationale: (...a) => AN.verifyRationale(...a),
  auditRationale: (c, a, r, j) => AN.auditRationale(c, a, nul(r), judgeOf(j)),
  validateArgSchema: (s) => AN.validateArgSchema(s),
  toolSchemaCaveat: (t, s) => AN.toolSchemaCaveat(t, s),
  evaluateToolSchema: (c, k) => AN.evaluateToolSchema(c, k),
  toolSchemaEvaluator: (c, x) => AN.toolSchemaEvaluator(c, x),
  predicatesCaveat: (a) => AN.predicatesCaveat(a),
  actionSpendUsd: (a) => AN.actionSpendUsd(a),
  agentNativeCaveatEvaluator: (c, x) => AN.agentNativeCaveatEvaluator(c, x),
  describeEnvelope: (ch, n, r, p) => AN.describeEnvelope(ch, nul(n), nul(r), nul(p)),
  envelopePermits: (e, v, r, n, p) => AN.envelopePermits(e, v, r, nul(n), nul(p)),
  envelopePermitsToolCall: (e, c) => AN.envelopePermitsToolCall(e, c),
  grantLease: (a) => AN.grantLease(a),
  leaseState: (l, n) => AN.leaseState(l, n),
  signHeartbeat: (b, s) => AN.signHeartbeat(b, s),
  renewLease: (l, h, n) => AN.renewLease(l, h, n),
};
REF.constants = () => Object.fromEntries(Object.entries(AN).filter(([k, v]) => typeof v !== 'function' && /^[A-Z][A-Z0-9_]+$/.test(k)));
const { capture } = await import('../oracles-base/lib.mjs') as any;
let seq = 0;
/** Record one case: args are JSON-clean (secrets as Uint8Array); the reference runs on the revived copy. */
const add = async (fn: string, name: string, args: any[]) => {
  const a = revive(JSON.parse(ser2(args)));
  const out = await capture(REF[fn], a);
  o.add(fn, `${name}#${seq++}`, JSON.parse(ser2(args)), out);
};
// args -> JSON with Uint8Array as {$bytes} and -0 kept; an undefined array slot becomes null
const { ser } = await import('../oracles-base/lib.mjs') as any;
function ser2(a: any) { return ser(a); }

const D = hashCanonical({ verb: 'pay', resource: 'acct:1', params: { amount: 5 } }); // an action digest
const NUMS: any[] = [0, -0, 1, 0.5, 0.25, 0.999999, 1e-9, 1.0000001, -0.0001, -1, 2, 1e21, 5e-324, 2 ** 53, { $num: 'NaN' }, { $num: 'Infinity' }, { $num: '-Infinity' }, '0.5', true, [], {}];

// ============================ 1. caution ============================
const body = (over: any = {}) => ({ action_digest: D, caution: 0.5, holder: H.pk, ...over });
const sc = (name: string, b: any, k = H) => add('signCaution', name, [b, k.sk]);
await sc('ok', body());
await sc('ok-reason', body({ reason: 'ambiguous_instruction' }));
await sc('caution-0', body({ caution: 0 }));
await sc('caution-1', body({ caution: 1 }));
await sc('reason-64', body({ reason: 'a'.repeat(64) }));
await sc('reason-65', body({ reason: 'a'.repeat(65) }));
await sc('reason-empty', body({ reason: '' }));
await sc('reason-bad-char', body({ reason: 'has space' }));
await sc('reason-chars-ok', body({ reason: 'A_b.c:d-9' }));
await sc('reason-num', body({ reason: 5 }));
await sc('reason-null', body({ reason: null }));
for (const [i, c] of NUMS.entries()) await sc('caution-' + i, body({ caution: c }));
await sc('digest-empty', body({ action_digest: '' }));
await sc('digest-num', body({ action_digest: 5 }));
await sc('holder-empty', body({ holder: '' }));
await sc('holder-missing', { action_digest: D, caution: 0.5 });
await sc('digest-missing', { caution: 0.5, holder: H.pk });
await sc('body-null', null);
await sc('body-array', []);
await sc('body-extra-key-dropped', { ...body(), sneaky: 1 });
await sc('body-string', 'x');
await sc('holder-other-key', body({ holder: H2.pk }), H); // signature by another key than the holder

const good = J(AN.signCaution(body({ reason: 'ood' }), H.sk));
const good0 = J(AN.signCaution(body(), H.sk));
const goodHi = J(AN.signCaution(body({ caution: 0.9 }), H.sk));
const goodLo = J(AN.signCaution(body({ caution: 0.1 }), H.sk));
const foreign = J(AN.signCaution(body({ holder: H2.pk }), H2.sk));
const forged = J(AN.signCaution(body({ holder: H.pk }), H2.sk)); // claims holder H, signed by H2
const flip = (s: string) => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'BB' : 'AA');
const claimVariants: [string, any][] = [
  ['good', good], ['good-noreason', good0], ['hi', goodHi], ['lo', goodLo], ['foreign', foreign], ['forged', forged],
  ['bad-sig-flip', { ...good, sig: flip(good.sig) }], ['sig-empty', { ...good, sig: '' }], ['sig-num', { ...good, sig: 5 }], ['sig-missing', (({ sig, ...r }) => r)(good)],
  ['sig-trunc', { ...good, sig: good.sig.slice(0, 20) }], ['sig-padded', { ...good, sig: good.sig + '=' }], ['sig-nonb64', { ...good, sig: '!!!' }],
  ['extra-key', { ...good, extra: 1 }], ['extra-key-null', { ...good, extra: null }], ['caution-tampered', { ...good, caution: 0.1 }], ['caution-neg', { ...good, caution: -0.1 }],
  ['caution-gt1', { ...good, caution: 1.5 }], ['caution-str', { ...good, caution: '0.5' }], ['caution-nan', { ...good, caution: { $num: 'NaN' } }], ['caution-inf', { ...good, caution: { $num: 'Infinity' } }],
  ['reason-tampered', { ...good, reason: 'ood2' }], ['reason-dropped', (({ reason, ...r }) => r)(good)], ['reason-bad', { ...good, reason: 'a b' }], ['reason-long', { ...good, reason: 'a'.repeat(65) }],
  ['digest-tampered', { ...good, action_digest: D + 'x' }], ['holder-tampered', { ...good, holder: H2.pk }], ['holder-empty', { ...good, holder: '' }], ['holder-nonkey', { ...good, holder: 'AAAA' }],
  ['null', null], ['array', []], ['string', 'x'], ['number', 5], ['empty', {}], ['key-reorder', { sig: good.sig, holder: good.holder, reason: good.reason, caution: good.caution, action_digest: good.action_digest }],
];
for (const [n, c] of claimVariants) {
  await add('verifyCaution', n + '/bare', [c, null, null]);
  await add('verifyCaution', n + '/digest', [c, D, null]);
  await add('verifyCaution', n + '/digest+holder', [c, D, H.pk]);
}
await add('verifyCaution', 'wrong-digest', [good, D + 'x', null]);
await add('verifyCaution', 'wrong-holder', [good, null, H2.pk]);
await add('verifyCaution', 'empty-digest-expected', [good, '', null]);
await add('verifyCaution', 'empty-holder-expected', [good, null, '']);
await add('verifyCaution', 'num-digest-expected', [good, 5, null]);
await add('verifyCaution', 'foreign-holder-ok', [foreign, D, H2.pk]);
await add('verifyCaution', 'foreign-vs-pinned-holder', [foreign, D, H.pk]);

for (const s of [0, 0.5, 1]) for (const d of [null, ...NUMS.slice(0, 18)]) await add('combineCaution', `d${JSON.stringify(d)}/s${s}`, [d, s]);
for (const s of NUMS) for (const d of [null, 0.3, 0.7, 1]) await add('combineCaution', `server-${JSON.stringify(s)}/d${d}`, [d, s]);
await add('combineCaution', 'under-report', [0.1, 0.6]);
await add('combineCaution', 'over-report', [0.9, 0.6]);
await add('combineCaution', 'equal', [0.6, 0.6]);
await add('combineCaution', 'clamp-hi', [7, 0.2]);
await add('combineCaution', 'clamp-hi-server', [0.2, 7]);
await add('combineCaution', 'clamp-neg-server', [0.2, -3]);

const signedCases: [string, any, string, number, string | null][] = [
  ['good-escalates', good, D, 0.2, H.pk], ['good-under', good, D, 0.8, H.pk], ['good-equal', good, D, 0.5, H.pk], ['good-no-holder-pin', good, D, 0.2, null],
  ['wrong-holder-pin', good, D, 0.2, H2.pk], ['wrong-digest', good, D + 'x', 0.2, H.pk], ['forged', forged, D, 0.2, null], ['foreign-ok', foreign, D, 0.2, H2.pk],
  ['tampered', { ...good, caution: 0.1 }, D, 0.9, null], ['null-claim', null, D, 0.4, null], ['server-nan', good, D, NaN as any, null], ['server-inf', good, D, Infinity as any, null],
  ['server-neg', good, D, -1, null], ['server-gt1', good, D, 2, null], ['hi-claim', goodHi, D, 0.3, H.pk], ['lo-claim', goodLo, D, 0.3, H.pk], ['bad-shape', { ...good, extra: 1 }, D, 0.3, null],
];
for (const [n, c, d, s, h] of signedCases) await add('combineSignedCaution', n, [c, d, Number.isNaN(s) ? { $num: 'NaN' } : s === Infinity ? { $num: 'Infinity' } : s, h]);

const grids: any[] = [[], [0], [0, 0.5, 1], [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1], [-1, 0, 1, 2], [{ $num: 'NaN' }, 0.5, { $num: 'Infinity' }], [1e-9, 0.5, 1 - 1e-9], [0.5, 0.5, 0.5], [3, -3], [0.7, 0.2, 0.9, 0.1], ['a', 0.5, null, true]];
for (const [i, g] of grids.entries()) await add('checkCautionMonotone', 'grid' + i, [g]);
await add('checkCautionMonotone', 'grid-big', [Array.from({ length: 41 }, (_, i) => i / 40)]);
await add('checkCautionMonotone', 'not-array-guarded', [[0.25, 0.75]]);

// ============================ 2. rationale ============================
const b64 = (n: number, f: (i: number) => number) => Buffer.from(Array.from({ length: n }, (_, i) => f(i) & 255)).toString('base64url');
const SALT = b64(32, (i) => i * 7 + 3);
const SALTS: [string, any][] = [
  ['ok-32', SALT], ['ok-16-distinct', b64(16, (i) => i)], ['ok-exact-8-distinct', b64(16, (i) => i % 8)], ['7-distinct', b64(16, (i) => i % 7)], ['15-bytes', b64(15, (i) => i)], ['16-bytes-same', b64(16, () => 9)],
  ['all-A', 'A'.repeat(43)], ['256-chars', 'Qb'.repeat(128)], ['257-chars', 'Qb'.repeat(128) + 'Q'], ['empty', ''], ['std-b64-plus', SALT.replace(/[-_]/, '+') + '+'], ['padded', b64(16, (i) => i) + '=='],
  ['space', SALT + ' '], ['unicode', SALT + 'é'], ['num', 5], ['null', null], ['array', ['x']], ['obj', {}], ['bool', true],
  ['long-valid-64', b64(64, (i) => i * 5)], ['len-mod-1', b64(17, (i) => i * 3 + 1) + 'A'], ['url-chars', b64(40, (i) => 250 - i)], ['exactly-16-with-8', b64(16, (i) => (i < 8 ? i : i - 8))], ['dash-underscore', '-_-_-_-_-_-_-_-_-_-_-_-_'],
];
for (const [n, s] of SALTS) await add('isStrongSalt', n, [s]);

const ACT = { verb: 'pay', resource: 'acct:1', params: { amount: 5 } };
const bind = (name: string, a: any, t: any, s: any = SALT) => add('bindRationale', name, [a, t, s]);
await bind('ok', ACT, 'pay vendor invoice 42');
await bind('empty-text', ACT, '');
await bind('unicode', ACT, 'ünï☃ \u{1F600} line\nbreak');
await bind('max-len', ACT, 'x'.repeat(8192));
await bind('over-len', ACT, 'x'.repeat(8193));
await bind('utf16-units-8192', ACT, '\u{1F600}'.repeat(4096));
await bind('utf16-units-8194', ACT, '\u{1F600}'.repeat(4097));
await bind('text-num', ACT, 5);
await bind('text-null', ACT, null);
await bind('text-obj', ACT, {});
for (const [n, s] of SALTS) await bind('salt-' + n, ACT, 'r', s);
await bind('action-null', null, 'r');
await bind('action-str', 'x', 'r');
await bind('action-nonfinite', { a: { $num: 'NaN' } }, 'r');
await bind('action-neg-zero', { a: -0 }, 'r');
await bind('action-unsafe-int', { a: 2 ** 53 }, 'r');
await bind('action-float', { a: 0.1 }, 'r');
await bind('action-float-exp', { a: 1e-7 }, 'r');
await bind('action-float-16-digits', { a: 0.1234567890123456 }, 'r');
await bind('action-lone-surrogate', { a: '\ud800' }, 'r');
await bind('action-key-order', { b: 1, a: 2 }, 'r');
await bind('action-key-order-2', { a: 2, b: 1 }, 'r');
await bind('action-deep-33', (() => { let v: any = 1; for (let i = 0; i < 33; i++) v = { a: v }; return v; })(), 'r');
await bind('action-deep-31', (() => { let v: any = 1; for (let i = 0; i < 30; i++) v = { a: v }; return v; })(), 'r');
await bind('action-nested-array', { a: [1, [2, { z: null }]], 'é': 'ü' }, 'r');
await bind('weak-salt-first', ACT, 5, 'A'); // text error wins over the salt error

const bound = AN.bindRationale(ACT, 'pay vendor invoice 42', SALT);
const CM = J(bound.commitment), RV = J(bound.reveal);
const CM2 = J(AN.bindRationale({ verb: 'other' }, 'pay vendor invoice 42', SALT).commitment);
const vr = (n: string, c: any, r: any, ...rest: any[]) => add('verifyRationale', n, [c, r, ...rest]);
await vr('ok', CM, RV);
await vr('ok+action', CM, RV, ACT);
await vr('wrong-action', CM, RV, { verb: 'other' });
await vr('action-null-given', CM, RV, null);
await vr('action-key-reorder', CM, RV, { params: { amount: 5 }, resource: 'acct:1', verb: 'pay' });
await vr('wrong-rationale', CM, { ...RV, rationale: 'x' });
await vr('wrong-salt', CM, { ...RV, salt: b64(32, (i) => i * 11 + 1) });
await vr('weak-salt-hash-ok', J(AN.bindRationale(ACT, 'r', SALT).commitment), { rationale: 'r', salt: 'A'.repeat(43) });
await vr('reveal-extra-key', CM, { ...RV, extra: 1 });
await vr('reveal-missing-salt', CM, { rationale: RV.rationale });
await vr('reveal-missing-rationale', CM, { salt: RV.salt });
await vr('reveal-rationale-num', CM, { ...RV, rationale: 5 });
await vr('reveal-too-long', CM, { ...RV, rationale: 'x'.repeat(8193) });
await vr('reveal-null', CM, null);
await vr('reveal-array', CM, []);
await vr('commit-v2', { ...CM, v: 2 }, RV);
await vr('commit-v-str', { ...CM, v: '1' }, RV);
await vr('commit-v-missing', (({ v, ...r }) => r)(CM), RV);
await vr('commit-digest-empty', { ...CM, action_digest: '' }, RV);
await vr('commit-commitment-empty', { ...CM, commitment: '' }, RV);
await vr('commit-commitment-tampered', { ...CM, commitment: flip(CM.commitment) }, RV);
await vr('commit-other-action', CM2, RV);
await vr('commit-null', null, RV);
await vr('commit-extra-key', { ...CM, extra: 1 }, RV);
await vr('commit-string', 'x', RV);
await vr('unicode-ok', J(AN.bindRationale(ACT, 'ünï☃\u{1F600}', SALT).commitment), { rationale: 'ünï☃\u{1F600}', salt: SALT });
await vr('empty-rationale-ok', J(AN.bindRationale(ACT, '', SALT).commitment), { rationale: '', salt: SALT });
await vr('max-len-ok', J(AN.bindRationale(ACT, 'x'.repeat(8192), SALT).commitment), { rationale: 'x'.repeat(8192), salt: SALT }, ACT);
await vr('action-nonhashable', CM, RV, { a: { $num: 'NaN' } });

const au = (n: string, c: any, a: any, r: any, j: string) => add('auditRationale', n, [c, a, r, j]);
for (const j of ['true', 'false', 'throw', 'truthy', 'contains:invoice', 'contains:zzz', 'action-verb:pay', 'action-verb:other']) await au('open/' + j, CM, ACT, RV, j);
await au('unopened/null', CM, ACT, null, 'true');
await au('unopened/wrong-salt', CM, ACT, { ...RV, salt: b64(32, (i) => i * 11 + 1) }, 'true');
await au('unopened/weak-salt', J(AN.bindRationale(ACT, 'r', SALT).commitment), ACT, { rationale: 'r', salt: 'A'.repeat(43) }, 'true');
await au('unopened/wrong-rationale', CM, ACT, { ...RV, rationale: 'nope' }, 'true');
await au('unopened/reveal-array', CM, ACT, [], 'true');
await au('unopened/reveal-extra', CM, ACT, { ...RV, extra: 1 }, 'false');
await au('wrong-action', CM, { verb: 'other' }, RV, 'true');
await au('wrong-action/no-reveal', CM, { verb: 'other' }, null, 'true');
await au('malformed/null', null, ACT, RV, 'true');
await au('malformed/v2', { ...CM, v: 2 }, ACT, RV, 'true');
await au('malformed/empty-digest', { ...CM, action_digest: '' }, ACT, RV, 'true');
await au('malformed/array', [], ACT, RV, 'true');
await au('malformed/empty-commitment', { ...CM, commitment: '' }, ACT, RV, 'true');
await au('malformed/nonhashable-action', CM, { a: { $num: 'NaN' } }, RV, 'true');
await au('malformed/digest-num', { ...CM, action_digest: 5 }, ACT, RV, 'true'); // evidence digests collapse to ''
await au('malformed/commitment-num', { ...CM, commitment: 5 }, ACT, RV, 'true');

// ============================ 3. tool-schema firewall ============================
const S_STR = { type: 'string' }, S_INT = { type: 'integer' }, S_NUM = { type: 'number' }, S_BOOL = { type: 'boolean' };
const SCHEMAS: [string, any][] = [
  ['empty', { props: {} }],
  ['simple', { props: { to: { type: 'string', prefix: 'acct:', maxLength: 64 }, amount: { type: 'integer', min: 1, max: 1000 } }, required: ['to', 'amount'] }],
  ['all-types', { props: { s: { type: 'string', enum: ['a', 'b'], minLength: 1, maxLength: 5 }, n: { type: 'number', min: -1.5, max: 1.5 }, i: { type: 'integer', const: 3 }, b: { type: 'boolean', const: true }, c: { type: 'string', const: 'k' }, e: { type: 'number', enum: [1, 2.5] } } }],
  ['nested', { props: { o: { type: 'object', props: { x: S_INT, y: { type: 'array', items: S_STR, minItems: 1, maxItems: 3 } }, required: ['x'] } }, required: ['o'] }],
  ['arrays', { props: { xs: { type: 'array', items: { type: 'object', props: { k: S_STR }, required: ['k'] }, maxItems: 2 } } }],
  ['bool-enum', { props: { b: { type: 'boolean', enum: [true] } } }],
];
const BADSCHEMAS: [string, any][] = [
  ['null', null], ['array', []], ['string', 'x'], ['unknown-top-key', { props: {}, extra: 1 }], ['props-missing', {}], ['props-array', { props: [] }], ['props-null', { props: null }],
  ['bad-name-dash', { props: { 'a-b': S_STR } }], ['bad-name-empty', { props: { '': S_STR } }], ['name-65', { props: { ['a'.repeat(65)]: S_STR } }], ['name-64', { props: { ['a'.repeat(64)]: S_STR } }], ['name-unicode', { props: { é: S_STR } }],
  ['too-many-props', { props: Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['p' + i, S_STR])) }], ['64-props', { props: Object.fromEntries(Array.from({ length: 64 }, (_, i) => ['p' + i, S_STR])) }],
  ['unknown-type', { props: { a: { type: 'null' } } }], ['type-missing', { props: { a: {} } }], ['type-num', { props: { a: { type: 5 } } }], ['type-proto', { props: { a: { type: 'constructor' } } }], ['spec-array', { props: { a: [] } }], ['spec-null', { props: { a: null } }],
  ['spec-unknown-key', { props: { a: { type: 'string', pattern: '.*' } } }], ['string-with-min', { props: { a: { type: 'string', min: 1 } } }], ['number-with-minLength', { props: { a: { type: 'number', minLength: 1 } } }],
  ['required-undeclared', { props: { a: S_STR }, required: ['b'] }], ['required-not-array', { props: { a: S_STR }, required: 'a' }], ['required-num-entry', { props: { a: S_STR }, required: [5] }], ['required-empty-ok', { props: { a: S_STR }, required: [] }],
  ['required-dup-ok', { props: { a: S_STR }, required: ['a', 'a'] }], ['required-65', { props: { a: S_STR }, required: Array.from({ length: 65 }, () => 'a') }],
  ['required-proto', { props: { a: S_STR }, required: ['toString'] }],
  ['enum-empty', { props: { a: { type: 'string', enum: [] } } }], ['enum-not-array', { props: { a: { type: 'string', enum: 'a' } } }], ['enum-wrong-type', { props: { a: { type: 'string', enum: [1] } } }], ['enum-256', { props: { a: { type: 'string', enum: Array.from({ length: 256 }, (_, i) => 'v' + i) } } }],
  ['enum-257', { props: { a: { type: 'string', enum: Array.from({ length: 257 }, (_, i) => 'v' + i) } } }], ['enum-str-1025', { props: { a: { type: 'string', enum: ['x'.repeat(1025)] } } }], ['enum-str-1024', { props: { a: { type: 'string', enum: ['x'.repeat(1024)] } } }],
  ['enum-int-frac', { props: { a: { type: 'integer', enum: [1.5] } } }], ['enum-int-negzero', { props: { a: { type: 'integer', enum: [-0] } } }], ['enum-num-negzero-ok', { props: { a: { type: 'number', enum: [-0] } } }], ['enum-nan', { props: { a: { type: 'number', enum: [{ $num: 'NaN' }] } } }],
  ['const-wrong-type', { props: { a: { type: 'boolean', const: 'true' } } }], ['const-null', { props: { a: { type: 'string', const: null } } }], ['const-int-frac', { props: { a: { type: 'integer', const: 2.5 } } }], ['const-inf', { props: { a: { type: 'number', const: { $num: 'Infinity' } } } }],
  ['minLength-neg', { props: { a: { type: 'string', minLength: -1 } } }], ['minLength-frac', { props: { a: { type: 'string', minLength: 1.5 } } }], ['minLength-negzero', { props: { a: { type: 'string', minLength: -0 } } }], ['maxLength-too-big', { props: { a: { type: 'string', maxLength: 1048577 } } }],
  ['maxLength-abs-ok', { props: { a: { type: 'string', maxLength: 1048576 } } }], ['min>max-len', { props: { a: { type: 'string', minLength: 5, maxLength: 4 } } }], ['min=max-len', { props: { a: { type: 'string', minLength: 4, maxLength: 4 } } }],
  ['prefix-513', { props: { a: { type: 'string', prefix: 'x'.repeat(513) } } }], ['prefix-512', { props: { a: { type: 'string', prefix: 'x'.repeat(512) } } }], ['prefix-num', { props: { a: { type: 'string', prefix: 5 } } }],
  ['min-nan', { props: { a: { type: 'number', min: { $num: 'NaN' } } } }], ['max-inf', { props: { a: { type: 'number', max: { $num: 'Infinity' } } } }], ['min-str', { props: { a: { type: 'number', min: '1' } } }], ['min>max', { props: { a: { type: 'number', min: 2, max: 1 } } }], ['min=max', { props: { a: { type: 'integer', min: 2, max: 2 } } }],
  ['array-no-items', { props: { a: { type: 'array' } } }], ['array-minItems-neg', { props: { a: { type: 'array', items: S_STR, minItems: -1 } } }], ['array-maxItems-4097', { props: { a: { type: 'array', items: S_STR, maxItems: 4097 } } }], ['array-maxItems-4096', { props: { a: { type: 'array', items: S_STR, maxItems: 4096 } } }],
  ['array-min>max', { props: { a: { type: 'array', items: S_STR, minItems: 3, maxItems: 2 } } }], ['array-items-bad', { props: { a: { type: 'array', items: { type: 'x' } } } }],
  ['object-no-props', { props: { a: { type: 'object' } } }], ['object-props-array', { props: { a: { type: 'object', props: [] } } }],
  ['depth-8-ok', (() => { let s: any = S_STR; for (let i = 0; i < 3; i++) s = { type: 'array', items: s }; return { props: { a: s } }; })()],
  ['depth-over', (() => { let s: any = S_STR; for (let i = 0; i < 9; i++) s = { type: 'array', items: s }; return { props: { a: s } }; })()],
  ['depth-objects-over', (() => { let s: any = S_STR; for (let i = 0; i < 9; i++) s = { type: 'object', props: { a: s } }; return { props: { a: s } }; })()],
  ['depth-objects-edge', (() => { let s: any = S_STR; for (let i = 0; i < 6; i++) s = { type: 'object', props: { a: s } }; return { props: { a: s } }; })()],
  ['nodes-over', { props: Object.fromEntries(Array.from({ length: 64 }, (_, i) => ['p' + i, { type: 'object', props: Object.fromEntries(Array.from({ length: 5 }, (_, j) => ['q' + j, S_STR])) }])) }],
  ['nodes-edge', { props: Object.fromEntries(Array.from({ length: 51 }, (_, i) => ['p' + i, { type: 'object', props: { q: S_STR } }])) }],
  ['class-instance-guard-null-proto', Object.create(null)],
];
for (const [n, s] of [...SCHEMAS, ...BADSCHEMAS]) await add('validateArgSchema', n, [s]);

const TSIG = { name: 'pay', params: [{ n: 'to', t: 'string' }, { n: 'amount', t: 'integer' }] };
const TC = J(AN.toolSchemaCaveat(TSIG, SCHEMAS[1]![1]));
for (const [n, s] of SCHEMAS) {
  await add('toolSchemaCaveat', 'obj-sig/' + n, [TSIG, s]);
  await add('toolSchemaCaveat', 'string-sig/' + n, ['pay', s]);
}
for (const [n, s] of BADSCHEMAS.filter(([n]) => !n.includes('null-proto'))) await add('toolSchemaCaveat', 'bad/' + n, [TSIG, s]);
for (const [n, t] of [['null', null], ['number', 5], ['empty-string', ''], ['obj-no-name', { params: [] }], ['obj-name-num', { name: 5 }], ['obj-name-empty', { name: '' }], ['array', []], ['name-only', { name: 'x' }], ['unicode-name', 'tôol'], ['sig-key-order', { params: [], name: 'pay' }], ['sig-nonhashable', { name: 'pay', x: { $num: 'NaN' } }]] as [string, any][]) {
  await add('toolSchemaCaveat', 'sig/' + n, [t, SCHEMAS[0]![1]]);
}
await add('toolSchemaCaveat', 'schema-key-order-canonical', [TSIG, { required: ['a'], props: { a: S_STR } }]);
await add('toolSchemaCaveat', 'schema-with-neg-zero-min', [TSIG, { props: { a: { type: 'number', min: -0 } } }]);
await add('toolSchemaCaveat', 'schema-with-frac-bound', [TSIG, { props: { a: { type: 'number', min: 0.1, max: 0.30000000000000004 } } }]);

const call = (args: any, extra: any = {}) => ({ tool: 'pay', args, ...extra });
const ARGS_OK = { to: 'acct:9', amount: 10 };
const ev = (n: string, c: any, k: any) => add('evaluateToolSchema', n, [c, k]);
await ev('ok', TC, call(ARGS_OK));
await ev('ok-sig', TC, call(ARGS_OK, { toolSignature: TSIG }));
await ev('ok-sig-digest', TC, call(ARGS_OK, { toolSignatureDigest: TC.signature_digest }));
await ev('wrong-sig', TC, call(ARGS_OK, { toolSignature: { name: 'pay', params: [] } }));
await ev('wrong-sig-digest', TC, call(ARGS_OK, { toolSignatureDigest: 'zzz' }));
await ev('sig-null', TC, call(ARGS_OK, { toolSignature: null }));
await ev('sig-digest-null', TC, call(ARGS_OK, { toolSignatureDigest: null }));
await ev('wrong-tool', TC, { tool: 'refund', args: ARGS_OK });
await ev('tool-num', TC, { tool: 5, args: ARGS_OK });
await ev('args-null', TC, { tool: 'pay', args: null });
await ev('args-array', TC, { tool: 'pay', args: [] });
await ev('args-missing', TC, { tool: 'pay' });
await ev('call-null', TC, null);
await ev('call-string', TC, 'pay');
await ev('extra-arg', TC, call({ ...ARGS_OK, memo: 'x' }));
await ev('extra-arg-long-name', TC, call({ ...ARGS_OK, ['k'.repeat(60)]: 1 }));
await ev('missing-required', TC, call({ to: 'acct:1' }));
await ev('missing-required-2', TC, call({}));
await ev('wrong-type-int', TC, call({ to: 'acct:1', amount: '10' }));
await ev('int-frac', TC, call({ to: 'acct:1', amount: 1.5 }));
await ev('int-negzero', TC, call({ to: 'acct:1', amount: -0 }));
await ev('int-nan', TC, call({ to: 'acct:1', amount: { $num: 'NaN' } }));
await ev('int-inf', TC, call({ to: 'acct:1', amount: { $num: 'Infinity' } }));
await ev('int-null', TC, call({ to: 'acct:1', amount: null }));
await ev('int-bool', TC, call({ to: 'acct:1', amount: true }));
await ev('below-min', TC, call({ to: 'acct:1', amount: 0 }));
await ev('at-min', TC, call({ to: 'acct:1', amount: 1 }));
await ev('at-max', TC, call({ to: 'acct:1', amount: 1000 }));
await ev('above-max', TC, call({ to: 'acct:1', amount: 1001 }));
await ev('big-int-2^53', TC, call({ to: 'acct:1', amount: 2 ** 53 }));
await ev('prefix-bad', TC, call({ to: 'x:1', amount: 5 }));
await ev('prefix-exact', TC, call({ to: 'acct:', amount: 5 }));
await ev('string-64', TC, call({ to: 'acct:' + 'a'.repeat(59), amount: 5 }));
await ev('string-65', TC, call({ to: 'acct:' + 'a'.repeat(60), amount: 5 }));
await ev('string-utf16-units', TC, call({ to: 'acct:' + '\u{1F600}'.repeat(30), amount: 5 })); // 5 + 60 units = 65
await ev('string-utf16-units-ok', TC, call({ to: 'acct:' + '\u{1F600}'.repeat(29), amount: 5 })); // 63 units
await ev('string-num', TC, call({ to: 5, amount: 5 }));
await ev('proto-key', TC, call(JSON.parse('{"__proto__":1,"to":"acct:1","amount":5}')));
await ev('constructor-key', TC, call({ constructor: 1, to: 'acct:1', amount: 5 }));
await ev('toString-key', TC, call({ toString: 1 }));
const sch = (n: number) => J(AN.toolSchemaCaveat('t', SCHEMAS[n]![1]));
const T2 = sch(2), T3 = sch(3), T4 = sch(4), T5 = sch(5);
const t2 = (a: any) => ev('allt/' + JSON.stringify(a), T2, { tool: 't', args: a });
for (const a of [{}, { s: 'a' }, { s: 'c' }, { s: '' }, { s: 'abcdef' }, { s: 'a', n: 1.5 }, { n: 1.50001 }, { n: -1.5 }, { n: -1.51 }, { i: 3 }, { i: 4 }, { i: 3.0 }, { b: true }, { b: false }, { c: 'k' }, { c: 'K' }, { e: 1 }, { e: 2.5 }, { e: 2 }, { n: '1' }, { n: [] }, { s: ['a'] }, { s: { x: 1 } }]) await t2(a);
const t3 = (a: any) => ev('nested/' + JSON.stringify(a), T3, { tool: 't', args: a });
for (const a of [{ o: { x: 1 } }, { o: { x: 1, y: ['a'] } }, { o: { x: 1, y: [] } }, { o: { x: 1, y: ['a', 'b', 'c'] } }, { o: { x: 1, y: ['a', 'b', 'c', 'd'] } }, { o: {} }, { o: { x: 1, z: 1 } }, { o: [] }, { o: null }, {}, { o: { x: 1, y: [1] } }, { o: { x: 1, y: 'a' } }, { o: { x: 1, y: [['a']] } }]) await t3(a);
const t4 = (n: string, a: any) => ev('arr/' + n, T4, { tool: 't', args: a });
await t4('ok', { xs: [{ k: 'a' }, { k: 'b' }] });
await t4('over-max', { xs: [{ k: 'a' }, { k: 'b' }, { k: 'c' }] });
await t4('empty', { xs: [] });
await t4('elem-extra', { xs: [{ k: 'a', z: 1 }] });
await t4('elem-missing', { xs: [{}] });
await t4('elem-null', { xs: [null] });
await t4('not-array', { xs: {} });
const SM = J(AN.toolSchemaCaveat('t', { props: { xs: { type: 'array', items: S_INT, maxItems: 4096 } } }));
await ev('arr/4096-ok', SM, { tool: 't', args: { xs: Array.from({ length: 4096 }, () => 1) } });
const SD = J(AN.toolSchemaCaveat('t', { props: { xs: { type: 'array', items: S_INT } } }));
await ev('arr/default-256-ok', SD, { tool: 't', args: { xs: Array.from({ length: 256 }, () => 1) } });
await ev('arr/default-257', SD, { tool: 't', args: { xs: Array.from({ length: 257 }, () => 1) } });
const SS = J(AN.toolSchemaCaveat('t', { props: { s: S_STR } }));
await ev('str/default-65536-ok', SS, { tool: 't', args: { s: 'a'.repeat(65536) } });
await ev('str/default-65537', SS, { tool: 't', args: { s: 'a'.repeat(65537) } });
const SNEST = (() => { let s: any = S_INT; for (let i = 0; i < 3; i++) s = { type: 'array', items: s, maxItems: 4096 }; return J(AN.toolSchemaCaveat('t', { props: { a: s } })); })();
await ev('values/10000-ok', SNEST, { tool: 't', args: { a: Array.from({ length: 40 }, () => Array.from({ length: 40 }, () => Array.from({ length: 6 }, () => 1))) } }); // 1+40+1600+9600 nodes counted past 10000 -> too many
await ev('values/few', SNEST, { tool: 't', args: { a: [[[1, 2], [3]], []] } });
await ev('values/deep-args', SNEST, { tool: 't', args: { a: [[[[1]]]] } });
// the caveat itself tampered
const tamp = (n: string, c: any, k: any = call(ARGS_OK)) => ev('tamper/' + n, c, k);
await tamp('schema-widened', { ...TC, schema: { props: { to: S_STR, amount: S_INT } } });
await tamp('schema-digest', { ...TC, schema_digest: 'x' });
await tamp('binding-digest', { ...TC, binding_digest: 'x' });
await tamp('signature-digest', { ...TC, signature_digest: 'x' });
await tamp('tool-renamed', { ...TC, tool: 'refund' }, { tool: 'refund', args: ARGS_OK });
await tamp('type-wrong', { ...TC, type: 'other' });
await tamp('tool-empty', { ...TC, tool: '' }, { tool: '', args: {} });
await tamp('tool-num', { ...TC, tool: 5 });
await tamp('schema-invalid', { ...TC, schema: { props: { 'a-b': S_STR } } });
await tamp('schema-null', { ...TC, schema: null });
await tamp('signature-digest-num', { ...TC, signature_digest: 5 });
await tamp('null-caveat', null);
await tamp('array-caveat', []);
await tamp('extra-member-ok', { ...TC, extra: 1 });
await tamp('missing-binding', (({ binding_digest, ...r }) => r)(TC));

await add('toolSchemaEvaluator', 'ok', [TC, { toolCall: call(ARGS_OK) }]);
await add('toolSchemaEvaluator', 'bad-args', [TC, { toolCall: call({}) }]);
await add('toolSchemaEvaluator', 'no-ctx', [TC, null]);
await add('toolSchemaEvaluator', 'no-toolcall', [TC, {}]);
await add('toolSchemaEvaluator', 'toolcall-array', [TC, { toolCall: [] }]);
await add('toolSchemaEvaluator', 'ctx-array', [TC, []]);
await add('toolSchemaEvaluator', 'other-type', [{ type: 'expires', at: 5 }, { toolCall: call(ARGS_OK) }]);
await add('toolSchemaEvaluator', 'caveat-null', [null, { toolCall: call(ARGS_OK) }]);

const PRED = { verb: 'pay', resource: 'acct:*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] };
for (const [n, a] of [['one', [PRED]], ['empty', []], ['verb-array', [{ verb: ['a', 'b'] }]], ['key-order', [{ resource: 'r', verb: 'v' }]], ['not-array', 'x'], ['null', null], ['nonfinite', [{ verb: 'a', where: [{ field: 'f', op: 'eq', value: { $num: 'NaN' } }] }]], ['frac', [{ verb: 'a', where: [{ field: 'f', op: 'lt', value: 0.1 }] }]], ['negzero', [{ verb: 'a', where: [{ field: 'f', op: 'lt', value: -0 }] }]]] as [string, any][]) await add('predicatesCaveat', n, [a]);

const spend = (a: any) => add('actionSpendUsd', JSON.stringify(a).slice(0, 60), [a]);
for (const a of [
  { action: { params: { amount: 5 } } }, { action: { params: { amount: 0 } } }, { action: { params: { amount: -0 } } }, { action: { params: { amount: -1 } } }, { action: { params: { amount: 5, currency: 'usd' } } },
  { action: { params: { amount: 5, currency: 'USD' } } }, { action: { params: { amount: 5, currency: 'Usd' } } }, { action: { params: { amount: 5, currency: 'eur' } } }, { action: { params: { amount: 5, currency: null } } }, { action: { params: { amount: 5, currency: 5 } } },
  { action: { params: { amount: '5' } } }, { action: { params: { amount: { $num: 'NaN' } } } }, { action: { params: { amount: { $num: 'Infinity' } } } }, { action: { params: { amount: 0.1 } } }, { action: { params: { amount: 1e21 } } },
  { action: { params: {} } }, { action: { params: [] } }, { action: { params: null } }, { action: {} }, { action: [] }, { action: null }, {}, null, [], 'x', 5, { params: { amount: 5 } },
  { action: { params: JSON.parse('{"amount":5,"__proto__":{"currency":"eur"}}') } }, { action: { params: { amount: 5, currency: 'usd', extra: 1 } } },
]) await spend(a);

const maxspend = (usd: any) => ({ type: 'max_spend', usd });
const ctxA = (params: any) => ({ now: 1, action: { action: { verb: 'pay', resource: 'r', params } } });
for (const [n, usd, params] of [
  ['ok', 100, { amount: 50 }], ['equal', 100, { amount: 100 }], ['over', 100, { amount: 100.01 }], ['zero-lim', 0, { amount: 0 }], ['zero-lim-pos', 0, { amount: 0.01 }], ['neg-lim', -1, { amount: 0 }], ['nan-lim', { $num: 'NaN' }, { amount: 1 }],
  ['inf-lim', { $num: 'Infinity' }, { amount: 1e300 }], ['str-lim', '100', { amount: 1 }], ['null-lim', null, { amount: 1 }], ['no-amount', 100, {}], ['amount-str', 100, { amount: '1' }], ['eur', 100, { amount: 1, currency: 'eur' }], ['USD', 100, { amount: 1, currency: 'USD' }],
  ['neg-amount', 100, { amount: -1 }], ['frac-sum', 0.3, { amount: 0.30000000000000004 }], ['frac-ok', 0.30000000000000004, { amount: 0.1 + 0.2 }],
] as [string, any, any][]) await add('agentNativeCaveatEvaluator', 'max_spend/' + n, [maxspend(usd), ctxA(params)]);
await add('agentNativeCaveatEvaluator', 'max_spend/usd-missing', [{ type: 'max_spend' }, ctxA({ amount: 1 })]);
await add('agentNativeCaveatEvaluator', 'max_spend/no-action', [maxspend(5), { now: 1 }]);
await add('agentNativeCaveatEvaluator', 'max_spend/action-null', [maxspend(5), { now: 1, action: null }]);
const actx = (verb: string, resource: string, params?: any) => ({ now: 1000, action: { action: { verb, resource, ...(params ? { params } : {}) } } });
await add('agentNativeCaveatEvaluator', 'predicates/match', [J(AN.predicatesCaveat([PRED])), actx('pay', 'acct:1', { amount: 5 })]);
await add('agentNativeCaveatEvaluator', 'predicates/where-fail', [J(AN.predicatesCaveat([PRED])), actx('pay', 'acct:1', { amount: 500 })]);
await add('agentNativeCaveatEvaluator', 'predicates/verb-fail', [J(AN.predicatesCaveat([PRED])), actx('refund', 'acct:1', { amount: 5 })]);
await add('agentNativeCaveatEvaluator', 'predicates/resource-fail', [J(AN.predicatesCaveat([PRED])), actx('pay', 'other:1', { amount: 5 })]);
await add('agentNativeCaveatEvaluator', 'predicates/any-of-two', [{ type: 'predicates', allow: [{ verb: 'a' }, { verb: 'pay' }] }, actx('pay', 'r')]);
await add('agentNativeCaveatEvaluator', 'predicates/empty-allow', [{ type: 'predicates', allow: [] }, actx('pay', 'r')]);
await add('agentNativeCaveatEvaluator', 'predicates/allow-not-array', [{ type: 'predicates', allow: 'x' }, actx('pay', 'r')]);
await add('agentNativeCaveatEvaluator', 'predicates/no-action', [{ type: 'predicates', allow: [{ verb: '*' }] }, { now: 1 }]);
await add('agentNativeCaveatEvaluator', 'predicates/star', [{ type: 'predicates', allow: [{ verb: '*' }] }, actx('x', 'y')]);
await add('agentNativeCaveatEvaluator', 'predicates/regex-resource', [{ type: 'predicates', allow: [{ verb: '*', resource: 're:acct:[0-9]+' }] }, actx('x', 'acct:12')]);
await add('agentNativeCaveatEvaluator', 'predicates/regex-resource-miss', [{ type: 'predicates', allow: [{ verb: '*', resource: 're:acct:[0-9]+' }] }, actx('x', 'acct:12x')]);
await add('agentNativeCaveatEvaluator', 'tool_schema/ok', [TC, { now: 1, toolCall: call(ARGS_OK) }]);
await add('agentNativeCaveatEvaluator', 'tool_schema/bad', [TC, { now: 1, toolCall: call({}) }]);
await add('agentNativeCaveatEvaluator', 'tool_schema/no-toolcall', [TC, { now: 1 }]);
await add('agentNativeCaveatEvaluator', 'caveat-null', [null, { now: 1 }]);
await add('agentNativeCaveatEvaluator', 'ctx-null', [{ type: 'expires', at: 5 }, null]);
await add('agentNativeCaveatEvaluator', 'ctx-array', [{ type: 'expires', at: 5 }, []]);
// stock caveats fall through to the stock evaluator
const stock: [string, any, any][] = [
  ['expires-ok', { type: 'expires', at: 2000 }, { now: 1000 }], ['expires-edge', { type: 'expires', at: 1000 }, { now: 1000 }], ['expires-past', { type: 'expires', at: 500 }, { now: 1000 }], ['expires-nan', { type: 'expires', at: { $num: 'NaN' } }, { now: 1000 }], ['expires-nonum', { type: 'expires' }, { now: 1000 }],
  ['not_before-ok', { type: 'not_before', at: 500 }, { now: 1000 }], ['not_before-edge', { type: 'not_before', at: 1000 }, { now: 1000 }], ['not_before-future', { type: 'not_before', at: 1001 }, { now: 1000 }],
  ['blast-ok', { type: 'max_blast_radius', max: 5 }, { now: 1, blastRadius: 5 }], ['blast-over', { type: 'max_blast_radius', max: 5 }, { now: 1, blastRadius: 6 }], ['blast-missing', { type: 'max_blast_radius', max: 5 }, { now: 1 }],
  ['rev-ok', { type: 'reversibility_max', class: 'rate_limited' }, { now: 1, reversibilityClass: 'reversible' }], ['rev-over', { type: 'reversibility_max', class: 'reversible' }, { now: 1, reversibilityClass: 'irreversible' }], ['rev-unknown', { type: 'reversibility_max', class: 'x' }, { now: 1, reversibilityClass: 'reversible' }],
  ['depth-ok', { type: 'delegation_depth', max: 2 }, { now: 1, delegationDepth: 2 }], ['depth-over', { type: 'delegation_depth', max: 2 }, { now: 1, delegationDepth: 3 }],
  ['rate-ok', { type: 'rate', max: 2, per_secs: 10 }, { now: 100_000, recentActionTimes: [95_000] }], ['rate-over', { type: 'rate', max: 2, per_secs: 10 }, { now: 100_000, recentActionTimes: [95_000, 96_000] }],
  ['unknown-type', { type: 'wat' }, { now: 1 }], ['type-missing', {}, { now: 1 }], ['envelope', { type: 'envelope' }, { now: 1 }],
];
for (const [n, c, x] of stock) await add('agentNativeCaveatEvaluator', 'stock/' + n, [c, x]);

// ============================ 4. introspection ============================
const grantRoot = (caveats: any[], holder = AG.pk) => mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder, caveats });
const envCaveat = (predicates: any[], caveats: any[] = [], extra: any = {}) => ({ type: 'envelope', goal_commit: 'gc', predicates, caveats, agent_binding: {}, risk_policy: P.DEFAULT_RISK_POLICY ?? (P.default ?? P).DEFAULT_RISK_POLICY, ...extra });
const chainOf = (root: any, ...hops: [string, any[], any][]) => { const c = [root]; for (const [to, add2, sk] of hops) c.push(delegate(c[c.length - 1], to, add2, sk)); return J(c); };
const PW = (field: string, op: string, value: any) => ({ field, op, value });
const P1 = { verb: 'pay', resource: 'acct:*', where: [PW('action.params.amount', 'lte', 100)] };
const R_ENV = grantRoot([envCaveat([P1, { verb: ['read', 'list'], resource: '*' }])]);
const R_ENV2 = grantRoot([envCaveat([{ verb: '*', resource: 'acct:*' }], [{ type: 'max_blast_radius', max: 0.5 }, { type: 'expires', at: 5000 }])]);
const R_NOENV = grantRoot([]);
const CH: [string, any][] = [
  ['root-only', chainOf(R_ENV)],
  ['root-noenv', chainOf(R_NOENV)],
  ['root-envelope-caveats', chainOf(R_ENV2)],
  ['predicates-narrow', chainOf(R_ENV, [SUB.pk, [{ type: 'predicates', allow: [{ verb: 'pay', resource: 'acct:7' }] }], AG.sk])],
  ['predicates-disjoint', chainOf(R_ENV, [SUB.pk, [{ type: 'predicates', allow: [{ verb: 'refund' }] }], AG.sk])],
  ['predicates-star-verb', chainOf(R_ENV2, [SUB.pk, [{ type: 'predicates', allow: [{ verb: ['pay', 'refund'], resource: 'acct:1*' }] }], AG.sk])],
  ['prefix-vs-prefix', chainOf(R_ENV2, [SUB.pk, [{ type: 'predicates', allow: [{ verb: '*', resource: 'acct:1*' }] }], AG.sk], [H.pk, [{ type: 'predicates', allow: [{ verb: '*', resource: 'acct:12*' }] }], SUB.sk])],
  ['regex-opaque', chainOf(R_ENV2, [SUB.pk, [{ type: 'predicates', allow: [{ verb: '*', resource: 're:acct:[0-9]+' }] }], AG.sk])],
  ['regex-with-literal', chainOf(R_ENV2, [SUB.pk, [{ type: 'predicates', allow: [{ verb: '*', resource: 're:a.*' }, { verb: 'x', resource: 'acct:5' }] }], AG.sk])],
  ['where-conjoined', chainOf(R_ENV, [SUB.pk, [{ type: 'predicates', allow: [{ verb: 'pay', resource: 'acct:*', where: [PW('action.params.amount', 'gte', 5)] }] }], AG.sk])],
  ['predicates-where-not-array', chainOf(R_ENV, [SUB.pk, [{ type: 'predicates', allow: [{ verb: 'pay', where: 'x' }] }], AG.sk])],
  ['predicates-no-verb', chainOf(R_ENV, [SUB.pk, [{ type: 'predicates', allow: [{ resource: 'x' }] }], AG.sk])],
  ['predicates-not-array', chainOf(R_ENV, [SUB.pk, [{ type: 'predicates', allow: 5 }], AG.sk])],
  ['predicates-no-envelope', chainOf(R_NOENV, [SUB.pk, [{ type: 'predicates', allow: [{ verb: 'pay' }] }], AG.sk])],
  ['tool-schema', chainOf(R_ENV, [SUB.pk, [TC], AG.sk])],
  ['tool-schema-two-same', chainOf(R_ENV, [SUB.pk, [TC, J(AN.toolSchemaCaveat('pay', { props: { to: S_STR } }))], AG.sk])],
  ['tool-schema-two-different', chainOf(R_ENV, [SUB.pk, [TC, J(AN.toolSchemaCaveat('refund', { props: {} }))], AG.sk])],
  ['tool-schema-tampered', chainOf(R_ENV, [SUB.pk, [{ ...TC, schema_digest: 'x' }], AG.sk])],
  ['tool-schema-no-tool', chainOf(R_ENV, [SUB.pk, [{ type: 'tool_schema', tool: '' }], AG.sk])],
  ['expires-min', chainOf(R_ENV2, [SUB.pk, [{ type: 'expires', at: 9000 }, { type: 'expires', at: 3000 }], AG.sk])],
  ['not-before-max', chainOf(R_ENV, [SUB.pk, [{ type: 'not_before', at: 100 }, { type: 'not_before', at: 400 }], AG.sk])],
  ['rate-pick', chainOf(R_ENV, [SUB.pk, [{ type: 'rate', max: 10, per_secs: 60 }, { type: 'rate', max: 1, per_secs: 60 }, { type: 'rate', max: 2, per_secs: 120 }], AG.sk])],
  ['rate-tie', chainOf(R_ENV, [SUB.pk, [{ type: 'rate', max: 4, per_secs: 20 }, { type: 'rate', max: 2, per_secs: 10 }], AG.sk])],
  ['rate-bad', chainOf(R_ENV, [SUB.pk, [{ type: 'rate', max: 4, per_secs: 0 }], AG.sk])],
  ['blast-min', chainOf(R_ENV2, [SUB.pk, [{ type: 'max_blast_radius', max: 0.2 }, { type: 'max_blast_radius', max: 0.9 }], AG.sk])],
  ['reversibility', chainOf(R_ENV, [SUB.pk, [{ type: 'reversibility_max', class: 'rate_limited' }, { type: 'reversibility_max', class: 'irreversible' }], AG.sk])],
  ['reversibility-bad', chainOf(R_ENV, [SUB.pk, [{ type: 'reversibility_max', class: 'cosmic' }], AG.sk])],
  ['depth-remaining', chainOf(R_ENV, [SUB.pk, [{ type: 'delegation_depth', max: 3 }], AG.sk], [H.pk, [], SUB.sk])],
  ['depth-negative', chainOf(R_ENV, [SUB.pk, [{ type: 'delegation_depth', max: 0 }], AG.sk], [H.pk, [], SUB.sk])],
  ['budget-alloc', chainOf(R_ENV, [SUB.pk, [{ type: 'budget_alloc', limit: 7 }, { type: 'budget_alloc', limit: 3 }], AG.sk])],
  ['budget-alloc-bad', chainOf(R_ENV, [SUB.pk, [{ type: 'budget_alloc', limit: -1 }], AG.sk])],
  ['max-spend', chainOf(R_ENV, [SUB.pk, [{ type: 'max_spend', usd: 50 }, { type: 'max_spend', usd: 20 }], AG.sk])],
  ['max-spend-bad', chainOf(R_ENV, [SUB.pk, [{ type: 'max_spend', usd: -1 }], AG.sk])],
  ['max-spend-root', chainOf(R_ENV2, [SUB.pk, [], AG.sk])],
  ['unknown-caveat', chainOf(R_ENV, [SUB.pk, [{ type: 'mystery' }], AG.sk])],
  ['second-envelope', chainOf(R_ENV, [SUB.pk, [envCaveat([{ verb: '*' }])], AG.sk])],
  ['nested-envelope', chainOf(grantRoot([envCaveat([{ verb: '*' }], [envCaveat([{ verb: '*' }])])]))],
  ['envelope-bad-predicate', chainOf(grantRoot([envCaveat([{ nope: 1 }])]))],
  ['expires-past', chainOf(R_ENV, [SUB.pk, [{ type: 'expires', at: 5 }], AG.sk])],
  ['three-hop', chainOf(R_ENV, [SUB.pk, [{ type: 'expires', at: 7000 }], AG.sk], [H.pk, [{ type: 'predicates', allow: [{ verb: 'pay', resource: 'acct:1' }] }], SUB.sk], [H2.pk, [{ type: 'rate', max: 3, per_secs: 30 }], H.sk])],
];
const mutate = (ch: any, f: (c: any) => any) => f(J(ch));
CH.push(['bad-sig', mutate(chainOf(R_ENV, [SUB.pk, [{ type: 'expires', at: 5 }], AG.sk]), (c) => { c[1].sig = flip(c[1].sig); return c; })]);
CH.push(['empty', []]);
CH.push(['not-array', { x: 1 }]);
CH.push(['null', null]);
CH.push(['wrong-parent', mutate(chainOf(R_ENV, [SUB.pk, [], AG.sk]), (c) => { c[1].parent = 'x'; return c; })]);
CH.push(['bad-issuer-hop', mutate(chainOf(R_ENV, [SUB.pk, [], AG.sk]), (c) => { c[1].issuer = H.pk; return c; })]);
CH.push(['hop-null', [null]]);
const NOWS: any[] = [null, 1000, 0, -1, 4999, 5000, 5001, 1e15, { $num: 'NaN' }];
for (const [n, ch] of CH) {
  for (const now of n === 'root-envelope-caveats' || n === 'expires-min' ? NOWS : [null, 1000]) await add('describeEnvelope', `${n}/now=${JSON.stringify(now)}`, [ch, now, null, null]);
}
await add('describeEnvelope', 'expected-root-ok', [chainOf(R_ENV), 1000, PR.pk, null]);
await add('describeEnvelope', 'expected-root-wrong', [chainOf(R_ENV), 1000, H.pk, null]);
await add('describeEnvelope', 'policy-allowed-suites', [chainOf(R_ENV), 1000, null, { allowedSuites: ['ed25519'] }]);
await add('describeEnvelope', 'policy-suite-excluded', [chainOf(R_ENV), 1000, null, { allowedSuites: ['ml-dsa-65'] }]);
await add('describeEnvelope', 'policy-null-ok', [chainOf(R_ENV), 1000, null, null]);
await add('describeEnvelope', 'now-float', [chainOf(R_ENV2), 1234.5, null, null]);
await add('describeEnvelope', 'now-string', [chainOf(R_ENV2), '1000', null, null]);

// envelopePermits / envelopePermitsToolCall: over real describeEnvelope results and hand-built ones
const E = (n: string) => J(AN.describeEnvelope(CH.find(([k]) => k === n)![1], 1000));
const ENVS: [string, any][] = [
  ['root-only', E('root-only')], ['root-noenv', E('root-noenv')], ['narrow', E('predicates-narrow')], ['disjoint', E('predicates-disjoint')], ['prefix-vs-prefix', E('prefix-vs-prefix')], ['regex', E('regex-opaque')],
  ['tool', E('tool-schema')], ['tool-two-diff', E('tool-schema-two-different')], ['expires-min', E('expires-min')], ['not-before', E('not-before-max')], ['depth-negative', E('depth-negative')], ['max-spend', E('max-spend')],
  ['noenv-predicates', E('predicates-no-envelope')], ['unknown-caveat', E('unknown-caveat')], ['bad-sig', E('bad-sig')], ['envelope-caveats', E('root-envelope-caveats')], ['where-conjoined', E('where-conjoined')], ['three-hop', E('three-hop')],
  ['hand-ok-unrestricted', { ok: true, hasEnvelope: false, scopes: null, verbs: null, resources: null, opaqueResourceConstraints: [], tools: null, toolSchemas: [], unsatisfiable: [], caveats: [], remainingBudgetHints: {} }],
  ['hand-not-ok', { ok: false, reason: 'nope', hasEnvelope: false, scopes: [], verbs: [], resources: [], opaqueResourceConstraints: [], tools: [], toolSchemas: [], unsatisfiable: [], caveats: [], remainingBudgetHints: {} }],
  ['hand-unsatisfiable', { ok: true, hasEnvelope: true, scopes: [], verbs: [], resources: [], opaqueResourceConstraints: [], tools: [], toolSchemas: [], unsatisfiable: ['x'], caveats: [], remainingBudgetHints: {}, reason: 'unsatisfiable caveat(s): x' }],
  ['hand-star', { ok: true, hasEnvelope: true, scopes: [{ verbs: ['*'], resources: ['*'], where: [] }], verbs: ['*'], resources: ['*'], opaqueResourceConstraints: [], tools: null, toolSchemas: [], unsatisfiable: [], caveats: [], remainingBudgetHints: { expiresAt: 5000, notBefore: 100, maxSpendUsd: 10 } }],
  ['hand-hints-nan', { ok: true, hasEnvelope: true, scopes: null, verbs: null, resources: null, opaqueResourceConstraints: [], tools: null, toolSchemas: [], unsatisfiable: [], caveats: [], remainingBudgetHints: { expiresAt: { $num: 'NaN' } } }],
  ['null', null], ['empty-object', {}],
];
const VR: [string, string][] = [['pay', 'acct:1'], ['pay', 'acct:7'], ['read', 'x'], ['refund', 'acct:1'], ['*', '*'], ['pay', 'acct:12x'], ['', ''], ['pay', 'acct:']];
for (const [n, e] of ENVS) {
  for (const [v, r] of VR) await add('envelopePermits', `${n}/${v}:${r}`, [e, v, r, null, null]);
  await add('envelopePermits', `${n}/pay-acct:1/now0`, [e, 'pay', 'acct:1', 0, null]);
  await add('envelopePermits', `${n}/pay-acct:1/now1000`, [e, 'pay', 'acct:1', 1000, null]);
  await add('envelopePermits', `${n}/pay-acct:1/now5000`, [e, 'pay', 'acct:1', 5000, null]);
  await add('envelopePermits', `${n}/pay-acct:1/nowNaN`, [e, 'pay', 'acct:1', { $num: 'NaN' }, null]);
  await add('envelopePermits', `${n}/pay-acct:1/amount5`, [e, 'pay', 'acct:1', null, { amount: 5 }]);
  await add('envelopePermits', `${n}/pay-acct:1/amount500`, [e, 'pay', 'acct:1', null, { amount: 500 }]);
  await add('envelopePermits', `${n}/pay-acct:1/amount30`, [e, 'pay', 'acct:1', null, { amount: 30 }]);
  await add('envelopePermits', `${n}/pay-acct:1/no-amount`, [e, 'pay', 'acct:1', null, {}]);
  await add('envelopePermits', `${n}/pay-acct:1/eur`, [e, 'pay', 'acct:1', null, { amount: 1, currency: 'eur' }]);
}
await add('envelopePermits', 'where-boundary-100', [E('root-only'), 'pay', 'acct:1', null, { amount: 100 }]);
await add('envelopePermits', 'where-boundary-100.01', [E('root-only'), 'pay', 'acct:1', null, { amount: 100.01 }]);
await add('envelopePermits', 'where-gte-boundary', [E('where-conjoined'), 'pay', 'acct:1', null, { amount: 5 }]);
await add('envelopePermits', 'where-gte-below', [E('where-conjoined'), 'pay', 'acct:1', null, { amount: 4.99 }]);
await add('envelopePermits', 'spend-boundary', [E('max-spend'), 'read', 'x', null, { amount: 20 }]);
await add('envelopePermits', 'spend-over', [E('max-spend'), 'read', 'x', null, { amount: 20.5 }]);
await add('envelopePermits', 'spend-no-params-ok', [E('max-spend'), 'read', 'x', null, null]);
await add('envelopePermits', 'spend-nonnumeric', [E('max-spend'), 'read', 'x', null, { amount: 'a' }]);

for (const [n, e] of ENVS) {
  await add('envelopePermitsToolCall', `${n}/ok`, [e, call(ARGS_OK)]);
  await add('envelopePermitsToolCall', `${n}/bad-args`, [e, call({ to: 'acct:1' })]);
  await add('envelopePermitsToolCall', `${n}/other-tool`, [e, { tool: 'refund', args: {} }]);
}
await add('envelopePermitsToolCall', 'refund-two-diff', [E('tool-schema-two-different'), { tool: 'refund', args: {} }]);
await add('envelopePermitsToolCall', 'sig-mismatch', [E('tool-schema'), call(ARGS_OK, { toolSignature: { name: 'pay', params: [] } })]);
await add('envelopePermitsToolCall', 'sig-match', [E('tool-schema'), call(ARGS_OK, { toolSignature: TSIG })]);
await add('envelopePermitsToolCall', 'two-schemas-second-fails', [E('tool-schema-two-same'), call(ARGS_OK)]);
await add('envelopePermitsToolCall', 'call-null', [E('tool-schema'), null]);
await add('envelopePermitsToolCall', 'tool-num', [E('tool-schema'), { tool: 5, args: {} }]);
await add('envelopePermitsToolCall', 'long-tool-name', [E('tool-schema'), { tool: 'z'.repeat(100), args: {} }]);

// ============================ 5. leases ============================
const T = 1_700_000_000_000;
const gl = (n: string, a: any) => add('grantLease', n, [a]);
const LA = { cap_id: 'cap1', holder: H.pk, now: T, ttl_ms: 60_000 };
await gl('ok', LA);
await gl('ok-hard', { ...LA, hard_expires_at: T + 30_000 });
await gl('ok-hard-longer', { ...LA, hard_expires_at: T + 120_000 });
await gl('ok-renewals-0', { ...LA, max_renewals: 0 });
await gl('ok-renewals-5', { ...LA, max_renewals: 5 });
await gl('ttl-1', { ...LA, ttl_ms: 1 });
await gl('ttl-max', { ...LA, ttl_ms: 7 * 24 * 3_600_000 });
await gl('ttl-max+1', { ...LA, ttl_ms: 7 * 24 * 3_600_000 + 1 });
await gl('ttl-0', { ...LA, ttl_ms: 0 });
await gl('ttl-neg', { ...LA, ttl_ms: -5 });
await gl('ttl-frac', { ...LA, ttl_ms: 1.5 });
await gl('ttl-nan', { ...LA, ttl_ms: { $num: 'NaN' } });
await gl('ttl-inf', { ...LA, ttl_ms: { $num: 'Infinity' } });
await gl('ttl-str', { ...LA, ttl_ms: '60000' });
await gl('ttl-missing', { cap_id: 'cap1', holder: H.pk, now: T });
await gl('now-nan', { ...LA, now: { $num: 'NaN' } });
await gl('now-inf', { ...LA, now: { $num: 'Infinity' } });
await gl('now-str', { ...LA, now: '5' });
await gl('now-neg', { ...LA, now: -100 });
await gl('now-0', { ...LA, now: 0 });
await gl('now-frac', { ...LA, now: 0.5, ttl_ms: 1.5 });
await gl('cap-empty', { ...LA, cap_id: '' });
await gl('cap-num', { ...LA, cap_id: 5 });
await gl('holder-empty', { ...LA, holder: '' });
await gl('holder-missing', { cap_id: 'c', now: T, ttl_ms: 5 });
await gl('hard-equal-now', { ...LA, hard_expires_at: T });
await gl('hard-before-now', { ...LA, hard_expires_at: T - 1 });
await gl('hard-now+1', { ...LA, hard_expires_at: T + 1 });
await gl('hard-nan', { ...LA, hard_expires_at: { $num: 'NaN' } });
await gl('hard-inf', { ...LA, hard_expires_at: { $num: 'Infinity' } });
await gl('hard-str', { ...LA, hard_expires_at: 'x' });
await gl('hard-null', { ...LA, hard_expires_at: null });
await gl('renewals-neg', { ...LA, max_renewals: -1 });
await gl('renewals-negzero', { ...LA, max_renewals: -0 });
await gl('renewals-frac', { ...LA, max_renewals: 1.5 });
await gl('renewals-nan', { ...LA, max_renewals: { $num: 'NaN' } });
await gl('renewals-str', { ...LA, max_renewals: '1' });
await gl('renewals-null', { ...LA, max_renewals: null });
await gl('renewals-big', { ...LA, max_renewals: 2 ** 53 });
await gl('args-extra-ignored', { ...LA, extra: 1 });
await gl('args-null', null);
await gl('args-array', []);

const L = J(AN.grantLease({ ...LA, max_renewals: 2 }));
const LH = J(AN.grantLease({ ...LA, hard_expires_at: T + 90_000 }));
const ls = (n: string, l: any, now: any) => add('leaseState', n, [l, now]);
for (const [n, now] of [['at-issue', T], ['mid', T + 30_000], ['one-before-expiry', T + 59_999], ['at-expiry', T + 60_000], ['past', T + 60_001], ['far-past', T + 1e12], ['skew-edge-before', T - 30_000], ['skew-before-over', T - 30_001], ['nan', { $num: 'NaN' }], ['inf', { $num: 'Infinity' }], ['neg-inf', { $num: '-Infinity' }], ['str', String(T)], ['null', null], ['frac', T + 0.5]] as [string, any][]) await ls(n, L, now);
await ls('hard-cap', LH, T + 89_999);
await ls('hard-cap-edge', LH, T + 90_000);
const LB: [string, any][] = [
  ['null', null], ['array', []], ['string', 'x'], ['empty', {}], ['cap-empty', { ...L, cap_id: '' }], ['holder-empty', { ...L, holder: '' }], ['issued-str', { ...L, issued_at: '1' }], ['issued-nan', { ...L, issued_at: { $num: 'NaN' } }], ['renewed-missing', (({ renewed_at, ...r }) => r)(L)],
  ['ttl-0', { ...L, ttl_ms: 0, expires_at: T }], ['ttl-over', { ...L, ttl_ms: 7 * 24 * 3_600_000 + 1 }], ['ttl-max-ok', { ...L, ttl_ms: 7 * 24 * 3_600_000, expires_at: T + 60_000 }], ['expires-nan', { ...L, expires_at: { $num: 'NaN' } }], ['expires-inf', { ...L, expires_at: { $num: 'Infinity' } }],
  ['expires-over-ttl', { ...L, expires_at: L.renewed_at + L.ttl_ms + 1 }], ['expires-exact-ttl', { ...L, expires_at: L.renewed_at + L.ttl_ms }], ['expires-under-ok', { ...L, expires_at: L.renewed_at + 1 }],
  ['renewals-neg', { ...L, renewals: -1 }], ['renewals-frac', { ...L, renewals: 0.5 }], ['renewals-negzero', { ...L, renewals: -0 }], ['renewals-str', { ...L, renewals: '0' }], ['seq-neg', { ...L, last_seq: -1 }], ['seq-negzero', { ...L, last_seq: -0 }], ['seq-frac', { ...L, last_seq: 1.5 }], ['seq-big-ok', { ...L, last_seq: 2 ** 60 }],
  ['maxren-neg', { ...L, max_renewals: -1 }], ['maxren-frac', { ...L, max_renewals: 1.5 }], ['maxren-negzero', { ...L, max_renewals: -0 }], ['maxren-null', { ...L, max_renewals: null }], ['hard-nan', { ...L, hard_expires_at: { $num: 'NaN' } }],
  ['hard-below-expires', { ...L, hard_expires_at: L.expires_at - 1 }], ['hard-equal-expires', { ...L, hard_expires_at: L.expires_at }], ['hard-null', { ...L, hard_expires_at: null }],
  ['extra-key-ok', { ...L, extra: 1 }], ['renewed-future', { ...L, renewed_at: T + 100_000, expires_at: T + 100_000 + 10 }], ['renewed-after-issue', { ...L, renewed_at: T + 10, expires_at: T + 20 }],
];
for (const [n, l] of LB) { await ls('bad/' + n, l, T + 1000); await ls('bad-late/' + n, l, T + 100_000_000); }
await ls('clock-rollback', { ...L, renewed_at: T + 100_000, expires_at: T + 130_000 }, T + 60_000);
await ls('clock-rollback-edge', { ...L, renewed_at: T + 100_000, expires_at: T + 130_000 }, T + 70_000);
await ls('clock-rollback-over', { ...L, renewed_at: T + 100_000, expires_at: T + 130_000 }, T + 69_999);

const hbBody = (over: any = {}) => ({ cap_id: L.cap_id, seq: 1, at: T + 1000, holder: H.pk, lease_issued_at: L.issued_at, ...over });
const sh = (n: string, b: any, k = H) => add('signHeartbeat', n, [b, k.sk]);
await sh('ok', hbBody());
await sh('seq-0', hbBody({ seq: 0 }));
await sh('seq-neg', hbBody({ seq: -1 }));
await sh('seq-frac', hbBody({ seq: 1.5 }));
await sh('seq-nan-throws', hbBody({ seq: { $num: 'NaN' } }));
await sh('extra-dropped', { ...hbBody(), sneaky: 1 });
await sh('other-key', hbBody(), H2);
await sh('missing-fields', { cap_id: 'x' });
await sh('at-str', hbBody({ at: '5' }));
await sh('unicode-cap', hbBody({ cap_id: 'câp☃' }));

const HB = (over: any = {}, k = H) => J(AN.signHeartbeat(hbBody(over), k.sk));
const rl = (n: string, l: any, hb: any, now: any) => add('renewLease', n, [l, hb, now]);
const N1 = T + 1000;
await rl('ok', L, HB(), N1);
await rl('ok-at-now', L, HB({ at: N1 }), N1);
await rl('ok-skew-edge-low', L, HB({ at: N1 - 30_000 }), N1);
await rl('ok-skew-edge-high', L, HB({ at: N1 + 30_000 }), N1);
await rl('skew-over-low', L, HB({ at: N1 - 30_001 }), N1);
await rl('skew-over-high', L, HB({ at: N1 + 30_001 }), N1);
await rl('seq-equal-last', { ...L, last_seq: 1 }, HB(), N1);
await rl('seq-lower', { ...L, last_seq: 5 }, HB(), N1);
await rl('seq-next', { ...L, last_seq: 1 }, HB({ seq: 2 }), N1);
await rl('seq-jump', L, HB({ seq: 1000 }), N1);
await rl('seq-unsafe', L, { ...HB(), seq: 2 ** 53 }, N1);
await rl('seq-safe-max', L, HB({ seq: 2 ** 53 - 1 }), N1);
await rl('seq-frac', L, { ...HB(), seq: 1.5 }, N1);
await rl('seq-str', L, { ...HB(), seq: '1' }, N1);
await rl('seq-0', L, HB({ seq: 0 }), N1);
await rl('seq-negzero', L, { ...HB(), seq: -0 }, N1);
await rl('wrong-cap', L, HB({ cap_id: 'other' }), N1);
await rl('wrong-holder-field', L, HB({ holder: H2.pk }, H2), N1);
await rl('wrong-lease-issued', L, HB({ lease_issued_at: L.issued_at + 1 }), N1);
await rl('signed-by-other-key', L, HB({}, H2), N1);
await rl('bad-sig-flip', L, { ...HB(), sig: flip(HB().sig) }, N1);
await rl('sig-empty', L, { ...HB(), sig: '' }, N1);
await rl('sig-num', L, { ...HB(), sig: 5 }, N1);
await rl('sig-missing', L, (({ sig, ...r }) => r)(HB()), N1);
await rl('extra-key', L, { ...HB(), extra: 1 }, N1);
await rl('hb-null', L, null, N1);
await rl('hb-array', L, [], N1);
await rl('hb-string', L, 'x', N1);
await rl('at-nan', L, { ...HB(), at: { $num: 'NaN' } }, N1);
await rl('at-tampered', L, { ...HB(), at: N1 + 1 }, N1);
await rl('lapsed', L, HB({ at: T + 60_001 }), T + 60_001);
await rl('lapsed-edge', L, HB({ at: T + 60_000 }), T + 60_000);
await rl('last-ms', L, HB({ at: T + 59_999 }), T + 59_999);
await rl('malformed-lease', { ...L, ttl_ms: 0 }, HB(), N1);
await rl('lease-null', null, HB(), N1);
await rl('now-nan', L, HB(), { $num: 'NaN' });
await rl('clock-rolled-back', { ...L, renewed_at: T + 100_000, expires_at: T + 130_000 }, HB({ at: T + 60_000 }), T + 60_000);
await rl('budget-exhausted', { ...L, renewals: 2 }, HB(), N1);
await rl('budget-last', { ...L, renewals: 1 }, HB(), N1);
await rl('budget-zero', J(AN.grantLease({ ...LA, max_renewals: 0 })), HB(), N1);
await rl('no-budget-unbounded', { ...L, max_renewals: undefined, renewals: 999 }, HB(), N1);
await rl('hard-caps-renewal', LH, HB({ at: T + 50_000 }), T + 50_000);
await rl('hard-caps-renewal-2', J(AN.renewLease(LH, HB({ at: T + 50_000 }), T + 50_000).lease), HB({ seq: 2, at: T + 85_000 - 30_000 }), T + 55_000);
await rl('never-shortens', { ...L, expires_at: T + 60_000, renewed_at: T }, HB({ at: T + 5 }), T + 5);
await rl('expires-extends', L, HB({ at: T + 40_000 }), T + 40_000);
await rl('renewed-at-max', { ...L, renewed_at: T + 500 }, HB(), T + 400);
await rl('renewed-at-forward', L, HB({ at: T + 30_000 }), T + 30_000);
await rl('non-integer-now', L, HB({ at: T + 1000.5 }), T + 1000.5);
await rl('shorter-expires-not-shortened', { ...L, expires_at: T + 30_000 }, HB({ at: T + 100 }), T + 100);

// ============================ constants ============================
await add('constants', 'all', []);

(o as any).constantByDesign = { checkCautionMonotone: 'a property check over a grid: it holds for every grid unless combineCaution itself is wrong (the differential of combineCaution is the real test)' };
refWrite(o, 'agent-native');
