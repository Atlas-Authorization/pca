// Oracle: every export of packages/pca/src/safety-certificate.ts (signed risk-budget bound certificate), TS reference.
// Writes out/ref-safety-certificate.json.gz. Deterministic: Ed25519 and ML-DSA-65 keys from seed(label), no clock (issuedAt / now are arguments).
// Case shape {fn, name, args, out}; `out` is the reference's JSON result or {"$throws": message} (message text is not compared).
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw = the native refuses)
//   args: {"$num":"NaN"|"Infinity"|"-Infinity"} = that double; {"$bytes": {"$seed": label}} = sha256("atlas-pca-conformance/" + label) as the Ed25519 secret;
//   null in an OPTIONAL position = not given. A `suite` argument is {alg, pqSeed?: {"$bytes":{"$seed"}}}: the ML-DSA-65 key pair is mlDsa65Keygen(pqSeed)
//   (every suite in the corpus is ed25519, ml-dsa-65 or hybrid-ed25519-ml-dsa-65; ML-DSA signing is deterministic, so signatures compare byte for byte).
//   safetyCertificateBound [{bMax, kappa}]                       -> number (0 when kappa <= 0)
//   safetyCertificateStatement [bound]                           -> string
//   validateSafetyChecks [checks]                                -> string | null
//   safetyCertificateMessage [certOrClaim]                       -> {"$bytes": b64u} (SAFETY_CERT_DOMAIN || canonical(claim without sig / pq_sig))
//   issueSafetyCertificate [{policy, guardianSecret, grantRef?, instance?, checks?, issuedAt, suite?}] -> certificate (throws on a malformed policy / checks / alg)
//   verifySafetyCertificate [cert, opts|null]                    -> {ok, reason?, recomputedBound?}   (never throws; reason strings are compared exactly)
//   encodeSafetyCertificate [cert]                               -> canonical JSON string
//   decodeSafetyCertificate [text]                               -> certificate | null
//   safetyCertificateForCompliance [cert, opts|null]             -> {control, guardian, issued_at, bound, checks:[{id,status,evidence}]} | null
//   constants []                                                 -> {NAME: value}
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder, nul } from './foundation.mjs';

const SC: any = await import('../../../packages/pca/src/safety-certificate.ts');
const { publicKeyOf } = await import('../../../packages/pca/src/keys.ts') as any;
const { b64u } = await import('../../../packages/pca/src/hash.ts') as any;
const PQ: any = await import('../../../packages/pca/src/pq.ts');

const o = new Oracle('safety-certificate', 'tools/pca-audit/oracles/safety-certificate.mts', 'TS-reference oracle for packages/pca/src/safety-certificate.ts.');
const G = seed('sc/guardian'), G2 = seed('sc/guardian2'), PQS = seed('sc/pq');
const GPK = b64u(publicKeyOf(G)), G2PK = b64u(publicKeyOf(G2));
const J = (x: any) => JSON.parse(JSON.stringify(x));
const suiteOf = (s: any) => (s == null ? undefined : s.alg === 'ed25519' ? { alg: s.alg } : { alg: s.alg, mlDsa: PQ.mlDsa65Keygen(s.pqSeed) });
const opt = (x: any) => (x == null ? undefined : x);
const REF: Record<string, (...a: any[]) => any> = {
  safetyCertificateBound: (p) => SC.safetyCertificateBound(p),
  safetyCertificateStatement: (b) => SC.safetyCertificateStatement(b),
  validateSafetyChecks: (c) => SC.validateSafetyChecks(c),
  safetyCertificateMessage: (c) => SC.safetyCertificateMessage(c),
  issueSafetyCertificate: (a) => SC.issueSafetyCertificate({ ...a, suite: suiteOf(a.suite) }),
  verifySafetyCertificate: (c, op) => SC.verifySafetyCertificate(c, nul(op) ?? {}),
  encodeSafetyCertificate: (c) => SC.encodeSafetyCertificate(c),
  decodeSafetyCertificate: (s) => SC.decodeSafetyCertificate(s),
  safetyCertificateForCompliance: (c, op) => SC.safetyCertificateForCompliance(c, nul(op) ?? {}),
  constants: () => Object.fromEntries(Object.entries(SC).filter(([k, v]) => typeof v !== 'function' && /^[A-Z][A-Z0-9_]+$/.test(k))),
};
const add = adder(o, REF);

const POL = { weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 }, theta1: 0.25, theta2: 0.6, kappa: 1, lambda: 0.0005, rho: 0.5, bMax: 2 };
const pol = (over: any = {}) => ({ ...POL, ...over });
const T0 = 1_800_000_000_000;
const SHA = 'a'.repeat(64);
const chk = (id: string, status = 'passed', over: any = {}) => ({ id, status, evidence: { kind: 'sha256', ref: SHA }, at: T0 - 1000, ...over });
const URLC = (u: string) => chk('u', 'passed', { evidence: { kind: 'url', ref: u } });

// ---- bound / statement
for (const [i, p] of [[{ bMax: 2, kappa: 1 }], [{ bMax: 1, kappa: 4 }], [{ bMax: 0, kappa: 1 }], [{ bMax: -3, kappa: 1 }], [{ bMax: 5, kappa: 0 }], [{ bMax: 5, kappa: -1 }],
  [{ bMax: 1e308, kappa: 1e-308 }], [{ bMax: { $num: 'NaN' }, kappa: 1 }], [{ bMax: 1, kappa: { $num: 'NaN' } }], [{ bMax: { $num: 'Infinity' }, kappa: 2 }], [{ bMax: 3, kappa: { $num: 'Infinity' } }], [{ bMax: 0.1, kappa: 0.3 }], [{ bMax: 7, kappa: 3 }], [{ bMax: 2 ** 53, kappa: 3 }]].entries())
  await add('safetyCertificateBound', 'p' + i, p);
for (const [i, b] of [0, 2, 0.5, 1 / 3, 1e21, 1e-7, 123456789.123, -1, { $num: 'NaN' }, { $num: 'Infinity' }, 5e-324, 2 ** 53].entries()) await add('safetyCertificateStatement', 'b' + i, [b]);

// ---- validateSafetyChecks
const V = (name: string, c: any) => add('validateSafetyChecks', name, [c]);
await V('empty', []); await V('one', [chk('a')]); await V('two', [chk('a'), chk('b', 'failed'), chk('c', 'not_run')]);
await V('not-array', null); await V('obj', {}); await V('string', 'x'); await V('num', 5);
await V('64', Array.from({ length: 64 }, (_, i) => chk('c' + i))); await V('65', Array.from({ length: 65 }, (_, i) => chk('c' + i)));
await V('el-null', [null]); await V('el-num', [5]); await V('el-array', [[]]); await V('el-string', ['x']);
await V('id-empty', [chk('')]); await V('id-64', [chk('i'.repeat(64))]); await V('id-65', [chk('i'.repeat(65))]); await V('id-num', [chk(5 as any)]); await V('id-missing', [{ status: 'passed', evidence: { kind: 'sha256', ref: SHA }, at: 0 }]);
await V('dup', [chk('a'), chk('a')]);
await V('status-bad', [chk('a', 'ok')]); await V('status-missing', [{ id: 'a', evidence: { kind: 'sha256', ref: SHA }, at: 0 }]); await V('status-case', [chk('a', 'Passed')]);
for (const [i, at] of [0, -1, -0, 1.5, 2 ** 53, 2 ** 53 - 1, '5', null, { $num: 'NaN' }, { $num: 'Infinity' }].entries()) await V('at' + i, [chk('a', 'passed', { at })]);
await V('evidence-missing', [{ id: 'a', status: 'passed', at: 0 }]); await V('evidence-null', [chk('a', 'passed', { evidence: null })]); await V('evidence-str', [chk('a', 'passed', { evidence: 'x' })]);
await V('evidence-ref-num', [chk('a', 'passed', { evidence: { kind: 'sha256', ref: 5 } })]);
await V('sha-upper', [chk('a', 'passed', { evidence: { kind: 'sha256', ref: 'A'.repeat(64) } })]); await V('sha-short', [chk('a', 'passed', { evidence: { kind: 'sha256', ref: 'a'.repeat(63) } })]);
await V('sha-long', [chk('a', 'passed', { evidence: { kind: 'sha256', ref: 'a'.repeat(65) } })]); await V('sha-nonhex', [chk('a', 'passed', { evidence: { kind: 'sha256', ref: 'g'.repeat(64) } })]);
await V('sha-newline', [chk('a', 'passed', { evidence: { kind: 'sha256', ref: 'a'.repeat(64) + '\n' } })]);
await V('kind-bad', [chk('a', 'passed', { evidence: { kind: 'md5', ref: SHA } })]); await V('kind-missing', [chk('a', 'passed', { evidence: { ref: SHA } })]);
for (const [i, u] of ['https://example.com/e', 'https://example.com', 'http://example.com/e', 'ftp://example.com/e', 'https://user@example.com/e', 'https://user:pw@example.com/e', 'https://:pw@example.com/e', 'https://@example.com/e',
  'not a url', '', 'https://', 'https://example.com/' + 'a'.repeat(2030), 'https://example.com/' + 'a'.repeat(2029), 'https://EXAMPLE.com:8443/x?y=1#z', 'HTTPS://example.com/x', 'javascript:alert(1)', 'https://exa mple.com/', 'https://[::1]/x', 'https://例え.jp/x', '//example.com/e'].entries()) await V('url' + i, [URLC(u)]);

// ---- message / issue
const C0 = J(SC.issueSafetyCertificate({ policy: POL, guardianSecret: G, issuedAt: T0 }));
await add('safetyCertificateMessage', 'cert', [C0]);
await add('safetyCertificateMessage', 'claim', [(({ sig, ...r }: any) => r)(C0)]);
await add('safetyCertificateMessage', 'with-checks-grant', [J(SC.issueSafetyCertificate({ policy: POL, guardianSecret: G, issuedAt: T0, grantRef: 'g1', instance: 'i1', checks: [chk('a'), URLC('https://example.com/e')] }))]);
await add('safetyCertificateMessage', 'extra-members', [{ ...C0, extra: 1, nested: { b: 2, a: 1 } }]);
await add('safetyCertificateMessage', 'pq-sig-excluded', [{ ...C0, pq_sig: 'xyz' }]);

const iss = (name: string, a: any) => add('issueSafetyCertificate', name, [{ guardianSecret: G, issuedAt: T0, ...a }]);
await iss('default', { policy: POL });
await iss('weights-zero', { policy: pol({ weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } }) });
await iss('bound-frac', { policy: pol({ bMax: 1, kappa: 3 }) });
await iss('bmax-zero', { policy: pol({ bMax: 0 }) });
await iss('theta-equal', { policy: pol({ theta1: 0.5, theta2: 0.5 }) });
await iss('grant-instance', { policy: POL, grantRef: 'grant-1', instance: 'ins_1' });
await iss('empty-strings', { policy: POL, grantRef: '', instance: '' });
await iss('checks-empty', { policy: POL, checks: [] });
await iss('checks', { policy: POL, checks: [chk('lint'), chk('tests', 'failed'), chk('fuzz', 'not_run'), URLC('https://example.com/report')] });
await iss('checks-extra-member-dropped', { policy: POL, checks: [{ ...chk('a'), junk: 1, evidence: { kind: 'sha256', ref: SHA, junk: 1 } }] });
await iss('checks-bad', { policy: POL, checks: [chk('a'), chk('a')] });
await iss('checks-not-array', { policy: POL, checks: 'x' });
await iss('issued-zero', { policy: POL, issuedAt: 0 });
await iss('issued-float', { policy: POL, issuedAt: 1.5 });
await iss('issued-neg', { policy: POL, issuedAt: -5 });
await iss('issued-nan', { policy: POL, issuedAt: { $num: 'NaN' } });
await iss('issued-huge', { policy: POL, issuedAt: 2 ** 53 });
await iss('policy-null', { policy: null });
await iss('policy-no-weights', { policy: (({ weights, ...r }) => r)(POL) });
await iss('weight-neg', { policy: pol({ weights: { ...POL.weights, alpha: -0.1 } }) });
await iss('weight-nan', { policy: pol({ weights: { ...POL.weights, beta: { $num: 'NaN' } } }) });
await iss('weight-missing', { policy: pol({ weights: { alpha: 1 } }) });
await iss('kappa-zero', { policy: pol({ kappa: 0 }) });
await iss('kappa-neg', { policy: pol({ kappa: -1 }) });
await iss('theta-inverted', { policy: pol({ theta1: 0.7, theta2: 0.6 }) });
await iss('theta1-neg', { policy: pol({ theta1: -0.1 }) });
await iss('lambda-neg', { policy: pol({ lambda: -1 }) });
await iss('rho-neg', { policy: pol({ rho: -1 }) });
await iss('bmax-neg', { policy: pol({ bMax: -1 }) });
await iss('bmax-inf', { policy: pol({ bMax: { $num: 'Infinity' } }) });
await iss('policy-extra-member-dropped', { policy: { ...POL, extra: 9 } });
await iss('alg-ed25519', { policy: POL, suite: { alg: 'ed25519' } });
await iss('alg-ml-dsa-65', { policy: POL, suite: { alg: 'ml-dsa-65', pqSeed: PQS } });
await iss('alg-hybrid', { policy: POL, suite: { alg: 'hybrid-ed25519-ml-dsa-65', pqSeed: PQS }, checks: [chk('a')] });
await iss('alg-unknown', { policy: POL, suite: { alg: 'rot13' } });

// ---- verify
const CK = [chk('lint'), chk('tests', 'failed'), chk('fuzz', 'not_run')];
const mk = (a: any = {}) => J(SC.issueSafetyCertificate({ policy: POL, guardianSecret: G, issuedAt: T0, ...a }));
const CE = mk(), CC = mk({ checks: CK, grantRef: 'g', instance: 'i' });
const CP = J(SC.issueSafetyCertificate({ policy: POL, guardianSecret: G, issuedAt: T0, suite: { alg: 'ml-dsa-65', mlDsa: PQ.mlDsa65Keygen(PQS) } }));
const CH = J(SC.issueSafetyCertificate({ policy: POL, guardianSecret: G, issuedAt: T0, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: PQ.mlDsa65Keygen(PQS) } }));
const CF = mk({ policy: pol({ bMax: 1, kappa: 3 }) });
const CG2 = J(SC.issueSafetyCertificate({ policy: POL, guardianSecret: G2, issuedAt: T0 }));
const V2 = (name: string, c: any, op: any = null) => add('verifySafetyCertificate', name, [c, op]);
const cc = (c: any, over: any) => ({ ...c, ...over });
await V2('ok', CE); await V2('ok-checks', CC); await V2('ok-fraction-bound', CF); await V2('ok-opts-empty', CE, {});
await V2('guardian-pinned', CE, { guardian: GPK }); await V2('guardian-wrong-pin', CE, { guardian: G2PK }); await V2('guardian-pin-empty', CE, { guardian: '' }); await V2('other-guardian-ok', CG2);
await V2('swapped-guardian', cc(CE, { guardian: G2PK }));
await V2('pure-pq-no-pin', CP); await V2('pure-pq-pinned', CP, { pqPins: { [CP.guardian]: CP.pq_pk } }); await V2('pure-pq-unbound-allowed', CP, { allowUnboundPq: true });
await V2('pure-pq-wrong-pin', CP, { pqPins: { [CP.guardian]: CH.pq_pk.slice(0, -4) + 'AAAA' } });
await V2('hybrid-no-pin', CH); await V2('hybrid-pinned', CH, { pqPins: { [CH.guardian]: CH.pq_pk } }); await V2('hybrid-unbound-allowed', CH, { allowUnboundPq: true });
await V2('hybrid-pq-sig-flip', cc(CH, { pq_sig: flip(CH.pq_sig) }), { pqPins: { [CH.guardian]: CH.pq_pk } });
await V2('hybrid-pq-sig-missing', (({ pq_sig, ...r }: any) => r)(CH), { pqPins: { [CH.guardian]: CH.pq_pk } });
await V2('hybrid-downgrade-to-ed25519', (({ alg, pq_pk, pq_sig, ...r }: any) => r)(CH), { pqPins: { [CH.guardian]: CH.pq_pk } });
await V2('alg-unknown', cc(CE, { alg: 'rot13' })); await V2('alg-ed25519-explicit', cc(CE, { alg: 'ed25519' })); await V2('alg-num', cc(CE, { alg: 5 }));
function flip(s: string) { return s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'BB' : 'AA'); }
await V2('sig-flip', cc(CE, { sig: flip(CE.sig) })); await V2('sig-empty', cc(CE, { sig: '' })); await V2('sig-num', cc(CE, { sig: 5 })); await V2('sig-missing', (({ sig, ...r }: any) => r)(CE));
await V2('sig-trunc', cc(CE, { sig: CE.sig.slice(0, 40) })); await V2('sig-padded', cc(CE, { sig: CE.sig + '=' }));
await V2('guardian-missing', (({ guardian, ...r }: any) => r)(CE)); await V2('guardian-num', cc(CE, { guardian: 5 })); await V2('guardian-short', cc(CE, { guardian: 'abc' }));
for (const [i, c] of [null, 5, 'x', [], {}, true].entries()) await V2('shape' + i, c);
await V2('v-2', cc(CE, { v: 2 })); await V2('v-missing', (({ v, ...r }: any) => r)(CE)); await V2('v-string', cc(CE, { v: '1' }));
await V2('scope-other', cc(CE, { scope: 'agent-is-safe' })); await V2('scope-missing', (({ scope, ...r }: any) => r)(CE));
await V2('bound-tampered', cc(CE, { bound: 100 })); await V2('bound-nan', cc(CE, { bound: { $num: 'NaN' } })); await V2('bound-string', cc(CE, { bound: '2' })); await V2('bound-missing', (({ bound, ...r }: any) => r)(CE));
await V2('blast-tampered', cc(CE, { blastRadiusPerCheckpoint: 3 })); await V2('blast-missing', (({ blastRadiusPerCheckpoint, ...r }: any) => r)(CE));
await V2('statement-tampered-still-signs-over', cc(CE, { statement: 'x' }));
await V2('params-tampered-bmax', cc(CE, { params: { ...CE.params, bMax: 9 } })); await V2('params-tampered-kappa-keeps-bound', cc(CE, { params: { ...CE.params, kappa: 2 } }));
await V2('params-null', cc(CE, { params: null })); await V2('params-missing', (({ params, ...r }: any) => r)(CE)); await V2('params-array', cc(CE, { params: [] }));
await V2('params-kappa-zero', cc(CE, { params: { ...CE.params, kappa: 0 }, bound: 0, blastRadiusPerCheckpoint: 0 }));
await V2('params-weights-neg', cc(CE, { params: { ...CE.params, weights: { ...CE.params.weights, gamma: -1 } } }));
await V2('params-extra-signed-over', cc(CE, { params: { ...CE.params, extra: 1 } }));
await V2('issued-tampered', cc(CE, { issued_at: T0 + 1 })); await V2('extra-member', cc(CE, { extra: 1 })); await V2('checks-added', cc(CE, { checks: [chk('a')] }));
await V2('checks-dup', cc(CC, { checks: [chk('a'), chk('a')] })); await V2('checks-null', cc(CE, { checks: null })); await V2('checks-bad-evidence', cc(CC, { checks: [{ ...CK[0], evidence: { kind: 'url', ref: 'http://x/' } }] }));
await V2('checks-status-tampered', cc(CC, { checks: [{ ...CK[0], status: 'failed' }, CK[1], CK[2]] }));
for (const [i, r] of [['lint'], ['tests'], ['fuzz'], ['missing'], ['lint', 'tests'], ['lint', 'missing'], [], ['']].entries()) await V2('require' + i, CC, { requireChecks: r });
await V2('require-no-checks', CE, { requireChecks: ['lint'] }); await V2('require-empty-no-checks', CE, { requireChecks: [] });
await V2('require-unsigned-sig-first', cc(CC, { sig: flip(CC.sig) }), { requireChecks: ['missing'] });
for (const [i, [ma, now]] of ([[1000, T0 + 500], [1000, T0 + 1000], [1000, T0 + 1001], [0, T0], [0, T0 + 1], [1000, T0 - 1], [1000, T0], [{ $num: 'NaN' }, T0], [1000, { $num: 'NaN' }], [{ $num: 'Infinity' }, T0 + 5], [-1, T0], [1.5, T0 + 1], [1000, T0 + 0.5], [{ $num: 'Infinity' }, { $num: 'Infinity' }]] as any[]).entries()) await V2('age' + i, CE, { maxAgeMs: ma, now });
await V2('age-bad-issued-nan', cc(CE, { issued_at: { $num: 'NaN' } }), { maxAgeMs: 10, now: T0 });
await V2('age-future-fails-before-checks', CC, { maxAgeMs: 10, now: T0 - 5, requireChecks: ['lint'] });
await V2('age-then-checks', CC, { maxAgeMs: 10, now: T0 + 5, requireChecks: ['tests'] });
await V2('guardian-before-sig', cc(CE, { sig: flip(CE.sig) }), { guardian: G2PK });
await V2('issue-zero-time', mk({ issuedAt: 0 }), { maxAgeMs: 5, now: 3 });
await V2('bound-zero-bmax', mk({ policy: pol({ bMax: 0 }) }));

// ---- encode / decode
const E = (name: string, c: any) => add('encodeSafetyCertificate', name, [c]);
await E('plain', CE); await E('checks', CC); await E('pq', CP); await E('member-order', { z: 1, ...CE, a: [3, { y: 1, x: 2 }] });
const D = (name: string, s: any) => add('decodeSafetyCertificate', name, [s]);
await D('plain', JSON.stringify(CE)); await D('checks', JSON.stringify(CC)); await D('pq', JSON.stringify(CP)); await D('whitespace', ' ' + JSON.stringify(CE, null, 2) + ' ');
await D('empty', ''); await D('garbage', '{'); await D('null', 'null'); await D('array', '[]'); await D('number', '5'); await D('string', '"x"');
await D('v2', JSON.stringify({ ...CE, v: 2 })); await D('sig-num', JSON.stringify({ ...CE, sig: 5 })); await D('guardian-missing', JSON.stringify((({ guardian, ...r }: any) => r)(CE)));
await D('params-null', JSON.stringify({ ...CE, params: null })); await D('params-missing', JSON.stringify((({ params, ...r }: any) => r)(CE))); await D('params-array', JSON.stringify({ ...CE, params: [] }));
await D('unverified-fields-pass', JSON.stringify({ ...CE, bound: 999, scope: 'x' })); await D('arg-number', 5); await D('arg-null', null);
await D('oversize', JSON.stringify({ ...CE, pad: 'a'.repeat(1 << 21) }));

// ---- compliance row
const F = (name: string, c: any, op: any = null) => add('safetyCertificateForCompliance', name, [c, op]);
await F('ok', CE); await F('ok-checks', CC); await F('url-and-sha', mk({ checks: [chk('a'), URLC('https://example.com/e')] })); await F('bad-sig', cc(CE, { sig: flip(CE.sig) }));
await F('guardian-pin-ok', CE, { guardian: GPK }); await F('guardian-pin-bad', CE, { guardian: G2PK }); await F('require-ok', CC, { requireChecks: ['lint'] }); await F('require-failed', CC, { requireChecks: ['tests'] });
await F('age-ok', CE, { maxAgeMs: 10, now: T0 + 5 }); await F('age-old', CE, { maxAgeMs: 10, now: T0 + 50 }); await F('hybrid-pinned', CH, { pqPins: { [CH.guardian]: CH.pq_pk } }); await F('hybrid-unpinned', CH);
await F('malformed', null);

await add('constants', 'all', []);
refWrite(o, 'safety-certificate');
