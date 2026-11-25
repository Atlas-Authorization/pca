// Oracle: @atlasauth/pca-compliance (AuditEvent normalisation, the control-mapping table, per-framework compliance reports and their
// renderers, and the console-activity framework report). Writes out/ref-compliance.json.gz. Every case that reads the clock is given an
// explicit `now`; the reference is run on the re-parsed JSON a native sees. Argument shapes:
//   toAuditEvent(input)                      input = {pcactn, verify, decision?, now, session?}
//   controlMappings() / controlMappings(fw)  the table (filtered)
//   toComplianceReport(events, opts)         opts = {framework, now}
//   renderJson(report) / renderMarkdown(report)
//   frameworkReport(framework, input, now)   input = {policy, events, decisions?, hasGoalCommitment?, erasureSupported?}
//   frameworkReportToMarkdown(report)
//   constants()                              COMPLIANCE_FRAMEWORKS + CONTROL_MAPPINGS
import { Oracle, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-compliance/src/index.ts');
const o = new Oracle('compliance', 'tools/pca-audit/oracles/compliance.mts', 'TS-reference oracle for @atlasauth/pca-compliance.');
const NOW = 1_700_000_100_000;
const K = (c: string, n = 43) => c.repeat(n).slice(0, n);
const A = K('A'), B = K('B'), C = K('C'), D = K('D');

const cap = (issuer: string, holder: string, caveats: any[] = []) => ({ issuer, holder, caveats });
const CV_ENV = { type: 'envelope', predicates: [{ a: 1 }, { b: 2 }], caveats: [{ type: 'x' }] };
const CV_BUDGET = { type: 'budget_alloc', limit: 100 };
const CHAIN3 = [cap(A, B, [CV_ENV]), cap(B, C, [CV_ENV, CV_BUDGET]), cap(C, D, [CV_ENV, CV_BUDGET, { type: 'max_amount', amount: 25, currency: 'EUR', tags: ['a', 'b'], meta: { k: 1, '2': 'two', '1': 'one' } }])];
const pcactn = (over: any = {}) => ({
  v: 2, action: { verb: 'pay', resource: 'invoice/42', params_digest: K('P'), reversibility_class: 'reversible' }, grant_ref: 'grant-1', plan: { root: K('R') },
  sig: K('S', 86), alg: 'ed25519', counter: 7, nonce: 'n-1', iat: 1_700_000_000_000, exp: 1_700_000_060_000, cap_chain: CHAIN3, ...over,
});
const V_OK = { allow: true, checks: { wire: 'pass', audience: 'pass', cap_chain: 'pass', leaf_signature: 'pass' } };
const V_THR = { allow: true, checks: { wire: 'pass', leaf_signature: 'pass', threshold: 'pass' } };
const D_ADMIT = { admit: true, releaseGuardianShare: false, reasons: ['within budget'], r: 0.12, requiredThreshold: { t: 1, proof: 'agent' }, budget: { B: 5, tau: 1 } };
const D_STEP = { admit: false, releaseGuardianShare: true, reasons: ['needs human'], r: 0.6, requiredThreshold: { t: 3, proof: 'human' }, budget: { B: 2, tau: 1 } };
const D_DENY = { admit: false, releaseGuardianShare: false, reasons: ['over limit'], r: 0.99, requiredThreshold: { t: 3, proof: 'human' } };
const SHARES = [{ role: 'principal', publicKey: A, sig: 'x' }, { role: 'guardian', publicKey: B, sig: 'y' }];
const inp = (p: any, verify: any = V_OK, decision?: any, extra: any = {}) => ({ pcactn: p, verify, ...(decision !== undefined ? { decision } : {}), now: NOW, ...extra });
const T = (name: string, i: any) => o.run('toAuditEvent', name, M.toAuditEvent, [i]);

// ---- toAuditEvent ----
await T('allow no decision', inp(pcactn()));
await T('allow admit', inp(pcactn(), V_OK, D_ADMIT));
await T('step-up', inp(pcactn(), V_OK, D_STEP));
await T('deny by policy', inp(pcactn(), V_OK, D_DENY));
await T('deny by verify', inp(pcactn(), { allow: false, reason: 'plan inclusion failed', checks: { wire: 'pass', leaf_signature: 'pass' } }, D_ADMIT));
await T('deny verify no reason', inp(pcactn(), { allow: false, checks: {} }));
await T('deny verify non-string reason', inp(pcactn(), { allow: false, reason: 5, checks: {} }));
await T('deny verify null reason', inp(pcactn(), { allow: false, reason: null, checks: {} }));
await T('verify allow string', inp(pcactn(), { allow: 'true', checks: {} }));
await T('verify null', inp(pcactn(), null));
await T('verify absent', { pcactn: pcactn(), now: NOW });
for (const [n, v] of Object.entries({ zero: 0, empty: '', text: 'x', list: [], one: 1, bool: true })) await T(`verify ${n}`, inp(pcactn(), v as any));
await T('verify no checks', inp(pcactn(), { allow: true }));
await T('verify checks null', inp(pcactn(), { allow: true, checks: null }));
await T('verify checks number', inp(pcactn(), { allow: true, checks: 5 }));
await T('verify checks list', inp(pcactn(), { allow: true, checks: ['wire'] }));
await T('verify wire only', inp(pcactn(), { allow: true, checks: { wire: 'pass' } }));
await T('verify leaf only', inp(pcactn(), { allow: true, checks: { leaf_signature: 'pass' } }));
await T('verify checks fail values', inp(pcactn(), { allow: false, reason: 'r', checks: { wire: 'fail', leaf_signature: 'fail', cap_chain: 'skip' } }));
await T('threshold verified', inp(pcactn({ threshold: { shares: SHARES } }), V_THR, D_STEP));
await T('threshold verified guardian only', inp(pcactn({ threshold: { shares: [SHARES[1]] } }), V_THR, D_STEP));
await T('threshold verified principal only', inp(pcactn({ threshold: { shares: [SHARES[0]] } }), V_THR, D_STEP));
await T('threshold verified two guardians', inp(pcactn({ threshold: { shares: [SHARES[1], { role: 'guardian', publicKey: C }] } }), V_THR, D_STEP));
await T('threshold unverified fail', inp(pcactn({ threshold: { shares: SHARES } }), { allow: true, checks: { threshold: 'fail' } }, D_STEP));
await T('threshold unverified absent', inp(pcactn({ threshold: { shares: SHARES } }), V_OK, D_STEP));
await T('threshold check number', inp(pcactn({ threshold: { shares: SHARES } }), { allow: true, checks: { threshold: 5 } }, D_STEP));
await T('threshold check null', inp(pcactn({ threshold: { shares: SHARES } }), { allow: true, checks: { threshold: null } }, D_STEP));
await T('threshold check object', inp(pcactn({ threshold: { shares: SHARES } }), { allow: true, checks: { threshold: { a: 1 } } }, D_STEP));
await T('threshold check list', inp(pcactn({ threshold: { shares: SHARES } }), { allow: true, checks: { threshold: [1, null, 'a'] } }, D_STEP));
await T('threshold check bool', inp(pcactn({ threshold: { shares: SHARES } }), { allow: true, checks: { threshold: true } }, D_STEP));
await T('threshold empty shares', inp(pcactn({ threshold: { shares: [] } }), V_THR, D_STEP));
await T('threshold shares not array', inp(pcactn({ threshold: { shares: 'x' } }), V_THR, D_STEP));
await T('threshold null', inp(pcactn({ threshold: null }), V_THR, D_STEP));
await T('threshold hostile shares', inp(pcactn({ threshold: { shares: [null, 0, 'x', { role: 5 }, { role: 'principal' }, { role: 'principal', publicKey: 5 }, { role: 'other', publicKey: A }, { publicKey: A }, [], { role: 'principal', publicKey: C }] } }), V_THR, D_STEP));
await T('threshold tier from decision absent', inp(pcactn({ threshold: { shares: SHARES } }), V_THR, { admit: false, releaseGuardianShare: true }));
await T('threshold tier string', inp(pcactn({ threshold: { shares: SHARES } }), V_THR, { ...D_STEP, requiredThreshold: { t: 'two' } }));
await T('decision admit no reasons', inp(pcactn(), V_OK, { admit: true }));
await T('decision admit empty reasons', inp(pcactn(), V_OK, { admit: true, reasons: [] }));
await T('decision admit non-string reason', inp(pcactn(), V_OK, { admit: true, reasons: [5, 'x'] }));
await T('decision admit reasons not array', inp(pcactn(), V_OK, { admit: true, reasons: 'x' }));
await T('decision step no reasons', inp(pcactn(), V_OK, { releaseGuardianShare: true }));
await T('decision deny empty', inp(pcactn(), V_OK, {}));
await T('decision truthy admit values', inp(pcactn(), V_OK, { admit: 1 }));
await T('decision admit string', inp(pcactn(), V_OK, { admit: 'no' }));
await T('decision admit zero', inp(pcactn(), V_OK, { admit: 0, releaseGuardianShare: 'yes' }));
for (const [n, d] of Object.entries({ zero: 0, text: 'x', list: [], number: 5, bool: true, null: null, empty: '' })) await T(`decision ${n}`, inp(pcactn(), V_OK, d as any));
await T('decision risk only', inp(pcactn(), V_OK, { admit: true, r: 0 }));
await T('decision risk fields types', inp(pcactn(), V_OK, { admit: true, r: 'high', requiredThreshold: { t: null, proof: 5 }, budget: [] }));
await T('decision requiredThreshold null', inp(pcactn(), V_OK, { admit: true, requiredThreshold: null }));
await T('decision requiredThreshold number', inp(pcactn(), V_OK, { admit: true, requiredThreshold: 5 }));
// chains
await T('chain empty', inp(pcactn({ cap_chain: [] })));
await T('chain absent', inp(pcactn({ cap_chain: undefined })));
await T('chain not array', inp(pcactn({ cap_chain: 'x' })));
await T('chain object', inp(pcactn({ cap_chain: { 0: cap(A, B) } })));
await T('chain one hop no caveats', inp(pcactn({ cap_chain: [cap(A, B)] })));
await T('chain one hop', inp(pcactn({ cap_chain: [cap(A, B, [CV_ENV])] })));
await T('chain rebind only', inp(pcactn({ cap_chain: [cap(A, B, [CV_ENV]), cap(B, C, [CV_ENV])] })));
await T('chain child shorter than parent', inp(pcactn({ cap_chain: [cap(A, B, [CV_ENV, CV_BUDGET]), cap(B, C, [CV_ENV])] })));
await T('chain null hop', inp(pcactn({ cap_chain: [cap(A, B), null, cap(C, D, [CV_ENV])] })));
await T('chain null first hop', inp(pcactn({ cap_chain: [null, cap(A, B, [CV_ENV])] })));
await T('chain zero hop', inp(pcactn({ cap_chain: [0, cap(A, B)] })));
await T('chain empty string hop', inp(pcactn({ cap_chain: ['', cap(A, B)] })));
await T('chain primitive hops', inp(pcactn({ cap_chain: [5, 'abc', true, [], {}] })));
await T('chain last null', inp(pcactn({ cap_chain: [cap(A, B), null] })));
await T('chain hop missing issuer holder', inp(pcactn({ cap_chain: [{ caveats: [] }, { caveats: [CV_ENV] }] })));
await T('chain hop null issuer', inp(pcactn({ cap_chain: [{ issuer: null, holder: null, caveats: [] }] })));
await T('chain hop numeric issuer', inp(pcactn({ cap_chain: [{ issuer: 5, holder: 6, caveats: [] }] })));
await T('chain hop caveats not array', inp(pcactn({ cap_chain: [{ issuer: A, holder: B, caveats: 'x' }, { issuer: B, holder: C, caveats: [CV_ENV] }] })));
await T('chain parent caveats not array', inp(pcactn({ cap_chain: [{ issuer: A, holder: B, caveats: null }, { issuer: B, holder: C, caveats: [CV_ENV, CV_BUDGET] }] })));
await T('chain parent not object', inp(pcactn({ cap_chain: [5, { issuer: B, holder: C, caveats: [CV_ENV] }] })));
await T('chain deep', inp(pcactn({ cap_chain: Array.from({ length: 6 }, (_, i) => cap(K(String.fromCharCode(65 + i)), K(String.fromCharCode(66 + i)), [CV_ENV, { type: 'n', i }].slice(0, 1 + (i > 2 ? 1 : 0)))) })));
await T('short keys', inp(pcactn({ cap_chain: [cap('short', 'k'.repeat(13), [CV_ENV]), cap('k'.repeat(13), 'k'.repeat(14), [CV_ENV]), cap('', 'x', [CV_ENV])] })));
await T('emoji keys', inp(pcactn({ cap_chain: [cap('\u{1F600}'.repeat(10), '\u{1F600}'.repeat(6) + 'a', [CV_ENV]), cap('a\u{1F600}'.repeat(6), 'é'.repeat(20), [CV_ENV])] })));
await T('lone surrogate key', inp(pcactn({ cap_chain: [cap('a'.repeat(11) + '\ud83d' + 'b'.repeat(5), 'k', [CV_ENV])] })));
// caveats
const caveatCase = (n: string, ...cv: any[]) => T(`caveats ${n}`, inp(pcactn({ cap_chain: [cap(A, B, cv)] })));
await caveatCase('envelope plain', { type: 'envelope' });
await caveatCase('envelope bad members', { type: 'envelope', predicates: 'x', caveats: 5 });
await caveatCase('envelope arrays', { type: 'envelope', predicates: [1, 2, 3], caveats: [] });
await caveatCase('budget int', { type: 'budget_alloc', limit: 5 });
await caveatCase('budget zero', { type: 'budget_alloc', limit: 0 });
await caveatCase('budget fraction', { type: 'budget_alloc', limit: 2.5 });
await caveatCase('budget fraction long', { type: 'budget_alloc', limit: 1.23456789 });
await caveatCase('budget rounding', { type: 'budget_alloc', limit: 0.00005 }, { type: 'budget_alloc', limit: 0.00015 }, { type: 'budget_alloc', limit: 2.99995 }, { type: 'budget_alloc', limit: 1e-7 });
await caveatCase('budget huge', { type: 'budget_alloc', limit: 1e21 }, { type: 'budget_alloc', limit: 123456789012345680000 }, { type: 'budget_alloc', limit: 1e-9 }, { type: 'budget_alloc', limit: 12345.678901 });
await caveatCase('budget negative falls through', { type: 'budget_alloc', limit: -1 });
await caveatCase('budget string limit falls through', { type: 'budget_alloc', limit: '5' });
await caveatCase('budget missing limit', { type: 'budget_alloc' });
await caveatCase('budget two takes first', { type: 'budget_alloc', limit: 5 }, { type: 'budget_alloc', limit: 4 });
await caveatCase('budget invalid then valid', { type: 'budget_alloc', limit: -1 }, { type: 'budget_alloc', limit: 4 });
await caveatCase('generic scalar values', { type: 'cap', s: 'str', n: 3, f: 0.5, b: true, z: null });
await caveatCase('generic object values', { type: 'cap', o: { b: 1, a: [1, 'x', null, { c: false }] }, l: [], e: {} });
await caveatCase('generic json formatting', { type: 'cap', o: { s: 'q"\\\n\t\u0001\u007f é😀\ud800', n: [1.5, -0, 1e21, 1e-7, 123456789012345680000, 0.1] } });
await caveatCase('generic integer-like keys order', { type: 'cap', b: 1, '2': 'two', a: 2, '1': 'one', o: { z: 1, '10': 10, '9': 9 } });
await caveatCase('generic more than 8 keys', { type: 'cap', k1: 1, k2: 2, k3: 3, k4: 4, k5: 5, k6: 6, k7: 7, k8: 8, k9: 9 });
await caveatCase('generic type not first', { k1: 1, k2: 2, k3: 3, k4: 4, k5: 5, k6: 6, k7: 7, type: 'late', k8: 8 });
await caveatCase('generic only type', { type: 'bare' });
await caveatCase('generic number formats', { type: 'cap', a: 1.5, b: 100, c: 0.0001, d: 0.00005, e: 1e21, f: 12.34567, g: -2.5, h: -0.00004 });
await caveatCase('generic rounding halves', { type: 'cap', a: 0.00005, b: 0.00015, c: 2.00005, d: 0.49995, e: -0.00005, f: -1.00005 });
await caveatCase('generic big numbers', { type: 'cap', a: 2 ** 53, b: 1e300, c: 9007199254740993, d: 123456789.123456789 });
await caveatCase('malformed null', null);
await caveatCase('malformed number', 5);
await caveatCase('malformed string', 'x');
await caveatCase('malformed array', []);
await caveatCase('malformed no type', { a: 1 });
await caveatCase('malformed type number', { type: 5 });
await caveatCase('malformed empty type', { type: '' });
await caveatCase('mixed', { type: 'a', x: 1 }, null, CV_BUDGET, CV_ENV, { type: 'z' });
// pcactn shape
await T('pcactn empty', inp({}));
await T('pcactn null', inp(null));
await T('pcactn absent', { verify: V_OK, now: NOW });
await T('pcactn array', inp([]));
await T('pcactn number', inp(5));
await T('pcactn string', inp('x'));
await T('pcactn action missing', inp(pcactn({ action: undefined })));
await T('pcactn action null', inp(pcactn({ action: null })));
await T('pcactn action number members', inp(pcactn({ action: { verb: 5, resource: null, params_digest: 7, reversibility_class: [] } })));
await T('pcactn action irreversible', inp(pcactn({ action: { verb: 'delete', resource: 'db/1', params_digest: K('Q'), reversibility_class: 'irreversible' } })));
await T('pcactn sig missing', inp(pcactn({ sig: undefined })));
await T('pcactn alg other', inp(pcactn({ alg: 'ml-dsa-65' })));
await T('pcactn alg number', inp(pcactn({ alg: 5 })));
await T('pcactn plan missing', inp(pcactn({ plan: undefined })));
await T('pcactn plan root number', inp(pcactn({ plan: { root: 5 } })));
await T('pcactn grant_ref missing', inp(pcactn({ grant_ref: undefined })));
await T('pcactn grant_ref number', inp(pcactn({ grant_ref: 5 })));
await T('pcactn nonce missing', inp(pcactn({ nonce: undefined })));
await T('pcactn nonce number', inp(pcactn({ nonce: 5 })));
await T('pcactn counter missing', inp(pcactn({ counter: undefined })));
await T('pcactn counter zero', inp(pcactn({ counter: 0 })));
await T('pcactn counter string', inp(pcactn({ counter: '3' })));
await T('pcactn counter fraction', inp(pcactn({ counter: 1.5 })));
await T('pcactn undigestible', inp(pcactn({ big: 2 ** 53 + 2 })));
await T('pcactn undigestible fraction', inp(pcactn({ f: 1.5 })));
await T('pcactn undigestible surrogate', inp(pcactn({ s: '\ud800' })));
await T('pcactn digestible unicode', inp(pcactn({ s: 'é😀', z: [null, true] })));
// times
for (const [n, t] of Object.entries({ zero: 0, epoch1: 1, neg1: -1, fraction: 1.5, negfraction: -1.5, y2038: 2147483648000, y2100: 4102444800000, y9999: 253402300799999, y10000: 253402300800000, y275760: 8.64e15, over: 8.64e15 + 1, negmax: -8.64e15, negover: -8.64e15 - 1, yneg1: -62198755200000, y0: -62167219200000, yneg: -62167219200001, leap: 951782400000, feb29: 1709164800000, leapnext: 1709251199999, big: 1e300, string: '1700000000000', nulls: null, bool: true, list: [5], object: {}, tiny: 1e-300, maxsafe: 2 ** 53 - 1 }))
  await T(`iat ${n}`, inp(pcactn({ iat: t, exp: t })));
await T('iat missing exp missing', inp(pcactn({ iat: undefined, exp: undefined })));
for (const [n, t] of Object.entries({ zero: 0, fraction: 1700000000000.9, string: 'x', big: 1e300, y10000: 253402300800000, neg: -5e13 })) await T(`now ${n}`, { ...inp(pcactn()), now: t });
// session
await T('session given', inp(pcactn(), V_OK, undefined, { session: 'sess-9' }));
await T('session null', inp(pcactn(), V_OK, undefined, { session: null }));
await T('session number', inp(pcactn(), V_OK, undefined, { session: 5 }));
await T('session empty', inp(pcactn(), V_OK, undefined, { session: '' }));
await T('session default grant_ref missing', inp(pcactn({ grant_ref: undefined })));
// hostile inputs
await o.run('toAuditEvent', 'input null', M.toAuditEvent, [null]);
await o.run('toAuditEvent', 'input absent', M.toAuditEvent, []);
await T('input only now', { now: NOW });
await T('input verify only', { now: NOW, verify: V_OK });

// ---- controlMappings + constants ----
await o.run('constants', 'all', () => ({ COMPLIANCE_FRAMEWORKS: M.COMPLIANCE_FRAMEWORKS, CONTROL_MAPPINGS: M.CONTROL_MAPPINGS }), []);
await o.run('controlMappings', 'all', M.controlMappings, []);
for (const fw of ['eu-ai-act', 'iso-42001', 'soc2', 'gdpr', '', 'EU-AI-ACT', 'constructor', '__proto__', 'toString', null, 5, [], {}, 'soc2 ', ['soc2']]) await o.run('controlMappings', `fw ${JSON.stringify(fw)}`, M.controlMappings, [fw]);

// ---- events for the reports ----
const ev = (p: any, verify: any = V_OK, decision?: any, extra: any = {}) => JSON.parse(JSON.stringify(M.toAuditEvent(inp(p, verify, decision, extra))));
const E_ALLOW = ev(pcactn(), V_OK, D_ADMIT);
const E_ALLOW2 = ev(pcactn({ counter: 8, iat: 1_700_000_030_000, cap_chain: [cap(A, B, [CV_ENV])] }), V_OK, D_ADMIT);
const E_STEP_H = ev(pcactn({ counter: 9, iat: 1_700_000_020_000, threshold: { shares: SHARES } }), V_THR, D_STEP);
const E_STEP_G = ev(pcactn({ counter: 10, iat: 1_700_000_040_000, threshold: { shares: [SHARES[1]] } }), V_THR, D_STEP);
const E_STEP = ev(pcactn({ counter: 11 }), V_OK, D_STEP);
const E_DENY = ev(pcactn({ counter: 12, iat: 1_699_999_990_000 }), V_OK, D_DENY);
const E_BADPROOF = ev(pcactn({ counter: 13 }), { allow: false, reason: 'bad sig', checks: { wire: 'pass', leaf_signature: 'fail' } });
const E_NOCHAIN = ev(pcactn({ counter: 14, cap_chain: [] }), V_OK, D_ADMIT);
const E_NOPLAN = ev(pcactn({ counter: 15, plan: undefined }), V_OK, D_ADMIT);
const E_UNDIG = ev(pcactn({ counter: 16, f: 1.5 }), V_OK, D_ADMIT);
const E_NOTIME = ev(pcactn({ counter: 17, iat: undefined }), V_OK, D_ADMIT);
const E_BIGTIME = ev(pcactn({ counter: 18, iat: 8.64e15 + 10 }), V_OK, D_ADMIT);
const E_OTHER = ev(pcactn({ counter: 19, grant_ref: 'grant-2', cap_chain: [cap(C, D, [CV_BUDGET])] }), V_OK, D_ADMIT);
const E_BARE = ev({}, { allow: false }, undefined);
const SETS: Record<string, any[]> = {
  empty: [], single: [E_ALLOW], two: [E_ALLOW, E_ALLOW2], allow3: [E_ALLOW, E_ALLOW2, E_OTHER], 'human step-up': [E_ALLOW, E_STEP_H], 'guardian step-up': [E_ALLOW, E_STEP_G],
  'step-up no co-sign': [E_STEP], 'deny only': [E_DENY], 'bad proof': [E_ALLOW, E_BADPROOF], 'no chain': [E_ALLOW, E_NOCHAIN], 'all no chain': [E_NOCHAIN], 'no plan': [E_ALLOW, E_NOPLAN], 'all no plan': [E_NOPLAN],
  undigestible: [E_UNDIG], 'undigestible first': [E_UNDIG, E_ALLOW], 'all undigestible': [E_UNDIG, E_UNDIG], 'no time': [E_ALLOW, E_NOTIME], 'only no time': [E_NOTIME], 'big time': [E_ALLOW, E_BIGTIME],
  bare: [E_BARE], 'bare + good': [E_BARE, E_ALLOW], everything: [E_ALLOW, E_ALLOW2, E_STEP_H, E_STEP_G, E_STEP, E_DENY, E_BADPROOF, E_NOCHAIN, E_NOPLAN, E_UNDIG, E_NOTIME, E_OTHER],
  'null entries': [null, E_ALLOW, 0, '', false, E_STEP_H], order: [E_DENY, E_ALLOW, E_STEP_H],
};
const reports: Record<string, any> = {};
for (const [sn, evs] of Object.entries(SETS)) {
  for (const fw of M.COMPLIANCE_FRAMEWORKS) {
    await o.run('toComplianceReport', `${fw} ${sn}`, M.toComplianceReport, [evs, { framework: fw, now: NOW }]);
    reports[`${fw}/${sn}`] = JSON.parse(JSON.stringify(M.toComplianceReport(evs, { framework: fw, now: NOW })));
  }
}
const TR = (n: string, evs: any, opts: any) => o.run('toComplianceReport', n, M.toComplianceReport, [evs, opts]);
await TR('events not array object', { a: 1 }, { framework: 'soc2', now: NOW });
await TR('events null', null, { framework: 'soc2', now: NOW });
await TR('events string', 'abc', { framework: 'soc2', now: NOW });
for (const fw of ['gdpr', '', 'constructor', null, 5, ['soc2'], 'SOC2']) await TR(`bad framework ${JSON.stringify(fw)}`, [E_ALLOW], { framework: fw, now: NOW });
await TR('framework absent', [E_ALLOW], { now: NOW });
await TR('opts null', [E_ALLOW], null);
await TR('opts absent', [E_ALLOW], undefined);
for (const [n, t] of Object.entries({ zero: 0, string: 'x', huge: 1e300, y10000: 253402300800000, fraction: 1.5 })) await TR(`now ${n}`, [E_ALLOW], { framework: 'soc2', now: t });
// hostile events (each must refuse the same way, or degrade the same way)
const strip = (e: any, f: (c: any) => void) => { const c = JSON.parse(JSON.stringify(e)); f(c); return c; };
const HOSTILE: Record<string, any> = {
  'no evidence': strip(E_ALLOW, (c) => delete c.evidence), 'evidence null': strip(E_ALLOW, (c) => (c.evidence = null)), 'evidence empty': strip(E_ALLOW, (c) => (c.evidence = {})),
  'no decision': strip(E_ALLOW, (c) => delete c.decision), 'decision empty': strip(E_ALLOW, (c) => (c.decision = {})), 'outcome other': strip(E_ALLOW, (c) => (c.decision.outcome = 'maybe')),
  'no delegation': strip(E_ALLOW, (c) => delete c.delegation), 'delegation empty': strip(E_ALLOW, (c) => (c.delegation = {})), 'hops string': strip(E_ALLOW, (c) => (c.delegation.hops = 'abc')),
  'hops empty string': strip(E_ALLOW, (c) => (c.delegation.hops = '')), 'hops object': strip(E_ALLOW, (c) => (c.delegation.hops = {})), 'hops number': strip(E_ALLOW, (c) => (c.delegation.hops = 5)),
  'depth string': strip(E_ALLOW, (c) => (c.delegation.depth = '4')), 'depth text': strip(E_ALLOW, (c) => (c.delegation.depth = 'deep')), 'depth null': strip(E_ALLOW, (c) => (c.delegation.depth = null)),
  'depth big': strip(E_ALLOW, (c) => (c.delegation.depth = 1.5)), 'depth negative': strip(E_ALLOW, (c) => (c.delegation.depth = -3)),
  'no agent': strip(E_ALLOW, (c) => delete c.agent), 'agent empty': strip(E_ALLOW, (c) => (c.agent = {})), 'holder object': strip(E_ALLOW, (c) => (c.agent.holder = { a: 1 })),
  'holder number': strip(E_ALLOW, (c) => (c.agent.holder = 5)), 'principal null': strip(E_ALLOW, (c) => (c.agent.principal = null)), 'principal number': strip(E_ALLOW, (c) => (c.agent.principal = 5)),
  'no timestamps': strip(E_ALLOW, (c) => delete c.timestamps), 'timestamps empty': strip(E_ALLOW, (c) => (c.timestamps = {})), 'issuedAt empty': strip(E_ALLOW, (c) => (c.timestamps.issuedAt = {})),
  'issuedAt string': strip(E_ALLOW, (c) => (c.timestamps.issuedAt.epochMs = '5')), 'issuedAt null': strip(E_ALLOW, (c) => (c.timestamps.issuedAt.epochMs = null)),
  'planRoot missing': strip(E_ALLOW, (c) => delete c.evidence.planRoot), 'digest missing': strip(E_ALLOW, (c) => delete c.evidence.pcactnDigest), 'digest number': strip(E_ALLOW, (c) => (c.evidence.pcactnDigest = 5)),
  'verifiable string': strip(E_ALLOW, (c) => (c.evidence.cryptographicallyVerifiable = 'yes')), 'verifiable empty list': strip(E_ALLOW, (c) => (c.evidence.cryptographicallyVerifiable = [])),
  'humanOverride true': strip(E_ALLOW, (c) => (c.humanOverride = { humanApproved: true })), 'humanOverride string': strip(E_ALLOW, (c) => (c.humanOverride = { humanApproved: 'x' })),
  'humanOverride null': strip(E_ALLOW, (c) => (c.humanOverride = null)), 'humanOverride number': strip(E_ALLOW, (c) => (c.humanOverride = 5)),
  'array event': [], 'string event': 'x', 'number event': 5, 'object event': {}, 'true event': true,
};
for (const [n, e] of Object.entries(HOSTILE)) {
  await TR(`hostile ${n}`, [e], { framework: 'soc2', now: NOW });
  await TR(`hostile ${n} + good`, [E_ALLOW, e], { framework: 'eu-ai-act', now: NOW });
  await TR(`hostile ${n} iso`, [e, E_STEP_H], { framework: 'iso-42001', now: NOW });
}
// agents / principals sets (identity of primitives vs objects)
await TR('holders 1 and "1" and true', [strip(E_ALLOW, (c) => (c.agent.holder = 1)), strip(E_ALLOW, (c) => (c.agent.holder = '1')), strip(E_ALLOW, (c) => (c.agent.holder = true))], { framework: 'soc2', now: NOW });
await TR('holders equal objects distinct', [strip(E_ALLOW, (c) => (c.agent.holder = { a: 1 })), strip(E_ALLOW, (c) => (c.agent.holder = { a: 1 }))], { framework: 'soc2', now: NOW });
await TR('holders null and missing', [strip(E_ALLOW, (c) => (c.agent.holder = null)), strip(E_ALLOW, (c) => delete c.agent.holder), strip(E_ALLOW, (c) => delete c.agent.holder)], { framework: 'soc2', now: NOW });
await TR('principals null counted', [strip(E_ALLOW, (c) => (c.agent.principal = null)), strip(E_ALLOW, (c) => delete c.agent.principal)], { framework: 'eu-ai-act', now: NOW });
await TR('number holders 1 and 1.0', [strip(E_ALLOW, (c) => (c.agent.holder = 1)), strip(E_ALLOW, (c) => (c.agent.holder = 1.0))], { framework: 'soc2', now: NOW });
// 40 events: counters and percent rounding (1/8 = 12.5%)
await TR('many allowed', Array.from({ length: 40 }, () => E_ALLOW), { framework: 'iso-42001', now: NOW });

// ---- render ----
for (const [rn, rep] of Object.entries(reports)) {
  await o.run('renderJson', rn, M.renderJson, [rep]);
  await o.run('renderMarkdown', rn, M.renderMarkdown, [rep]);
}
const R0 = reports['iso-42001/everything'];
const mutate = (f: (c: any) => void) => { const c = JSON.parse(JSON.stringify(R0)); f(c); return c; };
const RH: Record<string, any> = {
  'no coverage': mutate((c) => delete c.coverage), 'coverage empty': mutate((c) => (c.coverage = {})), 'no items': mutate((c) => delete c.items), 'items object': mutate((c) => (c.items = {})), 'items empty': mutate((c) => (c.items = [])),
  'items null entry': mutate((c) => (c.items = [null])), 'item empty': mutate((c) => (c.items = [{}])), 'item status unknown': mutate((c) => (c.items[0].status = 'weird')), 'item status number': mutate((c) => (c.items[0].status = 5)),
  'item status missing': mutate((c) => delete c.items[0].status), 'item findings missing': mutate((c) => delete c.items[0].findings), 'item findings string': mutate((c) => (c.items[0].findings = 'ab')),
  'item findings object': mutate((c) => (c.items[0].findings = { a: 1 })), 'item findings with non-strings': mutate((c) => (c.items[0].findings = [1, null, { a: 1 }, 'x'])), 'item findings empty': mutate((c) => (c.items[0].findings = [])),
  'no assurances': mutate((c) => delete c.assurances), 'assurances falsy': mutate((c) => (c.assurances = { cryptographicallyVerifiable: 0, explicitDelegationChain: '', signedHumanOverrides: null, narrative: 5 })),
  'assurances truthy': mutate((c) => (c.assurances = { cryptographicallyVerifiable: 'x', explicitDelegationChain: [], signedHumanOverrides: {}, narrative: ['a', 'b'] })),
  'eventCount zero': mutate((c) => (c.eventCount = 0)), 'eventCount string': mutate((c) => (c.eventCount = '3')), 'eventCount missing': mutate((c) => delete c.eventCount), 'eventCount null': mutate((c) => (c.eventCount = null)),
  'no period': mutate((c) => delete c.period), 'no generatedAt': mutate((c) => delete c.generatedAt), 'framework number': mutate((c) => (c.framework = 5)), 'framework missing': mutate((c) => delete c.framework),
  'report null': null, 'report array': [], 'report empty': {}, 'report string': 'x', 'strings with markdown': mutate((c) => { c.items[0].evidence = '|a|\n**b**'; c.items[0].controlTitle = 'T|x'; }),
  'percent float': mutate((c) => (c.coverage.satisfiedPercent = 12.5)), 'percent big': mutate((c) => (c.coverage.satisfiedPercent = 1e21)),
};
for (const [n, r] of Object.entries(RH)) {
  await o.run('renderMarkdown', `hostile ${n}`, M.renderMarkdown, [r]);
  await o.run('renderJson', `hostile ${n}`, M.renderJson, [r]);
}
for (const [n, v] of Object.entries({ nested: { a: [1, { b: [] , c: {} }], '2': 1, '1': 2 }, numbers: [1.5, -0, 1e21, 1e-7, 0.1, 123456789012345680000], strings: ['é\u0001 😀\ud800"\\/'], empty: {}, emptyList: [], null: null, scalar: 5, text: 'x', deep: { a: { b: { c: { d: [[[]]] } } } } }))
  await o.run('renderJson', `generic ${n}`, M.renderJson, [v]);

// ---- frameworkReport ----
const POL = { riskPolicy: { bMax: 100, kappa: 4 }, predicates: [{ type: 'p' }] };
const evs = (...x: any[]) => x;
const FE = [
  { outcome: 'auto', agent: 'a1', at: 1000, taint: 0.2 }, { outcome: 'executed', agent: 'a2', at: 3000 }, { outcome: 'step_up', agent: 'a1', at: 2000, taint: 1.5 },
  { outcome: 'deny', agent: 'a3', at: 5000 }, { outcome: 'other', agent: 'a1', at: 4000, taint: 0 },
];
const FI = (over: any = {}) => ({ policy: POL, events: FE, ...over });
const FR = (n: string, fw: any, input: any, now: any = NOW) => o.run('frameworkReport', n, M.frameworkReport, [fw, input, now]);
const frReports: Record<string, any> = {};
for (const fw of ['eu-ai-act', 'soc2', 'gdpr']) {
  for (const [n, input] of Object.entries({
    base: FI(), 'no events': FI({ events: [] }), 'goal+erasure': FI({ hasGoalCommitment: true, erasureSupported: true }), 'goal only': FI({ hasGoalCommitment: true }), 'truthy flags': FI({ hasGoalCommitment: 'yes', erasureSupported: 1 }),
    'falsy flags': FI({ hasGoalCommitment: 0, erasureSupported: '' }), 'decisions': FI({ decisions: [{}, {}, {}] }), 'decisions string': FI({ decisions: 'abcd' }), 'decisions object': FI({ decisions: { a: 1 } }),
    'decisions null': FI({ decisions: null }), 'decisions number': FI({ decisions: 5 }), 'no predicates': FI({ policy: { riskPolicy: POL.riskPolicy } }), 'empty predicates': FI({ policy: { ...POL, predicates: [] } }),
    'predicates not array': FI({ policy: { ...POL, predicates: 'x' } }), 'kappa zero': FI({ policy: { riskPolicy: { bMax: 100, kappa: 0 }, predicates: [1] } }), 'kappa negative': FI({ policy: { riskPolicy: { bMax: 100, kappa: -2 }, predicates: [1] } }),
    'bMax negative': FI({ policy: { riskPolicy: { bMax: -100, kappa: 4 }, predicates: [1] } }), 'bMax zero': FI({ policy: { riskPolicy: { bMax: 0, kappa: 4 }, predicates: [1] } }), 'bound fraction': FI({ policy: { riskPolicy: { bMax: 10, kappa: 3 }, predicates: [1] } }),
    'bound tiny': FI({ policy: { riskPolicy: { bMax: 1, kappa: 3e-7 }, predicates: [1] } }), 'bound huge': FI({ policy: { riskPolicy: { bMax: 1e300, kappa: 1e-10 }, predicates: [1] } }), 'bound 0.1 0.3': FI({ policy: { riskPolicy: { bMax: 0.1, kappa: 0.3 }, predicates: [1] } }),
    'bound exponent': FI({ policy: { riskPolicy: { bMax: 1e21, kappa: 1 }, predicates: [1] } }), 'kappa string': FI({ policy: { riskPolicy: { bMax: 100, kappa: '4' }, predicates: [1] } }), 'bMax string': FI({ policy: { riskPolicy: { bMax: '100', kappa: 4 }, predicates: [1] } }),
    'bMax missing': FI({ policy: { riskPolicy: { kappa: 4 }, predicates: [1] } }), 'kappa missing': FI({ policy: { riskPolicy: { bMax: 4 }, predicates: [1] } }), 'bMax null': FI({ policy: { riskPolicy: { bMax: null, kappa: 4 }, predicates: [1] } }),
    'kappa null': FI({ policy: { riskPolicy: { bMax: 4, kappa: null }, predicates: [1] } }), 'bMax text': FI({ policy: { riskPolicy: { bMax: 'x', kappa: 4 }, predicates: [1] } }),
    'taint infinite string': FI({ events: [{ outcome: 'auto', agent: 'a', at: 1, taint: 'high' }] }), 'taint null': FI({ events: [{ outcome: 'auto', agent: 'a', at: 1, taint: null }] }), 'taint negative': FI({ events: [{ outcome: 'auto', agent: 'a', at: 1, taint: -4 }] }),
    'taint big': FI({ events: [{ outcome: 'auto', agent: 'a', at: 1, taint: 1e21 }, { outcome: 'auto', agent: 'a', at: 2, taint: 3 }] }), 'taint fraction': FI({ events: [{ outcome: 'auto', agent: 'a', at: 1, taint: 0.1 }, { outcome: 'auto', agent: 'b', at: 2, taint: 0.30000000000000004 }] }),
    'at non-number': FI({ events: [{ outcome: 'auto', agent: 'a', at: 'x' }, { outcome: 'deny', agent: 'b', at: 10 }, { outcome: 'deny', agent: 'c' }, { outcome: 'deny', agent: 'c', at: null }] }),
    'agents types': FI({ events: [{ outcome: 'auto', agent: 1, at: 1 }, { outcome: 'auto', agent: '1', at: 1 }, { outcome: 'auto', agent: null, at: 1 }, { outcome: 'auto', at: 1 }, { outcome: 'auto', agent: { a: 1 }, at: 1 }, { outcome: 'auto', agent: { a: 1 }, at: 1 }] }),
    'all autonomous': FI({ events: Array.from({ length: 12 }, (_, i) => ({ outcome: i % 2 ? 'auto' : 'executed', agent: 'a' + (i % 3), at: i })) }),
    'only step_up': FI({ events: [{ outcome: 'step_up', agent: 'a', at: 1 }, { outcome: 'step_up', agent: 'a', at: 2 }] }),
    'only deny': FI({ events: [{ outcome: 'deny', agent: 'a', at: 1 }] }),
  }) as [string, any][]) {
    await FR(`${fw} ${n}`, fw, input);
    if (['base', 'no events', 'goal+erasure', 'no predicates', 'kappa zero', 'taint infinite string', 'bound fraction', 'agents types'].includes(n)) frReports[`${fw}/${n}`] = JSON.parse(JSON.stringify(M.frameworkReport(fw, input, NOW)));
  }
}
for (const fw of ['', 'constructor', '__proto__', 'toString', 'hasOwnProperty', 'EU-AI-ACT', 'iso-42001', null, 5, {}]) await FR(`bad framework ${JSON.stringify(fw)}`, fw, FI());
for (const [n, input] of Object.entries({
  null: null, array: [], empty: {}, 'no policy': { events: FE }, 'policy null': { policy: null, events: FE }, 'policy empty': { policy: {}, events: FE }, 'riskPolicy null': { policy: { riskPolicy: null }, events: FE }, 'no events': { policy: POL },
  'events null': { policy: POL, events: null }, 'events object': { policy: POL, events: {} }, 'events string': { policy: POL, events: 'abc' }, 'event null': FI({ events: [null] }), 'event number': FI({ events: [5] }), 'event string': FI({ events: ['x'] }),
  'event empty': FI({ events: [{}] }), 'event list': FI({ events: [[]] }),
}) as [string, any][]) await FR(`hostile ${n}`, 'soc2', input);
for (const [n, t] of Object.entries({ zero: 0, string: 'x', null: null, fraction: 1.5, huge: 1e300, y10000: 253402300800000, neg: -1 })) await FR(`now ${n}`, 'soc2', FI(), t);
await o.run('frameworkReport', 'now default is not called', M.frameworkReport, ['soc2', FI(), 5]);
for (const [rn, rep] of Object.entries(frReports)) await o.run('frameworkReportToMarkdown', rn, M.frameworkReportToMarkdown, [rep]);
const F0 = frReports['soc2/base'];
const fm = (f: (c: any) => void) => { const c = JSON.parse(JSON.stringify(F0)); f(c); return c; };
for (const [n, r] of Object.entries({
  'generatedAt zero': fm((c) => (c.generatedAt = 0)), 'generatedAt null': fm((c) => (c.generatedAt = null)), 'generatedAt huge': fm((c) => (c.generatedAt = 8.64e15 + 1)), 'generatedAt max': fm((c) => (c.generatedAt = 8.64e15)),
  'generatedAt fraction': fm((c) => (c.generatedAt = 1.9)), 'generatedAt negative': fm((c) => (c.generatedAt = -1)), 'generatedAt y10000': fm((c) => (c.generatedAt = 253402300800000)), 'generatedAt y-1': fm((c) => (c.generatedAt = -62198755200000)),
  'generatedAt bool': fm((c) => (c.generatedAt = true)), 'generatedAt missing': fm((c) => delete c.generatedAt), 'pass false': fm((c) => (c.pass = false)), 'pass zero': fm((c) => (c.pass = 0)), 'pass missing': fm((c) => delete c.pass),
  'no summary': fm((c) => delete c.summary), 'summary empty': fm((c) => (c.summary = {})), 'no controls': fm((c) => delete c.controls), 'controls object': fm((c) => (c.controls = {})), 'controls empty': fm((c) => (c.controls = [])),
  'control null': fm((c) => (c.controls = [null])), 'control empty': fm((c) => (c.controls = [{}])), 'control status upper': fm((c) => (c.controls[0].status = 'fail')), 'control status number': fm((c) => (c.controls[0].status = 5)),
  'control strings': fm((c) => (c.controls[0].name = 'a|b\nc')), 'framework number': fm((c) => (c.framework = 5)), 'report null': null, 'report empty': {},
}) as [string, any][]) await o.run('frameworkReportToMarkdown', `hostile ${n}`, M.frameworkReportToMarkdown, [r]);

refWrite(o, 'compliance');
