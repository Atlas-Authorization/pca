// Oracle: validateReputationInput + the fail-closed edges of reputation() (packages/pca/src/reputation.ts). The scoring, priceCoverage and the signed
// coverage quote are already in ref-core-sweep-java (which every lane gets), disputesFromSettlements in ref-core-research-java; this fills the validator.
// Writes out/ref-reputation.json.gz. No keys, no clock. The 100000-record cap is in `constants`; a corpus of 100001 records would be megabytes, so lanes test the cap with a generated array.
//   validateReputationInput [input] -> string | null     reputation [input] -> Reputation (invalid input = score 0 with factors ["invalid input: <reason>"]; reasons compared exactly)
//   constants [] -> {MAX_REPUTATION_RECORDS, COVERAGE_QUOTE_DOMAIN} (the domain ends in a NUL byte)
import { Oracle, refWrite } from './lib.mjs';
import { adder } from './foundation.mjs';
const R: any = await import('../../../packages/pca/src/reputation.ts');
const o = new Oracle('reputation', 'tools/pca-audit/oracles/reputation.mts', 'TS-reference oracle for packages/pca/src/reputation.ts (validator and fail-closed edges).');
const REF: Record<string, (...a: any[]) => any> = {
  validateReputationInput: (i) => R.validateReputationInput(i), reputation: (i) => R.reputation(i),
  constants: () => ({ MAX_REPUTATION_RECORDS: R.MAX_REPUTATION_RECORDS, COVERAGE_QUOTE_DOMAIN: R.COVERAGE_QUOTE_DOMAIN }),
};
const add = adder(o, REF);
const ev = (outcome: any) => ({ agent: 'a', outcome });
const dp = (over: any = {}) => ({ id: 'd1', subject: 's', slashed: true, at: 5, ...over });
const cases: [string, any][] = [
  ['ok-empty', { subject: 's' }], ['ok-events', { subject: 's', events: [ev('auto'), ev('step_up'), ev('deny'), ev('executed')] }], ['ok-disputes', { subject: 's', disputes: [dp(), dp({ id: 'd2', slashed: false, amount: 3 })] }],
  ['subject-empty', { subject: '' }], ['subject-missing', {}], ['subject-num', { subject: 5 }], ['subject-null', { subject: null }], ['input-null', null], ['input-string', 'x'], ['input-array', []], ['input-number', 5],
  ['events-not-array', { subject: 's', events: 'x' }], ['disputes-not-array', { subject: 's', disputes: {} }], ['events-null', { subject: 's', events: null }], ['disputes-null', { subject: 's', disputes: null }],
  ['event-unknown-outcome', { subject: 's', events: [ev('maybe')] }], ['event-null', { subject: 's', events: [null] }], ['event-no-outcome', { subject: 's', events: [{ agent: 'a' }] }], ['event-num', { subject: 's', events: [5] }],
  ['dispute-no-id', { subject: 's', disputes: [dp({ id: '' })] }], ['dispute-id-num', { subject: 's', disputes: [dp({ id: 5 })] }], ['dispute-null', { subject: 's', disputes: [null] }],
  ['dispute-other-subject', { subject: 's', disputes: [dp({ subject: 't' })] }], ['dispute-slashed-str', { subject: 's', disputes: [dp({ slashed: 'true' })] }], ['dispute-slashed-missing', { subject: 's', disputes: [{ id: 'd', subject: 's', at: 1 }] }],
  ['dispute-at-neg', { subject: 's', disputes: [dp({ at: -1 })] }], ['dispute-at-nan', { subject: 's', disputes: [dp({ at: { $num: 'NaN' } })] }], ['dispute-at-inf', { subject: 's', disputes: [dp({ at: { $num: 'Infinity' } })] }], ['dispute-at-zero', { subject: 's', disputes: [dp({ at: 0 })] }],
  ['dispute-at-str', { subject: 's', disputes: [dp({ at: '5' })] }], ['dispute-at-missing', { subject: 's', disputes: [{ id: 'd', subject: 's', slashed: true }] }],
  ['dispute-amount-neg', { subject: 's', disputes: [dp({ amount: -1 })] }], ['dispute-amount-nan', { subject: 's', disputes: [dp({ amount: { $num: 'NaN' } })] }], ['dispute-amount-zero', { subject: 's', disputes: [dp({ amount: 0 })] }], ['dispute-amount-str', { subject: 's', disputes: [dp({ amount: '1' })] }], ['dispute-amount-null', { subject: 's', disputes: [dp({ amount: null })] }],
  ['dispute-dup-ids-ok', { subject: 's', disputes: [dp(), dp()] }], ['second-dispute-bad', { subject: 's', disputes: [dp(), dp({ id: 'd2', at: -1 })] }],
];
for (const [n, c] of cases) { await add('validateReputationInput', n, [c]); await add('reputation', n, [c]); }
for (const [n, c] of [['dedupe-slash', { subject: 's', disputes: [dp(), dp(), dp({ id: 'd2' })] }], ['mixed', { subject: 's', events: [ev('auto'), ev('deny'), ev('step_up'), ev('executed')], disputes: [dp({ slashed: false })] }], ['only-disputes-clean', { subject: 's', disputes: [dp({ slashed: false })] }],
  ['slash-saturate', { subject: 's', disputes: [1, 2, 3, 4].map((i) => dp({ id: 'x' + i })) }], ['all-deny', { subject: 's', events: [ev('deny'), ev('deny')] }], ['score-floor', { subject: 's', events: [ev('deny')], disputes: [1, 2, 3, 4].map((i) => dp({ id: 'y' + i })) }],
  ['rate-rounding', { subject: 's', events: [ev('deny'), ev('auto'), ev('auto')] }], ['rate-round-half', { subject: 's', events: [ev('step_up'), ev('auto'), ev('auto'), ev('auto'), ev('auto'), ev('auto'), ev('auto'), ev('auto')] }]] as any) await add('reputation', n, [c]);
await add('constants', 'all', []);
refWrite(o, 'reputation');
