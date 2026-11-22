// conformance/decision-vectors.json: the ternary decision, rules 20 (units) and 21 (tighten-only) and the escalation wire.
//
// ONE generator owns the whole file. Every `expect` is computed by the TypeScript reference (decision.ts / escalation.ts), so a
// native can never drift from it unnoticed; the Go, Rust and Python verifiers replay the same file (sdks/*: decision / escalation
// conformance tests) and must reproduce each expectation exactly, REASON TEXT INCLUDED.
//
//   primitives.intent_units        decideUnits   {ok, reason?}
//   primitives.intent_tighten      decideTighten {outcome, legacy, offending, reason?}
//   primitives.decision_of         decisionOf over {allow, checks, reasons} (one failing check, several, mixed deny / escalate)
//   primitives.decision_lattice    meet / pepDecision / tighten (hand-written inputs, kept as committed)
//   primitives.escalation_fold     foldV2Reasons + decisionOf: the ordered reason list and the decision of a verdict whose
//                                  intent-v2 pipeline reported several failing checks of mixed deny / escalate classes
//   primitives.escalation_truncate request reasons cut at 512 UTF-16 units, wire text of the result (a lone surrogate as \udXXX)
//   primitives.escalation_answer   verifyEscalationAnswer under EVERY suite of the registry (ed25519, ML-DSA, SLH-DSA, FN-DSA,
//                                  the hybrids), the pin rules, the wire shape. `requires_suite` names the suite a verifier must
//                                  implement to reproduce an `ok` entry; a verifier without it must answer `unsupported_suite`.
// Deterministic: fixed seeds; Ed25519, ML-DSA, SLH-DSA and FN-DSA signing are deterministic here.
//
//     node packages/pca/scripts/gen-conformance-decision.mjs [--check]                 (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-decision.mjs  (reads ../src)
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, serializeCorpus } from './conformance-io.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');
const art = process.env.PCA_SRC ? await import('../src/intent-artifacts.ts') : await import('../dist/intent-artifacts.js');
const OUT = join(confDir, 'decision-vectors.json');
const prev = JSON.parse(readFileSync(OUT, 'utf8'));
const keys = JSON.parse(readFileSync(join(confDir, 'keys.json'), 'utf8'));

const rep = (s, n) => s.repeat(n);
const NOW = 1_800_000_000_000;

// ------------------------------------------------------------------------------------------------ units / tighten
const SCHEMA_UNITS = {
  usd_minor: { kind: 'money', currency: 'USD', exponent: 2 },
  usd_major: { kind: 'money', currency: 'USD', exponent: 0 },
  eur_minor: { kind: 'money', currency: 'EUR', exponent: 2 },
};
const VERB_PARAMS = { 'action.params.amount': { unit: 'usd_minor' }, 'action.params.note': {} };
const AMOUNT = 'action.params.amount';
const usd2 = { kind: 'money', currency: 'USD', exponent: 2 };
const unitsIn = (o) => ({ units: { [AMOUNT]: usd2 }, schema_units: SCHEMA_UNITS, verb_params: VERB_PARAMS, verb: 'refund', ...o });
const withoutKey = (o, k) => Object.fromEntries(Object.entries(o).filter(([x]) => x !== k));
const termOf = (field, verb = 'refund') => [[{ verb, where: [{ field, op: 'lte', value: 100 }] }]];

const unitsNew = [
  ['u20-units-null', 'units: null is not an object', unitsIn({ units: null })],
  ['u20-units-absent', 'units absent is not an object either', withoutKey(unitsIn({}), 'units')],
  ['u20-units-array', 'units: []', unitsIn({ units: [] })],
  ['u20-units-string', 'units: a string', unitsIn({ units: 'usd' })],
  ['u20-units-empty', 'units: {} tags nothing and verifies', unitsIn({ units: {} })],
  ['u20-tag-null', 'a tag that is null', unitsIn({ units: { [AMOUNT]: null } })],
  ['u20-tag-array', 'a tag that is an array', unitsIn({ units: { [AMOUNT]: [] } })],
  ['u20-tag-empty', 'a tag without a kind', unitsIn({ units: { [AMOUNT]: {} } })],
  ['u20-kind-number', 'kind must be a string', unitsIn({ units: { [AMOUNT]: { kind: 5 } } })],
  ['u20-kind-null', 'kind: null', unitsIn({ units: { [AMOUNT]: { kind: null } } })],
  ['u20-kind-empty', 'kind: ""', unitsIn({ units: { [AMOUNT]: { kind: '' } } })],
  ['u20-kind-64', 'a 64 character kind is accepted (then compared)', unitsIn({ units: { [AMOUNT]: { kind: rep('k', 64) } } })],
  ['u20-kind-65', 'a 65 character kind is refused', unitsIn({ units: { [AMOUNT]: { kind: rep('k', 65) } } })],
  ['u20-kind-utf16-64', '32 astral characters are 64 UTF-16 units: accepted (length is counted in UTF-16 units)', unitsIn({ units: { [AMOUNT]: { kind: rep('\u{1F600}', 32) } } })],
  ['u20-kind-utf16-66', '33 astral characters are 66 UTF-16 units: refused', unitsIn({ units: { [AMOUNT]: { kind: rep('\u{1F600}', 33) } } })],
  ['u20-currency-null', 'currency: null', unitsIn({ units: { [AMOUNT]: { kind: 'money', currency: null } } })],
  ['u20-currency-empty', 'currency: ""', unitsIn({ units: { [AMOUNT]: { kind: 'money', currency: '' } } })],
  ['u20-currency-16', 'a 16 character currency is accepted (then compared)', unitsIn({ units: { [AMOUNT]: { kind: 'money', currency: rep('c', 16) } } })],
  ['u20-currency-17', 'a 17 character currency is refused', unitsIn({ units: { [AMOUNT]: { kind: 'money', currency: rep('c', 17) } } })],
  ['u20-currency-utf16-18', '9 astral characters are 18 UTF-16 units: refused', unitsIn({ units: { [AMOUNT]: { kind: 'money', currency: rep('\u{1F600}', 9) } } })],
  ['u20-exponent-neg', 'exponent -1', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: -1 } } })],
  ['u20-exponent-19', 'exponent 19', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: 19 } } })],
  ['u20-exponent-18', 'exponent 18 is the largest accepted (then compared)', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: 18 } } })],
  ['u20-exponent-fraction', 'exponent 1.5', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: 1.5 } } })],
  ['u20-exponent-string', 'exponent "2"', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: '2' } } })],
  ['u20-exponent-null', 'exponent: null', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: null } } })],
  ['u20-exponent-bool', 'exponent: true', unitsIn({ units: { [AMOUNT]: { kind: 'money', exponent: true } } })],
  ['u20-key-newline', 'a key with a trailing newline is not a parameter path', unitsIn({ units: { [`${AMOUNT}\n`]: usd2 } })],
  ['u20-key-long', 'a 65 character parameter name', unitsIn({ units: { [`action.params.${rep('a', 65)}`]: usd2 } })],
  ['u20-key-nested', 'a nested path is not a parameter path', unitsIn({ units: { 'action.params.a.b': usd2 } })],
  ['u20-65-entries', 'more than 64 tags', unitsIn({ units: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`action.params.p${i}`, usd2])) })],
  ['u20-verb-null', 'the verb is null', unitsIn({ verb: null })],
  ['u20-verb-empty', 'the verb is empty', unitsIn({ verb: '' })],
  ['u20-verb-number', 'the verb is a number', unitsIn({ verb: 5 })],
  ['u20-schema-units-null', 'schema_units: null is an empty table (the tagged param then has no unit)', unitsIn({ schema_units: null })],
  ['u20-schema-units-array', 'schema_units: []', unitsIn({ schema_units: [] })],
  ['u20-schema-units-string', 'schema_units: a string', unitsIn({ schema_units: 'x' })],
  ['u20-verb-params-null', 'verb_params: null', unitsIn({ verb_params: null })],
  ['u20-verb-params-array', 'verb_params: []', unitsIn({ verb_params: [] })],
  ['u20-verb-params-absent', 'verb_params absent', withoutKey(unitsIn({}), 'verb_params')],
  ['u20-param-decl-null', 'the param declaration is null: undeclared, the tag is ignored', unitsIn({ verb_params: { [AMOUNT]: null } })],
  ['u20-unit-not-string', 'unit: 5 is no unit (a schema entry named "" does not match it)', unitsIn({ verb_params: { [AMOUNT]: { unit: 5 } }, schema_units: { ...SCHEMA_UNITS, '': usd2 } })],
  ['u20-unit-empty-id', 'unit: "" names the table entry "" (a string id)', unitsIn({ verb_params: { [AMOUNT]: { unit: '' } }, schema_units: { '': usd2 } })],
  ['u20-unit-proto', 'a unit id that is an inherited member name has no tag', unitsIn({ verb_params: { [AMOUNT]: { unit: 'toString' } } })],
  ['u20-tag-in-schema-not-object', 'the schema tag is not an object', unitsIn({ schema_units: { usd_minor: 5 } })],
  ['u20-first-sorted', 'two confused tags: the first by key order is reported', unitsIn({ units: { 'action.params.zeta': usd2, [AMOUNT]: { kind: 'money', currency: 'USD', exponent: 0 } }, verb_params: { ...VERB_PARAMS, 'action.params.zeta': { unit: 'usd_major' } } })],
  ['u20-tag-no-exponent', 'the policy tag omits the exponent the schema declares', unitsIn({ units: { [AMOUNT]: { kind: 'money', currency: 'USD' } } })],
  ['u20-term-array-verb', 'a term scoped by a verb list', unitsIn({ units: {}, predicates: termOf(AMOUNT, ['x', 'refund']) })],
  ['u20-term-other-verb-list', 'a term scoped by a verb list without this verb', unitsIn({ units: {}, predicates: termOf(AMOUNT, ['x', 'y']) })],
  ['u20-term-collection', 'a term that names the param as a collection', unitsIn({ units: {}, predicates: [[{ verb: '*', where: [{ any_of: [{ collection: AMOUNT, op: 'contains', value: 1 }] }] }]] })],
  ['u20-term-not-array-list', 'a predicate list that is not an array is skipped', unitsIn({ units: {}, predicates: ['x', null, { verb: '*' }] })],
  ['u20-term-undeclared-path', 'a term reading a param the verb does not declare', unitsIn({ units: {}, predicates: termOf('action.params.other') })],
  ['u20-term-note-no-unit', 'a term reading a declared param without a unit', unitsIn({ units: {}, predicates: termOf('action.params.note') })],
];

const tightenCtx = { action: { verb: 'v', resource: 'r', params: { amount: 80 } }, env: { class: { tone: 'hostile' } } };
const big = { id: 'big', when: { field: 'action.params.amount', op: 'gt', value: 50 }, signal: 'escalate' };
const hostile = { id: 'h', when: { field: 'env.class.tone', op: 'eq', value: 'hostile' }, signal: 'deny' };
const onlyTighten = (t) => ({ tighten: t, context: tightenCtx });
const ruleWith = (o) => onlyTighten([{ ...big, ...o }]);
const tightenNew = [
  ['t21-tighten-null', 'tighten: null is malformed (never read as absent)', { tighten: null }],
  ['t21-tighten-empty', 'tighten: [] adds no friction', { tighten: [] }],
  ['t21-tighten-string', 'tighten: a string', { tighten: 'x' }],
  ['t21-tighten-number', 'tighten: 5', { tighten: 5 }],
  ['t21-tighten-object', 'tighten: {}', { tighten: {} }],
  ['t21-tighten-bool', 'tighten: false', { tighten: false }],
  ['t21-rule-null', 'a rule that is null', { tighten: [null] }],
  ['t21-rule-array', 'a rule that is an array', { tighten: [[]] }],
  ['t21-rule-empty', 'a rule without members', { tighten: [{}] }],
  ['t21-rule-missing-when', 'a rule without when', { tighten: [{ id: 'a', signal: 'deny' }] }],
  ['t21-rule-id-number', 'id: 5', ruleWith({ id: 5 })],
  ['t21-rule-id-upper', 'id: "Big"', ruleWith({ id: 'Big' })],
  ['t21-rule-id-newline', 'id with a trailing newline', ruleWith({ id: 'big\n' })],
  ['t21-rule-id-64', 'a 64 character id', ruleWith({ id: `a${rep('b', 63)}` })],
  ['t21-rule-id-65', 'a 65 character id', ruleWith({ id: `a${rep('b', 64)}` })],
  ['t21-rule-when-null', 'when: null', ruleWith({ when: null })],
  ['t21-rule-when-array', 'when: []', ruleWith({ when: [] })],
  ['t21-rule-when-string', 'when: a string', ruleWith({ when: 'x' })],
  ['t21-rule-signal-ok', 'signal: "ok" is not a rule signal', ruleWith({ signal: 'ok' })],
  ['t21-rule-signal-null', 'signal: null', ruleWith({ signal: null })],
  ['t21-rule-reason-256', 'a 256 character reason', ruleWith({ reason: rep('r', 256) })],
  ['t21-rule-reason-257', 'a 257 character reason', ruleWith({ reason: rep('r', 257) })],
  ['t21-rule-reason-utf16', '129 astral characters are 258 UTF-16 units', ruleWith({ reason: rep('\u{1F600}', 129) })],
  ['t21-rule-reason-number', 'reason: 5', ruleWith({ reason: 5 })],
  ['t21-rule-reason-null', 'reason: null', ruleWith({ reason: null })],
  ['t21-rule-reason-shown', 'a firing rule reports its reason', ruleWith({ reason: 'large refund' })],
  ['t21-rule-deny-text', 'a firing deny rule', onlyTighten([hostile])],
  ['t21-rule-order', 'the first rule that lowers the outcome names the reason; a later rule at the same level does not replace it', onlyTighten([big, { ...big, id: 'big2' }, hostile, { ...hostile, id: 'h2' }])],
  ['t21-rule-escalate-after-deny', 'an escalate rule after a deny rule does not raise the outcome', onlyTighten([hostile, big])],
  ['t21-rule-unknown-text', 'an undecidable rule', onlyTighten([{ id: 'm', when: { field: 'env.class.missing', op: 'eq', value: 'x' }, signal: 'deny' }])],
  ['t21-65-rules', 'more than 64 rules', { tighten: Array.from({ length: 65 }, (_, i) => ({ ...big, id: `r${i}` })) }],
  ['t21-64-rules', 'exactly 64 rules', { tighten: Array.from({ length: 64 }, (_, i) => ({ ...big, id: `r${i}` })), context: tightenCtx }],
  ['t21-polarity-null', 'model_polarity: null is not "legacy"', { polarity: null }],
  ['t21-polarity-strict', 'model_polarity: "strict" is not "legacy"', { polarity: 'strict' }],
  ['t21-polarity-number', 'model_polarity: 5', { polarity: 5 }],
  ['t21-polarity-legacy-clean', 'legacy with nothing model-derived is not degraded', { polarity: 'legacy' }],
  ['t21-single-source-not-array', 'single_source that is not an array is ignored', { single_source: 'risk', predicates: [[{ verb: '*', where: [{ field: 'env.world.risk', op: 'eq', value: 'x' }] }]] }],
  ['t21-single-source-mixed', 'non-string single_source entries are dropped', { single_source: [5, 'risk', null], predicates: [[{ verb: '*', where: [{ field: 'env.world.risk', op: 'eq', value: 'x' }] }]] }],
  ['t21-world-bare-single', 'env.world itself is model-derived when any world is single-source', { single_source: ['risk'], predicates: [[{ verb: '*', where: [{ field: 'env.world', op: 'eq', value: 'x' }] }]] }],
  ['t21-world-bare-multi', 'env.world with no single-source world is not model-derived', { predicates: [[{ verb: '*', where: [{ field: 'env.world', op: 'eq', value: 'x' }] }]] }],
  ['t21-offending-sorted', 'offending paths are sorted by UTF-8 bytes and listed once', { predicates: [[{ verb: '*', where: [{ field: 'env.judge.b', op: 'eq', value: 1 }, { field: 'env.class.z', op: 'eq', value: 1 }, { field: 'env.class.a', op: 'eq', value: 1 }, { field: 'env.judge.b', op: 'eq', value: 2 }] }]] }],
  ['t21-offending-utf8-order', 'UTF-8 byte order, not UTF-16: U+FF5E sorts before U+1F600', { predicates: [[{ verb: '*', where: [{ field: 'env.class.\u{1F600}', op: 'eq', value: 1 }, { field: 'env.class.～', op: 'eq', value: 1 }] }]] }],
  ['t21-offending-deep', 'a path under all_of / any_of / not is found', { predicates: [[{ verb: '*', where: [{ all_of: [{ any_of: [{ not: { field: 'env.prov.src', op: 'eq', value: 1 } }] }] }] }]] }],
  ['t21-offending-depth-65', 'a path nested deeper than 64 levels is not read', { predicates: [[{ verb: '*', where: [deepNot(65)] }]] }],
  ['t21-offending-depth-64', 'a path nested 64 levels deep is read', { predicates: [[{ verb: '*', where: [deepNot(64)] }]] }],
  ['t21-predicates-not-array', 'predicates that are not a list read nothing', { predicates: 'x' }],
  ['t21-predicate-lists-skipped', 'a list that is not an array, a predicate without where', { predicates: ['x', null, [null, 5, { verb: '*' }, { verb: '*', where: 'x' }]] }],
  ['t21-context-not-object', 'a context that is not an object is empty: the rule is undecidable (escalate)', { tighten: [big], context: 'x' }],
  ['t21-context-array', 'a context that is an array is empty', { tighten: [big], context: [] }],
  ['t21-legacy-with-rule', 'legacy: offending paths are reported, the rules still run', { polarity: 'legacy', tighten: [hostile], context: tightenCtx, predicates: [[{ verb: '*', where: [{ field: 'env.class.tone', op: 'eq', value: 'x' }] }]] }],
];
function deepNot(n) {
  let c = { field: 'env.class.deep', op: 'eq', value: 1 };
  for (let i = 0; i < n; i++) c = { not: c };
  return c;
}

function regen(section, fresh, evalFn) {
  const names = new Set(fresh.map(([n]) => n));
  const out = [];
  // the hand-written entries keep their inputs (their expectations are recomputed); an entry this generator owns is rebuilt
  for (const e of prev.primitives[section]) if (!names.has(e.name) && e.input_text === undefined) out.push({ name: e.name, description: e.description, input: e.input, expect: evalFn(e.input) });
  for (const [name, description, input] of fresh) out.push({ name, description, input, expect: evalFn(input) });
  return out;
}
const unitsExpect = (i) => {
  const r = pca.decideUnits(i);
  return r.ok ? { ok: true } : { ok: false, reason: r.reason };
};
const tightenExpect = (i) => {
  const r = pca.decideTighten(i);
  return { outcome: r.outcome, legacy: r.legacy, offending: r.offending, ...(r.reason !== undefined ? { reason: r.reason } : {}) };
};

// ---- insertion order of simultaneous violations: `input_text` is parsed by each runner's own JSON parser (JSON.parse puts
// integer-like keys first, ascending, then the rest in text order; a runner that sorts keys reports another member)
const orderUnits = [
  ['u20-order-two-bad-keys', 'two bad units keys: the first in text order is reported, not the smallest', '{"units":{"zz_bad":{"kind":"m"},"aa_bad":{"kind":"m"}},"verb":"refund"}'],
  ['u20-order-int-key-first', 'an integer-like key is visited before the others whatever its position in the text', '{"units":{"abc":{"kind":"m"},"7":{"kind":"m"}},"verb":"refund"}'],
  ['u20-order-int-keys-numeric', 'integer-like keys ascend numerically ("10" after "9")', '{"units":{"10":{"kind":"m"},"9":{"kind":"m"}},"verb":"refund"}'],
  ['u20-order-tag-unknown-members', 'two unknown members of one tag: the first in text order', '{"units":{"action.params.amount":{"kind":"money","zz":1,"aa":2}},"verb":"refund"}'],
  ['u20-order-tag-missing-then-unknown', 'an unknown member is reported before a missing one', '{"units":{"action.params.amount":{"zz":1}},"verb":"refund"}'],
  ['u20-order-two-bad-tags', 'two tags that are not objects: the first key in text order', '{"units":{"action.params.z":5,"action.params.a":5},"verb":"refund"}'],
];
const orderTighten = [
  ['t21-order-rule-unknown-members', 'two unknown members of one rule: the first in text order', '{"tighten":[{"id":"a","when":{"field":"action.params.amount","op":"gt","value":1},"signal":"deny","zz":1,"aa":2}]}'],
  ['t21-order-rule-int-key', 'an integer-like unknown member is reported first', '{"tighten":[{"id":"a","when":{"field":"action.params.amount","op":"gt","value":1},"signal":"deny","abc":1,"3":2}]}'],
  ['t21-order-second-rule-first', 'rules are an array: the first malformed rule is reported', '{"tighten":[{"id":"a","when":{},"signal":"deny"},{"id":"b","when":{},"signal":"deny","zz":1}]}'],
];
const regenJson = (list, evalFn) => list.map(([name, description, text]) => ({ name, description, input_text: text, expect: evalFn(JSON.parse(text)) }));

// ---- pepDecision returns anything but an answered escalate UNCHANGED (even a string that is no decision); `answered` must be the
// boolean true
const pepNew = [
  ['pep-unknown-unchanged', 'a string that is no decision is returned as is', { decision: 'weird', answered: true }],
  ['pep-empty-unchanged', 'the empty string too', { decision: '', answered: true }],
  ['pep-case-sensitive', "'Escalate' is not 'escalate'", { decision: 'Escalate', answered: true }],
  ['pep-allow-answered', 'allow stays allow', { decision: 'allow', answered: true }],
  ['pep-deny-answered', 'an answer never upgrades deny', { decision: 'deny', answered: true }],
  ['pep-escalate-answered-string', "answered must be the boolean true: 'true' is not", { decision: 'escalate', answered: 'true' }],
  ['pep-escalate-answered-one', 'answered: 1 is not true', { decision: 'escalate', answered: 1 }],
  ['pep-escalate-answered-null', 'answered: null is not true', { decision: 'escalate', answered: null }],
  ['pep-escalate-answered-absent', 'answered absent is not true', { decision: 'escalate' }],
];

// ---- integer-valued numbers spelled 2.0 / 1e3 are the integers 2 / 1000 (JavaScript has one number type)
const floatUnits = [
  ['u20-float-exponent-match', 'exponent 2.0 is the integer 2: it matches the schema unit', '{"units":{"action.params.amount":{"kind":"money","currency":"USD","exponent":2.0}},"schema_units":{"usd_minor":{"kind":"money","currency":"USD","exponent":2}},"verb_params":{"action.params.amount":{"unit":"usd_minor"}},"verb":"refund"}'],
  ['u20-float-exponent-exp-form', 'exponent 2e0 likewise', '{"units":{"action.params.amount":{"kind":"money","currency":"USD","exponent":2e0}},"schema_units":{"usd_minor":{"kind":"money","currency":"USD","exponent":2}},"verb_params":{"action.params.amount":{"unit":"usd_minor"}},"verb":"refund"}'],
  ['u20-float-exponent-mismatch', 'a mismatch prints the exponent as the integer it is', '{"units":{"action.params.amount":{"kind":"money","currency":"USD","exponent":2.0}},"schema_units":{"usd_major":{"kind":"money","currency":"USD","exponent":0.0}},"verb_params":{"action.params.amount":{"unit":"usd_major"}},"verb":"refund"}'],
  ['u20-float-exponent-18', 'exponent 18.0 is the largest accepted', '{"units":{"action.params.amount":{"kind":"money","exponent":18.0}},"verb":"refund"}'],
  ['u20-float-exponent-19', 'exponent 19.0 is refused', '{"units":{"action.params.amount":{"kind":"money","exponent":19.0}},"verb":"refund"}'],
  ['u20-float-exponent-fraction', 'exponent 2.5 stays a fraction', '{"units":{"action.params.amount":{"kind":"money","exponent":2.5}},"verb":"refund"}'],
];

// ---- reason truncation (escalation.ts: `String(r).slice(0, 512)` in UTF-16 units, at most 16 reasons). A cut inside a surrogate
// pair keeps the LONE high surrogate; `wire` is JSON.stringify of the request's reasons (a lone surrogate is `\udXXX`).
const A = (n) => 'a'.repeat(n);
const truncCases = [
  ['tr-ascii-512', 'exactly 512 units: unchanged', [A(512)]],
  ['tr-ascii-513', '513 units: cut to 512', [A(513)]],
  ['tr-astral-split', 'the cut falls inside a surrogate pair: a lone high surrogate is kept', [`${A(511)}\u{1F600}tail`]],
  ['tr-astral-split-other', 'another high surrogate (U+1D4B3 = D835 DCB3)', [`${A(511)}\u{1D4B3}tail`]],
  ['tr-astral-fits', 'the pair ends exactly at 512: kept whole', [`${A(510)}\u{1F600}x`]],
  ['tr-astral-after', 'the pair starts at 512: dropped whole', [`${A(512)}\u{1F600}`]],
  ['tr-all-astral', '300 astral characters: 256 kept (512 units), no split', ['\u{1F600}'.repeat(300)]],
  ['tr-short', 'a short reason is untouched', ['facts: intent_required: q']],
  ['tr-escapes', 'JSON.stringify escaping: quote, backslash, controls, DEL, U+2028 (raw)', ['q"\\\n\r\t\b\f\u0001\u001f\u007f\u2028 é€']],
  ['tr-cap-16', 'at most 16 reasons are kept', Array.from({ length: 17 }, (_, i) => `r${i}`)],
  ['tr-mixed', 'each reason is cut on its own', [A(600), `${A(511)}\u{1F600}`, 'short']],
];
const truncExpect = (reasons) => {
  const r = pca.buildEscalationRequest({ aud: 'a', grant: { id: 'g' }, pcactn: { action: { verb: 'v', resource: 'r' } }, lastCounter: undefined, reasons, now: 1 });
  return { wire: JSON.stringify(r.reasons) };
};

// ------------------------------------------------------------------------------------------------ decision_of / fold
const E = 'intent_required: a question';
const decisionNew = [
  ['d-multi-escalate', 'several failing checks, every one escalate-class: escalate', { allow: false, checks: { facts: 'fail', provenance: 'fail', classes: 'fail' }, reasons: ['facts: intent_required: q1', 'provenance: intent_required: q2', 'classes: escalate: ask'] }],
  ['d-multi-one-hard', 'several failing checks, one hard: deny', { allow: false, checks: { facts: 'fail', provenance: 'fail', classes: 'fail' }, reasons: ['facts: intent_required: q1', 'provenance: unsigned fact', 'classes: intent_required: q3'] }],
  ['d-multi-hard-listed-first', 'a hard failure listed before the escalate ones', { allow: false, checks: { policy: 'fail', facts: 'fail' }, reasons: ['policy: no predicate permits', 'facts: intent_required: q'] }],
  ['d-two-reasons-one-check', 'one check, two reasons, both escalate-class', { allow: false, checks: { facts: 'fail' }, reasons: ['facts: intent_required: q1', 'facts: escalate: q2'] }],
  ['d-two-reasons-one-hard', 'one check, two reasons, one hard: deny', { allow: false, checks: { facts: 'fail' }, reasons: ['facts: intent_required: q1', 'facts: bad signature'] }],
  ['d-multi-one-unexplained', 'an escalate-class check plus a failing check with no reason of its own: deny', { allow: false, checks: { facts: 'fail', replay: 'fail' }, reasons: ['facts: intent_required: q'] }],
  ['d-pass-and-escalate', 'passing checks around one escalating check', { allow: false, checks: { wire: 'pass', facts: 'fail', policy: 'pass', replay: 'not-enforced' }, reasons: ['facts: intent_required: q'] }],
  ['d-prefix-case', 'the prefix is matched exactly (case sensitive)', { allow: false, checks: { facts: 'fail' }, reasons: ['facts: Intent_required: q'] }],
  ['d-prefix-no-space', 'the check head needs ": " after the name', { allow: false, checks: { facts: 'fail' }, reasons: ['facts:intent_required: q'] }],
  ['d-prefix-name-overlap', 'a reason of another check whose name starts with this one is not this check\'s reason', { allow: false, checks: { fact: 'fail' }, reasons: ['facts: intent_required: q'] }],
  ['d-escalate-body-only-prefix', 'the body is exactly the prefix', { allow: false, checks: { facts: 'fail' }, reasons: ['facts: escalate:'] }],
  ['d-non-string-reason', 'a non-string reason is not any check\'s reason', { allow: false, checks: { facts: 'fail' }, reasons: [5, null, 'facts: intent_required: q'] }],
  ['d-allow-true-wins', 'allow: true is allow whatever the checks say', { allow: true, checks: { facts: 'fail' }, reasons: [] }],
  ['d-allow-string', 'allow must be the boolean true', { allow: 'true', checks: { facts: 'fail' }, reasons: ['facts: intent_required: q'] }],
  ['d-unsupported-not-failing', 'an unsupported check is not a failing check', { allow: false, checks: { facts: 'unsupported' }, reasons: ['facts: intent_required: q'] }],
];

const foldNew = [
  // [name, description, core reasons, v2 checks (ordered), all checks]
  ['f-single-escalate', 'one failing v2 check: its reason is listed after the core reason', [], [{ name: 'facts', ok: false, reason: E }], { wire: 'pass', facts: 'fail' }],
  ['f-core-first', 'the core reason stays first', ['leaf_signature: bad'], [{ name: 'facts', ok: false, reason: E }], { leaf_signature: 'fail', facts: 'fail' }],
  ['f-core-is-v2', 'the core reason is already the first v2 failure: listed once', [`facts: ${E}`], [{ name: 'facts', ok: false, reason: E }, { name: 'provenance', ok: false, reason: 'escalate: q2' }], { facts: 'fail', provenance: 'fail' }],
  ['f-all-escalate', 'three failing v2 checks, all escalate-class: all reasons in pipeline order, decision escalate', [`schema: ${E}`], [{ name: 'schema', ok: false, reason: E }, { name: 'facts', ok: false, reason: 'intent_required: q2' }, { name: 'classes', ok: false, reason: 'escalate: q3' }], { schema: 'fail', facts: 'fail', classes: 'fail' }],
  ['f-mixed-deny-last', 'escalate, escalate, then a hard v2 failure: deny', [`facts: ${E}`], [{ name: 'facts', ok: false, reason: E }, { name: 'provenance', ok: false, reason: 'intent_required: q2' }, { name: 'classes', ok: false, reason: 'class receipt does not verify' }], { facts: 'fail', provenance: 'fail', classes: 'fail' }],
  ['f-mixed-deny-first', 'a hard v2 failure, then escalate ones: deny', ['facts: unsigned fact'], [{ name: 'facts', ok: false, reason: 'unsigned fact' }, { name: 'provenance', ok: false, reason: 'intent_required: q2' }, { name: 'classes', ok: false, reason: 'intent_required: q3' }], { facts: 'fail', provenance: 'fail', classes: 'fail' }],
  ['f-core-hard-v2-escalate', 'a hard core failure (no v2 involvement) plus an escalating v2 check: deny', ['chain: chain root is not the grant'], [{ name: 'facts', ok: false, reason: E }], { chain: 'fail', facts: 'fail' }],
  ['f-core-escalate-v2-hard', 'the core reason is an escalation, a later v2 check fails hard: deny', [`facts: ${E}`], [{ name: 'facts', ok: false, reason: E }, { name: 'classes', ok: false, reason: 'bad' }], { facts: 'fail', classes: 'fail' }],
  ['f-v2-passing-ignored', 'passing v2 checks add no reason', [`facts: ${E}`], [{ name: 'schema', ok: true }, { name: 'facts', ok: false, reason: E }, { name: 'classes', ok: true }], { schema: 'pass', facts: 'fail', classes: 'pass' }],
  ['f-no-reason-v2-fail', 'a failing v2 check with no reason adds nothing and (no reason of its own) denies', [`facts: ${E}`], [{ name: 'facts', ok: false, reason: E }, { name: 'classes', ok: false }], { facts: 'fail', classes: 'fail' }],
  ['f-empty-reason', 'an empty reason is a reason', [], [{ name: 'facts', ok: false, reason: '' }], { facts: 'fail' }],
  ['f-duplicate-v2', 'the same v2 reason twice is listed once', [], [{ name: 'facts', ok: false, reason: E }, { name: 'facts', ok: false, reason: E }], { facts: 'fail' }],
  ['f-two-reasons-one-check', 'a check with two different reasons lists both, in order', [], [{ name: 'facts', ok: false, reason: 'intent_required: q1' }, { name: 'facts', ok: false, reason: 'escalate: q2' }], { facts: 'fail' }],
  ['f-reason-text-only-prefix', 'a reason that merely contains the prefix is not an escalation', [], [{ name: 'facts', ok: false, reason: 'see intent_required: q' }], { facts: 'fail' }],
  ['f-units-tighten', 'rule 20 hard failure and a rule 21 escalation together: deny', [], [{ name: 'units', ok: false, reason: "'action.params.amount' is declared as money/USD/e2 by the action schema but the policy term is tagged no unit (unit confusion)" }, { name: 'tighten', ok: false, reason: "escalate: asked by tighten rule 'big'" }], { units: 'fail', tighten: 'fail' }],
  ['f-two-tighten-escalate', 'a tighten escalation and an escalating question: escalate', [], [{ name: 'facts', ok: false, reason: E }, { name: 'tighten', ok: false, reason: "escalate: asked by tighten rule 'big'" }], { facts: 'fail', tighten: 'fail' }],
  ['f-tighten-deny-rule', 'a deny tighten rule with an escalating question: deny', [], [{ name: 'facts', ok: false, reason: E }, { name: 'tighten', ok: false, reason: "denied by tighten rule 'h'" }], { facts: 'fail', tighten: 'fail' }],
  ['f-no-failure', 'nothing failed: no reasons, allow', [], [{ name: 'schema', ok: true }], { schema: 'pass' }],
];
const foldExpect = (i) => {
  const reasons = pca.foldV2Reasons(i.core_reasons, i.v2);
  const allow = !Object.values(i.checks).includes('fail');
  return { reasons, decision: pca.decisionOf({ allow, checks: i.checks, reasons }) };
};

// ------------------------------------------------------------------------------------------------ escalation answers
const dg = (c) => pca.b64u(new Uint8Array(32).fill(c.charCodeAt(0)));
const BIND = { policy_digest: dg('a'), action_digest: dg('b'), history_head: dg('c') };
const PUB = keys.principal.public;
const OTHER = keys.rogue.public;
const sk = pca.unb64u(keys.principal.seed);
const seedOf = (n, len = 32) => new Uint8Array(len).fill(n);
const fnKey = (gen, n) => ({ ...gen(seedOf(n)), signSeed: seedOf(n + 100) });
const bodyOf = (o = {}) => ({ v: 1, kind: 'pca-escalation-answer', principal: PUB, ...BIND, decision: 'allow', iat: NOW, expires_at: NOW + 1000, nonce: pca.b64u(new Uint8Array(16).fill(7)), ...o });
const answer = (o = {}, suite) => art.signArtifact(pca.ESCALATION_ANSWER_DOMAIN, bodyOf(o), sk, suite);

// every suite of the registry a verifier of this repository can sign here; the suite-name list is the registry itself
const SUITES = [
  { alg: 'ml-dsa-65', material: (n) => ({ mlDsa: pca.mlDsa65Keygen(seedOf(n)) }) },
  { alg: 'hybrid-ed25519-ml-dsa-65', material: (n) => ({ mlDsa: pca.mlDsa65Keygen(seedOf(n)) }) },
  { alg: 'hybrid-nested-ed25519-ml-dsa-65', material: (n) => ({ mlDsa: pca.mlDsa65Keygen(seedOf(n)) }) },
  { alg: 'ml-dsa-87', material: (n) => ({ mlDsa87: pca.mlDsa87Keygen(seedOf(n)) }) },
  { alg: 'hybrid-ed25519-ml-dsa-87', material: (n) => ({ mlDsa87: pca.mlDsa87Keygen(seedOf(n)) }) },
  { alg: 'slh-dsa-sha2-128f', light: true, material: (n) => ({ slhDsa: pca.slhDsa128fKeygen(seedOf(n, 48)) }) },
  { alg: 'hybrid-ed25519-slh-dsa-sha2-128f', light: true, material: (n) => ({ slhDsa: pca.slhDsa128fKeygen(seedOf(n, 48)) }) },
  { alg: 'slh-dsa-sha2-256s', minimal: true, material: (n) => ({ slhDsa256s: pca.slhDsa256sKeygen(seedOf(n, 96)) }) },
  { alg: 'hybrid-ed25519-slh-dsa-sha2-256s', minimal: true, material: (n) => ({ slhDsa256s: pca.slhDsa256sKeygen(seedOf(n, 96)) }) },
  { alg: 'fn-dsa-512', material: (n) => ({ fnDsa512: fnKey(pca.fnDsa512Keygen, n) }) },
  { alg: 'fn-dsa-1024', material: (n) => ({ fnDsa1024: fnKey(pca.fnDsa1024Keygen, n) }) },
];

function ev(name, description, ans, ok, { now = NOW, principals, bind = BIND, reason, decision, requires } = {}) {
  const input = { answer: ans, principals: principals ?? [PUB], bind, now };
  const r = pca.verifyEscalationAnswer(input.answer, input.principals, input.bind, input.now);
  if (r.ok !== ok) throw new Error(`${name}: the reference says ${JSON.stringify(r)}`);
  const expect = { ok };
  if (ok) {
    if (r.principal !== PUB || r.decision !== (decision ?? 'allow')) throw new Error(`${name}: wrong principal / decision ${JSON.stringify(r)}`);
    expect.principal = PUB;
    expect.decision = r.decision;
  } else {
    if (!r.reason.includes(reason)) throw new Error(`${name}: the reference reason is ${JSON.stringify(r.reason)}, expected it to contain ${JSON.stringify(reason)}`);
    expect.reason_contains = reason;
  }
  return { name, description, ...(requires !== undefined ? { requires_suite: requires } : {}), input, expect };
}

const a = answer();
const flip = (s) => {
  const b = pca.unb64u(s);
  b[0] ^= 1;
  return pca.b64u(b);
};
const ANSWERS = [
  ev('ea-valid', 'a bound, signed, in-window allow answer', a, true),
  ev('ea-valid-deny-answer', 'a valid deny answer verifies (ok) but its decision is deny', answer({ decision: 'deny' }), true, { decision: 'deny' }),
  ev('ea-valid-explicit-alg', 'alg ed25519 spelled out', answer({ alg: 'ed25519' }), true),
  ev('ea-boundary-iat', 'now == iat is inside', a, true, { now: NOW }),
  ev('ea-boundary-exp', 'now == expires_at is inside', a, true, { now: NOW + 1000 }),
  ev('ea-expired', 'one tick past expires_at', a, false, { now: NOW + 1001, reason: 'the answer has expired' }),
  ev('ea-future', 'one tick before iat', a, false, { now: NOW - 1, reason: 'the answer is from the future' }),
  ev('ea-bad-clock', 'a non-integer clock is refused', a, false, { now: 1.5, reason: 'the verifier clock is not a safe integer' }),
  ev('ea-unpinned', 'signed by a key the verifier did not pin', a, false, { principals: [OTHER], reason: 'not pinned' }),
  ev('ea-no-pins', 'no pinned principal', a, false, { principals: [], reason: 'no principal is pinned' }),
  ev('ea-pin-object', 'a pin object {pk}', a, true, { principals: [{ pk: PUB }] }),
  ev('ea-pin-first-match', 'the first pin naming the principal decides: a bare pin, then an object pin', a, true, { principals: [OTHER, PUB, { pk: PUB, pq_pk: 'x' }] }),
  ev('ea-tampered-decision', 'decision flipped after signing', { ...a, decision: 'deny' }, false, { reason: 'signature invalid' }),
  ev('ea-other-policy', 'bound to another policy', a, false, { bind: { ...BIND, policy_digest: dg('z') }, reason: 'another policy' }),
  ev('ea-other-action', 'bound to another action', a, false, { bind: { ...BIND, action_digest: dg('z') }, reason: 'another action' }),
  ev('ea-other-history', 'bound to another history state', a, false, { bind: { ...BIND, history_head: dg('z') }, reason: 'another state of the history' }),
  ev('ea-unknown-member', 'a closed wire: an extra member', { ...a, x: 1 }, false, { reason: 'unknown member' }),
  ev('ea-missing-member', 'a closed wire: a missing member', withoutKey(a, 'nonce'), false, { reason: 'missing member' }),
  ev('ea-short-nonce', 'a nonce under 16 bytes', answer({ nonce: pca.b64u(new Uint8Array(15)) }), false, { reason: 'nonce must be' }),
  ev('ea-lifetime-max', 'exactly 24 h is allowed', answer({ expires_at: NOW + 86_400_000 }), true),
  ev('ea-lifetime-over', '24 h + 1 ms is refused', answer({ expires_at: NOW + 86_400_001 }), false, { reason: 'an answer lives at most' }),
  ev('ea-exp-not-after-iat', 'expires_at must exceed iat', answer({ expires_at: NOW }), false, { reason: 'expires_at must be greater than iat' }),
  ev('ea-bad-decision', 'decision other than allow / deny', answer({ decision: 'maybe' }), false, { reason: 'decision must be' }),
  ev('ea-not-an-object', 'a non-object answer', 5, false, { reason: 'not an object' }),
  ev('ea-null', 'a null answer', null, false, { reason: 'not an object' }),
  ev('ea-array', 'an array answer', [], false, { reason: 'not an object' }),
  ev('ea-bad-kind', 'another kind', answer({ kind: 'pca-escalation-request' }), false, { reason: 'not a pca-escalation-answer v1' }),
  ev('ea-bad-version', 'v: 2', answer({ v: 2 }), false, { reason: 'not a pca-escalation-answer v1' }),
  ev('ea-principal-short', 'a principal that is not 32 bytes', answer({ principal: pca.b64u(new Uint8Array(31)) }), false, { reason: 'principal must be canonical base64url' }),
  ev('ea-digest-noncanonical', 'a non-canonical digest', answer({ policy_digest: `${BIND.policy_digest.slice(0, -1)}B` }), false, { reason: 'policy_digest must be canonical base64url' }),
  ev('ea-negative-iat', 'a negative iat', answer({ iat: -1 }), false, { reason: 'iat and expires_at must be non-negative safe integers' }),
  ev('ea-float-iat', 'a fractional iat', answer({ iat: 1.5 }), false, { reason: 'iat and expires_at must be non-negative safe integers' }),
  ev('ea-sig-not-string', 'sig: 5', { ...a, sig: 5 }, false, { reason: 'sig must be a string' }),
  ev('ea-alg-not-string', 'alg: 5', { ...a, alg: 5 }, false, { reason: 'alg must be a string' }),
  ev('ea-alg-unknown', 'an algorithm that is not in the registry', { ...a, alg: 'rsa-2048' }, false, { reason: 'unsupported_suite' }),
  ev('ea-pq-pk-not-string', 'pq_pk: 5', { ...a, pq_pk: 5 }, false, { reason: 'pq_pk must be a string' }),
  ev('ea-pq-sig-not-string', 'pq_sig: 5', { ...a, pq_sig: 5 }, false, { reason: 'pq_sig must be a string' }),
  ev('ea-ed25519-with-pq-pk', 'an ed25519 answer must not carry pq_pk', { ...a, pq_pk: 'AAAA' }, false, { reason: 'an ed25519 artifact must not carry pq_pk / pq_sig' }),
  ev('ea-ed25519-with-pq-sig', 'an ed25519 answer must not carry pq_sig', { ...a, pq_sig: 'AAAA' }, false, { reason: 'an ed25519 artifact must not carry pq_pk / pq_sig' }),
];

for (const S of SUITES) {
  const m = S.material(11);
  const m2 = S.material(12);
  const suite = { alg: S.alg, ...m };
  const ans = answer({}, suite);
  const pinPq = ans.pq_pk;
  const wrongPq = art.signArtifact(pca.ESCALATION_ANSWER_DOMAIN, bodyOf(), sk, { alg: S.alg, ...m2 }).pq_pk;
  const t = S.alg;
  const hybrid = S.alg.startsWith('hybrid');
  ANSWERS.push(ev(`ea-${t}-valid`, `an allow answer signed under ${t}, the principal pinned with its PQ key`, ans, true, { principals: [{ pk: PUB, pq_pk: pinPq }], requires: t }));
  if (S.minimal) continue;
  ANSWERS.push(ev(`ea-${t}-tampered`, `${t}: the decision flipped after signing`, { ...ans, decision: 'deny' }, false, { principals: [{ pk: PUB, pq_pk: pinPq }], reason: 'signature invalid', requires: t }));
  if (S.light) continue;
  ANSWERS.push(ev(`ea-${t}-bare-pin`, `${t}: the principal pinned by Ed25519 key only (no PQ key): refused`, ans, false, { principals: [PUB], reason: 'signature invalid', requires: t }));
  ANSWERS.push(ev(`ea-${t}-wrong-pq-pin`, `${t}: the principal pinned with another PQ key: refused`, ans, false, { principals: [{ pk: PUB, pq_pk: wrongPq }], reason: 'signature invalid', requires: t }));
  ANSWERS.push(ev(`ea-${t}-bad-sig`, `${t}: a flipped signature byte`, { ...ans, sig: flip(ans.sig) }, false, { principals: [{ pk: PUB, pq_pk: pinPq }], reason: 'signature invalid', requires: t }));
  if (hybrid) ANSWERS.push(ev(`ea-${t}-missing-pq-sig`, `${t}: the hybrid's PQ signature removed`, withoutKey(ans, 'pq_sig'), false, { principals: [{ pk: PUB, pq_pk: pinPq }], reason: 'signature invalid', requires: t }));
}

// integer-valued numbers spelled 2.0 / 1e3 in the answer and the clock: the same integers, the same canonical signed bytes
{
  const base = { answer: a, principals: [PUB], bind: BIND, now: NOW };
  const spelled = (text, name, description, swaps) => {
    let t = text;
    for (const [from, to] of swaps) {
      if (!t.includes(from)) throw new Error(`${name}: ${from} not found`);
      t = t.replace(from, to);
    }
    const i = JSON.parse(t);
    const r = pca.verifyEscalationAnswer(i.answer, i.principals, i.bind, i.now);
    if (!r.ok) throw new Error(`${name}: the reference refuses: ${r.reason}`);
    ANSWERS.push({ name, description, input_text: t, expect: { ok: true, principal: PUB, decision: 'allow' } });
  };
  const text = JSON.stringify(base);
  spelled(text, 'ea-float-spelling', 'v, iat, expires_at and the clock written 1.0 / 1800000000000.0: the same integers, the same signature', [['"v":1,', '"v":1.0,'], [`"iat":${NOW},`, `"iat":${NOW}.0,`], [`"expires_at":${NOW + 1000},`, `"expires_at":${NOW + 1000}.0,`], [`"now":${NOW}}`, `"now":${NOW}.0}`]]);
  spelled(text, 'ea-exponent-spelling', 'iat written 1.8e12, the clock 1.8e12: exponent forms are the same integers', [[`"iat":${NOW},`, '"iat":1.8e12,'], [`"now":${NOW}}`, '"now":1.8e12}']]);
}

// ------------------------------------------------------------------------------------------------ write / check
const primitives = {
  intent_units: [...regen('intent_units', unitsNew, unitsExpect), ...regenJson(orderUnits, unitsExpect), ...regenJson(floatUnits, unitsExpect)],
  intent_tighten: [...regen('intent_tighten', tightenNew, tightenExpect), ...regenJson(orderTighten, tightenExpect)],
  escalation_truncate: truncCases.map(([name, description, reasons]) => ({ name, description, input: { reasons }, expect: truncExpect(reasons) })),
  decision_of: regen('decision_of', decisionNew, (i) => ({ decision: pca.decisionOf(i) })),
  decision_lattice: [...prev.primitives.decision_lattice.filter((e) => !pepNew.some(([n]) => n === e.name)), ...pepNew.map(([name, description, input]) => ({ name, description, input, expect: { decision: pca.pepDecision(input.decision, input.answered) } }))],
  escalation_fold: foldNew.map(([name, description, core, v2, checks]) => {
    const input = { core_reasons: core, v2, checks };
    return { name, description, input, expect: foldExpect(input) };
  }),
  escalation_answer: ANSWERS,
};
const names = Object.values(primitives).flat().map((e) => e.name);
const dup = names.find((n, i) => names.indexOf(n) !== i);
if (dup) throw new Error(`duplicate vector name ${dup}`);
// the multi-check fold must exercise every outcome
for (const d of ['allow', 'escalate', 'deny']) if (!primitives.escalation_fold.some((e) => e.expect.decision === d)) throw new Error(`escalation_fold has no ${d} vector`);
const file = {
  format: prev.format,
  ver: 2,
  rules: prev.rules,
  description: 'Generated by packages/pca/scripts/gen-conformance-decision.mjs from the TypeScript reference; do not edit. Reason text is part of every expectation.',
  primitives,
};
const text = serializeCorpus(file);
const counts = Object.entries(primitives).map(([k, v]) => `${k}=${v.length}`).join(' ');
if (process.argv.includes('--check')) {
  let committed = '';
  try { committed = readFileSync(OUT, 'utf8'); } catch { /* absent */ }
  if (committed !== text) { console.error(`decision-vectors.json differs from a fresh regeneration (${counts}): re-run gen-conformance-decision.mjs and commit`); process.exit(1); }
  console.log(`decision-vectors.json up to date (${counts})`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${counts}`);
}
