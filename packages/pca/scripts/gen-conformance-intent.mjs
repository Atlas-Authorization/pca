// Stage 8 of the conformance pipeline (run AFTER gen-conformance-041.mjs; idempotent): the Intent Layer M2 binding.
//
//   vectors[]  intent-*   the signed `envelope.intent` slot of a PCActn ({ref, map_digest, goal_salt, fidelity_ppm,
//                         residual_risk_ppm}) and the `intent` check (normative rules: packages/pca/src/intent-binding.ts,
//                         conformance/README.md "Intent binding"). A vector may carry `context.intent_policy`
//                         ({require?, min_fidelity_ppm?, max_residual_risk_ppm?}); a runner passes it to its verifier.
//                         `expect.checks.intent` is present iff the check was evaluated (the PCActn carries `intent` or the
//                         policy is active), appended after `counter`; otherwise the verdict is the pre-M2 one.
//                         A vector may instead carry `context.intent_policy_json`, the policy as RAW JSON TEXT, so
//                         lexical forms survive every JSON round trip (950000.0, 1e6, -0.0): a runner parses it with its
//                         platform JSON parser. A threshold is judged by its numeric value only.
//
//     node packages/pca/scripts/gen-conformance-intent.mjs            (reads ../dist, like every stage)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-intent.mjs   (reads ../src)
import { createHash } from 'node:crypto';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent');
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)
const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
const KEYMAP = { chain: 'cap_chain' };
const SALT = 'c2FsdC1pbnRlbnQtY29uZm9ybWFuY2U';

// A real signed IntentStatement + a (digest-only) Intent Map: the ref / map_digest the grant's goal commits to.
const stmt = pca.signIntentStatement({
  v: 1,
  text: 'Refund customers up to $200, only alice or bob',
  slots: { verbs: ['stripe.refund'], constraints: [{ verb: 'stripe.refund', path: 'action.params.amount', max: 200 }] },
  sources: [{ kind: 'ticket', uri: 'T-1', digest: pca.b64u(seed('intent/ticket')) }],
  created_at: 1_700_000_000_000,
  nonce: 'bm9uY2UtMQ',
}, principal.sk);
const REF = pca.intentRef(stmt);
const MAP = {
  v: 1, kind: 'pca-intent-map', intent_ref: REF, principals: [REF],
  grant: { predicates: [], caveats: [] },
  metrics: { residual_risk_ppm: 4_310_000, burden_ppm: 1834, uncertainty_ppm: 912, disagreement_ppm: 1834, mean_harm_ppm: 4_310_000, fidelity_est_ppm: 950_000, entropy_mbits: 3170, log2_vs_mbits: 1585, questions: 7, conflicts: 0 },
};
const MAP_DIGEST = pca.intentMapDigest(MAP);
const OTHER = pca.b64u(seed('intent/other'));

const envelopeOf = (goal, salt = SALT) => ({ type: 'envelope', goal_commit: pca.goalCommitOf(goal, salt), predicates: [], caveats: [], agent_binding: {}, risk_policy: pca.DEFAULT_RISK_POLICY });
const rootWith = (caveats) => pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });
const mint = (goal, salt = SALT) => pca.mintGrant({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: pca.DEFAULT_RISK_POLICY }, goal, salt }).grant;

const G = mint(pca.intentGoal(REF, MAP_DIGEST));
const plan = [{ id: 'only', verb: 'read', resource: 'db/users' }];
const INTENT = { ref: REF, map_digest: MAP_DIGEST, goal_salt: SALT, fidelity_ppm: 950_000, residual_risk_ppm: 4_310_000 };
const build = (grant, intent) => pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant, chain: [grant], plan, nodeId: 'only', params: {}, counter: 1, signerSecret: agent.sk, ...(intent !== undefined ? { intent } : {}) });
/** Re-sign a PCActn whose (signed) body was mutated, so only the rule under test can fail. */
const resign = (p) => { const { sig: _s, ...body } = p; return pca.signPCActn(body, agent.sk); };
const withIntent = (grant, intent) => resign({ ...clone(build(grant)), intent });

const vectors = [];
async function add(name, description, { grant = G, pcactn, policy, policyJson, must }) {
  const eff = policyJson !== undefined ? JSON.parse(policyJson) : policy;
  const r = await pca.verifyPCActnCore(pcactn, { grant, nowEpoch: NOW, audience: AUD, ...(eff ? { intent: eff } : {}) });
  const c = r.checks;
  const checks = {};
  if (c.wire === 'fail') checks.wire = false;
  else {
    checks.wire = true;
    for (const k of CHECKS) checks[k] = c[KEYMAP[k] ?? k] === 'pass';
    if (c.intent !== undefined) checks.intent = c.intent === 'pass';
  }
  const ok =
    must === 'allow' ? r.allow === true && checks.intent !== false :
    must === 'absent' ? r.allow === true && !('intent' in checks) :
    must === 'wire' ? checks.wire === false :
    must === 'intent' ? r.allow === false && checks.intent === false && CHECKS.every((k) => checks[k]) :
    must === 'leaf' ? r.allow === false && checks.leaf_signature === false && checks.intent === true : false;
  if (!ok) throw new Error(`vector intent-${name}: reference ${JSON.stringify(checks)} allow=${r.allow} does not meet intent ${must} (${r.reason ?? ''})`);
  vectors.push({
    name: 'intent-' + name, class: r.allow ? 'positive' : 'negative', description,
    grant, plan_nodes: plan, context: { now: NOW, aud: AUD, ...(policy ? { intent_policy: policy } : {}), ...(policyJson !== undefined ? { intent_policy_json: policyJson } : {}) }, pcactn, expect: { allow: r.allow === true, checks },
  });
}

const P = build(G, INTENT);
// ---- accept
await add('bound', 'A PCActn carrying envelope.intent whose ref/map_digest/goal_salt open the root grant goal commitment: intent passes (no policy).', { pcactn: P, must: 'allow' });
await add('bound-require', 'Same, under a verifier policy {require:true}.', { pcactn: P, policy: { require: true }, must: 'allow' });
await add('bound-thresholds-boundary', 'Thresholds equal to the claimed figures are inclusive: min_fidelity_ppm == fidelity_ppm and max_residual_risk_ppm == residual_risk_ppm pass.', { pcactn: P, policy: { min_fidelity_ppm: 950_000, max_residual_risk_ppm: 4_310_000 }, must: 'allow' });
await add('bound-ppm-extremes', 'fidelity_ppm = 1000000 and residual_risk_ppm = 0 (range edges) are well-formed and bound.', { pcactn: withIntent(G, { ...INTENT, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 }), must: 'allow' });
await add('bound-residual-over-1e6', 'residual_risk_ppm is in harm-units x 1e6 and may exceed 1000000 (here 9007199254740991, the largest safe integer).', { pcactn: withIntent(G, { ...INTENT, residual_risk_ppm: 9_007_199_254_740_991 }), must: 'allow' });
await add('absent-no-policy', 'A grant minted for an intent goal, PCActn WITHOUT intent, no policy: no intent check at all (pre-M2 verdict, back-compat).', { pcactn: build(G), must: 'absent' });
await add('absent-zero-policy', 'An empty policy {} (and {require:false}) is not active: no intent check.', { pcactn: build(G), policy: { require: false }, must: 'absent' });
{
  const g2 = rootWith([{ type: 'max_spend', usd: 100 }, envelopeOf(pca.intentGoal(REF, MAP_DIGEST))]);
  await add('envelope-not-first-caveat', "The root grant's envelope is its SECOND caveat: the binding uses the first caveat whose type is envelope.", { grant: g2, pcactn: withIntent(g2, INTENT), must: 'allow' });
}
{
  const salt = 'é'.repeat(64); // 128 UTF-8 bytes
  const g3 = mint(pca.intentGoal(REF, MAP_DIGEST), salt);
  await add('goal-salt-128-bytes', 'goal_salt of exactly 128 UTF-8 bytes (64 x U+00E9) is well-formed.', { grant: g3, pcactn: withIntent(g3, { ...INTENT, goal_salt: salt }), must: 'allow' });
}

// ---- intent check fails
await add('absent-required', 'Policy {require:true}, PCActn without intent: intent fails closed.', { pcactn: build(G), policy: { require: true }, must: 'intent' });
await add('absent-threshold-implies-require', 'Policy {min_fidelity_ppm} only, PCActn without intent: a threshold implies require, so intent fails (no dodging the floor by omission).', { pcactn: build(G), policy: { min_fidelity_ppm: 1 }, must: 'intent' });
await add('ref-mismatch', 'intent.ref names a different statement than the grant goal commits to: intent fails.', { pcactn: withIntent(G, { ...INTENT, ref: OTHER }), must: 'intent' });
await add('map-digest-mismatch', 'intent.map_digest differs from the committed map: intent fails.', { pcactn: withIntent(G, { ...INTENT, map_digest: OTHER }), must: 'intent' });
await add('goal-salt-mismatch', 'intent.goal_salt does not open the grant goal commitment: intent fails.', { pcactn: withIntent(G, { ...INTENT, goal_salt: 'wrong-salt' }), must: 'intent' });
{
  const g4 = rootWith([]);
  await add('grant-no-envelope', 'The root grant has no envelope caveat (nothing to bind to): intent fails.', { grant: g4, pcactn: withIntent(g4, INTENT), must: 'intent' });
  const g5 = mint('refund the duplicate charge');
  await add('grant-goal-not-intent', 'The root grant goal is a plain-text goal, not pca-intent:v1:<ref>:<map>: intent fails.', { grant: g5, pcactn: withIntent(g5, INTENT), must: 'intent' });
  const g6 = mint(pca.intentGoal(REF));
  await add('grant-goal-without-map', 'The root grant goal binds the statement but no map (pca-intent:v1:<ref>): the slot requires the map, intent fails.', { grant: g6, pcactn: withIntent(g6, INTENT), must: 'intent' });
  const g7 = rootWith([envelopeOf('decoy'), envelopeOf(pca.intentGoal(REF, MAP_DIGEST))]);
  await add('first-envelope-wins', 'Two envelope caveats: only the FIRST one counts; it commits to another goal, so intent fails even though the second would match.', { grant: g7, pcactn: withIntent(g7, INTENT), must: 'intent' });
  const g8 = rootWith([{ type: 'envelope', goal_commit: 7 }]);
  await add('goal-commit-not-string', "The root grant's envelope goal_commit is not a string: intent fails.", { grant: g8, pcactn: withIntent(g8, INTENT), must: 'intent' });
}
await add('fidelity-below-min', 'Bound intent, fidelity_ppm 950000 below policy min_fidelity_ppm 950001: intent fails.', { pcactn: P, policy: { min_fidelity_ppm: 950_001 }, must: 'intent' });
await add('residual-above-max', 'Bound intent, residual_risk_ppm 4310000 above policy max_residual_risk_ppm 4309999: intent fails.', { pcactn: P, policy: { max_residual_risk_ppm: 4_309_999 }, must: 'intent' });
await add('policy-misconfigured', 'Policy min_fidelity_ppm = -1 (negative): misconfigured, intent fails closed.', { pcactn: P, policy: { min_fidelity_ppm: -1 }, must: 'intent' });
await add('policy-misconfigured-fraction', 'Policy max_residual_risk_ppm = 0.5 (not an integer): misconfigured, intent fails closed.', { pcactn: P, policy: { max_residual_risk_ppm: 0.5 }, must: 'intent' });

// ---- thresholds in non-integer lexical forms (raw policy text): only the numeric value counts
await add('policy-float-literal', 'Policy text {"min_fidelity_ppm":950000.0}: an integral value in float form is a valid threshold (inclusive), intent passes.', { pcactn: P, policyJson: '{"min_fidelity_ppm":950000.0}', must: 'allow' });
await add('policy-exponent', 'Policy text {"max_residual_risk_ppm":4.31e6}: an integral value in exponent form is a valid threshold (inclusive), intent passes.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":4.31e6}', must: 'allow' });
await add('policy-exponent-floor', 'Policy text {"min_fidelity_ppm":1e6}: a valid threshold of 1000000 above the claimed 950000, intent fails on the floor.', { pcactn: P, policyJson: '{"min_fidelity_ppm":1e6}', must: 'intent' });
await add('policy-float-zero', 'Policy text {"min_fidelity_ppm":0.0}: zero in float form is valid, intent passes.', { pcactn: P, policyJson: '{"min_fidelity_ppm":0.0}', must: 'allow' });
await add('policy-negative-zero', 'Policy text {"min_fidelity_ppm":-0.0}: negative zero is not a non-negative safe integer, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"min_fidelity_ppm":-0.0}', must: 'intent' });
await add('policy-negative-zero-int', 'Policy text {"min_fidelity_ppm":-0}: a bare integer-form negative zero is negative zero too (JSON.parse keeps the sign), misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"min_fidelity_ppm":-0}', must: 'intent' });
await add('policy-float-fraction', 'Policy text {"min_fidelity_ppm":950000.5}: a fraction, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"min_fidelity_ppm":950000.5}', must: 'intent' });
await add('policy-over-safe', 'Policy text {"max_residual_risk_ppm":9007199254740992}: above 2^53-1, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":9007199254740992}', must: 'intent' });
// near 2^53 and beyond 17 significant digits the value is the NEAREST binary64 (ties to even), as JSON.parse gives it
await add('policy-round-to-max-safe', 'Policy text {"max_residual_risk_ppm":9007199254740991.4}: rounds to the double 9007199254740991 (2^53-1), a valid threshold, intent passes.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":9007199254740991.4}', must: 'allow' });
await add('policy-round-to-2p53', 'Policy text {"max_residual_risk_ppm":9007199254740991.5}: rounds (tie, to even) to the double 2^53, above 2^53-1, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":9007199254740991.5}', must: 'intent' });
await add('policy-round-odd-tie', 'Policy text {"max_residual_risk_ppm":9007199254740993}: an integer lexeme that rounds (tie, to even) to the double 2^53, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":9007199254740993}', must: 'intent' });
await add('policy-half-below-2p52', 'Policy text {"min_fidelity_ppm":4503599627370495.5}: exactly representable as a double (spacing 0.5 below 2^52) and not integral, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"min_fidelity_ppm":4503599627370495.5}', must: 'intent' });
await add('policy-round-up-integral', 'Policy text {"min_fidelity_ppm":949999.99999999999999}: rounds to the double 950000 (the claimed fidelity), a valid inclusive floor, intent passes.', { pcactn: P, policyJson: '{"min_fidelity_ppm":949999.99999999999999}', must: 'allow' });
await add('policy-round-down-integral', 'Policy text {"min_fidelity_ppm":950000.00000000000001}: rounds to the double 950000, a valid inclusive floor, intent passes.', { pcactn: P, policyJson: '{"min_fidelity_ppm":950000.00000000000001}', must: 'allow' });
await add('policy-underflow-zero', 'Policy text {"max_residual_risk_ppm":1e-400}: underflows to the double 0, a valid threshold of 0 below the claimed residual risk, intent fails on the ceiling.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":1e-400}', must: 'intent' });
await add('policy-negative-underflow', 'Policy text {"max_residual_risk_ppm":-1e-400}: underflows to negative zero, misconfigured, intent fails closed.', { pcactn: P, policyJson: '{"max_residual_risk_ppm":-1e-400}', must: 'intent' });
await add('policy-null-threshold', 'Policy text {"min_fidelity_ppm":null}: a present null threshold is set and invalid, intent fails closed.', { pcactn: P, policyJson: '{"min_fidelity_ppm":null}', must: 'intent' });

// ---- signed: tampering without re-signing breaks the leaf signature (the binding itself still holds)
await add('unsigned-tamper', 'fidelity_ppm raised AFTER signing (not re-signed): intent is signed, so leaf_signature fails.', { pcactn: { ...clone(P), intent: { ...INTENT, fidelity_ppm: 999_999 } }, must: 'leaf' });

// ---- wire (terminal)
const W = (name, description, intent) => add('wire-' + name, description + ' The wire check fails (terminal).', { pcactn: withIntent(G, intent), must: 'wire' });
const without = (k) => Object.fromEntries(Object.entries(INTENT).filter(([x]) => x !== k));
await W('not-object', 'intent is a string.', 'x');
await W('null', 'intent is null.', null);
await W('array', 'intent is an array.', [INTENT]);
await W('unknown-member', 'intent carries an unknown member (closed set).', { ...INTENT, note: 'x' });
for (const k of ['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm']) await W('missing-' + k.replace(/_/g, '-'), `intent lacks ${k} (all five members are required).`, without(k));
await W('ref-31-bytes', 'intent.ref decodes to 31 bytes.', { ...INTENT, ref: pca.b64u(seed('x').slice(0, 31)) });
await W('ref-padded', 'intent.ref carries base64 padding (not canonical base64url).', { ...INTENT, ref: REF + '=' });
await W('map-digest-std-alphabet', 'intent.map_digest uses the standard base64 alphabet (+ or /).', { ...INTENT, map_digest: '+' + MAP_DIGEST.slice(1) });
await W('ref-number', 'intent.ref is a number.', { ...INTENT, ref: 1 });
await W('goal-salt-empty', 'intent.goal_salt is empty.', { ...INTENT, goal_salt: '' });
await W('goal-salt-129-bytes', 'intent.goal_salt is 129 UTF-8 bytes (64 x U+00E9 + "a").', { ...INTENT, goal_salt: 'é'.repeat(64) + 'a' });
await W('goal-salt-number', 'intent.goal_salt is a number.', { ...INTENT, goal_salt: 5 });
await W('fidelity-over-1e6', 'intent.fidelity_ppm is 1000001.', { ...INTENT, fidelity_ppm: 1_000_001 });
await W('fidelity-negative', 'intent.fidelity_ppm is -1.', { ...INTENT, fidelity_ppm: -1 });
await W('fidelity-fraction', 'intent.fidelity_ppm is 1.5 (not an integer).', { ...INTENT, fidelity_ppm: 1.5 });
await W('fidelity-string', 'intent.fidelity_ppm is the string "950000".', { ...INTENT, fidelity_ppm: '950000' });
await W('residual-negative', 'intent.residual_risk_ppm is -1.', { ...INTENT, residual_risk_ppm: -1 });
await W('residual-fraction', 'intent.residual_risk_ppm is 0.25 (not an integer).', { ...INTENT, residual_risk_ppm: 0.25 });
await W('residual-bool', 'intent.residual_risk_ppm is true.', { ...INTENT, residual_risk_ppm: true });

const file = readCore();
file.vectors = file.vectors.filter((v) => !v.name.startsWith('intent-')).concat(vectors);
writeCore(file);
console.log(`intent: ${vectors.length} vectors (${vectors.filter((v) => v.class === 'positive').length} positive)`);
