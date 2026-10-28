// conformance/model-rules-vectors.json: rules 20 (units) and 21 (tighten-only) END TO END through authorize().
//
// Each case is one signed PCActn under a signed grant whose ENVELOPE carries `units`, `tighten` and / or `model_polarity` (or
// whose grant-side `where` reads a model-derived env path), the operation the server executes, the verifier's v2 context and
// host context env, and the outcome the TypeScript reference `authorize()` computes: the ternary `decision`, `status`, the
// sorted failing checks, the ordered model-rule reasons (`units: ...`, `tighten: ...`) and the `degraded` report. The Go, Rust
// and Python `authorize()` replay the file (sdks/*: model-rules tests) and must decide the same, REASON TEXT INCLUDED: a
// grant's `tighten[]` rule, its unit tags and its polarity are signed policy, and a verifier that ignored them would let a
// model move a decision up (rule 21) or a policy term be read in the wrong unit (rule 20).
//
// Deterministic: fixed key seeds, Ed25519, a fixed grant salt and clock.
//
//     node packages/pca/scripts/gen-conformance-model-rules.mjs [--check]                 (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-model-rules.mjs  (reads ../src)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, serializeCorpus } from './conformance-io.mjs';
import { loadPca } from './pca-all.mjs';

const pca = await loadPca();
const OUT = join(confDir, 'model-rules-vectors.json');

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/model-rules/${l}`).digest());
const mk = (l) => {
  const sk = seed(l);
  return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) };
};
const principal = mk('principal');
const agent = mk('agent');
const site = mk('site');
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments/acme';
const ZERO_RISK = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1_000 };
const ANY = [{ verb: [VERB], resource: 'payments/*' }];
const AMOUNT = 'action.params.amount';

// ---- the site's action schema (rule 14 / 20): `amount` is money in USD cents ---------------------------------------
const UNSIGNED = {
  v: 1, kind: 'pca-action-schema', site: 'https://pay.example', aud: AUD, version: '2026-10-01',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
  verbs: [
    {
      verb: VERB, kind: 'write',
      params: {
        [AMOUNT]: { type: 'integer', unit: 'usd_cents', min: 0, max: 5_000_000, semantic: 'money.amount', sensitivity: 'critical' },
        'action.params.currency': { type: 'string', values: ['usd'], semantic: 'money.currency', sensitivity: 'material' },
      },
      reversibility: 'irreversible',
    },
  ],
};
const SCHEMA = pca.signActionSchema(UNSIGNED, 'pay-2026', site.sk);
const SCHEMA_CTX = { schema: { docs: [SCHEMA], keys: [pca.actionSchemaKeyOf('pay-2026', site.sk)] } };
const USD2 = { kind: 'money', currency: 'USD', exponent: 2 };

const mint = (o = {}) =>
  pca.mintGrant({
    principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, goal: 'pay invoices', salt: 'model-rules-salt',
    envelope: {
      predicates: o.predicates ?? ANY, caveats: [], agent_binding: {}, risk_policy: ZERO_RISK,
      ...(o.units !== undefined ? { units: o.units } : {}), ...(o.tighten !== undefined ? { tighten: o.tighten } : {}), ...(o.polarity !== undefined ? { model_polarity: o.polarity } : {}),
    },
  }).grant;
const pay = (amount) => ({ amount, currency: 'usd' });
const sign = (grant, params) => {
  const node = { id: 'n1', verb: VERB, resource: RES, params_digest: pca.paramsDigest(params), reversibility_class: 'irreversible' };
  return pca.buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: 1, signerSecret: agent.sk, aud: AUD, now: NOW });
};

const big = (over = {}) => ({ id: 'big', when: { field: AMOUNT, op: 'gt', value: 50 }, signal: 'escalate', ...over });
const hostile = (over = {}) => ({ id: 'hostile', when: { field: 'env.judge.tone', op: 'eq', value: 'hostile' }, signal: 'deny', ...over });
const whereJudge = [{ verb: [VERB], resource: 'payments/*', where: [{ field: 'env.judge.tone', op: 'ne', value: 'hostile' }] }];
const whereAmount = [{ verb: [VERB], resource: 'payments/*', where: [{ field: AMOUNT, op: 'lte', value: 100000 }] }];
const HOSTILE = { judge: { tone: 'hostile' } };
const CALM = { judge: { tone: 'calm' } };

const cases = [];
const add = (name, description, { grant, amount = 80, intent_v2, env }) => {
  const params = pay(amount);
  cases.push({ name, description, grant, pcactn: sign(grant, params), operation: { verb: VERB, resource: RES, params }, ...(intent_v2 !== undefined ? { intent_v2 } : {}), ...(env !== undefined ? { context: { env } } : {}) });
};

// ---- rule 21: tighten[] -----------------------------------------------------------------------------------------------
add('tighten-quiet', 'A tighten rule that does not fire: allowed, the tighten check passes.', { grant: mint({ tighten: [big({ when: { field: AMOUNT, op: 'gt', value: 1000 } })] }) });
add('tighten-escalate', 'A rule that fires with signal escalate: the decision is escalate (never allow).', { grant: mint({ tighten: [big()] }) });
add('tighten-deny', 'A rule that fires with signal deny (and a reason): denied.', { grant: mint({ tighten: [big({ id: 'cap', signal: 'deny', reason: 'over the cap' })] }) });
add('tighten-unknown-escalates', 'A rule that reads a model value the verifier does not have is undecidable: escalate (never allow, never skipped).', { grant: mint({ tighten: [hostile()] }) });
add('tighten-host-env-deny', 'The host env carries env.judge.tone = hostile: the deny rule fires.', { grant: mint({ tighten: [hostile()] }), env: HOSTILE });
add('tighten-host-env-clean', 'The host env carries env.judge.tone = calm: the rule does not fire, allowed.', { grant: mint({ tighten: [hostile()] }), env: CALM });
add('tighten-v2-env-deny', 'The v2 context env (no authorize context env) carries hostile: the deny rule fires.', { grant: mint({ tighten: [hostile()] }), intent_v2: { env: HOSTILE } });
add('tighten-v2-env-wins', 'The v2 context env wins over the authorize context env.', { grant: mint({ tighten: [hostile()] }), intent_v2: { env: CALM }, env: HOSTILE });
add('tighten-meet', 'An escalate rule then a deny rule: the outcome is the meet, the deny rule names the reason.', { grant: mint({ tighten: [big(), hostile()] }), env: HOSTILE });
add('tighten-deny-then-escalate', 'A deny rule then an escalate rule: still deny, the first lowering rule names the reason.', { grant: mint({ tighten: [hostile(), big()] }), env: HOSTILE });
add('tighten-first-escalate-reason', 'Two escalate rules fire: the first one names the reason.', { grant: mint({ tighten: [big(), big({ id: 'big2' })] }) });

// ---- rule 21: model-derived paths in a grant-side where (typing) -------------------------------------------------
add('model-path-in-where', 'The grant allows an action only when a model-derived value is calm: a model could move a decision UP, so it is refused outright.', { grant: mint({ predicates: whereJudge }), env: CALM });
add('legacy-model-path', "model_polarity 'legacy' (signed in the envelope) lets the grant through, reported degraded.", { grant: mint({ predicates: whereJudge, polarity: 'legacy' }), env: CALM });
add('legacy-strict-policy-overrides', "The verifier's policy.model_polarity 'strict' forbids it even for a 'legacy' envelope.", { grant: mint({ predicates: whereJudge, polarity: 'legacy' }), env: CALM, intent_v2: { policy: { model_polarity: 'strict' } } });
add('legacy-policy-accepts', "The verifier's policy.model_polarity 'legacy' accepts a grant that reads a model-derived path (degraded).", { grant: mint({ predicates: whereJudge }), env: CALM, intent_v2: { policy: { model_polarity: 'legacy' } } });
add('legacy-without-model-path', "model_polarity 'legacy' with nothing model-derived read: allowed and NOT degraded.", { grant: mint({ polarity: 'legacy' }) });
add('model-path-other-root', 'A where that reads a deterministic env member (env.acc) is not model-derived: allowed.', { grant: mint({ predicates: [{ verb: [VERB], resource: 'payments/*', where: [{ field: 'env.acc.x', op: 'eq', value: 1 }] }] }), env: { acc: { x: 1 } } });
add('legacy-with-rule', "Legacy compatibility still evaluates the grant's tighten rules.", { grant: mint({ predicates: [{ verb: [VERB], resource: 'payments/*', where: [{ field: 'env.judge.tone', op: 'ne', value: 'rude' }] }], polarity: 'legacy', tighten: [hostile()] }), env: HOSTILE });

// ---- the verifier context members rules 20 / 21 added -------------------------------------------------------------
add('context-bad-polarity', 'policy.model_polarity must be strict or legacy: a malformed context fails closed.', { grant: mint({ tighten: [big()] }), intent_v2: { policy: { model_polarity: 'loose' } } });
add('context-env-not-object', 'The v2 context env must be an object: a malformed context fails closed.', { grant: mint({ tighten: [big()] }), intent_v2: { env: 'x' } });
add('context-env-null', 'The v2 context env must not be null.', { grant: mint({ tighten: [big()] }), intent_v2: { env: null } });

// ---- rule 20: units ---------------------------------------------------------------------------------------------------
add('units-match', 'The policy tags amount as USD cents, the signed schema says USD cents: allowed.', { grant: mint({ units: { [AMOUNT]: USD2 } }), intent_v2: SCHEMA_CTX });
add('units-cents-vs-dollars', 'The policy tags amount as whole USD, the schema says USD cents: refused (unit confusion).', { grant: mint({ units: { [AMOUNT]: { kind: 'money', currency: 'USD', exponent: 0 } } }), intent_v2: SCHEMA_CTX });
add('units-currency-mismatch', 'The policy tags amount as EUR cents: refused.', { grant: mint({ units: { [AMOUNT]: { kind: 'money', currency: 'EUR', exponent: 2 } } }), intent_v2: SCHEMA_CTX });
add('units-no-exponent', 'The policy tag omits the exponent the schema declares: refused.', { grant: mint({ units: { [AMOUNT]: { kind: 'money', currency: 'USD' } } }), intent_v2: SCHEMA_CTX });
add('units-no-schema', 'A grant with unit tags and a verifier with no action schema: refused (units cannot be checked).', { grant: mint({ units: { [AMOUNT]: USD2 } }) });
add('units-untagged-term', 'A where term reads the unit-bearing amount without a unit tag: refused.', { grant: mint({ predicates: whereAmount, units: {} }), intent_v2: SCHEMA_CTX });
add('units-tagged-term', 'The same term with its unit tag: allowed.', { grant: mint({ predicates: whereAmount, units: { [AMOUNT]: USD2 } }), intent_v2: SCHEMA_CTX });
add('units-undeclared-param-ignored', 'A tag for a parameter the verb does not declare is ignored.', { grant: mint({ units: { 'action.params.other': USD2 } }), intent_v2: SCHEMA_CTX });

// ---- both rules together ----------------------------------------------------------------------------------------------
add('units-hard-and-tighten-escalate', 'A unit confusion (hard) and a tighten escalation: the decision is deny, both reasons are reported in pipeline order.', { grant: mint({ units: { [AMOUNT]: { kind: 'money', currency: 'USD', exponent: 0 } }, tighten: [big()] }), intent_v2: SCHEMA_CTX });
add('units-ok-tighten-escalate', 'Units fine, the tighten rule escalates: escalate.', { grant: mint({ units: { [AMOUNT]: USD2 }, tighten: [big()] }), intent_v2: SCHEMA_CTX });
add('units-ok-tighten-quiet', 'Units fine, the tighten rule quiet: allowed, both checks pass.', { grant: mint({ units: { [AMOUNT]: USD2 }, tighten: [big({ when: { field: AMOUNT, op: 'gt', value: 100000 } })] }), intent_v2: SCHEMA_CTX });

// ---- the outcome of the TypeScript reference ---------------------------------------------------------------------------
const MODEL = /^(units|tighten|schema|intent_session): /;
for (const c of cases) {
  const run = pca.createAuthorizer({
    audience: AUD,
    resolveGrant: async (ref) => (ref === c.grant.id ? c.grant : null),
    budgetStore: pca.atomicMemoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    now: () => NOW,
    ...(c.intent_v2 !== undefined ? { intentV2: c.intent_v2 } : {}),
    context: async () => ({ ...(c.context?.env !== undefined ? { env: c.context.env } : {}) }),
  });
  const r = await run({ pcactn: c.pcactn, operation: c.operation });
  const checks = r.verdict?.checks ?? {};
  const failed = Object.entries(checks).filter(([, s]) => s === 'fail').map(([n]) => n).sort();
  const degraded = Object.fromEntries(Object.entries(r.assurance ?? {}).filter(([, e]) => e?.degraded === true).map(([n, e]) => [n, e.reason]));
  c.expect = {
    allow: r.allow, decision: r.decision, status: r.status, failed,
    reasons: (r.verdict?.reasons ?? []).filter((x) => MODEL.test(x)),
    ...(Object.keys(degraded).length ? { degraded } : {}),
    ...(checks.units !== undefined ? { units: checks.units } : {}),
    ...(checks.tighten !== undefined ? { tighten: checks.tighten } : {}),
  };
  const stray = failed.filter((n) => !['units', 'tighten', 'schema', 'intent_session'].includes(n));
  if (stray.length) throw new Error(`${c.name}: unexpected failing checks ${stray.join(', ')} (${JSON.stringify(r.verdict?.reasons)})`);
}
for (const d of ['allow', 'escalate', 'deny']) if (!cases.some((c) => c.expect.decision === d)) throw new Error(`no ${d} case`);

const file = {
  format: 'pca-model-rules-vectors/1',
  description: 'Rules 20 and 21 end to end through authorize(), signed and decided by the TypeScript reference; do not edit. Generated by packages/pca/scripts/gen-conformance-model-rules.mjs.',
  now: NOW,
  audience: AUD,
  cases,
};
const text = serializeCorpus(file);
if (process.argv.includes('--check')) {
  let committed = '';
  try { committed = readFileSync(OUT, 'utf8'); } catch { /* absent */ }
  if (committed !== text) { console.error(`model-rules-vectors.json differs from a fresh regeneration (${cases.length} cases): re-run gen-conformance-model-rules.mjs and commit`); process.exit(1); }
  console.log(`model-rules-vectors.json up to date (${cases.length} cases)`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${cases.length} cases (${['allow', 'escalate', 'deny'].map((d) => `${d} ${cases.filter((c) => c.expect.decision === d).length}`).join(', ')})`);
}
