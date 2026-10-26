/**
 * Shared `authorize` acceptance fixtures for the native SDKs (0.5, T6), signed by the TypeScript reference.
 *
 *   tsx packages/pca/scripts/gen-authorize-fixtures.ts [out.json]
 *     (run from the repo root; default out: sdks/python-pca/testdata/authorize-fixtures.json)
 *
 * Each case is an ordered list of steps run against ONE fresh replay store: a signed PCActn, the operation the server
 * executes, whether the grant is revoked, and the expected outcome (`allow`, `status`, sorted failing checks of the
 * native pipeline). Every grant uses a zero-weight risk policy, so the TypeScript Policy VM's risk / budget / threshold
 * stages admit every action and the decision rests on what the natives port (binding, predicates, caveats, revocation,
 * replay).
 *
 * When `src/server/authorize.ts` is present, every step is also run through the TypeScript `authorize()` and its
 * outcome is recorded as `ts` (`allow`, `status`): the natives assert they decide the same.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { delegate, mintRoot, type Capability, type Caveat } from '../src/capability';
import { mintGrant } from '../src/envelope';
import { encodeKey, generateKeyPair } from '../src/keys';
import { paramsDigest, type PlanNode } from '../src/merkle';
import { buildPCActn, type PCActn } from '../src/pcactn';
import { predicatesCaveat, toolSchemaCaveat } from '../src/agent-native';
import type { RiskPolicy } from '../src/risk';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments/acme';
const ZERO_RISK: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1_000 };

const principal = generateKeyPair();
const agent = generateKeyPair();
const pPub = encodeKey(principal.publicKey);
const aPub = encodeKey(agent.publicKey);

type Pred = { verb: string | string[]; resource: string; where?: unknown[] };
const anyPayment: Pred[] = [{ verb: [VERB, 'payments.refund'], resource: 'payments/*' }];

function envelopeGrant(o: { predicates?: Pred[]; caveats?: Caveat[]; agentBinding?: Record<string, unknown>; holder?: string } = {}): Capability {
  return mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: o.holder ?? aPub,
    goal: 'pay invoices',
    envelope: { predicates: (o.predicates ?? anyPayment) as never, caveats: o.caveats ?? [], agent_binding: (o.agentBinding ?? {}) as never, risk_policy: ZERO_RISK },
  }).grant;
}
const withRootCaveats = (g: Capability, extra: Caveat[], holder = aPub): Capability =>
  mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder, caveats: [...g.caveats, ...extra] });

/** A grant held by the principal and delegated to the agent with `hop` caveats: chain [root, hop]. */
function delegated(hop: Caveat[], root: Capability = envelopeGrant({ holder: pPub })): { grant: Capability; chain: Capability[] } {
  return { grant: root, chain: [root, delegate(root, aPub, hop, principal.secretKey)] };
}

const pay = (amount: number, extra: Record<string, unknown> = {}) => ({ amount, currency: 'usd', ...extra });

interface Sign {
  verb?: string;
  resource?: string;
  params: Record<string, unknown>;
  counter: number;
  aud?: string;
  toolBinding?: string;
}
function sign(grant: Capability, chain: Capability[], s: Sign): PCActn {
  const node: PlanNode = { id: 'n1', verb: s.verb ?? VERB, resource: s.resource ?? RES, params_digest: paramsDigest(s.params), reversibility_class: 'irreversible' };
  return buildPCActn({ grant, chain, plan: [node], nodeId: 'n1', params: s.params, counter: s.counter, signerSecret: agent.secretKey, aud: s.aud ?? AUD, now: NOW, ...(s.toolBinding ? { toolBinding: s.toolBinding } : {}) });
}

interface Expect {
  allow: boolean;
  status: 200 | 401 | 403;
  failed: string[];
  /** A substring the decisive reason / reasons must contain (B6: the failing limit, `replay:`). Checked against TS here. */
  reason?: string;
}
interface Step {
  pcactn: PCActn;
  operation: { verb: string; resource: string; params: Record<string, unknown> };
  revoked: boolean;
  expect: Expect;
  ts?: { allow: boolean; status: number };
}
interface Case {
  name: string;
  description: string;
  grant: Capability;
  steps: Step[];
}

const ALLOW: Expect = { allow: true, status: 200, failed: [] };
const deny = (status: 401 | 403, ...failed: string[]): Expect => ({ allow: false, status, failed: failed.sort() });
const op = (params: Record<string, unknown>, o: { verb?: string; resource?: string } = {}) => ({ verb: o.verb ?? VERB, resource: o.resource ?? RES, params });

function one(name: string, description: string, grant: Capability, chain: Capability[], s: Sign, operation: Step['operation'], expect: Expect, revoked = false): Case {
  return { name, description, grant, steps: [{ pcactn: sign(grant, chain, s), operation, revoked, expect }] };
}

const cases: Case[] = [];
const gPred = envelopeGrant({ predicates: [{ verb: VERB, resource: 'payments/*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }] });
const gEnvCav = envelopeGrant({ caveats: [{ type: 'max_spend', usd: 100 }] });
const gRoot = withRootCaveats(envelopeGrant(), [{ type: 'max_spend', usd: 100 }]);
const dSpend = delegated([{ type: 'max_spend', usd: 100 }]);

// ---- the reviewer acceptance: $400 under a $100 grant, set four ways
for (const [tag, g, chain, failed] of [
  ['envelope-predicate', gPred, [gPred], 'policy'],
  ['envelope-max-spend', gEnvCav, [gEnvCav], 'policy'],
  ['root-max-spend', gRoot, [gRoot], 'policy'],
  ['delegated-max-spend', dSpend.grant, dSpend.chain, 'delegated_caveats'],
] as const) {
  cases.push(one(`${tag}-within`, `$100 limit (${tag}), a $50 payment: allowed.`, g, [...chain], { params: pay(50), counter: 1 }, op(pay(50)), ALLOW));
  cases.push(one(`${tag}-400-refused`, `$100 limit (${tag}), a validly signed $400 payment: refused before the handler runs.`, g, [...chain], { params: pay(400), counter: 1 }, op(pay(400)), tag === 'envelope-predicate' ? { ...deny(403, failed), reason: 'amount <= 100 not satisfied for payments.send on payments/acme' } : deny(403, failed)));
  cases.push(
    one(`${tag}-signed-50-executes-400`, `$100 limit (${tag}): a proof signed for $50 used to execute $400 is refused (binding, and the limit judges the executed $400).`, g, [...chain], { params: pay(50), counter: 1 }, op(pay(400)), deny(403, 'operation', 'params_digest', 'plan_root_authorized', failed)),
  );
}

// ---- binding: a proof for operation X used for Y
cases.push(one('operation-other-verb', 'A payments.send proof used for payments.refund (same params): refused.', gEnvCav, [gEnvCav], { params: pay(50), counter: 1 }, op(pay(50), { verb: 'payments.refund' }), deny(403, 'operation', 'plan_root_authorized')));
cases.push(one('operation-other-resource', 'A proof for payments/acme used on payments/mallory: refused.', gEnvCav, [gEnvCav], { params: pay(50), counter: 1 }, op(pay(50), { resource: 'payments/mallory' }), deny(403, 'operation', 'plan_root_authorized')));
cases.push(one('operation-other-params', 'A proof for one payee used for another (same amount): refused.', gEnvCav, [gEnvCav], { params: pay(50, { payee: 'acme' }), counter: 1 }, op(pay(50, { payee: 'mallory' })), deny(403, 'operation', 'params_digest', 'plan_root_authorized')));

// ---- replay
{
  const p1 = sign(gEnvCav, [gEnvCav], { params: pay(50), counter: 1 });
  const p2 = sign(gEnvCav, [gEnvCav], { params: pay(60), counter: 2 });
  cases.push({
    name: 'replay',
    description: 'Counter 1 allowed, the same PCActn again refused, counter 2 allowed, counter 1 again refused (monotone per grant + holder).',
    grant: gEnvCav,
    steps: [
      { pcactn: p1, operation: op(pay(50)), revoked: false, expect: ALLOW },
      { pcactn: p1, operation: op(pay(50)), revoked: false, expect: { ...deny(403, 'replay'), reason: 'replay: 1 is not greater than last seen 1' } },
      { pcactn: p2, operation: op(pay(60)), revoked: false, expect: ALLOW },
      { pcactn: p1, operation: op(pay(50)), revoked: false, expect: deny(403, 'replay') },
    ],
  });
  const d1 = sign(gEnvCav, [gEnvCav], { params: pay(500), counter: 1 });
  cases.push({
    name: 'denied-does-not-consume',
    description: 'A denied action does not consume its counter: $500 refused at counter 1, then a $50 action at counter 1 is allowed.',
    grant: gEnvCav,
    steps: [
      { pcactn: d1, operation: op(pay(500)), revoked: false, expect: deny(403, 'policy') },
      { pcactn: p1, operation: op(pay(50)), revoked: false, expect: ALLOW },
    ],
  });
}

// ---- revocation
cases.push(one('revoked', 'A valid $50 payment under a revoked grant: refused.', gEnvCav, [gEnvCav], { params: pay(50), counter: 1 }, op(pay(50)), deny(403, 'revocation'), true));

// ---- caveat semantics
{
  const gNote = withRootCaveats(envelopeGrant(), [{ type: 'note', text: 'ops' } as Caveat]);
  cases.push(one('root-unknown-caveat', 'An unknown root caveat type ("note") fails closed.', gNote, [gNote], { params: pay(1), counter: 1 }, op(pay(1)), deny(403, 'policy')));
  const dNote = delegated([{ type: 'geo_fence', region: 'eu' } as Caveat]);
  cases.push(one('delegated-unknown-caveat', 'An unknown delegated caveat type fails closed.', dNote.grant, dNote.chain, { params: pay(1), counter: 1 }, op(pay(1)), deny(403, 'delegated_caveats')));
  const dPred = delegated([predicatesCaveat([{ verb: VERB, resource: 'payments/acme' } as never])]);
  cases.push(one('delegated-predicates-within', 'A delegated predicates caveat (payments/acme only): a payment to acme is allowed.', dPred.grant, dPred.chain, { params: pay(10), counter: 1 }, op(pay(10)), ALLOW));
  cases.push(one('delegated-predicates-outside', 'The same caveat: a payment to payments/other is refused (the envelope alone would allow it).', dPred.grant, dPred.chain, { params: pay(10), resource: 'payments/other', counter: 1 }, op(pay(10), { resource: 'payments/other' }), deny(403, 'delegated_caveats')));
  const ts = toolSchemaCaveat({ name: VERB, params: ['amount', 'currency'] }, { props: { amount: { type: 'number', min: 0, max: 100 }, currency: { type: 'string', enum: ['usd'] } }, required: ['amount'] });
  const dTool = delegated([ts]);
  cases.push(one('delegated-tool-schema-within', 'A delegated tool_schema caveat (amount <= 100, currency usd): $50 allowed.', dTool.grant, dTool.chain, { params: pay(50), counter: 1 }, op(pay(50)), ALLOW));
  cases.push(one('delegated-tool-schema-400', 'The same caveat: $400 refused.', dTool.grant, dTool.chain, { params: pay(400), counter: 1 }, op(pay(400)), deny(403, 'delegated_caveats')));
  cases.push(one('delegated-tool-schema-extra-arg', 'The same caveat: an argument the schema does not declare is refused.', dTool.grant, dTool.chain, { params: pay(50, { memo: 'x' }), counter: 1 }, op(pay(50, { memo: 'x' })), deny(403, 'delegated_caveats')));
  cases.push(one('delegated-tool-schema-bound-tool', 'The same caveat with a signed tool_binding equal to its signature digest: allowed.', dTool.grant, dTool.chain, { params: pay(50), counter: 1, toolBinding: ts.signature_digest }, op(pay(50)), ALLOW));
  cases.push(one('delegated-tool-schema-other-binding', 'The same caveat with a signed tool_binding for another tool signature: refused.', dTool.grant, dTool.chain, { params: pay(50), counter: 1, toolBinding: ts.binding_digest }, op(pay(50)), deny(403, 'delegated_caveats')));
  const gNone = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: aPub, caveats: [{ type: 'max_spend', usd: 100 } as Caveat] });
  cases.push(one('no-envelope', 'A grant without a policy envelope: refused (default deny).', gNone, [gNone], { params: pay(1), counter: 1 }, op(pay(1)), deny(403, 'policy')));
  const gPredOnly = envelopeGrant({ predicates: [{ verb: 'payments.refund', resource: 'payments/*' }] });
  cases.push(one('envelope-predicate-verb', 'Envelope predicates permit refunds only: a send is refused.', gPredOnly, [gPredOnly], { params: pay(1), counter: 1 }, op(pay(1)), deny(403, 'policy')));
  const gAtt = envelopeGrant({ agentBinding: { operator: 'acme-ops' } });
  cases.push(one('attestation-bound', 'A grant that pins the agent (agent_binding.operator) needs an attestation: refused without one.', gAtt, [gAtt], { params: pay(1), counter: 1 }, op(pay(1)), deny(403, 'attestation')));
  cases.push(one('wrong-audience', 'A proof for another resource server: refused as unauthenticated.', gEnvCav, [gEnvCav], { params: pay(1), counter: 1, aud: 'other-rs' }, op(pay(1)), deny(401, 'audience')));
}

async function main() {
  const out = resolve(process.argv[2] ?? 'sdks/python-pca/testdata/authorize-fixtures.json');
  let tsAuthorizer: ((c: Case) => Promise<void>) | undefined;
  try {
    const az = (await import('../src/server/authorize')) as typeof import('../src/server/authorize');
    const rp = (await import('../src/server/require-pca')) as Record<string, unknown>;
    // the atomic store (0.5, T2) when present, else the locked in-memory store
    const store = (rp.atomicMemoryPcaStore ?? rp.memoryPcaStore) as () => unknown;
    tsAuthorizer = async (c) => {
      let revoked = false;
      const run = az.createAuthorizer({
        audience: AUD,
        resolveGrant: async (ref: string) => (ref === c.grant.id ? c.grant : null),
        budgetStore: store(),
        hooks: { revocation: () => ({ enforced: true, ok: !revoked }) },
        plan: 'single-step',
        now: () => NOW,
      } as never);
      for (const s of c.steps) {
        revoked = s.revoked;
        const r = await run({ pcactn: s.pcactn, operation: s.operation });
        s.ts = { allow: r.allow, status: r.status };
        const why = [(r as { reason?: string }).reason, ...((r as { verdict?: { reasons?: string[] } }).verdict?.reasons ?? [])].filter(Boolean).join(' | ');
        if (s.expect.reason !== undefined && !why.includes(s.expect.reason)) throw new Error(`${c.name}: TS reason ${JSON.stringify(why)} does not contain ${JSON.stringify(s.expect.reason)}`);
      }
    };
  } catch {
    console.warn('src/server/authorize.ts not found: fixtures written without the `ts` outcomes');
  }
  if (tsAuthorizer) for (const c of cases) await tsAuthorizer(c);
  const doc = {
    format: 'pca-authorize-fixtures/1',
    description:
      'authorize() acceptance cases for native SDKs. Run each case against ONE fresh replay store, steps in order. `expect` is the native pipeline outcome (sorted failing checks); `ts` is the TypeScript authorize() outcome when recorded.',
    now: NOW,
    audience: AUD,
    plan: 'single-step',
    cases,
  };
  writeFileSync(out, JSON.stringify(doc, null, 1) + '\n');
  const mism = cases.flatMap((c) => c.steps.filter((s) => s.ts && (s.ts.allow !== s.expect.allow || s.ts.status !== s.expect.status)).map(() => c.name));
  console.log(`wrote ${cases.length} cases (${cases.reduce((n, c) => n + c.steps.length, 0)} steps) to ${out}${tsAuthorizer ? `; TS authorize disagreements: ${mism.length ? mism.join(', ') : 'none'}` : ''}`);
}

void main();
