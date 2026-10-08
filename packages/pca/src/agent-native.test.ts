import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical } from './hash';
import { generateKeyPair } from './keys';
import { attenuate, delegate, verifyChain, type Capability, type CapabilityChain } from './capability';
import { mintGrant } from './envelope';
import { evaluateCaveats } from './predicates';
import {
  CAVEAT_ENVELOPE,
  CAVEAT_PREDICATES,
  CAVEAT_TOOL_SCHEMA,
  HEARTBEAT_SKEW_MS,
  MAX_LEASE_TTL_MS,
  agentNativeCaveatEvaluator,
  auditRationale,
  bindRationale,
  checkCautionMonotone,
  combineCaution,
  combineSignedCaution,
  describeEnvelope,
  envelopePermits,
  envelopePermitsToolCall,
  evaluateToolSchema,
  grantLease,
  isStrongSalt,
  leaseState,
  predicatesCaveat,
  renewLease,
  signCaution,
  signHeartbeat,
  toolSchemaCaveat,
  toolSchemaEvaluator,
  validateArgSchema,
  verifyCaution,
  verifyRationale,
  type ArgSchema,
  type CautionClaim,
  type CapabilityLease,
  type ToolSchemaCaveat,
} from './agent-native';
import { requiredThreshold, DEFAULT_RISK_POLICY as P } from './risk';

const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pk: b64u(k.publicKey) };
};
const SALT = b64u(Uint8Array.from({ length: 16 }, (_, i) => i * 13 + 7));
const SALT2 = b64u(Uint8Array.from({ length: 16 }, (_, i) => i * 17 + 3));

describe('1. uncertainty attestation', () => {
  it('under-report gains nothing; over-report escalates', () => {
    expect(combineCaution(0, 0.6)).toBe(0.6);
    expect(combineCaution(0.1, 0.6)).toBe(0.6);
    expect(combineCaution(0.9, 0.2)).toBe(0.9);
    expect(requiredThreshold(combineCaution(0.95, 0.05), P).t).toBeGreaterThan(requiredThreshold(0.05, P).t);
    expect(requiredThreshold(combineCaution(0, 0.95), P).t).toBe(requiredThreshold(0.95, P).t);
  });
  it('monotone combine grid: >= server risk, non-decreasing in declared, result in [0,1], idempotent', () => {
    const grid = [-1, 0, 0.1, 0.25, 0.5, 0.75, 0.9, 1, 2];
    expect(checkCautionMonotone(grid).ok).toBe(true);
    for (const s of grid) {
      for (const d of grid) {
        const e = combineCaution(d, s);
        expect(e).toBeGreaterThanOrEqual(Math.min(1, Math.max(0, s)));
        expect(e).toBeLessThanOrEqual(1);
        expect(combineCaution(e, s)).toBe(e);
        expect(combineCaution(d, s)).toBe(combineCaution(d, s)); // deterministic
      }
    }
  });
  it('junk declarations ignored; junk server risk fails closed to 1', () => {
    expect(combineCaution(NaN, 0.4)).toBe(0.4);
    expect(combineCaution(Infinity, 0.4)).toBe(0.4);
    expect(combineCaution(undefined, 0.4)).toBe(0.4);
    expect(combineCaution('0' as never, 0.4)).toBe(0.4);
    expect(combineCaution(-5, 0.4)).toBe(0.4);
    expect(combineCaution(0.2, NaN)).toBe(1);
    expect(combineCaution(0, Infinity)).toBe(1);
    expect(combineCaution(0, undefined as never)).toBe(1);
  });
  it('signed claim binds to action digest; rebind to another action is rejected', () => {
    const a = kp();
    const action = { verb: 'pay', resource: '/acct/1' };
    const ad = hashCanonical(action);
    const other = hashCanonical({ verb: 'pay', resource: '/acct/2' });
    const claim = signCaution({ action_digest: ad, caution: 0.8, holder: a.pk, reason: 'ambiguous_instruction' }, a.sk);
    expect(verifyCaution(claim, ad)).toBe(true);
    expect(combineSignedCaution(claim, ad, 0.2)).toEqual({ effectiveRisk: 0.8, honoured: true, escalated: true });
    // rebind: same signed claim presented for a different action
    expect(verifyCaution(claim, other)).toBe(false);
    expect(combineSignedCaution(claim, other, 0.2)).toEqual({ effectiveRisk: 0.2, honoured: false, escalated: false });
    // re-pointing the digest field breaks the signature
    expect(verifyCaution({ ...claim, action_digest: other }, other)).toBe(false);
    const tampered = { ...claim, caution: 0.99 };
    expect(verifyCaution(tampered, ad)).toBe(false);
    expect(combineSignedCaution(tampered, ad, 0.2).effectiveRisk).toBe(0.2);
  });
  it('holder binding: a claim signed by another key is not honoured when expectedHolder is given', () => {
    const a = kp(), m = kp();
    const ad = hashCanonical({ x: 1 });
    const byM = signCaution({ action_digest: ad, caution: 0.9, holder: m.pk }, m.sk);
    expect(verifyCaution(byM, ad)).toBe(true); // self-consistent...
    expect(verifyCaution(byM, ad, a.pk)).toBe(false); // ...but not the PCActn holder
    expect(combineSignedCaution(byM, ad, 0.1, a.pk).honoured).toBe(false);
    // forgery: holder claims a.pk but signed by m
    const forged = { ...byM, holder: a.pk };
    expect(verifyCaution(forged, ad, a.pk)).toBe(false);
  });
  it('NaN / out-of-range / smuggled fields fail closed; signing invalid body throws', () => {
    const a = kp();
    const ad = hashCanonical({ x: 1 });
    expect(() => signCaution({ action_digest: ad, caution: NaN, holder: a.pk }, a.sk)).toThrow();
    expect(() => signCaution({ action_digest: ad, caution: 1.5, holder: a.pk }, a.sk)).toThrow();
    expect(() => signCaution({ action_digest: ad, caution: 0.5, holder: a.pk, reason: 'bad reason!' }, a.sk)).toThrow();
    const good = signCaution({ action_digest: ad, caution: 0.5, holder: a.pk }, a.sk);
    expect(verifyCaution({ ...good, caution: NaN }, ad)).toBe(false);
    expect(verifyCaution({ ...good, caution: 2 } as CautionClaim, ad)).toBe(false);
    expect(verifyCaution({ ...good, extra: 1 } as never, ad)).toBe(false);
    expect(verifyCaution({ ...good, sig: 'AAAA' }, ad)).toBe(false);
    expect(verifyCaution(null as never, ad)).toBe(false);
    expect(verifyCaution({} as never, ad)).toBe(false);
  });
});

describe('2. rationale binding', () => {
  const action = { verb: 'refund', resource: '/order/9', params: { amt: 10 } };
  it('commit/reveal round-trips, deterministic given salt, hiding via salt', () => {
    const r1 = bindRationale(action, 'customer requested refund per ticket 44', SALT);
    const r2 = bindRationale(action, 'customer requested refund per ticket 44', SALT);
    expect(r1).toEqual(r2);
    expect(verifyRationale(r1.commitment, r1.reveal, action)).toBe(true);
    expect(bindRationale(action, 'x', SALT).commitment.commitment).not.toBe(bindRationale(action, 'x', SALT2).commitment.commitment);
    const d1 = bindRationale(action, 'x'), d2 = bindRationale(action, 'x');
    expect(d1.commitment.commitment).not.toBe(d2.commitment.commitment);
    expect(isStrongSalt(d1.reveal.salt)).toBe(true);
  });
  it('commitment binds the action digest: cannot be re-attached to another action', () => {
    const { commitment, reveal } = bindRationale(action, 'reason A', SALT);
    expect(commitment.action_digest).toBe(hashCanonical(action));
    expect(verifyRationale(commitment, reveal, { ...action, resource: '/order/10' })).toBe(false);
    // forge: swap the digest, keep the commitment hash
    expect(verifyRationale({ ...commitment, action_digest: hashCanonical({ other: 1 }) }, reveal)).toBe(false);
  });
  it('detects mismatch: altered text or salt', () => {
    const { commitment, reveal } = bindRationale(action, 'reason A', SALT);
    expect(verifyRationale(commitment, { ...reveal, rationale: 'reason B' })).toBe(false);
    expect(verifyRationale(commitment, { ...reveal, salt: SALT2 })).toBe(false);
    expect(verifyRationale(commitment, { rationale: 1, salt: SALT } as never)).toBe(false);
    expect(verifyRationale({ ...commitment, v: 2 } as never, reveal)).toBe(false);
    expect(verifyRationale(null as never, reveal)).toBe(false);
  });
  it('low-entropy salt rejected at bind and at verify', () => {
    for (const weak of ['salt1', '', 'AAAAAAAAAAAAAAAAAAAAAA', b64u(new Uint8Array(32)), b64u(Uint8Array.from({ length: 16 }, (_, i) => i % 3)), 'not base64!!!!!!!!!!!!!!!!']) {
      expect(isStrongSalt(weak)).toBe(false);
      expect(() => bindRationale(action, 'x', weak)).toThrow();
    }
    expect(isStrongSalt(SALT)).toBe(true);
    // a commitment made with a weak salt by other means is not an acceptable opening
    const ad = hashCanonical(action);
    const weakCommit = { v: 1 as const, action_digest: ad, commitment: hashCanonical({ d: 'atlas-pca/rationale/v1', a: ad, s: 'salt1', r: 'x' }) };
    expect(verifyRationale(weakCommit, { rationale: 'x', salt: 'salt1' })).toBe(false);
    expect(() => bindRationale(action, 'x'.repeat(9000), SALT)).toThrow();
    expect(() => bindRationale(action, 5 as never, SALT)).toThrow();
  });
  it('audit: false rationale and withheld reveal are slashable; true one is not; judge crash is not', () => {
    const { commitment, reveal } = bindRationale(action, 'ticket 44 exists', SALT);
    expect(auditRationale(commitment, action, reveal, () => true)).toMatchObject({ verdict: 'consistent', slashable: false });
    expect(auditRationale(commitment, action, reveal, () => false)).toMatchObject({ verdict: 'false_rationale', slashable: true });
    expect(auditRationale(commitment, action, undefined, () => true)).toMatchObject({ verdict: 'unopened', slashable: true });
    expect(auditRationale(commitment, action, { ...reveal, rationale: 'swapped' }, () => true)).toMatchObject({ verdict: 'unopened', slashable: true });
    expect(auditRationale(commitment, { x: 1 }, reveal, () => false)).toMatchObject({ verdict: 'wrong_action', slashable: false });
    expect(auditRationale(commitment, action, reveal, () => { throw new Error('boom'); })).toMatchObject({ verdict: 'judge_error', slashable: false });
    expect(auditRationale(null as never, action, reveal, () => true)).toMatchObject({ verdict: 'malformed', slashable: false });
  });
});

describe('3. semantic firewall (nested tool-arg schemas)', () => {
  const sig = { name: 'create_order', params: { customer: 'object', items: 'array', note: 'string' } };
  const schema: ArgSchema = {
    props: {
      customer: {
        type: 'object',
        props: {
          id: { type: 'string', prefix: 'cus_', maxLength: 32 },
          address: { type: 'object', props: { country: { type: 'string', enum: ['US', 'CA'] }, zip: { type: 'string', minLength: 3, maxLength: 10 } }, required: ['country'] },
        },
        required: ['id'],
      },
      items: {
        type: 'array',
        minItems: 1,
        maxItems: 3,
        items: { type: 'object', props: { sku: { type: 'string', prefix: 'sku-' }, qty: { type: 'integer', min: 1, max: 5 }, gift: { type: 'boolean' } }, required: ['sku', 'qty'] },
      },
      note: { type: 'string', maxLength: 20 },
      tags: { type: 'array', items: { type: 'string', enum: ['a', 'b'] }, maxItems: 2 },
    },
    required: ['customer', 'items'],
  };
  const cav = toolSchemaCaveat(sig, schema);
  const goodArgs = () => ({
    customer: { id: 'cus_1', address: { country: 'US', zip: '94107' } },
    items: [{ sku: 'sku-1', qty: 2 }, { sku: 'sku-2', qty: 5, gift: true }],
    note: 'hello',
    tags: ['a'],
  });
  const call = (args: unknown) => ({ tool: 'create_order', args: args as Record<string, unknown>, toolSignature: sig });
  const reason = (args: unknown) => evaluateToolSchema(cav, call(args));
  const mut = (f: (a: ReturnType<typeof goodArgs>) => void) => {
    const a = goodArgs();
    f(a);
    return a;
  };

  it('valid nested call passes (and via the CaveatEvaluator adapters)', () => {
    expect(reason(goodArgs()).ok).toBe(true);
    expect(toolSchemaEvaluator(cav, { toolCall: call(goodArgs()) })).toBe(true);
    expect(agentNativeCaveatEvaluator(cav, { now: 1, toolCall: call(goodArgs()) })).toBe(true);
    expect(cav.type).toBe(CAVEAT_TOOL_SCHEMA);
  });
  it('rejects nested wrong type, with the failing path', () => {
    expect(reason(mut((a) => ((a.customer.address as { zip: unknown }).zip = 94107)))).toMatchObject({ ok: false, reason: expect.stringContaining('args.customer.address.zip') });
    expect(reason(mut((a) => ((a.items[0] as { qty: unknown }).qty = '2'))).ok).toBe(false);
    expect(reason(mut((a) => ((a.items[0] as { qty: unknown }).qty = 1.5))).ok).toBe(false);
    expect(reason(mut((a) => ((a as { items: unknown }).items = { sku: 'sku-1', qty: 1 }))).ok).toBe(false); // object where array expected
    expect(reason(mut((a) => ((a as { customer: unknown }).customer = ['cus_1']))).ok).toBe(false); // array where object expected
    expect(reason(mut((a) => ((a as { customer: unknown }).customer = null))).ok).toBe(false);
    expect(reason(mut((a) => ((a.items[1] as { gift: unknown }).gift = 'yes'))).ok).toBe(false);
    expect(reason(mut((a) => ((a as { tags: unknown }).tags = ['c']))).reason).toMatch(/enum/);
  });
  it('rejects nested extra properties (closed at every level)', () => {
    expect(reason(mut((a) => ((a as Record<string, unknown>).bcc = 'x')))).toMatchObject({ ok: false, reason: expect.stringMatching(/unexpected/) });
    expect(reason(mut((a) => ((a.customer as Record<string, unknown>).admin = true)))).toMatchObject({ ok: false, reason: expect.stringMatching(/unexpected/) });
    expect(reason(mut((a) => ((a.items[0] as Record<string, unknown>).price = 0)))).toMatchObject({ ok: false, reason: expect.stringMatching(/unexpected/) });
    // prototype-pollution style keys are just unexpected
    expect(reason(JSON.parse('{"customer":{"id":"cus_1"},"items":[{"sku":"sku-1","qty":1}],"__proto__":{"x":1}}')).ok).toBe(false);
    expect(reason(JSON.parse('{"customer":{"id":"cus_1","constructor":1},"items":[{"sku":"sku-1","qty":1}]}')).ok).toBe(false);
  });
  it('rejects nested missing required properties and array bounds', () => {
    expect(reason(mut((a) => delete (a.customer as Partial<typeof a.customer>).id)).reason).toMatch(/missing required argument 'id'/);
    expect(reason(mut((a) => delete (a.customer.address as { country?: string }).country)).reason).toMatch(/missing/);
    expect(reason(mut((a) => delete (a.items[0] as { qty?: number }).qty)).reason).toMatch(/missing/);
    expect(reason(mut((a) => ((a as { items: unknown[] }).items = []))).reason).toMatch(/minItems/);
    expect(reason(mut((a) => ((a as { items: unknown[] }).items = Array.from({ length: 4 }, () => ({ sku: 'sku-1', qty: 1 }))))).reason).toMatch(/maxItems/);
    expect(reason(mut((a) => ((a as { tags: unknown[] }).tags = ['a', 'b', 'a']))).reason).toMatch(/maxItems/);
    // sparse array hole
    const holey = goodArgs();
    (holey.items as unknown[]).length = 3;
    expect(reason(holey).reason).toMatch(/hole/);
  });
  it('rejects nested out-of-range / prefix / enum / length', () => {
    expect(reason(mut((a) => ((a.items[0] as { qty: number }).qty = 6))).reason).toMatch(/above max/);
    expect(reason(mut((a) => ((a.items[0] as { qty: number }).qty = 0))).reason).toMatch(/below min/);
    expect(reason(mut((a) => ((a.items[0] as { sku: string }).sku = 'evil-1'))).reason).toMatch(/prefix/);
    expect(reason(mut((a) => ((a.customer.address as { country: string }).country = 'RU'))).reason).toMatch(/enum/);
    expect(reason(mut((a) => ((a.customer.address as { zip: string }).zip = 'zz'))).reason).toMatch(/minLength/);
    expect(reason(mut((a) => ((a.customer as { id: string }).id = 'cus_' + 'x'.repeat(40)))).reason).toMatch(/maxLength/);
    expect(reason(mut((a) => ((a.items[0] as { qty: number }).qty = NaN))).ok).toBe(false);
    expect(reason(mut((a) => ((a.items[0] as { qty: number }).qty = Infinity))).ok).toBe(false);
  });
  it('rejects wrong tool, swapped signature, non-plain args', () => {
    expect(evaluateToolSchema(cav, { ...call(goodArgs()), tool: 'delete_all' }).ok).toBe(false);
    expect(evaluateToolSchema(cav, { ...call(goodArgs()), toolSignature: { ...sig, params: {} } }).reason).toMatch(/signature/);
    expect(evaluateToolSchema(cav, call(new Map())).ok).toBe(false);
    expect(evaluateToolSchema(cav, call([goodArgs()])).ok).toBe(false);
    expect(evaluateToolSchema(cav, null as never).ok).toBe(false);
    expect(toolSchemaEvaluator(cav, {})).toBe(false);
    expect(toolSchemaEvaluator({ type: 'other' }, { toolCall: call(goodArgs()) })).toBe(false);
  });
  it('DoS bounds: deep / huge / cyclic args fail closed (no throw, fast)', () => {
    const deep: Record<string, unknown> = {};
    let cur = deep;
    for (let i = 0; i < 5000; i++) cur = (cur.x = {}) as Record<string, unknown>;
    expect(reason({ customer: deep, items: [] }).ok).toBe(false);
    const cyc = goodArgs() as Record<string, unknown>;
    cyc.self = cyc;
    expect(reason(cyc).ok).toBe(false);
    const flat: ArgSchema = { props: { l: { type: 'array', items: { type: 'array', items: { type: 'integer' }, maxItems: 4096 }, maxItems: 4096 } } };
    const big = toolSchemaCaveat('big', flat);
    // Build the oversized input OUTSIDE the timed region (200x200 = 40k nodes, well
    // past the 10k visit cap) so we time the validator bailing, not array allocation.
    const bigArgs = { l: Array.from({ length: 200 }, () => Array.from({ length: 200 }, () => 1)) };
    const t0 = Date.now();
    const r = evaluateToolSchema(big, { tool: 'big', args: bigArgs });
    expect(r.ok).toBe(false);
    expect(Date.now() - t0).toBeLessThan(1000);
    // default array cap when the schema sets none
    const nocap = toolSchemaCaveat('t', { props: { l: { type: 'array', items: { type: 'integer' } } } });
    expect(evaluateToolSchema(nocap, { tool: 't', args: { l: Array.from({ length: 300 }, () => 1) } }).ok).toBe(false);
    // adversarial string "regex-looking" content is only compared with startsWith/length: linear
    const s = 'a'.repeat(60_000) + '!';
    expect(evaluateToolSchema(toolSchemaCaveat('t', { props: { s: { type: 'string', prefix: 'a' } } }), { tool: 't', args: { s } }).ok).toBe(true);
  });
  it('schema validation: bad schemas are refused at authoring and at evaluation', () => {
    expect(() => toolSchemaCaveat('', { props: {} })).toThrow();
    expect(() => toolSchemaCaveat('t', { props: { 'bad name': { type: 'string' } } })).toThrow();
    expect(() => toolSchemaCaveat('t', { props: { a: { type: 'string', pattern: '(a+)+$' } as never } })).toThrow(); // no regex keyword exists
    expect(() => toolSchemaCaveat('t', { props: { a: { type: 'wat' } as never } })).toThrow();
    expect(() => toolSchemaCaveat('t', { props: { a: { type: 'integer', min: 5, max: 1 } } })).toThrow();
    expect(() => toolSchemaCaveat('t', { props: { a: { type: 'string', enum: [1] as never } } })).toThrow();
    expect(() => toolSchemaCaveat('t', { props: {}, required: ['nope'] })).toThrow();
    let nest: never = { type: 'string' } as never;
    for (let i = 0; i < 12; i++) nest = { type: 'array', items: nest } as never;
    expect(validateArgSchema({ props: { a: nest } })).toMatch(/deep/);
    expect(validateArgSchema({ props: {}, evil: 1 })).toMatch(/unknown/);
    expect(validateArgSchema(null)).toMatch(/object/);
    // hand-crafted invalid schema inside a caveat is rejected at evaluation too
    const forged = { ...cav, schema: { props: { a: { type: 'wat' } } } } as unknown as ToolSchemaCaveat;
    expect(evaluateToolSchema(forged, call({})).ok).toBe(false);
  });
  it('post-sign schema edit rejected (standalone digest + chain signature)', () => {
    // standalone: digest mismatch
    const edited = { ...cav, schema: { ...cav.schema, props: { ...cav.schema.props, note: { type: 'string' as const } } } };
    expect(evaluateToolSchema(edited, call(goodArgs())).reason).toMatch(/digest/);
    // loosened tool name / signature binding
    expect(evaluateToolSchema({ ...cav, tool: 'other' }, { ...call(goodArgs()), tool: 'other' }).reason).toMatch(/binding/);
    expect(evaluateToolSchema({ ...cav, signature_digest: hashCanonical('x') }, { tool: 'create_order', args: goodArgs() }).reason).toMatch(/binding/);
    // re-digested edit (attacker recomputes digests) is caught by the capability signature
    const p = kp(), a = kp(), b = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'g',
      envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: P },
    }).grant;
    const child = delegate(root, b.pk, [cav], a.sk);
    expect(verifyChain([root, child]).ok).toBe(true);
    const looser = toolSchemaCaveat(sig, { props: { ...schema.props, note: { type: 'string' } }, required: ['customer'] });
    const tampered: Capability = { ...child, caveats: [...child.caveats.slice(0, -1), looser] };
    expect(verifyChain([root, tampered]).ok).toBe(false);
    expect(describeEnvelope([root, tampered])).toMatchObject({ ok: false, tools: [] });
  });
});

describe('4. capability introspection (canonical envelope)', () => {
  const sig = { name: 'send_email', params: { to: 'string', body: 'object' } };
  const toolCav = toolSchemaCaveat(sig, {
    props: { to: { type: 'string', prefix: 'ops@' }, body: { type: 'object', props: { text: { type: 'string', maxLength: 10 } }, required: ['text'] } },
    required: ['to'],
  });
  const build = () => {
    const p = kp(), a = kp(), b = kp(), c = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'ops',
      envelope: {
        predicates: [
          { verb: ['read', 'write', 'delete'], resource: '/acct/*' },
          { verb: 'read', resource: '/docs/*' },
        ],
        caveats: [
          { type: 'expires', at: 10_000 },
          { type: 'max_blast_radius', max: 0.5 },
          { type: 'delegation_depth', max: 3 },
        ],
        agent_binding: {},
        risk_policy: P,
      },
    }).grant;
    const h1 = delegate(root, b.pk, [
      predicatesCaveat([{ verb: ['read', 'write'], resource: '/acct/*' }, { verb: 'read', resource: '/docs/public/*' }]),
      { type: 'expires', at: 6_000 },
      { type: 'rate', max: 5, per_secs: 60 },
    ], a.sk);
    const h2 = delegate(h1, c.pk, [
      predicatesCaveat([{ verb: ['read', 'write', 'send'], resource: '/acct/42/*' }]),
      { type: 'max_blast_radius', max: 0.2 },
      { type: 'reversibility_max', class: 'rate_limited' },
      toolCav,
    ], b.sk);
    return { chain: [root, h1, h2] as CapabilityChain, root, h1, h2, a, b, c, p };
  };

  it('multi-hop delegation: narrowed canonical envelope incl. tool constraints', () => {
    const { chain } = build();
    const env = describeEnvelope(chain, 1_000);
    expect(env.ok).toBe(true);
    expect(env.hasEnvelope).toBe(true);
    expect(env.unsatisfiable).toEqual([]);
    expect(env.scopes).toEqual([{ verbs: ['read', 'write'], resources: ['/acct/42/*'], where: [] }]);
    expect(env.verbs).toEqual(['read', 'write']);
    expect(env.resources).toEqual(['/acct/42/*']);
    expect(env.tools).toEqual(['send_email']);
    expect(env.toolSchemas).toHaveLength(1);
    expect(env.remainingBudgetHints).toMatchObject({
      expiresAt: 6_000, expiresIn: 5_000, maxBlastRadius: 0.2, maxRate: { max: 5, per_secs: 60 },
      reversibilityMax: 'rate_limited', delegationDepthRemaining: 1,
    });
    // each hop strictly narrower than its parent
    const e0 = describeEnvelope([chain[0]!]), e1 = describeEnvelope(chain.slice(0, 2));
    expect(e0.verbs).toEqual(['delete', 'read', 'write']);
    expect(e0.resources).toEqual(['/acct/*', '/docs/*']);
    expect(e1.scopes).toEqual(
      expect.arrayContaining([
        { verbs: ['read', 'write'], resources: ['/acct/*'], where: [] },
        { verbs: ['read'], resources: ['/docs/public/*'], where: [] },
      ]),
    );
    expect(e1.scopes).toHaveLength(2);
    expect(describeEnvelope(chain, 1_000)).toEqual(describeEnvelope(chain, 1_000)); // deterministic
  });
  it('envelopePermits / envelopePermitsToolCall pre-flights match the narrowed envelope', () => {
    const env = describeEnvelope(build().chain, 1_000);
    expect(envelopePermits(env, 'read', '/acct/42/x', 1_000)).toBe(true);
    expect(envelopePermits(env, 'write', '/acct/42/x', 1_000)).toBe(true);
    expect(envelopePermits(env, 'delete', '/acct/42/x', 1_000)).toBe(false);
    expect(envelopePermits(env, 'send', '/acct/42/x', 1_000)).toBe(false); // root never allowed 'send'
    expect(envelopePermits(env, 'read', '/acct/7/x', 1_000)).toBe(false);
    expect(envelopePermits(env, 'read', '/docs/public/x', 1_000)).toBe(false); // narrowed away at hop 2
    expect(envelopePermits(env, 'read', '/acct/42/x', 6_000)).toBe(false); // expired
    expect(envelopePermits(env, 'read', '/acct/42/x', NaN)).toBe(false);
    const ok = { tool: 'send_email', args: { to: 'ops@a.com', body: { text: 'hi' } }, toolSignature: sig };
    expect(envelopePermitsToolCall(env, ok).ok).toBe(true);
    expect(envelopePermitsToolCall(env, { ...ok, args: { to: 'ops@a.com', body: { text: 'x'.repeat(11) } } }).ok).toBe(false);
    expect(envelopePermitsToolCall(env, { ...ok, args: { to: 'ops@a.com', body: {} } }).ok).toBe(false);
    expect(envelopePermitsToolCall(env, { ...ok, tool: 'drop_db' }).ok).toBe(false);
  });
  it('the narrowing is exactly what the superset verifier honours (soundness cross-check)', () => {
    const { chain } = build();
    const env = describeEnvelope(chain, 1_000);
    const leaf = chain[2]!;
    const extra = leaf.caveats.slice(1); // beyond the root envelope caveat
    const tc = { tool: 'send_email', args: { to: 'ops@a.com', body: { text: 'hi' } }, toolSignature: sig };
    const cases: [string, string][] = [['read', '/acct/42/x'], ['write', '/acct/42/y'], ['delete', '/acct/42/x'], ['read', '/acct/7/x'], ['read', '/docs/public/z'], ['send', '/acct/42/x']];
    for (const [verb, resource] of cases) {
      const ctx = { now: 1_000, blastRadius: 0.1, reversibilityClass: 'reversible', delegationDepth: 2, recentActionTimes: [], action: { action: { verb, resource } }, toolCall: tc };
      const verifier = evaluateCaveats(extra, ctx as never, agentNativeCaveatEvaluator).ok;
      // the envelope never claims "permit" where the verifier refuses on scope+tool, and vice versa
      expect(envelopePermits(env, verb, resource, 1_000)).toBe(verifier);
    }
  });
  it('stock evaluator rejects the new caveat types (documented: needs agentNativeCaveatEvaluator)', () => {
    const { chain } = build();
    const extra = chain[2]!.caveats.slice(1);
    const ctx = { now: 1_000, blastRadius: 0.1, reversibilityClass: 'reversible', delegationDepth: 2, recentActionTimes: [] };
    const stock = evaluateCaveats(extra, ctx);
    expect(stock.ok).toBe(false);
    expect(stock.failed).toEqual(expect.arrayContaining([CAVEAT_PREDICATES, CAVEAT_TOOL_SCHEMA]));
    expect(agentNativeCaveatEvaluator({ type: 'mystery' }, { now: 1 })).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'predicates', allow: [{ verb: '*' }] }, { now: 1 })).toBe(false); // no action ctx
  });
  it('conditional scopes (where) are carried; params evaluated when supplied', () => {
    const p = kp(), a = kp(), b = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'g',
      envelope: { predicates: [{ verb: 'pay', resource: '/acct/*' }], caveats: [], agent_binding: {}, risk_policy: P },
    }).grant;
    const c = delegate(root, b.pk, [predicatesCaveat([{ verb: 'pay', resource: '/acct/1', where: [{ field: 'action.params.amt', op: 'lte', value: 100 }] }])], a.sk);
    const env = describeEnvelope([root, c]);
    expect(env.scopes).toHaveLength(1);
    expect(env.scopes![0]!.where).toHaveLength(1);
    expect(envelopePermits(env, 'pay', '/acct/1')).toBe(true); // may permit
    expect(envelopePermits(env, 'pay', '/acct/1', undefined, { amt: 50 })).toBe(true);
    expect(envelopePermits(env, 'pay', '/acct/1', undefined, { amt: 500 })).toBe(false);
    expect(envelopePermits(env, 'pay', '/acct/1', undefined, {})).toBe(false); // missing => fail closed
  });
  it('regex resource constraints are reported opaque yet still enforced', () => {
    const p = kp(), a = kp(), b = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'g',
      envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], agent_binding: {}, risk_policy: P },
    }).grant;
    const c = delegate(root, b.pk, [predicatesCaveat([{ verb: 'read', resource: 're:/a/[0-9]+' }])], a.sk);
    const env = describeEnvelope([root, c]);
    expect(env.opaqueResourceConstraints).toEqual(['re:/a/[0-9]+']);
    expect(envelopePermits(env, 'read', '/a/12')).toBe(true);
    expect(envelopePermits(env, 'read', '/a/xx')).toBe(false);
    expect(envelopePermits(env, 'read', '/b/12')).toBe(false);
  });
  it('disjoint attenuation yields empty envelope; bad chain ok:false; two different tools => none callable', () => {
    const p = kp(), a = kp(), b = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'g',
      envelope: { predicates: [{ verb: '*', resource: '/a/*' }], caveats: [], agent_binding: {}, risk_policy: P },
    }).grant;
    const c = attenuate(root, [predicatesCaveat([{ verb: '*', resource: '/b/*' }]), toolSchemaCaveat('t', { props: {} })], a.sk);
    const env = describeEnvelope([root, c]);
    expect(env.scopes).toEqual([]);
    expect(env.tools).toEqual(['t']);
    expect(envelopePermits(env, 'read', '/a/x')).toBe(false);
    expect(describeEnvelope([c]).ok).toBe(false);
    expect(describeEnvelope([]).ok).toBe(false);
    const c2 = attenuate(c, [toolSchemaCaveat('u', { props: {} })], a.sk);
    void b;
    expect(describeEnvelope([root, c, c2]).tools).toEqual([]);
  });
  it('unknown / malformed / duplicate-envelope caveats make the envelope unsatisfiable (matches the verifier)', () => {
    const p = kp(), a = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'g',
      envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: P },
    }).grant;
    const legacy = attenuate(root, [{ type: 'verbs', allow: ['read'] }], a.sk); // the removed ad-hoc vocabulary
    const e1 = describeEnvelope([root, legacy]);
    expect(e1.unsatisfiable).toEqual(['verbs']);
    expect(envelopePermits(e1, 'read', '/x')).toBe(false);
    expect(e1.verbs).toEqual([]);
    const bad = attenuate(root, [{ type: 'expires', at: 'soon' }], a.sk);
    expect(describeEnvelope([root, bad]).unsatisfiable).toEqual(['expires']);
    const dup = attenuate(root, [{ type: CAVEAT_ENVELOPE, predicates: [], caveats: [] }], a.sk);
    expect(describeEnvelope([root, dup]).unsatisfiable).toEqual([CAVEAT_ENVELOPE]);
    const depth = attenuate(root, [{ type: 'delegation_depth', max: 0 }], a.sk);
    const env = describeEnvelope([root, depth]);
    expect(env.remainingBudgetHints.delegationDepthRemaining).toBe(-1);
    expect(envelopePermits(env, 'read', '/x')).toBe(false);
  });
  it('a chain without an envelope caveat is reported (hasEnvelope false, scope unrestricted by predicates)', () => {
    const p = kp(), a = kp();
    const root = mintGrant({
      principalSecret: p.sk, principalPublic: p.pk, holder: a.pk, goal: 'g',
      envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: P },
    }).grant;
    expect(describeEnvelope([root]).scopes).toEqual([]); // empty predicates = default deny
    expect(envelopePermits(describeEnvelope([root]), 'read', '/x')).toBe(false);
  });
});

describe('5. authority lease', () => {
  const a = kp();
  const base = () => grantLease({ cap_id: 'cap1', holder: a.pk, now: 1_000, ttl_ms: 10_000, hard_expires_at: 100_000, max_renewals: 2 });
  const hbFor = (l: CapabilityLease, seq: number, at: number, sk = a.sk) =>
    signHeartbeat({ cap_id: l.cap_id, seq, at, holder: l.holder, lease_issued_at: l.issued_at }, sk);
  const next = (r: ReturnType<typeof renewLease>) => (r as { ok: true; lease: CapabilityLease }).lease;

  it('expires without renewal; exact boundary is not live', () => {
    const l = base();
    expect(leaseState(l, 1_000)).toEqual({ live: true, expiresIn: 10_000 });
    expect(leaseState(l, 10_999)).toEqual({ live: true, expiresIn: 1 });
    expect(leaseState(l, 11_000)).toMatchObject({ live: false, expiresIn: 0, reason: 'lease lapsed' });
    expect(leaseState(l, 99_999).live).toBe(false);
  });
  it('renews with heartbeat; replay, wrong signer, lapsed, exhausted all refused', () => {
    let l = base();
    const r = renewLease(l, hbFor(l, 1, 8_000), 8_000);
    expect(r.ok).toBe(true);
    l = next(r);
    expect(l.renewals).toBe(1);
    expect(l.last_seq).toBe(1);
    expect(leaseState(l, 12_000).live).toBe(true);
    expect(leaseState(l, 18_000).live).toBe(false);
    expect(renewLease(l, hbFor(l, 1, 9_000), 9_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/stale/) });
    expect(renewLease(l, hbFor(l, 0, 9_000), 9_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/stale/) });
    const m = kp();
    expect(renewLease(l, hbFor(l, 2, 9_000, m.sk), 9_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/signature/) });
    expect(renewLease(l, hbFor(l, 2, 90_000), 9_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/skew/) });
    l = next(renewLease(l, hbFor(l, 2, 9_000), 9_000));
    expect(renewLease(l, hbFor(l, 3, 9_500), 9_500)).toMatchObject({ ok: false, reason: expect.stringMatching(/exhausted/) });
    const fresh = base();
    expect(renewLease(fresh, hbFor(fresh, 1, 50_000), 50_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/lapsed/) });
  });
  it('strictly-increasing seq: skipping ahead is fine, equal/lower refused, non-integer refused', () => {
    let l = base();
    l = next(renewLease(l, hbFor(l, 5, 2_000), 2_000));
    expect(renewLease(l, hbFor(l, 5, 2_100), 2_100).ok).toBe(false);
    expect(renewLease(l, hbFor(l, 4, 2_100), 2_100).ok).toBe(false);
    expect(renewLease(l, hbFor(l, 5.5, 2_100), 2_100).ok).toBe(false);
    expect(renewLease(l, { ...hbFor(l, 9, 2_100), seq: NaN }, 2_100).ok).toBe(false);
    expect(renewLease(l, hbFor(l, 6, 2_100), 2_100).ok).toBe(true);
  });
  it('heartbeat is bound to this grant: replay onto a re-granted lease is refused', () => {
    const old = base();
    const stale = hbFor(old, 1, 2_000);
    const regrant = grantLease({ cap_id: 'cap1', holder: a.pk, now: 1_500, ttl_ms: 10_000 });
    expect(renewLease(regrant, stale, 2_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/not for this lease/) });
    const other = grantLease({ cap_id: 'cap2', holder: a.pk, now: 1_000, ttl_ms: 10_000 });
    expect(renewLease(other, stale, 2_000).ok).toBe(false);
    expect(renewLease(old, { ...stale, extra: 1 } as never, 2_000)).toMatchObject({ ok: false, reason: 'malformed heartbeat' });
  });
  it('hard cap bounds renewal and never shortens; renewal budget zero means none', () => {
    const l = grantLease({ cap_id: 'cap1', holder: a.pk, now: 0, ttl_ms: 10_000, hard_expires_at: 12_000 });
    const r = renewLease(l, hbFor(l, 1, 8_000), 8_000);
    expect(next(r).expires_at).toBe(12_000);
    const r2 = renewLease(next(r), hbFor(next(r), 2, 9_000), 9_000);
    expect(next(r2).expires_at).toBe(12_000);
    expect(leaseState(next(r2), 12_000).live).toBe(false); // hard expiry is final
    const none = grantLease({ cap_id: 'cap1', holder: a.pk, now: 0, ttl_ms: 10_000, max_renewals: 0 });
    expect(renewLease(none, hbFor(none, 1, 1_000), 1_000)).toMatchObject({ ok: false, reason: expect.stringMatching(/exhausted/) });
    // grant itself clamps to hard expiry
    expect(grantLease({ cap_id: 'c', holder: a.pk, now: 0, ttl_ms: 10_000, hard_expires_at: 3_000 }).expires_at).toBe(3_000);
  });
  it('edge clocks: NaN/Infinity/rollback/early heartbeat all fail closed', () => {
    const l = base();
    expect(leaseState(l, NaN)).toMatchObject({ live: false, reason: 'invalid clock' });
    expect(leaseState(l, Infinity).live).toBe(false);
    expect(leaseState(l, -Infinity).live).toBe(false);
    expect(renewLease(l, hbFor(l, 1, 2_000), NaN).ok).toBe(false);
    // clock rolled back beyond skew before the last renewal => not live (cannot be stretched by a rollback)
    expect(leaseState(l, 1_000 - HEARTBEAT_SKEW_MS - 1)).toMatchObject({ live: false, reason: 'clock before last renewal' });
    expect(leaseState(l, 1_000 - HEARTBEAT_SKEW_MS).live).toBe(true); // within tolerated skew
    // skew boundary for heartbeat 'at'
    expect(renewLease(l, hbFor(l, 1, 5_000 + HEARTBEAT_SKEW_MS), 5_000).ok).toBe(true);
    expect(renewLease(l, hbFor(l, 1, 5_000 + HEARTBEAT_SKEW_MS + 1), 5_000).ok).toBe(false);
    expect(renewLease(l, hbFor(l, 1, 5_000 - HEARTBEAT_SKEW_MS - 1), 5_000).ok).toBe(false);
    expect(renewLease(l, { ...hbFor(l, 1, 5_000), at: Infinity }, 5_000).ok).toBe(false);
    // renewal at the very last live instant works; at expiry it does not
    expect(renewLease(l, hbFor(l, 1, 10_999), 10_999).ok).toBe(true);
    expect(renewLease(l, hbFor(l, 1, 11_000), 11_000).ok).toBe(false);
  });
  it('malformed / tampered / over-long lease records are not live and cannot be renewed', () => {
    const l = base();
    expect(leaseState({} as never, 0).live).toBe(false);
    expect(leaseState(null as never, 0).live).toBe(false);
    expect(leaseState({ ...l, expires_at: NaN }, 2_000).live).toBe(false);
    expect(leaseState({ ...l, expires_at: l.expires_at + 1e9 }, 2_000).live).toBe(false); // outlives hard expiry / ttl
    expect(leaseState({ ...l, renewals: -1 }, 2_000).live).toBe(false);
    expect(leaseState({ ...l, last_seq: 1.5 }, 2_000).live).toBe(false);
    expect(leaseState({ ...l, ttl_ms: 0 }, 2_000).live).toBe(false);
    expect(leaseState({ ...l, ttl_ms: MAX_LEASE_TTL_MS + 1 }, 2_000).live).toBe(false);
    expect(renewLease({ ...l, expires_at: NaN }, hbFor(l, 1, 2_000), 2_000).ok).toBe(false);
    expect(renewLease(l, null as never, 2_000)).toMatchObject({ ok: false });
    expect(renewLease(l, { ...hbFor(l, 1, 2_000), sig: 5 } as never, 2_000).ok).toBe(false);
  });
  it('grantLease refuses nonsense at authoring time', () => {
    const g = (o: object) => () => grantLease({ cap_id: 'c', holder: a.pk, now: 0, ttl_ms: 1_000, ...o });
    expect(g({})).not.toThrow();
    expect(g({ ttl_ms: 0 })).toThrow();
    expect(g({ ttl_ms: -5 })).toThrow();
    expect(g({ ttl_ms: NaN })).toThrow();
    expect(g({ ttl_ms: MAX_LEASE_TTL_MS + 1 })).toThrow();
    expect(g({ now: Infinity })).toThrow();
    expect(g({ hard_expires_at: 0 })).toThrow(); // not in the future
    expect(g({ hard_expires_at: NaN })).toThrow();
    expect(g({ max_renewals: -1 })).toThrow();
    expect(g({ max_renewals: 1.5 })).toThrow();
    expect(g({ cap_id: '' })).toThrow();
  });
  it('deterministic', () => {
    const l = base();
    expect(renewLease(l, hbFor(l, 1, 5_000), 5_000)).toEqual(renewLease(l, hbFor(l, 1, 5_000), 5_000));
    expect(verifyChain([])).toMatchObject({ ok: false });
  });
});
