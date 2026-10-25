/**
 * r13 mutation kills for agent-native.ts module-level constants and helper arrows (static mutants: every test re-evaluates
 * the module with vi.resetModules + dynamic import). Each value is pinned against an independent computation: the caveat
 * type names, the caution signature message (domain-separated canonical bytes, checked with a plain Ed25519 verify), the
 * rationale commitment, the tool_schema binding digest, the caution reason / property-name patterns, the per-type allowed
 * spec keys, the clamp in combineCaution, the quoted-name helper in firewall reasons and MAX_LEASE_TTL_MS.
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, canonicalBytes, hashCanonical } from './hash';
import { encodeKey, generateKeyPair, verifyB64u } from './keys';

async function fresh() {
  vi.resetModules();
  return import('./agent-native');
}
/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const SALT = b64u(Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1));

describe('agent-native constants (fresh module)', () => {
  it('caveat type names, lease ceiling', async () => {
    const m = await fresh();
    expect({
      expires: m.CAVEAT_EXPIRES,
      not_before: m.CAVEAT_NOT_BEFORE,
      rate: m.CAVEAT_RATE,
      max_blast_radius: m.CAVEAT_MAX_BLAST_RADIUS,
      reversibility_max: m.CAVEAT_REVERSIBILITY_MAX,
      delegation_depth: m.CAVEAT_DELEGATION_DEPTH,
      predicates: m.CAVEAT_PREDICATES,
      tool_schema: m.CAVEAT_TOOL_SCHEMA,
      max_spend: m.CAVEAT_MAX_SPEND,
      lease: m.MAX_LEASE_TTL_MS,
    }).toEqual({
      expires: 'expires',
      not_before: 'not_before',
      rate: 'rate',
      max_blast_radius: 'max_blast_radius',
      reversibility_max: 'reversibility_max',
      delegation_depth: 'delegation_depth',
      predicates: 'predicates',
      tool_schema: 'tool_schema',
      max_spend: 'max_spend',
      lease: 604_800_000,
    });
  });

  it('a caution is signed over canonical({d: "atlas-pca/caution/v1", b: body})', async () => {
    const m = await fresh();
    const k = generateKeyPair();
    const holder = encodeKey(k.publicKey);
    const r = settle(() => m.signCaution({ action_digest: 'ad', caution: 0.5, reason: 'ood', holder }, k.secretKey));
    expect(r.ok).toBe(true);
    const { sig, ...body } = (r as { value: { sig: string } & Record<string, unknown> }).value;
    expect(body).toEqual({ action_digest: 'ad', caution: 0.5, holder, reason: 'ood' });
    expect(verifyB64u(holder, canonicalBytes({ d: 'atlas-pca/caution/v1', b: body }), sig)).toBe(true);
  });

  it('the caution reason pattern is anchored and repeatable', async () => {
    const m = await fresh();
    const k = generateKeyPair();
    const holder = encodeKey(k.publicKey);
    const ok = (reason: string) => settle(() => m.signCaution({ action_digest: 'ad', caution: 0.5, reason, holder }, k.secretKey)).ok;
    expect(['ab', 'a.b:c_d-e', 'Z9'].map(ok)).toEqual([true, true, true]);
    expect(['!a', 'a!', 'a b', '', '!'].map(ok)).toEqual([false, false, false, false, false]);
  });

  it('combineCaution clamps into [0,1]', async () => {
    const m = await fresh();
    expect([m.combineCaution(2, 0.3), m.combineCaution(undefined, 0.3), m.combineCaution(-1, 0.3), m.combineCaution(0.1, 2)]).toEqual([1, 0.3, 0.3, 1]);
  });

  it('rationale commitments hash {d: "atlas-pca/rationale/v1", a, s, r}', async () => {
    const m = await fresh();
    const r = settle(() => m.bindRationale({ verb: 'x' }, 'because', SALT));
    const ad = hashCanonical({ verb: 'x' });
    expect(r).toEqual({
      ok: true,
      value: { commitment: { v: 1, action_digest: ad, commitment: hashCanonical({ d: 'atlas-pca/rationale/v1', a: ad, s: SALT, r: 'because' }) }, reveal: { rationale: 'because', salt: SALT } },
    });
  });

  it('tool_schema caveats bind hashCanonical({tool, signature_digest, schema})', async () => {
    const m = await fresh();
    const schema = { props: { n: { type: 'integer', min: 0, max: 5 } }, required: ['n'] };
    const r = settle(() => m.toolSchemaCaveat('t', schema as never));
    expect(r.ok).toBe(true);
    const c = (r as { value: { signature_digest: string; binding_digest: string } }).value;
    expect(c.binding_digest).toBe(hashCanonical({ tool: 't', signature_digest: hashCanonical('t'), schema }));
    expect(settle(() => m.evaluateToolSchema(c as never, { tool: 't', args: { n: 3 } }))).toEqual({ ok: true, value: { ok: true } });
  });

  it('property names: anchored [A-Za-z0-9_]{1,64}', async () => {
    const m = await fresh();
    const v = (name: string) => m.validateArgSchema({ props: { [name]: { type: 'string' } } });
    expect(['a', 'A_9', 'x'.repeat(64)].map(v)).toEqual([null, null, null]);
    expect(['!a', 'a!', 'x'.repeat(65)].map((n) => typeof v(n))).toEqual(['string', 'string', 'string']);
  });

  it('every documented spec key is accepted for its type', async () => {
    const m = await fresh();
    const specs: Record<string, unknown>[] = [
      { type: 'string' }, { type: 'string', enum: ['a'] }, { type: 'string', const: 'a' }, { type: 'string', minLength: 1 }, { type: 'string', maxLength: 2 }, { type: 'string', prefix: 'a' },
      { type: 'number' }, { type: 'number', enum: [1] }, { type: 'number', const: 1 }, { type: 'number', min: 0 }, { type: 'number', max: 2 },
      { type: 'integer' }, { type: 'integer', enum: [1] }, { type: 'integer', const: 1 }, { type: 'integer', min: 0 }, { type: 'integer', max: 2 },
      { type: 'boolean' }, { type: 'boolean', enum: [true] }, { type: 'boolean', const: true },
      { type: 'object', props: { x: { type: 'string' } } }, { type: 'object', props: { x: { type: 'string' } }, required: ['x'] },
      { type: 'array', items: { type: 'string' } }, { type: 'array', items: { type: 'string' }, minItems: 1 }, { type: 'array', items: { type: 'string' }, maxItems: 2 },
    ];
    expect(specs.map((s) => [s, m.validateArgSchema({ props: { f: s } })])).toEqual(specs.map((s) => [s, null]));
    // a key of another type is refused
    expect(typeof m.validateArgSchema({ props: { f: { type: 'boolean', min: 0 } } })).toBe('string');
  });

  it('firewall reasons quote the tool name, truncated at 48 characters', async () => {
    const m = await fresh();
    const c = m.toolSchemaCaveat('t', { props: {} } as never);
    const long = 'L'.repeat(50);
    expect(settle(() => m.evaluateToolSchema(c, { tool: long, args: {} }))).toEqual({ ok: true, value: { ok: false, reason: `tool ${JSON.stringify('L'.repeat(48) + '…')} not authorized` } });
    expect(settle(() => m.evaluateToolSchema(c, { tool: 'u', args: {} }))).toEqual({ ok: true, value: { ok: false, reason: 'tool "u" not authorized' } });
  });

  it('max_spend uses the finite-number test', async () => {
    const m = await fresh();
    const ctx = (amount: unknown) => ({ action: { action: { verb: 'v', resource: 'r', params: { amount } } } });
    expect([5, 11, Infinity, '5'].map((a) => settle(() => m.agentNativeCaveatEvaluator({ type: 'max_spend', usd: 10 } as never, ctx(a))))).toEqual([
      { ok: true, value: true },
      { ok: true, value: false },
      { ok: true, value: false },
      { ok: true, value: false },
    ]);
  });
});
