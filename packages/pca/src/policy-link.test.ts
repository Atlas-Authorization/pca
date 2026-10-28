import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { mintGrant, readEnvelope } from './envelope';
import { generateKeyPair, publicKeyOf } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  createLink,
  instantiateTemplate,
  linkDigest,
  resolveLink,
  signTemplate,
  signTighten,
  templateDefError,
  templateDigest,
  templateRefError,
  tightenOverlayError,
  verifyLinkedPolicy,
  verifyTemplate,
  verifyTighten,
  type TemplateDef,
  type TemplateRegistry,
} from './policy-link';
import { buildPolicyLinkVectors, PUB, TEMPLATE } from './test-support/policy-link-vectors';

const path = new URL('../conformance/policy-link-vectors.json', import.meta.url);
const file = JSON.parse(readFileSync(path, 'utf8')) as {
  template: { def: TemplateDef; digest: string };
  def_errors: Array<{ name: string; def: unknown; expect: string | null }>;
  instantiate: Array<{ name: string; slots: Record<string, unknown>; expect: { ok: boolean; policy?: unknown; reason?: string } }>;
  verify: Array<{ name: string; kind: 'template' | 'overlay'; signed: never; trusted: string[]; expect: { ok: boolean; reason?: string } }>;
  ref_errors: Array<{ name: string; ref: unknown; expect: string | null }>;
  resolve: Array<{ name: string; ref: never; registry: TemplateRegistry; expect: { ok: boolean; reason?: string; overlays?: number; policy?: unknown } }>;
};

describe('policy-link-vectors.json', () => {
  it('is what the generator writes', () => expect(`${JSON.stringify(buildPolicyLinkVectors(), null, 2)}\n`).toBe(readFileSync(path, 'utf8')));
  it('the digest of the template is pinned', () => expect(templateDigest(file.template.def)).toBe(file.template.digest));
  it.each(file.def_errors)('definition: $name', (v) => expect(templateDefError(v.def)).toBe(v.expect));
  it.each(file.instantiate)('instantiate: $name', (v) => {
    const r = instantiateTemplate(file.template.def, v.slots);
    expect(r.ok ? { ok: true, policy: r.policy } : { ok: false, reason: r.reason }).toEqual(v.expect);
  });
  it.each(file.verify)('verify: $name', (v) => expect(v.kind === 'template' ? verifyTemplate(v.signed, v.trusted) : verifyTighten(v.signed, v.trusted)).toEqual(v.expect));
  it.each(file.ref_errors)('reference: $name', (v) => expect(templateRefError(v.ref)).toBe(v.expect));
  it.each(file.resolve)('resolve: $name', (v) => {
    const r = resolveLink(v.ref, v.registry);
    expect(r.ok ? { ok: true, overlays: r.overlays, policy: r.policy } : { ok: false, reason: r.reason }).toEqual(v.expect);
  });
});

describe('template definitions', () => {
  const def = (over: Partial<TemplateDef> & Record<string, unknown>): TemplateDef => ({ ...TEMPLATE, ...over }) as TemplateDef;
  it('accepts the example and names the first problem otherwise', () => {
    expect(templateDefError(TEMPLATE)).toBeNull();
    expect(templateDefError(null)).toBe('template must be an object');
    expect(templateDefError(def({ v: 2 as never }))).toBe('template v / kind mismatch');
    expect(templateDefError(def({ id: 'Bad Id' }))).toMatch(/id must match/);
    expect(templateDefError(def({ version: '' }))).toMatch(/version/);
    expect(templateDefError(def({ slots: { A: { type: 'string' } } }))).toMatch(/slot name/);
    expect(templateDefError(def({ slots: { a: { type: 'float' as never } } }))).toMatch(/type must be/);
    expect(templateDefError(def({ slots: { a: { type: 'set' } } }))).toMatch(/closed values list/);
    expect(templateDefError(def({ slots: { ...TEMPLATE.slots, extra: { type: 'string' } } }))).toBe("slot 'extra' is declared but never used");
    expect(templateDefError(def({ body: { predicates: [{ verb: { $slot: 'nope' } as never }] } }))).toBe("placeholder names undeclared slot 'nope'");
    expect(templateDefError(def({ body: { predicates: [{ verb: { $slot: 'acct', other: 1 } as never }] }, slots: { acct: { type: 'string' } } }))).toBe("placeholder has unknown member 'other'");
  });

  it('a slot used for a verb or resource cannot carry a wildcard or regex', () => {
    const open: TemplateDef = { v: 1, kind: 'pca-policy-template', id: 'open', version: '1', slots: { v: { type: 'string' } }, body: { predicates: [{ verb: { $slot: 'v' } as never }] } };
    expect(instantiateTemplate(open, { v: 'mail.send' })).toMatchObject({ ok: true, policy: { predicates: [{ verb: 'mail.send' }] } });
    expect(instantiateTemplate(open, { v: '*' })).toEqual({ ok: false, reason: "slot 'v' would inject a wildcard or regex matcher into a verb or resource" });
    expect(instantiateTemplate(open, { v: 're:.*' })).toMatchObject({ ok: false });
    const res: TemplateDef = { ...open, id: 'res', body: { predicates: [{ verb: 'x', resource: { $slot: 'v' } as never }] } };
    expect(instantiateTemplate(res, { v: '/a/*' })).toMatchObject({ ok: false });
    expect(instantiateTemplate(res, { v: '/a/b' })).toMatchObject({ ok: true });
  });

  it('signing refuses a malformed template; instantiation does not mutate it', () => {
    const k = generateKeyPair();
    expect(() => signTemplate({ ...TEMPLATE, id: 'X' }, k.secretKey, b64u(k.publicKey))).toThrow(/signTemplate/);
    const before = JSON.stringify(TEMPLATE);
    instantiateTemplate(TEMPLATE, { acct: 'z', cap: 1, region: 'us', verbs: ['chat.post'] });
    expect(JSON.stringify(TEMPLATE)).toBe(before);
  });

  it('overlays can only add conditions and caveats', () => {
    expect(tightenOverlayError({ v: 1, kind: 'pca-template-tighten', template_id: 'support_agent', version_digest: 'd', add_where: [{ field: 'a', op: 'eq', value: 1 }] })).toBeNull();
    expect(tightenOverlayError({ v: 1, kind: 'pca-template-tighten', template_id: 'support_agent', version_digest: 'd', remove_where: [0] })).toMatch(/unknown member 'remove_where'/);
    expect(tightenOverlayError({ v: 1, kind: 'pca-template-tighten', template_id: 'support_agent', version_digest: 'd', predicates: [] })).toMatch(/unknown member 'predicates'/);
    expect(tightenOverlayError({ v: 1, kind: 'pca-template-tighten', template_id: 'support_agent', version_digest: 'd', add_caveats: [{}] })).toMatch(/add_caveats/);
    const k = generateKeyPair();
    expect(() => signTighten({ v: 1, kind: 'pca-template-tighten', template_id: 'support_agent', version_digest: 'd', predicates: [] } as never, k.secretKey, b64u(k.publicKey))).toThrow(/signTighten/);
  });
});

describe('a link in a grant', () => {
  const secret = new Uint8Array(32).fill(7);
  const slots = { acct: 'a42', cap: 200, region: 'eu', verbs: ['mail.draft', 'mail.send'] };
  const signed = signTemplate(TEMPLATE, secret, PUB);
  const reg: TemplateRegistry = { templates: { [templateDigest(TEMPLATE)]: signed }, trusted: [PUB] };
  const ref = createLink(TEMPLATE, slots);

  function mint(over: Record<string, unknown> = {}) {
    const principal = generateKeyPair();
    const policy = resolveLink(ref, reg);
    if (!policy.ok) throw new Error(policy.reason);
    return mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: b64u(principal.publicKey),
      holder: b64u(generateKeyPair().publicKey),
      goal: 'support',
      envelope: { predicates: policy.policy.predicates, caveats: policy.policy.caveats ?? [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, template_ref: ref, ...over },
    });
  }

  it('the grant carries the reference, covered by the grant signature, and verifies against the registry', () => {
    const { grant } = mint();
    const env = readEnvelope(grant)!;
    expect(env.template_ref).toEqual(ref);
    expect(verifyLinkedPolicy(env, reg)).toEqual({ ok: true, template: templateDigest(TEMPLATE) });
    expect(linkDigest(ref)).toBe(linkDigest({ ...ref }));
  });

  it('a grant whose policy was edited after linking is refused', () => {
    const { grant } = mint();
    const env = readEnvelope(grant)!;
    const widened = { ...env, predicates: [{ ...env.predicates[0]!, where: [] }] };
    expect(verifyLinkedPolicy(widened, reg)).toEqual({ ok: false, reason: 'grant policy differs from the linked template instantiation' });
  });

  it('a grant without a reference is not checked here; a bad reference cannot be minted', () => {
    expect(verifyLinkedPolicy({ predicates: [], caveats: [] }, reg)).toEqual({ ok: true });
    expect(() => mint({ template_ref: { template_id: 'X', version_digest: 'd', slots: {} } })).toThrow(/template_id/);
  });

  it('a new template version does not touch an existing link; a tighten overlay narrows it', () => {
    const v4 = { ...TEMPLATE, version: '4', slots: { ...TEMPLATE.slots, cap: { type: 'integer' as const, min: 1, max: 5000 } } };
    const reg2: TemplateRegistry = { ...reg, templates: { ...reg.templates, [templateDigest(v4)]: signTemplate(v4, secret, PUB) } };
    expect(resolveLink(ref, reg2)).toEqual(resolveLink(ref, reg)); // the old digest still means the old policy
    const overlay = signTighten({ v: 1, kind: 'pca-template-tighten', template_id: 'support_agent', version_digest: ref.version_digest, add_where: [{ field: 'env.tier', op: 'ne', value: 'frozen' }] }, secret, PUB);
    const tightened = resolveLink(ref, { ...reg, overlays: [overlay] });
    expect(tightened).toMatchObject({ ok: true, overlays: 1 });
    // a grant minted before the overlay no longer matches the (now tighter) link: it must be re-minted, never silently widened
    const { grant } = mint();
    expect(verifyLinkedPolicy(readEnvelope(grant)!, { ...reg, overlays: [overlay] }).ok).toBe(false);
  });

  it('is fail closed on garbage', () => {
    expect(resolveLink(null as never, reg)).toMatchObject({ ok: false });
    expect(verifyTemplate(null as never, [PUB]).ok).toBe(false);
    expect(verifyTighten(null as never, [PUB]).ok).toBe(false);
    expect(verifyLinkedPolicy({ template_ref: 5, predicates: [], caveats: [] }, reg).ok).toBe(false);
    expect(publicKeyOf(secret).length).toBe(32);
  });
});
