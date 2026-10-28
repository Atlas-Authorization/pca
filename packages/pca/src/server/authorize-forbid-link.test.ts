import { describe, expect, it } from 'vitest';
import { mintGrant } from '../envelope';
import { certify } from '../forbid-certificate';
import { b64u } from '../hash';
import { encodeKey, generateKeyPair, publicKeyOf } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn } from '../pcactn';
import { createLink, resolveLink, signTemplate, templateDigest, type TemplateDef, type TemplateRegistry } from '../policy-link';
import { DEFAULT_RISK_POLICY } from '../risk';
import { createAuthorizer, missingAuthorizeComponents, type AuthorizeOptions } from './authorize';
import { memoryPcaStore } from './require-pca';
import type { PcaOperation } from './verify';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const op = (amount: number, resource = 'payments'): PcaOperation => ({ verb: 'payments.send', resource, params: { amount } });

const TEMPLATE: TemplateDef = { v: 1, kind: 'pca-policy-template', id: 'payer', version: '1', slots: { cap: { type: 'integer', min: 1, max: 1000 } }, body: { predicates: [{ verb: 'payments.send', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: { $slot: 'cap' } as never }] }] } };
const orgSecret = new Uint8Array(32).fill(5);
const orgPub = b64u(publicKeyOf(orgSecret));
const registry: TemplateRegistry = { templates: { [templateDigest(TEMPLATE)]: signTemplate(TEMPLATE, orgSecret, orgPub) }, trusted: [orgPub] };

function world(linked: boolean) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const ref = createLink(TEMPLATE, { cap: 100 });
  const pol = resolveLink(ref, registry);
  if (!pol.ok) throw new Error(pol.reason);
  const predicates = linked ? pol.policy.predicates : [{ verb: 'payments.send', resource: '*', where: [{ field: 'action.params.amount', op: 'lte' as const, value: 100 }] }];
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'pay',
    envelope: { predicates, caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, ...(linked ? { template_ref: ref } : {}) },
  });
  let counter = 0;
  const sign = (params: Record<string, unknown>) => {
    const node: PlanNode = { id: 'n1', verb: 'payments.send', resource: 'payments', params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  };
  const opts = (over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
    audience: AUD,
    resolveGrant: async (r) => (r === grant.id ? grant : null),
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    now: () => NOW,
    risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 1, taint: 0, confidence: 1 }),
    ...over,
  });
  return { sign, opts };
}

describe('authorize: requireLinkedTemplate', () => {
  it('allows a grant that is the instantiation of its template, and says so', async () => {
    const w = world(true);
    const r = await createAuthorizer(w.opts({ requireLinkedTemplate: { registry } }))({ pcactn: w.sign(op(50).params!), operation: op(50) });
    expect(r).toMatchObject({ allow: true, template: 'linked' });
  });

  it('refuses a grant with no link, before the guard (the counter is not spent)', async () => {
    const w = world(false);
    const az = createAuthorizer(w.opts({ requireLinkedTemplate: { registry } }));
    const pc = w.sign(op(50).params!);
    const r = await az({ pcactn: pc, operation: op(50) });
    expect(r).toMatchObject({ allow: false, status: 403, reason: 'template: the grant carries no template_ref' });
    expect(Object.keys(r.verdict.checks)).toEqual(['template']);
  });

  it('refuses a link whose template is not in a trusted registry, and accepts a registry supplied lazily', async () => {
    const w = world(true);
    const bad: TemplateRegistry = { ...registry, trusted: [b64u(publicKeyOf(new Uint8Array(32).fill(6)))] };
    const r = await createAuthorizer(w.opts({ requireLinkedTemplate: { registry: bad } }))({ pcactn: w.sign(op(50).params!), operation: op(50) });
    expect(r).toMatchObject({ allow: false, reason: 'template: template signer is not trusted' });
    const w2 = world(true);
    expect((await createAuthorizer(w2.opts({ requireLinkedTemplate: { registry: async () => registry } }))({ pcactn: w2.sign(op(50).params!), operation: op(50) })).allow).toBe(true);
  });

  it('a missing registry is a configuration error that names it', () => {
    expect(missingAuthorizeComponents({ requireLinkedTemplate: {} as never })).toContain('requireLinkedTemplate.registry');
  });
});

describe('authorize: forbid', () => {
  const clauses = [
    { id: 'org-frozen', kind: 'forbid' as const, signer: 'org', when: { verb: 'payments.send', resource: 'frozen' } },
    { id: 'user-send', kind: 'permit' as const, signer: 'user', when: { verb: 'payments.send' } },
  ];
  const f = { clauses: () => clauses, precedence: ['org', 'user'] };

  it('allows when no forbid matches and returns the certificate', async () => {
    const w = world(true);
    const r = await createAuthorizer(w.opts({ forbid: f }))({ pcactn: w.sign(op(50).params!), operation: op(50) });
    expect(r.allow).toBe(true);
    expect(r.allow && r.forbid?.decision).toBe('allow');
  });

  it('a forbid refuses whoever signed the permit, naming the clause; the counter is not spent', async () => {
    const w = world(true);
    const az = createAuthorizer(w.opts({ forbid: f }));
    const pc = w.sign({ amount: 50 });
    const denied = await az({ pcactn: pc, operation: op(50, 'frozen') });
    expect(denied).toMatchObject({ allow: false, reason: 'forbid: deny by forbid org-frozen' });
  });

  it('requireCertificate: the call must carry a certificate that recomputes', async () => {
    const w = world(true);
    const az = createAuthorizer(w.opts({ forbid: { ...f, requireCertificate: true } }));
    const ctx = { action: { verb: 'payments.send', resource: 'payments', params: { amount: 50 } } };
    const none = await az({ pcactn: w.sign({ amount: 50 }), operation: op(50) });
    expect(none).toMatchObject({ allow: false, reason: 'forbid: the call carries no certificate (fail closed)' });
    const forged = { ...certify(clauses, ctx, { precedence: ['org', 'user'] }), decision: 'deny' as const };
    expect(await az({ pcactn: w.sign({ amount: 50 }), operation: op(50), forbidCertificate: forged })).toMatchObject({ allow: false });
    const ok = await az({ pcactn: w.sign({ amount: 50 }), operation: op(50), forbidCertificate: certify(clauses, ctx, { precedence: ['org', 'user'] }) });
    expect(ok.allow).toBe(true);
  });

  it('a clause source that is not a function is a configuration error', () => {
    expect(missingAuthorizeComponents({ forbid: {} as never })).toContain('forbid.clauses');
  });
});
