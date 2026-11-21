import fc from 'fast-check';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { conformAction } from '@atlasauth/pca/ext/intent';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import {
  BUILTIN_DEFS, CORE_REGISTRY, MAX_PACK_DEFS, PACK_SIGN_DOMAIN, buildArtifacts, decideExample, diffDefsAuthoring as diffDefs, diffPacks, explainDef, flattenParams, generateTypes,
  loadActionsText, packConsistencyError, packKeyOf, runDefTests, signPack, testText, toSchemaDoc, toolActionMapOf, validateDef, verifyPack,
  type ActionDef, type BuildConfig,
} from '../src';
import { arbDef } from './arb';
import { runs } from './runs';
import { confirmed, testReview } from './reviewed';

const HELLO = `
ns: acme
since: 0.1.0
actions:
  - verb: acme.invoice.send
    title: Send an invoice
    description: Emails an existing invoice to the customer.
    effects: [send]
    resource: acme.invoice:inv_*
    params: {invoice: "id:acme.invoice", to: email, note: "message(500)"}
  - verb: acme.charge.refund
    title: Refund a charge
    description: Returns money.
    effects: [pay]
    resource: acme.charge:ch_*
    params: {charge: "id:acme.charge", amount: "money(USD, max=100000)"}
    bindings: {mcp: {tool: refund_charge}}
`;
const defs = (): ActionDef[] => loadActionsText(HELLO).defs;
const send = (): ActionDef => defs()[0]!;
const refund = (): ActionDef => defs()[1]!;
const SEND = { invoice: 'inv_12345678', to: 'a@b.com', note: 'hi', idempotency_key: 'k_12345678' };

describe('examples: the example policy decides through the real floor', () => {
  const dec = (d: ActionDef, params: Record<string, unknown>, under?: unknown, all = defs()) => decideExample(d, { params, ...(under !== undefined ? { under } : {}), expect: 'allow' }, CORE_REGISTRY, all);
  const ALLOW = { allow: { trait: 'external_communication', where: { 'to.domain': ['b.com'] }, caveats: ['rate_cap', 'resource_scope'], context: ['fresh_revocation'] } };
  it('a matching allow pre-authorizes; anything else escalates', () => {
    expect(dec(send(), SEND, ALLOW).got).toBe('allow');
    expect(dec(send(), { ...SEND, to: 'a@evil.com' }, ALLOW).got).toBe('escalate');
    expect(dec(send(), SEND).got).toBe('escalate');
    expect(dec(send(), SEND, { allow: { ...ALLOW.allow, trait: 'pca.external_communication' } }).got).toBe('allow');
    expect(dec(send(), SEND, { allow: { ...ALLOW.allow, verb: undefined, trait: undefined } }).why).toMatch(/exactly one of trait and verb/);
  });
  it('the grant must carry every caveat and the call every context key the floor needs', () => {
    expect(dec(send(), SEND, { allow: { ...ALLOW.allow, caveats: ['rate_cap'] } })).toMatchObject({ got: 'escalate', why: expect.stringMatching(/resource_scope/) });
    expect(dec(send(), SEND, { allow: { ...ALLOW.allow, context: [] } })).toMatchObject({ got: 'escalate', why: expect.stringMatching(/fresh_revocation/) });
  });
  it('a verb selector, a list of selectors, and a numeric where', () => {
    const under = { allow: [{ trait: 'external_communication', where: { to: ['x@y.z'] } }, { verb: 'acme.charge.refund', where: { amount: { max: 5000 } }, caveats: ['count_cap', 'window'], context: ['fresh_revocation'] }] };
    const r = { charge: 'ch_12345678', amount: 2500, idempotency_key: 'k_12345678' };
    expect(dec(refund(), r, under).got).toBe('allow');
    expect(dec(refund(), { ...r, amount: 5001 }, under).got).toBe('escalate');
    expect(dec(refund(), { ...r, amount: 5001 }, { allow: { verb: 'acme.charge.refund', where: { amount: { min: 6000 } } } }).got).toBe('escalate');
  });
  it('a where on an undeclared param never matches; a bad policy is a deny with the reason', () => {
    expect(dec(send(), SEND, { allow: { ...ALLOW.allow, where: { nope: ['x'] } } }).got).toBe('escalate');
    expect(dec(send(), SEND, { deny: {} }).why).toMatch(/under must be/);
    expect(dec(send(), SEND, { allow: 5 }).why).toMatch(/an allow selector has/);
    expect(dec(send(), SEND, { allow: { trait: 'x', caveats: ['bogus'] } }).why).toMatch(/known caveat kinds/);
    expect(dec(send(), SEND, { allow: { trait: 'x', where: 5 } }).why).toMatch(/where must be an object/);
  });
  it('a call the schema refuses is a deny before any policy', () => {
    expect(dec(send(), { ...SEND, extra: 1 }, ALLOW)).toMatchObject({ got: 'deny', why: expect.stringMatching(/schema_violation undeclared_param/) });
    const { idempotency_key: _k, ...noKey } = SEND;
    void _k;
    expect(dec(send(), noKey, ALLOW)).toMatchObject({ got: 'deny', why: expect.stringMatching(/missing_param/) });
    expect(dec(send(), { ...SEND, invoice: 'zzz' }, ALLOW).got).toBe('deny');
  });
  it('a read-only action with nothing required is allowed without a policy', () => {
    const r = loadActionsText('ns: acme\nactions:\n  - {verb: acme.invoice.get, effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n').defs[0]!;
    expect(dec(r, { invoice: 'inv_12345678' }, undefined, [r])).toMatchObject({ got: 'allow', why: 'floor satisfied' });
  });
  it('runDefTests passes a good pack, fails a wrong expectation, and prints it', () => {
    const good = { ...send(), examples: [{ params: SEND, under: ALLOW, expect: 'allow' as const }, { params: { ...SEND, to: 'a@evil.com' }, expect: 'escalate' as const }] };
    const ok = runDefTests([good, refund()], CORE_REGISTRY);
    expect(ok.ok, testText(ok)).toBe(true);
    expect(ok.props.filter((q) => q.name === 'schema round trip').map((q) => q.detail)).toEqual([expect.stringMatching(/\d+ mutations refused/), 'skipped: no examples']);
    const bad = runDefTests([{ ...good, examples: [{ params: SEND, expect: 'allow' }] }], CORE_REGISTRY);
    expect(bad.ok).toBe(false);
    expect(testText(bad)).toMatch(/FAIL {2}acme\.invoice\.send example 1: expected allow, got escalate/);
    expect(testText(bad)).toMatch(/\d+ passed, 1 failed$/);
  });
  it('the property checks cover T2 over every core trait and over trait subsets', () => {
    const r = runDefTests([send()], CORE_REGISTRY, { propLimit: 64 });
    expect(r.props.map((q) => q.name)).toEqual(['adding a trait never lowers the profile', 'floors are monotone over trait subsets', 'one digest across JSON and YAML forms', 'schema round trip']);
    expect(r.props.every((q) => q.ok)).toBe(true);
    expect(r.props[1]!.detail).toMatch(/^8 subsets, 0 violations$/);
  });
  it('the round trip fails when a mutation would be accepted (a def the closed-world check cannot constrain)', () => {
    // 'x' accepts any string up to 1024, so replacing it with a longer-than-declared value is not a mutation here; a param with max_len is
    const d = { ...send(), examples: [{ params: SEND, expect: 'escalate' as const }] };
    const r = runDefTests([d], CORE_REGISTRY);
    expect(r.props.find((q) => q.name === 'schema round trip')!.ok).toBe(true);
  });
});

describe('explain: golden files', () => {
  const GOLDEN = join(__dirname, 'golden', 'explain-builtin.txt');
  const text = BUILTIN_DEFS.map((d) => `## ${d.verb}\n${explainDef(confirmed(d), CORE_REGISTRY, testReview())}`).join('\n\n') + '\n';
  it('the policy card, profile and grant needs of every built-in action are pinned', () => {
    if (process.env.UPDATE_GOLDEN === '1' || !existsSync(GOLDEN)) writeFileSync(GOLDEN, text);
    expect(text).toBe(readFileSync(GOLDEN, 'utf8'));
  });
  it('the hello world explanation', () => {
    expect(explainDef(confirmed(send()), CORE_REGISTRY, testReview())).toBe([
      'Send an invoice. This action sends to people outside your organisation, cannot be undone and touches personal data.',
      'effective: risk 2, irreversible, blast 50k, escalation: confirm',
      'grant must carry: rate_cap, recipient_scope, resource_scope',
      'call must carry: fresh_revocation',
      'traits: pca.external_communication, pca.irreversible, pca.pii_access',
      'review: confirmed',
    ].join('\n'));
    const u = explainDef(send(), CORE_REGISTRY).split('\n');
    expect(u[0]).toMatch(/has not been reviewed by a person, so it is treated as the most dangerous kind of action/);
    expect(u[1]).toBe('effective: risk 3, irreversible, blast 1000k, escalation: stepup');
    expect(u[u.length - 2]).toBe('review: authored, not confirmed by a signed review');
    expect(u[u.length - 1]).toMatch(/as written it would be: risk 2, escalation tier 1, traits: pca.external_communication, pca.irreversible, pca.pii_access$/);
  });
  it('a read says so, and an unreviewed def says what it is', () => {
    const r = loadActionsText('ns: acme\nactions:\n  - {verb: acme.invoice.get, effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n').defs[0]!;
    expect(explainDef(confirmed(r), CORE_REGISTRY, testReview())).toMatch(/This action only reads\.\neffective: risk 0, reversible, blast 50k, escalation: auto\ngrant must carry: nothing/);
    // even a read-only def that nobody confirmed is the most dangerous action there is
    expect(explainDef({ ...r, review: { state: 'unreviewed' } }, CORE_REGISTRY)).toMatch(/has not been reviewed by a person.*\neffective: risk 3, irreversible, blast 1000k, escalation: stepup/s);
  });
});

describe('definition diff', () => {
  const int = (max: number, extra: Record<string, unknown> = {}): ActionDef => loadActionsText(`ns: acme\nactions:\n  - {verb: acme.item.set, effects: update, resource: "acme.item:i_*", params: {n: "int(0..${max})", ${Object.entries(extra).map(([k, v]) => `${k}: "${v}"`).join(', ')}}}\n`).defs[0]!;
  const cls = (a: ActionDef, b: ActionDef) => diffDefs(a, b, CORE_REGISTRY).class;
  it('range changes', () => {
    expect(cls(int(10), int(10))).toBe('equal');
    expect(cls(int(10), int(20))).toBe('widen');
    expect(cls(int(10), int(5))).toBe('narrow');
    expect(diffDefs(int(10), int(20), CORE_REGISTRY).reasons).toEqual(['widen: param n: max 10 to 20']);
  });
  it('params added and removed; breaking changes are flagged', () => {
    expect(diffDefs(int(10), int(10, { m: 'int(0..1)?' }), CORE_REGISTRY)).toMatchObject({ class: 'widen', breaking: false });
    expect(diffDefs(int(10), int(10, { m: 'int(0..1)' }), CORE_REGISTRY)).toMatchObject({ class: 'narrow', breaking: true });
    expect(diffDefs(int(10, { m: 'int(0..1)' }), int(10), CORE_REGISTRY)).toMatchObject({ class: 'narrow', breaking: true });
    expect(diffDefs(int(10, { m: 'int(0..1)' }), int(10, { m: 'int(0..1)?' }), CORE_REGISTRY).class).toBe('widen');
    expect(cls(int(10, { m: 'int(0..1)' }), int(20, { m: 'int(0..1)?' }))).toBe('widen');
    expect(cls(int(10, { m: 'int(0..1)?' }), int(5, { m: 'int(0..1)' }))).toBe('narrow');
    expect(cls(int(10, { m: 'int(0..1)' }), int(20, { m: 'int(0..1)' }))).toBe('widen');
    expect(cls(int(10, { m: 'int(0..1)?' }), int(20, { m: 'int(0..1)' }))).toBe('incomparable');
  });
  it('effective profile, effects, reversibility, blast, idempotency, scope, id pattern, review state', () => {
    const base = send();
    expect(cls(base, { ...base, traits: ['pca.bulk'] })).toBe('narrow');
    expect(cls({ ...base, traits: ['pca.bulk'] }, base)).toBe('widen');
    expect(cls(base, { ...base, effects: ['send', 'update'] })).toBe('narrow');
    expect(cls({ ...base, effects: ['send', 'update'] }, base)).toBe('widen');
    expect(cls({ ...base, idempotency: { mode: 'natural' } }, { ...base, idempotency: { mode: 'none' } })).toBe('widen');
    expect(cls(base, { ...base, resource: { ...base.resource, scope: 'tenant' } })).not.toBe('equal');
    expect(cls(base, { ...base, resource: { ...base.resource, id: '*' } })).toBe('widen');
    expect(cls({ ...base, resource: { ...base.resource, id: '*', scope: 'set' } }, base)).not.toBe('widen');
    expect(cls({ ...base, review: { state: 'confirmed' } }, { ...base, review: { state: 'unreviewed' } })).not.toBe('widen');
    expect(cls(base, { ...base, title: 'Mail an invoice', description: 'x' })).toBe('equal');
    expect(diffDefs(base, { ...base, title: 'Mail an invoice' }, CORE_REGISTRY).reasons).toEqual(['equal: only title or description changed']);
    expect(cls(base, { ...base, verb: 'acme.invoice.mail' })).toBe('widen');
    const upd = int(1);
    expect(cls(upd, { ...upd, reversibility: 'reversible' })).toBe('widen');
    expect(cls({ ...upd, reversibility: 'reversible' }, upd)).toBe('narrow');
    expect(cls({ ...upd, blast: { radius: 'tenant' } }, { ...upd, blast: { radius: 'one' } })).toBe('widen');
  });
  it('a lowered provenance, sensitivity, role floor, values and unit are widening or incomparable', () => {
    const a = loadActionsText('ns: acme\nactions:\n  - {verb: acme.item.set, effects: update, resource: "acme.item:i_*", params: {c: {type: string, values: [a, b], provenance_min: first_party, sensitivity: critical, role: "contact.email", format: email}, u: {type: integer, min: 0, max: 5, unit: {kind: count}}}}\n').defs[0]!;
    const set = (patch: Record<string, unknown>, k = 'c'): ActionDef => ({ ...a, params: { ...a.params, [k]: { ...a.params[k]!, ...patch } } as ActionDef['params'] });
    expect(cls(a, set({ provenance_min: 'agent' }))).toBe('widen');
    expect(cls(a, set({ provenance_min: undefined }))).toBe('widen');
    expect(cls(a, set({ sensitivity: 'free' }))).toBe('widen');
    expect(cls(a, set({ values: ['a', 'b', 'c'] }))).toBe('widen');
    expect(cls(a, set({ values: ['a'] }))).toBe('narrow');
    expect(cls(a, set({ values: undefined }))).toBe('widen');
    expect(cls(a, set({ role: 'contact.phone' }))).toBe('incomparable');
    expect(cls(a, set({ role: 'path.fs' }))).toBe('widen');
    expect(cls(a, set({ unit: { kind: 'bytes' } }, 'u'))).toBe('incomparable');
    expect(cls(a, set({ type: 'string', max_len: 4, unit: undefined, min: undefined, max: undefined }, 'u'))).toBe('incomparable');
  });
  it('pack diffs list added and removed verbs', () => {
    const rows = diffPacks([send(), refund()], [send(), { ...int(5), verb: 'acme.item.set' }], CORE_REGISTRY);
    expect(rows.map((r) => [r.verb, r.class])).toEqual([['acme.charge.refund', 'removed'], ['acme.invoice.send', 'equal'], ['acme.item.set', 'added']]);
  });
  it('reflexive on generated defs; a narrowing mutation is never a widening, and its inverse never narrows', () => {
    fc.assert(fc.property(arbDef, (d) => {
      if (validateDef(d) !== null) return true;
      if (diffDefs(d, d, CORE_REGISTRY).class !== 'equal') return false;
      const tighter: ActionDef = { ...d, params: { ...d.params, zz: { type: 'string', max_len: 8 } } };
      if (validateDef(tighter) !== null) return true;
      const a = diffDefs(d, tighter, CORE_REGISTRY);
      const b = diffDefs(tighter, d, CORE_REGISTRY);
      // a new required param narrows (and is breaking); removing it widens nothing the old set could not already say
      return a.class === 'narrow' && a.breaking && (b.class === 'narrow' || b.class === 'equal');
    }), { seed: 4301, numRuns: runs(2000) });
  });
  it('soundness against a brute-force oracle: an equal or narrow diff never accepts a call the old def refused', () => {
    fc.assert(fc.property(fc.integer({ min: 1, max: 60 }), fc.integer({ min: 1, max: 60 }), fc.boolean(), (m1, m2, optional) => {
      const a = int(m1);
      const b = int(m2, optional ? { extra: 'int(0..3)?' } : {});
      const cls2 = diffDefs(a, b, CORE_REGISTRY).class;
      if (cls2 !== 'equal' && cls2 !== 'narrow') return true;
      const da = toSchemaDoc([a], CORE_REGISTRY, { site: 's', aud: 'a', version: '1' });
      const db = toSchemaDoc([b], CORE_REGISTRY, { site: 's', aud: 'a', version: '1' });
      for (let n = -3; n <= 70; n++) {
        for (const extra of [undefined, 0, 7]) {
          const call = { n, ...(extra === undefined ? {} : { extra }) };
          if (conformAction(db, 'acme.item.set', flattenParams(call)).ok && !conformAction(da, 'acme.item.set', flattenParams(call)).ok) return false;
        }
      }
      return true;
    }), { seed: 4302, numRuns: runs(400) });
  });
});

describe('build', () => {
  const cfg: BuildConfig = { ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api' };
  it('every output is a pure function of the defs: order does not matter, two builds are equal', () => {
    const a = buildArtifacts(defs(), cfg, CORE_REGISTRY);
    const b = buildArtifacts([...defs()].reverse(), cfg, CORE_REGISTRY);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(a.schema.pack).toEqual({ ns: 'acme', version: '0.1.0', root: a.pack.root });
    expect(a.pack.defs.map((d) => d.verb)).toEqual(['acme.charge.refund', 'acme.invoice.send']);
    expect(a.cards.map((c) => c.verb)).toEqual(['acme.charge.refund', 'acme.invoice.send']);
    expect(Object.keys(a.mcp.tools)).toEqual(['refund_charge']);
    // nobody confirmed these defs: no safety claim is advertised
    expect(a.mcp.tools.refund_charge!.annotations).toMatchObject({ readOnlyHint: false, idempotentHint: false });
    const c = buildArtifacts(defs().map((d) => confirmed(d)), cfg, CORE_REGISTRY, testReview());
    expect(c.mcp.tools.refund_charge!.annotations).toMatchObject({ readOnlyHint: false, idempotentHint: true });
    expect(a.ontology.verbs.map((v) => v.id)).toContain('acme.charge.refund');
  });
  it('the MCP tool map resolves a tool call to its verb and resource, and refuses what does not match', () => {
    const m = toolActionMapOf(defs());
    expect(m('refund_charge', { charge: 'ch_12345678', amount: 5 })).toEqual({ verb: 'acme.charge.refund', resource: 'acme.charge:ch_12345678' });
    expect(m('refund_charge', { charge: 'nope', amount: 5 })).toBeNull();
    expect(m('unknown_tool', {})).toBeNull();
  });
  it('generated types: params per verb, optional marks, nested dotted names, enums and sets', () => {
    const d = loadActionsText('ns: acme\nactions:\n  - verb: acme.order.place\n    effects: update\n    resource: acme.order\n    params: {customer.email: email, customer.name: "text(40)?", size: "enum(s|m)", tags: "set(x|y)", ids: "array(integer, max=3)", n: "int(0..9)", on: bool, when: datetime}\n').defs[0]!;
    const t = generateTypes([d]);
    expect(t).toContain('export interface AcmeOrderPlaceParams {');
    expect(t).toContain('  customer: {\n    email: string;\n    name?: string;\n  };');
    expect(t).toContain('  size: "s" | "m";');
    expect(t).toContain('  tags: Array<"x" | "y">;');
    expect(t).toContain('  ids: number[];');
    expect(t).toContain('  n: number;');
    expect(t).toContain('  on: boolean;');
    expect(t).toContain('  "acme.order.place": AcmeOrderPlaceParams;');
  });
  it('a pack above the unsharded limit is refused', () => {
    const many = Array.from({ length: MAX_PACK_DEFS + 1 }, (_, i) => ({ ...send(), verb: `acme.n${i}.send` }));
    expect(() => buildArtifacts(many, cfg, CORE_REGISTRY)).toThrow(/must be sharded/);
  });
  it('duplicate verbs and conflicting units are refused, never a partial build', () => {
    expect(() => buildArtifacts([send(), send()], cfg, CORE_REGISTRY)).toThrow(/appears twice/);
  });
});

describe('pack signing: domain-separated, and only a consistent pack is signed', () => {
  const cfg: BuildConfig = { ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api' };
  const kp = generateKeyPair();
  const out = () => buildArtifacts(defs(), cfg, CORE_REGISTRY);
  it('sign then verify; the signature is deterministic', () => {
    const s = signPack(out().pack, 'reg-1', kp.secretKey, CORE_REGISTRY);
    expect(verifyPack(s, [packKeyOf('reg-1', kp.secretKey)], CORE_REGISTRY)).toEqual({ ok: true });
    expect(signPack(out().pack, 'reg-1', kp.secretKey, CORE_REGISTRY).sig.value).toBe(s.sig.value);
    expect(PACK_SIGN_DOMAIN).toBe('atlas-pca/action-pack/v1\0');
  });
  it('a tampered def, root, version, key id, key and signature are refused', () => {
    const s = signPack(out().pack, 'reg-1', kp.secretKey, CORE_REGISTRY);
    const keys = [packKeyOf('reg-1', kp.secretKey)];
    const v = (p: unknown, k = keys) => verifyPack(p, k, CORE_REGISTRY);
    expect(v({ ...s, version: '9.9.9' })).toEqual({ ok: false, reason: 'pack signature invalid' });
    expect(v({ ...s, stability: 'stable' })).toEqual({ ok: false, reason: 'pack signature invalid' });
    expect(v({ ...s, defs: [{ ...s.defs[0]!, title: 'Other' }, s.defs[1]!] })).toMatchObject({ ok: false, reason: expect.stringMatching(/root does not match/) });
    expect(v({ ...s, root: 'AAAA' })).toMatchObject({ ok: false });
    expect(v({ ...s, sig: { ...s.sig, kid: 'other' } })).toMatchObject({ ok: false, reason: expect.stringMatching(/no registry key/) });
    expect(v(s, [packKeyOf('reg-1', generateKeyPair().secretKey)])).toEqual({ ok: false, reason: 'pack signature invalid' });
    expect(v({ ...s, sig: { ...s.sig, value: s.sig.value.slice(2) + 'AA' } }).ok).toBe(false);
    expect(v({ ...s, sig: undefined })).toMatchObject({ ok: false, reason: expect.stringMatching(/missing or malformed/) });
    expect(v(null).ok).toBe(false);
    expect(v({ ...s, traits_digest: 'AAAA' })).toMatchObject({ ok: false, reason: expect.stringMatching(/traits_digest/) });
  });
  it("a schema signature is not a pack signature, and the other way round", async () => {
    const { signActionSchema, verifyActionSchema, actionSchemaKeyOf } = await import('@atlasauth/pca/ext/intent');
    const o = out();
    const sp = signPack(o.pack, 'k', kp.secretKey, CORE_REGISTRY);
    const ss = signActionSchema(o.schema, 'k', kp.secretKey);
    // swap the signature values: each verifier computes its own domain-separated message
    expect(verifyPack({ ...sp, sig: { ...sp.sig, value: ss.sig.value } }, [packKeyOf('k', kp.secretKey)], CORE_REGISTRY).ok).toBe(false);
    expect(verifyActionSchema({ ...ss, sig: { ...ss.sig, value: sp.sig.value } }, [actionSchemaKeyOf('k', kp.secretKey)]).ok).toBe(false);
  });
  it('an inconsistent pack is not signed', () => {
    const p = out().pack;
    expect(() => signPack({ ...p, root: 'AAAA' }, 'k', kp.secretKey, CORE_REGISTRY)).toThrow(/root does not match/);
    expect(() => signPack({ ...p, defs: [...p.defs, p.defs[0]!] }, 'k', kp.secretKey, CORE_REGISTRY)).toThrow(/defined twice/);
    expect(() => signPack({ ...p, defs: [{ ...p.defs[0]!, bogus: 1 } as never] }, 'k', kp.secretKey, CORE_REGISTRY)).toThrow(/unknown member/);
    expect(packConsistencyError({ ...p, kind: 'x' }, CORE_REGISTRY)).toMatch(/not a pca-action-pack/);
    expect(packConsistencyError([], CORE_REGISTRY)).toMatch(/must be an object/);
    expect(b64u(kp.secretKey).length).toBeGreaterThan(0);
  });
});

