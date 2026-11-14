// Starter templates: every pack loads, validates, lints clean (no errors, no warnings) with its own custom traits, its business
// rules lint clean and their examples decide as written, its def examples pass the test runner, nothing in it is confirmed, and
// every undo it declares can really be derived. Checked under the default namespace and a second one.
import { describe, expect, it } from 'vitest';
import {
  CORE_REGISTRY, CORE_TRAIT_DEFS, STARTER_TEMPLATES, ActionKitError, compensationShape, effective, extendRegistry, isConfirmed, lintBusinessRules,
  lintDefs, loadActionsText, registryError, runDefTests, runRuleExamples, starterTemplate, validateDef,
  type ActionDef, type BusinessRules,
} from '../src';
import { testReview } from './reviewed';

// the product name must never appear in a template (built from parts so this file does not contain it either)
const BANNED = new RegExp(['forge', 'deck'].join(''), 'i');

describe('the starter template catalog', () => {
  it('has the five business types, each with picker text and a default namespace', () => {
    expect(STARTER_TEMPLATES.map((t) => t.id)).toEqual(['ecommerce', 'fintech', 'healthcare', 'saas_admin', 'devtools']);
    for (const t of STARTER_TEMPLATES) {
      expect(t.title.length).toBeGreaterThan(0);
      expect(t.description.length).toBeGreaterThan(20);
      expect(t.description.length).toBeLessThanOrEqual(300);
      expect(t.ns).toMatch(/^[a-z][a-z0-9_]{0,31}$/);
      expect(starterTemplate(t.id)).toBe(t);
    }
    expect(starterTemplate('nope')).toBeUndefined();
  });

  it('refuses a namespace that is not a plain identifier or is the reserved pca', () => {
    const t = STARTER_TEMPLATES[0]!;
    for (const bad of ['', 'Acme', 'a-b', 'acme\nactions: []', 'pca', 'x'.repeat(33)]) {
      expect(() => t.yaml(bad)).toThrow(ActionKitError);
      expect(() => t.traits(bad)).toThrow(ActionKitError);
    }
  });

  it('uses every business rule kind across the five templates', () => {
    const seen = new Set<string>();
    for (const t of STARTER_TEMPLATES) {
      for (const r of Object.values(loadActionsText(t.yaml(t.ns)).rules)) {
        if (r.amount) seen.add('amount');
        if (r.approval?.above) seen.add('approval.above');
        if (r.approval?.always) seen.add('approval.always');
        if (r.approval?.group) seen.add('approval.group');
        if ((r.approval?.approvers ?? 1) > 1) seen.add('approval.approvers');
        if (r.scope) seen.add('scope');
        for (const x of r.rate ?? []) { seen.add(`rate.${x.per}`); seen.add(`rate.${x.by ?? 'principal'}`); }
        if (r.hours) seen.add(r.hours.outside === 'deny' ? 'hours.deny' : 'hours.escalate');
        if (r.recipients?.domains) seen.add('recipients.domains');
        if (r.recipients?.addresses) seen.add('recipients.addresses');
        if (r.required) seen.add('required');
      }
    }
    expect([...seen].sort()).toEqual([
      'amount', 'approval.above', 'approval.always', 'approval.approvers', 'approval.group', 'hours.deny', 'hours.escalate',
      'rate.day', 'rate.hour', 'rate.org', 'rate.principal', 'recipients.addresses', 'recipients.domains', 'required', 'scope',
    ]);
  });
});

for (const t of STARTER_TEMPLATES) {
  for (const ns of [t.ns, 'acme_co']) {
    describe(`starter template ${t.id} under ns ${ns}`, () => {
      const text = t.yaml(ns);
      const res = loadActionsText(text);
      const traits = t.traits(ns);
      const reg = extendRegistry(CORE_REGISTRY, traits);
      const defs: ActionDef[] = res.defs;
      const byVerb = new Map(defs.map((d) => [d.verb, d]));

      it('loads with no errors, 6 to 12 actions, all in the namespace', () => {
        expect(res.errors).toEqual([]);
        expect(res.ns).toBe(ns);
        expect(defs.length).toBeGreaterThanOrEqual(6);
        expect(defs.length).toBeLessThanOrEqual(12);
        for (const d of defs) expect(d.verb.startsWith(`${ns}.`)).toBe(true);
      });

      it('every def validates', () => {
        for (const d of defs) expect(validateDef(d), d.verb).toBeNull();
      });

      it('lints with no errors and no warnings (stable pack, own custom traits)', () => {
        expect(lintDefs(defs, { customTraits: traits, ns, stability: 'stable' })).toEqual([]);
      });

      it('custom traits are namespaced, pass the registry checks and extend the core registry', () => {
        expect(traits.length).toBeGreaterThan(0);
        for (const tr of traits) expect(tr.id.startsWith(`${ns}.`)).toBe(true);
        expect(registryError([...CORE_TRAIT_DEFS, ...traits], { core: true })).toBeNull();
        expect(() => extendRegistry(CORE_REGISTRY, traits)).not.toThrow();
        // every custom trait is used by some action of the pack
        for (const tr of traits) expect(defs.some((d) => effective(d, reg).hint.closure.includes(tr.id)), tr.id).toBe(true);
      });

      it('every rules block lints clean, has examples, and every example decides as written', () => {
        expect(Object.keys(res.rules).length).toBeGreaterThan(0);
        for (const [verb, rules] of Object.entries(res.rules)) {
          const d = byVerb.get(verb)!;
          expect(d, verb).toBeDefined();
          expect(lintBusinessRules(d, rules), verb).toEqual([]);
          expect((rules.examples ?? []).length, verb).toBeGreaterThan(0);
          for (const x of runRuleExamples(d, rules)) expect(x.ok, `${verb} example ${x.index}: ${x.why}`).toBe(true);
        }
      });

      it('the def examples and property checks pass', () => {
        const r = runDefTests(defs, reg);
        expect(r.examples.filter((e) => !e.ok)).toEqual([]);
        expect(r.props.filter((p) => !p.ok)).toEqual([]);
        expect(r.ok).toBe(true);
      });

      it('nothing is confirmed, not even under pinned reviewer keys', () => {
        for (const d of defs) {
          expect(d.review.state, d.verb).toBe('authored');
          expect(d.review.attestation).toBeUndefined();
          expect(isConfirmed(d)).toBe(false);
          expect(isConfirmed(d, testReview(reg))).toBe(false);
          expect(effective(d, reg, testReview(reg)).confirmed).toBe(false);
        }
        expect(text).not.toMatch(/state:\s*confirmed/);
      });

      it('every compensating action is in the pack and can undo its action', () => {
        const comp = defs.filter((d) => d.compensates !== undefined);
        expect(comp.length).toBeGreaterThan(0);
        for (const d of comp) {
          const c = byVerb.get(d.compensates!);
          expect(c, `${d.verb} compensates ${d.compensates}`).toBeDefined();
          const s = compensationShape(d, c!);
          expect(s.ok, `${d.verb}: ${s.ok ? '' : s.reason}`).toBe(true);
        }
      });

      it('every money-moving action has a rules block with an amount ceiling', () => {
        const money = defs.filter((d) => effective(d, reg).hint.closure.includes('pca.money_moving'));
        for (const d of money) expect((res.rules[d.verb] as BusinessRules | undefined)?.amount, d.verb).toBeDefined();
      });

      it('never names the product', () => {
        expect(text).not.toMatch(BANNED);
        expect(JSON.stringify(traits)).not.toMatch(BANNED);
        expect(`${t.title} ${t.description}`).not.toMatch(BANNED);
      });
    });
  }
}
