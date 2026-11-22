// Trait provenance (review.provenance): traits the fail-strict union added from the suggestion rules can be batch-reviewed, and leave a def
// only through a signed dismissal. Provenance is review metadata: it does not change the def digest.
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { ActionKitError, CORE_REGISTRY, confirmDef, defDigest, lintDefs, validateDef, type ActionDef } from '../src';

const reviewer = generateKeyPair();
const pins = { keys: [{ kid: 'rev-1', pk: b64u(reviewer.publicKey), roles: ['reviewer' as const] }] };
const base = (over: Partial<ActionDef> = {}): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: 'acme.refund.create', title: 'Create a refund', description: 'Creates a refund.', effects: ['create'],
  resource: { type: 'acme.refund', id: '*', scope: 'set' },
  params: { note: { type: 'string', max_len: 100 }, idempotency_key: { type: 'string', max_len: 64, required: false } },
  reversibility: 'irreversible', idempotency: { mode: 'key_param', param: 'idempotency_key' },
  traits: ['pca.money_moving'], review: { state: 'authored', provenance: { union: ['pca.money_moving'] } }, since: '0.5.0', ...over,
});
const decide = (d: ActionDef, finalTraits: string[], dismissed: { trait: string; reason: string }[] = []): ActionDef =>
  confirmDef(d, { registry: CORE_REGISTRY, reviewer: { kid: 'rev-1', secret: reviewer.secretKey }, pins, finalTraits, dismissed, ts: 1_700_000_000 });
const ld011 = (d: ActionDef): string[] => lintDefs([d], { attestationVerified: () => true }).filter((f) => f.rule === 'LD-011').map((f) => f.message);

describe('provenance', () => {
  it('is accepted, shape-checked, and not part of the def digest', () => {
    expect(validateDef(base())).toBeNull();
    expect(validateDef(base({ review: { state: 'authored', provenance: { union: ['x'] } } as ActionDef['review'] }))).toMatch(/provenance/);
    expect(validateDef(base({ review: { state: 'authored', provenance: { other: [] } } as unknown as ActionDef['review'] }))).toMatch(/provenance/);
    expect(defDigest(base())).toBe(defDigest(base({ review: { state: 'authored' } })));
  });
  it('a union-added trait removed without a signed dismissal is a lint error', () => {
    expect(ld011(base())).toEqual([]);
    const silent = base({ traits: [] });
    expect(ld011(silent).join(' ')).toMatch(/pca\.money_moving.*without a signed dismissal/);
  });
  it('an authored def with union provenance can be reviewed; keeping the trait attests it', () => {
    const c = decide(base(), ['pca.money_moving']);
    expect(c.review.state).toBe('confirmed');
    expect(c.review.provenance?.union).toEqual(['pca.money_moving']);
    expect(ld011(c)).toEqual([]);
  });
  it('dropping the trait needs a recorded reason and the attestation then names it', () => {
    expect(() => decide(base(), [])).toThrowError(ActionKitError);
    const c = decide(base(), [], [{ trait: 'pca.money_moving', reason: 'a read-only lookup, not a payment' }]);
    expect(c.traits ?? []).not.toContain('pca.money_moving');
    expect(c.review.attestation?.dismissed).toEqual([{ trait: 'pca.money_moving', reason: 'a read-only lookup, not a payment' }]);
    expect(ld011(c)).toEqual([]);
  });
  it('an unsigned edit that strips a confirmed def of the trait is still caught', () => {
    const c = decide(base(), ['pca.money_moving']);
    expect(ld011({ ...c, traits: [] }).join(' ')).toMatch(/without a signed dismissal|different digest/);
  });
  it('an authored def with no union provenance is unconfirmed too: it can be signed, nothing else lets it count', () => {
    expect(decide(base({ review: { state: 'authored' } }), ['pca.money_moving']).review.state).toBe('confirmed');
  });
});
