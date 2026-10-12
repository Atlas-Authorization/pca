// Stryker survivor kills for the 0.4.1 changes (root caveats, max_spend, strict PCA-Action header).
import { describe, expect, it } from 'vitest';
import { PcaHeaderError, decodePcaHeader } from './adapters';
import { actionSpendUsd, agentNativeCaveatEvaluator, describeEnvelope, envelopePermits } from './agent-native';
import { delegate, mintRoot, type Capability, type Caveat } from './capability';
import { ENVELOPE_CAVEAT, mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { decide, policyCaveats, rootCaveats } from './policy-vm';
import { DEFAULT_RISK_POLICY } from './risk';
import { defaultExtract } from './server/require-pca';

const NOW = Date.UTC(2026, 9, 12);
const ENV = { type: ENVELOPE_CAVEAT, x: 1 };
const g = (caveats: unknown) => ({ caveats }) as unknown as Capability;

describe('rootCaveats / policyCaveats edge cases', () => {
  it('rootCaveats returns a copy, tolerates null entries and passes a non-array through', () => {
    const cs = [{ type: 'a' }];
    const r = rootCaveats(g(cs));
    expect(r).toEqual(cs);
    expect(r).not.toBe(cs);
    expect(rootCaveats(g([null, ENV, { type: 'b' }]))).toEqual([null, { type: 'b' }]);
    expect(rootCaveats(g(5))).toBe(5);
    expect(rootCaveats(undefined as never)).toBeUndefined();
  });
  it('policyCaveats appends only real hop caveats beyond the grant', () => {
    const grant = g([ENV, { type: 'r' }]);
    expect(policyCaveats(grant)).toEqual([{ type: 'r' }]);
    expect(policyCaveats(grant, [])).toEqual([{ type: 'r' }]);
    expect(policyCaveats(grant, [grant, g([ENV, { type: 'r' }, { type: 'h' }])])).toEqual([{ type: 'r' }, { type: 'h' }]);
    // an array-like is not a chain; a non-array leaf caveat list or a non-array grant list appends nothing
    expect(policyCaveats(grant, { length: 1, 0: g([ENV, { type: 'r' }, { type: 'x' }]) } as never)).toEqual([{ type: 'r' }]);
    expect(policyCaveats(grant, [g('abcdef')])).toEqual([{ type: 'r' }]);
    expect(policyCaveats(g(5), [g([1, 2])])).toBe(5);
    expect(policyCaveats(undefined as never, [g([1])])).toBeUndefined();
  });
});

describe('max_spend boundaries', () => {
  const ev = (cv: Record<string, unknown>, params: unknown) =>
    agentNativeCaveatEvaluator(cv as Caveat, { now: NOW, action: { action: { verb: 'pay', resource: 'r', params } } });
  it('usd 0 admits exactly a zero spend; a non-finite ceiling admits nothing', () => {
    expect(ev({ type: 'max_spend', usd: 0 }, { amount: 0 })).toBe(true);
    expect(ev({ type: 'max_spend', usd: 0 }, { amount: 0.01 })).toBe(false);
    expect(ev({ type: 'max_spend', usd: Infinity }, { amount: 1 })).toBe(false);
    expect(ev({ type: 'max_spend', usd: NaN }, { amount: 1 })).toBe(false);
  });
  it('actionSpendUsd never throws on a malformed action', () => {
    expect(actionSpendUsd({})).toBeUndefined();
    expect(actionSpendUsd({ action: 5 })).toBeUndefined();
    expect(actionSpendUsd({ action: {} })).toBeUndefined();
    expect(actionSpendUsd({ action: { params: 5 } })).toBeUndefined();
  });
});

describe('max_spend introspection', () => {
  const p = generateKeyPair();
  const pPub = encodeKey(p.publicKey);
  const { grant: g0 } = mintGrant({
    principalSecret: p.secretKey,
    principalPublic: pPub,
    holder: pPub,
    goal: 'g',
    envelope: { predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const chainWith = (root: Caveat[], hop: Caveat[]) => {
    const grant = mintRoot({ principalSecret: p.secretKey, principalPublic: pPub, holder: pPub, caveats: [...g0.caveats, ...root] });
    return [grant, delegate(grant, pPub, hop, p.secretKey)];
  };
  it('the tightest ceiling wins whatever the order', () => {
    expect(describeEnvelope(chainWith([{ type: 'max_spend', usd: 20 }], [{ type: 'max_spend', usd: 100 }])).remainingBudgetHints.maxSpendUsd).toBe(20);
    expect(describeEnvelope(chainWith([{ type: 'max_spend', usd: 100 }], [{ type: 'max_spend', usd: 20 }])).remainingBudgetHints.maxSpendUsd).toBe(20);
    expect(describeEnvelope(chainWith([], [])).remainingBudgetHints.maxSpendUsd).toBeUndefined();
  });
  it('a malformed ceiling is unsatisfiable; usd 0 is a valid ceiling', () => {
    expect(describeEnvelope(chainWith([{ type: 'max_spend', usd: -1 }], [])).unsatisfiable).toEqual(['max_spend']);
    expect(describeEnvelope(chainWith([{ type: 'max_spend', usd: '5' }], [])).unsatisfiable).toEqual(['max_spend']);
    expect(describeEnvelope(chainWith([{ type: 'max_spend' }], [])).unsatisfiable).toEqual(['max_spend']);
    const env = describeEnvelope(chainWith([{ type: 'max_spend', usd: 10 }], []));
    expect(envelopePermits(env, 'pay', 'r', NOW, {})).toBe(false); // a ceiling with no readable amount refuses
    expect(envelopePermits(env, 'pay', 'r', NOW, { amount: 10 })).toBe(true);
    const zero = describeEnvelope(chainWith([{ type: 'max_spend', usd: 0 }], []));
    expect(zero.unsatisfiable).toEqual([]);
    expect(zero.remainingBudgetHints.maxSpendUsd).toBe(0);
  });
  it('decide lists every failed root caveat, comma separated', () => {
    const [grant] = chainWith([{ type: 'note' }, { type: 'max_spend', usd: 1 }], []);
    const d = decide({ grant: grant!, action: { action: { verb: 'pay', resource: 'r', params: { amount: 5 } } }, risk: {}, budget: { B: 1, tau: NOW }, now: NOW });
    expect(d.reasons).toContain('root caveat(s) not satisfied: note, max_spend');
  });
});

describe('strict header decoder details', () => {
  it('the error carries its name, code and a specific message', () => {
    let err: unknown;
    try {
      decodePcaHeader('');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(PcaHeaderError);
    expect((err as PcaHeaderError).name).toBe('PcaHeaderError');
    expect((err as PcaHeaderError).code).toBe('invalid_pca_header');
    expect((err as Error).message).toBe('PCA-Action header is empty');
    expect(() => decodePcaHeader('a=')).toThrow('PCA-Action header is not strict unpadded base64url');
    // a non-string value is refused as such (never a TypeError, never another message)
    expect(() => decodePcaHeader(null as never)).toThrow('PCA-Action header is empty');
    expect(() => decodePcaHeader(5 as never)).toThrow('PCA-Action header is empty');
  });
  it('an empty header value falls through to the body', () => {
    const body = { pcactn: { a: 1 } };
    expect(defaultExtract({ headers: { 'pca-action': '' }, body })).toBe(body.pcactn);
    expect(defaultExtract({ headers: {}, body: { pcactn: null } })).toBeNull();
  });
});
