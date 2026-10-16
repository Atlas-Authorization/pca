import { describe, expect, it } from 'vitest';
import { b64u, buildDiscoveryDocument, generateKeyPair, parseDiscoveryDocument } from '@atlasauth/pca';
import { buildIntentDiscoveryBlock, intentBlockOf, parseIntentDiscoveryBlock, withIntentBlock } from './index';

const pk = b64u(generateKeyPair().publicKey);
const M1 = {
  versions: [1, 2],
  actions_uri: 'https://skyair.example/.well-known/pca-actions.json',
  schema_keys: [{ kid: 'skyair-schema-2026', alg: 'ed25519', pk }],
  question_relay: true,
  tiers: { 'air.search': 1, 'air.hold': 2, 'air.book': 3, 'air.refund': 4 },
  evidence_uri: 'https://skyair.example/pca/evidence',
};

describe('discovery intent block (M1)', () => {
  it('builds exactly the M1 member', () => {
    const b = buildIntentDiscoveryBlock({ versions: [2, 1], actionsUri: M1.actions_uri, schemaKeys: [{ kid: 'skyair-schema-2026', alg: 'ed25519', pk }], questionRelay: true, tiers: { 'air.search': 1, 'air.hold': 2, 'air.book': 3, 'air.refund': 4 }, evidenceUri: M1.evidence_uri });
    expect(b).toEqual(M1);
  });
  it('rides on the core document as its official intent member and reads back', () => {
    const doc = withIntentBlock(buildDiscoveryDocument({ audience: 'skyair.example' }), parseIntentDiscoveryBlock(M1));
    const wire = JSON.parse(JSON.stringify(doc)) as unknown;
    expect(intentBlockOf(wire)).toEqual(M1);
    expect(parseDiscoveryDocument(wire).intent?.versions).toEqual([1, 2]);
    expect(intentBlockOf({ audience: 'x' })).toBeNull();
  });
  it('fails closed on unknown or malformed members', () => {
    expect(() => parseIntentDiscoveryBlock({ ...M1, extra: true })).toThrow(/unknown member/);
    expect(() => parseIntentDiscoveryBlock({ ...M1, versions: [3] })).toThrow();
    expect(() => parseIntentDiscoveryBlock({ ...M1, versions: [] })).toThrow();
    expect(() => parseIntentDiscoveryBlock({ ...M1, schema_keys: [] })).toThrow(/at least one schema key/);
    expect(() => parseIntentDiscoveryBlock({ ...M1, schema_keys: [{ kid: 'a', alg: 'rs256', pk }] })).toThrow();
    expect(() => parseIntentDiscoveryBlock({ ...M1, schema_keys: [{ kid: 'a', alg: 'ed25519', pk: 'short' }] })).toThrow();
    expect(() => parseIntentDiscoveryBlock({ ...M1, schema_keys: [{ kid: 'a', alg: 'ed25519', pk }, { kid: 'a', alg: 'ed25519', pk }] })).toThrow(/duplicate/);
    expect(() => parseIntentDiscoveryBlock({ ...M1, tiers: { x: 7 } })).toThrow();
    expect(() => parseIntentDiscoveryBlock({ ...M1, actions_uri: 'ftp://x' })).toThrow();
    expect(() => intentBlockOf({ intent: { versions: [2] } })).toThrow();
    // a PQ suite key must pin its pq_pk; an ed25519 key must not carry one
    expect(() => parseIntentDiscoveryBlock({ ...M1, schema_keys: [{ kid: 'a', alg: 'hybrid-ed25519-ml-dsa-65', pk }] })).toThrow(/pq_pk/);
    expect(() => parseIntentDiscoveryBlock({ ...M1, schema_keys: [{ kid: 'a', alg: 'ed25519', pk, pq_pk: 'x' }] })).toThrow(/pq_pk/);
  });
});
