/** 0.4.2 mutation kills: parseDiscoveryIntent refusals with their exact messages, and the optional pq_pk of a schema key. */
import { describe, expect, it } from 'vitest';
import { parseDiscoveryIntent } from './discovery';

const msg = (v: unknown): string => {
  try {
    parseDiscoveryIntent(v);
  } catch (e) {
    return (e as Error).message;
  }
  return '<no throw>';
};
const K = { kid: 'k', alg: 'ed25519', pk: 'AAAA' };

describe('parseDiscoveryIntent', () => {
  it('refuses every malformed shape with its exact message', () => {
    for (const v of [null, 5, 'x', []]) expect(msg(v)).toBe('parseDiscoveryDocument: intent must be an object');
    expect(msg({ versions: [1], extra: 1 })).toBe("parseDiscoveryDocument: intent has unknown member 'extra'");
    expect(msg({ versions: [] })).toBe('parseDiscoveryDocument: intent.versions must list 1 and/or 2');
    expect(msg({ versions: [3] })).toBe('parseDiscoveryDocument: intent.versions must list 1 and/or 2');
    expect(msg({ versions: [1], actions_uri: '' })).toBe('parseDiscoveryDocument: intent.actions_uri must be a non-empty string');
    expect(msg({ versions: [1], evidence_uri: 5 })).toBe('parseDiscoveryDocument: intent.evidence_uri must be a non-empty string');
    expect(msg({ versions: [1], schema_keys: 'x' })).toBe('parseDiscoveryDocument: intent.schema_keys must be an array');
    expect(msg({ versions: [1], question_relay: 'yes' })).toBe('parseDiscoveryDocument: intent.question_relay must be a boolean');
    expect(msg({ versions: [1], tiers: [] })).toBe('parseDiscoveryDocument: intent.tiers must be an object');
    expect(msg({ versions: [1], tiers: { a: 5 } })).toBe('parseDiscoveryDocument: intent.tiers values must be integers 0..4');
  });
  it('schema_keys entries are {kid, alg, pk, pq_pk?}: pq_pk is optional but must be a string when present', () => {
    const bad = 'parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}';
    expect(msg({ versions: [1], schema_keys: [{ ...K, pq_pk: 5 }] })).toBe(bad);
    expect(msg({ versions: [1], schema_keys: [null] })).toBe(bad);
    expect(msg({ versions: [1], schema_keys: [{ ...K, kid: 1 }] })).toBe(bad);
    expect(parseDiscoveryIntent({ versions: [1], schema_keys: [K] }).schema_keys).toStrictEqual([K]);
    expect(parseDiscoveryIntent({ versions: [2], schema_keys: [{ ...K, pq_pk: 'BBBB', extra: 1 }] }).schema_keys).toStrictEqual([{ ...K, pq_pk: 'BBBB' }]);
  });
});
