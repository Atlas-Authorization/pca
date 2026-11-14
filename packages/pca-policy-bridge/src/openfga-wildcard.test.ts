import { describe, expect, it } from 'vitest';
import { decide, openfgaToPca } from './index';

const model = {
  schema_version: '1.1',
  type_definitions: [
    { type: 'user' },
    { type: 'bot' },
    {
      type: 'doc',
      relations: {
        viewer: { this: {} },
        banned: { this: {} },
        can_comment: { difference: { base: { computedUserset: { relation: 'viewer' } }, subtract: { computedUserset: { relation: 'banned' } } } },
      },
    },
  ],
};
const can = (tuples: object[], subject: string, relation: string) => {
  const r = openfgaToPca(model, tuples);
  expect(r.report.errors).toEqual([]);
  return decide(r, { subject: { id: subject }, action: { verb: relation, resource: 'doc:d' } } as never).allowed;
};

describe('public (type:*) tuples', () => {
  const pub = [{ user: 'user:*', relation: 'viewer', object: 'doc:d' }];
  it('grant every subject of that type, named by a tuple or not', () => {
    expect(can(pub, 'user:anyone', 'viewer')).toBe(true);
    expect(can([...pub, { user: 'user:u1', relation: 'banned', object: 'doc:d' }], 'user:u1', 'viewer')).toBe(true);
  });
  it('do not grant a subject of another type', () => {
    expect(can(pub, 'bot:b1', 'viewer')).toBe(false);
    expect(can(pub, 'user:u1', 'banned')).toBe(false);
  });
  it('a named exclusion in a difference still applies, and everyone else is allowed', () => {
    const t = [...pub, { user: 'user:u2', relation: 'banned', object: 'doc:d' }];
    expect(can(t, 'user:u2', 'can_comment')).toBe(false);
    expect(can(t, 'user:u1', 'can_comment')).toBe(true);
    expect(can(t, 'user:never-named', 'can_comment')).toBe(true);
  });
  it('a public ban on the subtracted side denies everyone of that type', () => {
    const t = [...pub, { user: 'user:*', relation: 'banned', object: 'doc:d' }, { user: 'user:u1', relation: 'viewer', object: 'doc:d' }];
    for (const u of ['user:u1', 'user:u9']) expect(can(t, u, 'can_comment')).toBe(false);
  });
  it('are not reported as skipped: the translation is exact', () => {
    expect(openfgaToPca(model, pub).report.skipped).toEqual([]);
  });
});
