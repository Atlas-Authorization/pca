import { describe, expect, it } from 'vitest';
import { evaluatePredicates, type ActionContext } from '@atlasauth/pca';
import { openfgaToPca } from './openfga';

const allow = (preds: Parameters<typeof evaluatePredicates>[0], ctx: ActionContext) =>
  evaluatePredicates(preds, ctx).allowed;

const model = {
  schema_version: '1.1',
  type_definitions: [
    { type: 'user' },
    {
      type: 'folder',
      relations: {
        viewer: { this: {} },
      },
    },
    {
      type: 'document',
      relations: {
        owner: { this: {} },
        editor: { this: {} },
        viewer: { this: {} },
        banned: { this: {} },
        gated: { this: {} },
        parent: { this: {} },
        can_view: {
          union: {
            child: [
              { computedUserset: { relation: 'viewer' } },
              { computedUserset: { relation: 'editor' } },
              { computedUserset: { relation: 'owner' } },
            ],
          },
        },
        can_edit: {
          union: { child: [{ computedUserset: { relation: 'editor' } }, { computedUserset: { relation: 'owner' } }] },
        },
        // intersection (AND): must be directly `gated` AND a viewer
        gated_view: {
          intersection: { child: [{ computedUserset: { relation: 'gated' } }, { computedUserset: { relation: 'viewer' } }] },
        },
        // difference (NOT): viewer AND NOT banned
        can_comment: {
          difference: { base: { computedUserset: { relation: 'viewer' } }, subtract: { computedUserset: { relation: 'banned' } } },
        },
        // tupleToUserset: viewer inherited from the parent folder
        inherited_view: {
          tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'viewer' } },
        },
      },
    },
  ],
};

const tuples = [
  { user: 'user:anne', relation: 'viewer', object: 'document:budget' },
  { user: 'user:beth', relation: 'editor', object: 'document:budget' },
  { user: 'user:carl', relation: 'owner', object: 'document:roadmap' },
  { user: 'group:eng#member', relation: 'viewer', object: 'document:roadmap' }, // userset-valued => skipped
  // intersection: dora is both directly `gated` and a viewer; anne is only a viewer
  { user: 'user:dora', relation: 'gated', object: 'document:budget' },
  { user: 'user:dora', relation: 'viewer', object: 'document:budget' },
  // difference: fred is a viewer (not banned); evan is a viewer AND banned
  { user: 'user:fred', relation: 'viewer', object: 'document:wiki' },
  { user: 'user:evan', relation: 'viewer', object: 'document:wiki' },
  { user: 'user:evan', relation: 'banned', object: 'document:wiki' },
  // tupleToUserset: budget's parent is folder:finance; gail is a viewer of that folder
  { user: 'folder:finance', relation: 'parent', object: 'document:budget' },
  { user: 'user:gail', relation: 'viewer', object: 'folder:finance' },
];

const ctx = (verb: string, resource: string, id: string): ActionContext => ({
  action: { verb, resource },
  subject: { id },
});

describe('openfgaToPca', () => {
  it('resolves direct relations and union/computedUserset expansion', () => {
    const { predicates, report } = openfgaToPca(model, tuples);
    expect(report.errors).toEqual([]);
    expect(allow(predicates, ctx('viewer', 'document:budget', 'user:anne'))).toBe(true);
    expect(allow(predicates, ctx('can_view', 'document:budget', 'user:anne'))).toBe(true);
    expect(allow(predicates, ctx('can_edit', 'document:budget', 'user:anne'))).toBe(false);
    expect(allow(predicates, ctx('can_view', 'document:budget', 'user:beth'))).toBe(true);
    expect(allow(predicates, ctx('can_edit', 'document:budget', 'user:beth'))).toBe(true);
    expect(allow(predicates, ctx('can_edit', 'document:roadmap', 'user:carl'))).toBe(true);
  });

  it('models intersection (AND): grants only when every conjunct holds', () => {
    const { predicates } = openfgaToPca(model, tuples);
    // dora is both `gated` and `viewer` => gated_view holds
    expect(allow(predicates, ctx('gated_view', 'document:budget', 'user:dora'))).toBe(true);
    // anne is a viewer but not `gated` => gated_view denied
    expect(allow(predicates, ctx('gated_view', 'document:budget', 'user:anne'))).toBe(false);
  });

  it('models difference (NOT): base minus subtract', () => {
    const { predicates } = openfgaToPca(model, tuples);
    // fred is a viewer and not banned => can_comment
    expect(allow(predicates, ctx('can_comment', 'document:wiki', 'user:fred'))).toBe(true);
    // evan is a viewer but banned => no can_comment
    expect(allow(predicates, ctx('can_comment', 'document:wiki', 'user:evan'))).toBe(false);
  });

  it('models tupleToUserset (bounded closure): viewer inherited from parent folder', () => {
    const { predicates } = openfgaToPca(model, tuples);
    // gail views folder:finance, which is budget's parent => inherited_view on budget
    expect(allow(predicates, ctx('inherited_view', 'document:budget', 'user:gail'))).toBe(true);
    // anne views budget directly but not the folder => no inherited_view
    expect(allow(predicates, ctx('inherited_view', 'document:budget', 'user:anne'))).toBe(false);
  });

  it('fails closed on absent tuples and wrong subject', () => {
    const { predicates } = openfgaToPca(model, tuples);
    expect(allow(predicates, ctx('can_view', 'document:roadmap', 'user:anne'))).toBe(false);
    expect(allow(predicates, ctx('can_view', 'document:budget', 'user:mallory'))).toBe(false);
  });

  it('still skips userset-valued tuples (the real remaining boundary)', () => {
    const { predicates, report } = openfgaToPca(model, tuples);
    expect(report.skipped.some((s) => s.includes('userset-valued'))).toBe(true);
    // the group#member userset tuple did not expand to a concrete viewer grant on roadmap
    expect(predicates.some((p) => p.resource === 'document:roadmap' && p.verb === 'viewer')).toBe(false);
  });

  it('terminates and fails closed on a cyclic model', () => {
    const cyclic = {
      type_definitions: [
        { type: 'user' },
        {
          type: 'node',
          relations: {
            direct_m: { this: {} },
            // a <- b <- a : computedUserset cycle
            m: { computedUserset: { relation: 'n' } },
            n: { computedUserset: { relation: 'm' } },
          },
        },
      ],
    };
    const { predicates } = openfgaToPca(cyclic, [{ user: 'user:x', relation: 'direct_m', object: 'node:1' }]);
    // m/n are a pure cycle with no direct source => nobody holds them (no hang)
    expect(allow(predicates, ctx('m', 'node:1', 'user:x'))).toBe(false);
    expect(allow(predicates, ctx('n', 'node:1', 'user:x'))).toBe(false);
  });

  it('fails closed on a malformed model', () => {
    const { predicates, report } = openfgaToPca({ nope: true }, tuples);
    expect(predicates).toEqual([]);
    expect(report.errors.length).toBeGreaterThan(0);
  });
});
