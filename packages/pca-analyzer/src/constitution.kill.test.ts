import { describe, expect, it } from 'vitest';
import type { prohibitions } from '@atlasauth/pca';
import { vetoesFromConstitution } from './index';

const when = { verb: 'v' };
const unless = [{ field: 'env.ok', op: 'eq' as const, value: true }];
const approved = [{ field: 'env.approved', op: 'eq' as const, value: true }];

describe('vetoesFromConstitution (exact mapping)', () => {
  it('maps every invariant kind to its exact veto or unmodeled entry', () => {
    const c = {
      version: 1,
      principal: 'p',
      invariants: [
        { kind: 'never', id: 'n', when },
        { kind: 'never_unless', id: 'nu', when, unless },
        { kind: 'require_approval_over', id: 'ra', when, amount: 'action.params.amount', threshold: 7, approved },
        { kind: 'cap', id: 'c', when, amount: 'action.params.amount', max: 5 },
        { kind: 'rate', id: 'r', when, max: 1, window_secs: 60 },
        { kind: 'never_after', id: 'na', after: when, forbid: when },
        { kind: 'require_prior', id: 'rp', when, prior: when },
      ],
    } as unknown as prohibitions.Constitution;
    expect(vetoesFromConstitution(c)).toStrictEqual({
      vetoes: [
        { id: 'n', kind: 'deny', when },
        { id: 'nu', kind: 'deny', when, unless },
        { id: 'ra', kind: 'approval', when, over: { path: 'action.params.amount', threshold: 7 }, unless: approved },
      ],
      unmodeled: [
        { id: 'c', kind: 'cap', reason: 'windowed total: bounded by maxExposure, not by a per-action veto' },
        { id: 'r', kind: 'rate', reason: 'windowed total: bounded by maxExposure, not by a per-action veto' },
        { id: 'na', kind: 'never_after', reason: 'needs action history' },
        { id: 'rp', kind: 'require_prior', reason: 'needs action history' },
      ],
    });
  });

  it('a missing or malformed constitution yields nothing and does not throw', () => {
    expect(vetoesFromConstitution(undefined as unknown as prohibitions.Constitution)).toStrictEqual({ vetoes: [], unmodeled: [] });
    expect(vetoesFromConstitution({} as unknown as prohibitions.Constitution)).toStrictEqual({ vetoes: [], unmodeled: [] });
    expect(vetoesFromConstitution({ invariants: 'x' } as unknown as prohibitions.Constitution)).toStrictEqual({ vetoes: [], unmodeled: [] });
    expect(vetoesFromConstitution({ version: 1, principal: 'p', invariants: [] })).toStrictEqual({ vetoes: [], unmodeled: [] });
  });
});
