import type { prohibitions } from '@atlasauth/pca';
import type { Veto } from './types';

type Constitution = prohibitions.Constitution;
type Invariant = prohibitions.Invariant;

export interface ConstitutionVetoes {
  /** The stateless invariants (`never`, `never_unless`, `require_approval_over`) in analyzable form. */
  vetoes: Veto[];
  /** Stateful invariants the enumeration cannot model: ignoring them can only OVER-approximate what is admitted. */
  unmodeled: Array<{ id: string; kind: Invariant['kind']; reason: string }>;
}

/**
 * Turn a constitution into analyzer vetoes. `cap` and `rate` are consumed by `maxExposure` (windowed totals); `never_after` and
 * `require_prior` need history and are reported in `unmodeled`. Because every unmodeled invariant can only remove actions,
 * leaving it out makes admitted-set queries an over-approximation (sound for exposure and reachability of danger, not for
 * "always denies").
 */
export function vetoesFromConstitution(c: Constitution): ConstitutionVetoes {
  const vetoes: Veto[] = [];
  const unmodeled: ConstitutionVetoes['unmodeled'] = [];
  for (const inv of Array.isArray(c?.invariants) ? c.invariants : []) {
    switch (inv.kind) {
      case 'never':
        vetoes.push({ id: inv.id, kind: 'deny', when: inv.when });
        break;
      case 'never_unless':
        vetoes.push({ id: inv.id, kind: 'deny', when: inv.when, unless: inv.unless });
        break;
      case 'require_approval_over':
        vetoes.push({ id: inv.id, kind: 'approval', when: inv.when, over: { path: inv.amount, threshold: inv.threshold }, unless: inv.approved });
        break;
      case 'cap':
      case 'rate':
        unmodeled.push({ id: inv.id, kind: inv.kind, reason: 'windowed total: bounded by maxExposure, not by a per-action veto' });
        break;
      default:
        unmodeled.push({ id: inv.id, kind: inv.kind, reason: 'needs action history' });
    }
  }
  return { vetoes, unmodeled };
}
