// legacy.ts - liftLegacy: the total, conservative lift of the facade's `{permissions, limits}` input to a Goal + Ontology
// (spec section 12). The corrected semantics of the four facade bugs live here, compiled by the proved compiler:
//   W5  `$200/day` is a SLIDING 86 400 000 ms sum bound (explicit window), not a per-call ceiling plus a one-day grant lifetime
//   W6  a `$` limit on a verb with no amount field is an error
//   W7  every limit is its own bound, so adding a limit only narrows; co-sign tiers are not part of the goal at all
// Money parameters are integers in MINOR units of USD (cents): this is the explicit unit the old facade left implicit (W18), and
// a caller that passes dollars is refused by the verifier-side units check rather than silently misread.
import { compilePolicy, parseLimit, type CompiledPolicy, type Limits, type PermissionMap } from '@atlasauth/pca';
import type { Bound, Cond, Goal, Grant, Ontology, VerbDecl } from './ir';

type ActionSpec = CompiledPolicy['actions'][number];
type Catalog = NonNullable<Parameters<typeof compilePolicy>[0]['catalog']>;

export interface LiftOptions {
  permissions: PermissionMap;
  limits?: Limits;
  catalog?: Catalog;
  principal: string;
  /** Epoch ms the grant stops being valid. Default: no expiry (the largest safe integer). */
  notAfter?: number;
  notBefore?: number;
  nlDigest?: string;
}
const USD = { k: 'money', ccy: 'USD' } as const;
const byCode = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0); // UTF-16 code-unit order, as StrLt in GoalIr.dfy

export function liftLegacy(o: LiftOptions): { goal: Goal; ontology: Ontology } {
  const raw = o.limits ?? {};
  const own = (k: string): string | undefined => (Object.prototype.hasOwnProperty.call(raw, k) ? raw[k] : undefined);
  // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
  const specs: ActionSpec[] = compilePolicy({ permissions: o.permissions, ...(o.catalog ? { catalog: o.catalog } : {}) }).actions;
  const grants: Grant[] = [];
  const bounds: Bound[] = [];
  const verbs: VerbDecl[] = [];
  for (const s of specs) {
    const gid = `g:${s.verb}`;
    const amountPath = s.amountField;
    verbs.push({ verb: s.verb, cls: s.reversibility, params: amountPath ? [{ path: amountPath, ty: { k: 'q', u: USD } }] : [] });
    const resource = s.resource ?? '*';
    if (/[*?]|^re:/.test(resource) && resource !== '*') throw new Error(`liftLegacy: resource pattern '${resource}' of ${s.verb} is not expressible; name exact resources or acknowledge a wildcard`);
    const rawLimit = own(s.verb) ?? own(s.action);
    let cond: Cond = { k: 'true' };
    if (rawLimit !== undefined) {
      const lim = parseLimit(rawLimit);
      if (lim.unit === 'usd') {
        if (!amountPath) throw new Error(`liftLegacy: '$' limit on '${s.verb}' but the catalog gives that verb no amount field, so the limit could not be enforced`);
        const minor = Math.round(lim.amount * 100);
        if (!Number.isSafeInteger(minor)) throw new Error(`liftLegacy: limit for ${s.verb} is out of range`);
        const amt = { k: 'param', path: amountPath, ty: { k: 'q', u: USD } } as const;
        cond = { k: 'and', a: { k: 'cmp', op: 'gte', l: amt, r: { k: 'lit', v: { k: 'q', q: { u: USD, n: 0 } } } }, b: { k: 'cmp', op: 'lte', l: amt, r: { k: 'lit', v: { k: 'q', q: { u: USD, n: minor } } } } };
        if (lim.periodMs !== undefined) {
          bounds.push({ bid: `b:${s.verb}`, sel: { k: 'gids', gids: [gid] }, agg: 'sum', value: amt, key: '', window: { k: 'sliding', ms: lim.periodMs }, scope: { k: 'session' }, cap: { u: USD, n: minor }, onExceed: 'deny' });
        }
      } else {
        if (!Number.isSafeInteger(lim.amount)) throw new Error(`liftLegacy: count limit for ${s.verb} must be a whole number`);
        bounds.push({
          bid: `b:${s.verb}`, sel: { k: 'gids', gids: [gid] }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: { k: 'count' }, n: 1 } } }, key: '',
          window: lim.periodMs !== undefined ? { k: 'sliding', ms: lim.periodMs } : { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: { k: 'count' }, n: lim.amount }, onExceed: 'deny',
        });
      }
    }
    grants.push({ gid, verb: s.verb, res: resource === '*' ? { k: 'any', reason: 'legacy default: no resource scope given' } : { k: 'exact', id: resource }, cond });
  }
  grants.sort((a, b) => byCode(a.gid, b.gid));
  bounds.sort((a, b) => byCode(a.bid, b.bid));
  for (let i = 1; i < grants.length; i++) if (grants[i]!.gid === grants[i - 1]!.gid) throw new Error(`liftLegacy: duplicate grant ${grants[i]!.gid}`);
  const goal: Goal = {
    v: 1, principal: o.principal, ontDigest: 'legacy-catalog', nlDigest: o.nlDigest ?? '', sources: [],
    grants, prohibits: [], bounds,
    validity: { notBefore: o.notBefore ?? 0, notAfter: o.notAfter ?? Number.MAX_SAFE_INTEGER, maxIdle: 0 },
    deleg: { maxDepth: 16, narrowOnly: true, mayTouch: grants.map((g) => g.gid) },
    escalateOn: [], wildcardAck: grants.filter((g) => g.res.k === 'any').map((g) => g.gid), holes: [],
  };
  const ontology: Ontology = { verbs: verbs.sort((a, b) => byCode(a.verb, b.verb)).filter((v, i, a) => i === 0 || a[i - 1]!.verb !== v.verb), rels: [] };
  return { goal, ontology };
}
