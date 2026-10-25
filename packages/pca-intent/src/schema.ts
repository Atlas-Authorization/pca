import {
  canonicalizeStrict,
  compareUtf8,
  effectiveSensitivity,
  verbReversibility,
  walletFloorOverrides,
  type ActionParamDecl,
  type ActionSchema,
  type SensitivityOverride,
  type UnsignedActionSchema,
} from '@atlasauth/pca';
import { deriveOmega, OTHER, type CatValue, type Dim, type NumDim, type Omega, type VerbSpace } from './omega';
import type { PolicyInput } from './policy';
import type { IntentSlots, SlotConstraint } from './slots';

/**
 * Ω FROM THE SITE'S SIGNED ACTION SCHEMA (PCA Intent Layer v2 §2.3, §3.2 step 3; milestone V1).
 *
 * Ω_𝒮 is Ω with D_v := every parameter of v whose EFFECTIVE sensitivity (after the wallet floor) is material or
 * critical. Free parameters are projected away. Dimension paths:
 *   - integer, string and date parameters use their own path (`action.params.<name>`): the grant predicates compare
 *     the raw value;
 *   - boolean, set and array parameters use `env.canon.<name>`, the verifier-computed canonical text (intent-v2.ts
 *     `canonProjection`), so a grant compares them with the ordinary `eq` / `in` operators.
 * Every numeric parameter gets the cuts its declared bounds, the slots, the policies and the confirmed / default values
 * imply. Every categorical parameter ALWAYS has ⊥.
 *
 * DEFAULT SET (closed world for silent parameters): a material parameter that the slots and policies never mention gets
 * the cells {default set} and ⊥, where the default set is the values confirmed in this session or by the profile, or
 * the schema `default` when it is `principal_neutral_default`. The derivation returns a slot constraint per such
 * parameter so the narrow start grant admits only the default set: the first non-default value is a lazy question,
 * never a silent allowance. A silent parameter with no default set has the single cell ⊥ (any value).
 */

export interface SchemaOmegaOptions {
  schema: Pick<ActionSchema | UnsignedActionSchema, 'verbs'>;
  /** Restrict Ω to these verbs (default: every write verb of the schema plus the slot verbs). */
  verbs?: string[];
  slots?: IntentSlots;
  policies?: PolicyInput[];
  /** path -> values confirmed in this session or by the profile (a confirmed value joins the default set). */
  confirmed?: Record<string, (string | number | boolean | string[])[]>;
  /** Wallet floor override (default: the pca wallet floor). */
  floor?: { prefixes?: readonly string[]; exact?: readonly string[] };
  /** Numeric domain overrides by path. */
  domains?: Record<string, { lo: number; hi: number }>;
}

export interface SchemaOmega {
  omega: Omega;
  /** Sensitivity overrides the wallet floor made (recorded in the map as `omega.overrides`). */
  overrides: SensitivityOverride[];
  /** Slot constraints that pin silent parameters to their default set (add them to the narrow start). */
  defaults: SlotConstraint[];
  /** dimension path -> parameter path, for the canonical projections. */
  canonOf: Record<string, string>;
}

const canonPath = (paramPath: string) => 'env.canon.' + paramPath.slice('action.params.'.length);
const usesCanon = (d: ActionParamDecl) => d.type === 'boolean' || d.type === 'set' || d.type === 'array';

/** The canonical text a value of a canon-projected parameter has (matches intent-v2 `canonProjection`). */
export function canonValue(d: ActionParamDecl, x: unknown): string {
  if (d.type === 'boolean') return x === true ? 'true' : 'false';
  if (d.type === 'set') return canonicalizeStrict([...(x as string[])].sort(compareUtf8));
  return canonicalizeStrict(x);
}

/** Derive Ω_𝒮 (see the module comment). */
export function deriveOmegaFromSchema(o: SchemaOmegaOptions): SchemaOmega {
  const verbNames = o.verbs ?? [...new Set([...o.schema.verbs.filter((v) => v.kind === 'write').map((v) => v.verb), ...(o.slots?.verbs ?? [])])];
  const base = deriveOmega({ policies: o.policies ?? [], slots: o.slots, extraVerbs: verbNames });
  const defaults: SlotConstraint[] = [];
  const canonOf: Record<string, string> = {};
  const verbs: VerbSpace[] = [];
  for (const verb of [...verbNames].sort(compareUtf8)) {
    const decl = o.schema.verbs.find((v) => v.verb === verb);
    if (!decl) continue; // an undeclared verb is ⊠ at the verifier: it is never a cell
    const lits = base.verbs.find((v) => v.verb === verb);
    const litDim = (path: string) => lits?.dims.find((d) => d.path === path);
    const dims: Dim[] = [];
    // non-parameter dimensions the slots / policies mention (env.*, subject.*, action.resource) are kept
    for (const d of lits?.dims ?? []) if (!d.path.startsWith('action.params.')) dims.push(d);
    for (const path of Object.keys(decl.params).sort(compareUtf8)) {
      const pd = decl.params[path]!;
      if (effectiveSensitivity(pd, o.floor) === 'free') continue;
      const lit = litDim(path);
      const silent = lit === undefined;
      const conf = o.confirmed?.[path] ?? [];
      const neutral = pd.principal_neutral_default === true && pd.default !== undefined ? [pd.default] : [];
      const defaultSet = [...conf, ...neutral];
      if (pd.type === 'integer') {
        const cuts = new Set<number>(lit && lit.kind === 'num' ? lit.cuts : []);
        for (const x of defaultSet) if (typeof x === 'number' && Number.isSafeInteger(x)) cuts.add(x);
        const sorted = [...cuts].sort((a, b) => a - b);
        const maxCut = sorted.length ? sorted[sorted.length - 1]! : 0;
        const dom = o.domains?.[path];
        const lo = dom?.lo ?? pd.min ?? Math.min(0, sorted.length ? sorted[0]! - 1 : 0);
        const hi = dom?.hi ?? pd.max ?? Math.max(10, 2 * maxCut, maxCut + 10);
        const nd: NumDim = { kind: 'num', path, lo, hi, cuts: sorted.filter((c) => c >= lo && c <= hi), dist: lo >= 0 ? 'loguniform' : 'uniform' };
        dims.push(nd);
        const nums = defaultSet.filter((x): x is number => typeof x === 'number');
        if (silent && nums.length === 1) defaults.push({ verb, path, min: nums[0], max: nums[0] });
        continue;
      }
      const dimPath = usesCanon(pd) ? canonPath(path) : path;
      if (usesCanon(pd)) canonOf[dimPath] = path;
      const exacts = new Set<string>();
      const prefixes = new Set<string>();
      if (lit && lit.kind === 'cat') for (const v of lit.values) (v.kind === 'exact' ? exacts : v.kind === 'prefix' ? prefixes : new Set<string>()).add(v.value);
      if (pd.type === 'string' && pd.values) pd.values.forEach((v) => exacts.add(v));
      if (pd.type === 'boolean') ['false', 'true'].forEach((v) => exacts.add(v));
      const defTexts = defaultSet.map((x) => (usesCanon(pd) ? canonValue(pd, x) : String(x)));
      defTexts.forEach((t) => exacts.add(t));
      const values: CatValue[] = [
        ...[...exacts].sort(compareUtf8).map((value) => ({ kind: 'exact' as const, value })),
        ...[...prefixes].sort(compareUtf8).map((value) => ({ kind: 'prefix' as const, value })),
        { kind: 'other', value: OTHER },
      ];
      dims.push({ kind: 'cat', path: dimPath, values });
      if (silent && defTexts.length > 0) defaults.push({ verb, path: dimPath, oneOf: [...new Set(defTexts)].sort(compareUtf8) });
    }
    dims.sort((a, b) => compareUtf8(a.path, b.path));
    verbs.push({ verb, reversibility: verbReversibility(decl), weight: 0, dims });
  }
  verbs.forEach((v) => (v.weight = 1 / (verbs.length || 1)));
  const overrides = walletFloorOverrides({ verbs: o.schema.verbs.filter((v) => verbNames.includes(v.verb)) }, o.floor);
  return { omega: { v: 1, verbs, approximate: base.approximate }, overrides, defaults, canonOf };
}
