import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { sign, verifyB64u } from './keys';
import type { Caveat } from './capability';
import type { Condition, Predicate } from './predicates';
import { templateRefError, type TemplateRef } from './envelope-rules';

export { templateRefError, type TemplateRef };

/**
 * LINKED POLICY TEMPLATES (borrowed-ideas item 6; security contract C-242, C-243).
 *
 * A grant can say "template T at version digest D, instantiated with slots S" instead of carrying an unexplained copy of the
 * policy. The verifier resolves D in a registry of templates signed by the operating organisation, rebuilds the policy from
 * (template, slots) and requires the envelope's `predicates` / `caveats` to equal it byte for byte. The principal's grant
 * signature covers the `template_ref`, so there is no silent edit.
 *
 * Versions are immutable and content addressed: a new template version applies to NEW grants only (it has a new digest). An
 * already-linked grant is changed only by a signed TIGHTEN overlay, which can append `where` conditions and caveats and nothing
 * else, so a link can never widen after the fact (the Cedar "update propagates" behaviour, restricted to the safe direction).
 *
 * Template bodies are plain policy JSON in which a value may be the placeholder `{"$slot": "name"}` (optionally with `pre` /
 * `post` strings, for a resource such as `/acct/{id}/*`). Slots are typed with a closed domain; an unfilled, extra, mistyped
 * or out-of-domain slot is refused, and a slot value that would inject a wildcard or a regex into a resource is refused.
 *
 * Pure, total, never throws except the authoring-time `sign*` helpers.
 */

export const TEMPLATE_VERSION = 1;
export const TEMPLATE_KIND = 'pca-policy-template';
export const TEMPLATE_SIG_DOMAIN = 'atlas-pca/policy-template/v1\0';
export const TIGHTEN_KIND = 'pca-template-tighten';
export const TIGHTEN_SIG_DOMAIN = 'atlas-pca/template-tighten/v1\0';
export const MAX_SLOTS = 32;
export const MAX_SLOT_STRING = 256;
export const MAX_SLOT_SET = 64;

export type SlotType = 'string' | 'integer' | 'set';

export interface SlotDecl {
  type: SlotType;
  /** string: closed value set. set: closed member set. */
  values?: string[];
  /** integer: inclusive bounds. */
  min?: number;
  max?: number;
}

export interface PolicyBody {
  predicates: Predicate[];
  caveats?: Caveat[];
}

export interface TemplateDef {
  v: typeof TEMPLATE_VERSION;
  kind: typeof TEMPLATE_KIND;
  id: string;
  /** Free label of this version (the identity is the digest, not the label). */
  version: string;
  slots: Record<string, SlotDecl>;
  body: PolicyBody;
}

export interface SignedTemplate {
  def: TemplateDef;
  /** The organisation key (b64u public key) that signed it. */
  signer: string;
  sig: string;
}

export interface TemplateTighten {
  v: typeof TEMPLATE_VERSION;
  kind: typeof TIGHTEN_KIND;
  template_id: string;
  /** The template version digest this overlay applies to. */
  version_digest: string;
  /** Appended to the `where` of EVERY predicate. */
  add_where?: Condition[];
  /** Appended to the caveats. */
  add_caveats?: Caveat[];
}

export interface SignedTighten {
  overlay: TemplateTighten;
  signer: string;
  sig: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

function domainMessage(domain: string, digest: string): Uint8Array {
  const pre = utf8(domain);
  const d = sha256(utf8(digest));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}

// ---- definitions -----------------------------------------------------------------------

/** Null = well formed. Placeholders inside the body are checked against the declared slots. */
export function templateDefError(def: unknown): string | null {
  if (!isObj(def)) return 'template must be an object';
  if (def.v !== TEMPLATE_VERSION || def.kind !== TEMPLATE_KIND) return 'template v / kind mismatch';
  if (typeof def.id !== 'string' || !NAME_RE.test(def.id)) return `template id must match ${NAME_RE.source}`;
  if (typeof def.version !== 'string' || def.version.length === 0 || def.version.length > 64) return 'template version must be a string of 1..64 characters';
  if (!isObj(def.slots)) return 'slots must be an object';
  const names = Object.keys(def.slots);
  if (names.length > MAX_SLOTS) return `more than ${MAX_SLOTS} slots`;
  for (const n of names) {
    const d = def.slots[n];
    if (!NAME_RE.test(n)) return `slot name '${n}' must match ${NAME_RE.source}`;
    if (!isObj(d)) return `slot '${n}' must be an object`;
    if (d.type !== 'string' && d.type !== 'integer' && d.type !== 'set') return `slot '${n}'.type must be string, integer or set`;
    if (d.type === 'set' && !Array.isArray(d.values)) return `set slot '${n}' needs a closed values list`;
    if (d.values !== undefined && (!Array.isArray(d.values) || d.values.length > MAX_SLOT_SET || d.values.some((x) => typeof x !== 'string'))) return `slot '${n}'.values must be a list of strings`;
    if (d.type === 'integer') {
      for (const k of ['min', 'max'] as const) if (d[k] !== undefined && !Number.isSafeInteger(d[k])) return `slot '${n}'.${k} must be a safe integer`;
    }
  }
  if (!isObj(def.body) || !Array.isArray(def.body.predicates)) return 'body.predicates must be an array';
  if (def.body.caveats !== undefined && !Array.isArray(def.body.caveats)) return 'body.caveats must be an array';
  const used = new Set<string>();
  const err = scanSlots(def.body, def.slots as Record<string, unknown>, used);
  if (err) return err;
  for (const n of names) if (!used.has(n)) return `slot '${n}' is declared but never used`;
  return null;
}

function scanSlots(v: unknown, decl: Record<string, unknown>, used: Set<string>): string | null {
  if (Array.isArray(v)) {
    for (const x of v) {
      const e = scanSlots(x, decl, used);
      if (e) return e;
    }
    return null;
  }
  if (!isObj(v)) return null;
  for (const k of Object.keys(v)) if (k === '__proto__' || k === 'constructor' || k === 'prototype') return `body has the forbidden key '${k}'`;
  if (has(v, '$slot')) {
    const keys = Object.keys(v).filter((k) => k !== '$slot' && k !== 'pre' && k !== 'post');
    if (keys.length > 0) return `placeholder has unknown member '${keys[0]}'`;
    if (typeof v.$slot !== 'string' || !has(decl, v.$slot)) return `placeholder names undeclared slot '${String(v.$slot)}'`;
    // the affixes are the template author's (signed by the organisation), so they may carry the wildcard; the SLOT VALUE may not
    for (const k of ['pre', 'post']) if (v[k] !== undefined && typeof v[k] !== 'string') return `placeholder ${k} must be a string`;
    used.add(v.$slot);
    return null;
  }
  for (const k of Object.keys(v)) {
    const e = scanSlots(v[k], decl, used);
    if (e) return e;
  }
  return null;
}

export const templateDigest = (def: TemplateDef): string => hashCanonical(def);

export function signTemplate(def: TemplateDef, secret: Uint8Array, signerPublic: string): SignedTemplate {
  const e = templateDefError(def);
  if (e) throw new TypeError('signTemplate: ' + e);
  return { def, signer: signerPublic, sig: b64u(sign(secret, domainMessage(TEMPLATE_SIG_DOMAIN, templateDigest(def)))) };
}

export function verifyTemplate(t: SignedTemplate, trusted: readonly string[]): { ok: boolean; reason?: string } {
  try {
    const e = templateDefError(t?.def);
    if (e) return { ok: false, reason: e };
    if (!trusted.includes(t.signer)) return { ok: false, reason: 'template signer is not trusted' };
    if (typeof t.sig !== 'string' || !verifyB64u(t.signer, domainMessage(TEMPLATE_SIG_DOMAIN, templateDigest(t.def)), t.sig)) return { ok: false, reason: 'bad template signature' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'template verification error (fail closed)' };
  }
}

// ---- tighten overlays ------------------------------------------------------------------

export function tightenOverlayError(o: unknown): string | null {
  if (!isObj(o)) return 'overlay must be an object';
  if (o.v !== TEMPLATE_VERSION || o.kind !== TIGHTEN_KIND) return 'overlay v / kind mismatch';
  for (const k of Object.keys(o)) if (!['v', 'kind', 'template_id', 'version_digest', 'add_where', 'add_caveats'].includes(k)) return `overlay has unknown member '${k}' (an overlay can only add where conditions and caveats)`;
  if (typeof o.template_id !== 'string' || !NAME_RE.test(o.template_id)) return 'overlay template_id invalid';
  if (typeof o.version_digest !== 'string' || o.version_digest.length === 0) return 'overlay version_digest invalid';
  if (o.add_where !== undefined && (!Array.isArray(o.add_where) || o.add_where.some((c) => !isObj(c)))) return 'overlay add_where must be a list of conditions';
  if (o.add_caveats !== undefined && (!Array.isArray(o.add_caveats) || o.add_caveats.some((c) => !isObj(c) || typeof c.type !== 'string'))) return 'overlay add_caveats must be a list of caveats';
  return null;
}

export function signTighten(overlay: TemplateTighten, secret: Uint8Array, signerPublic: string): SignedTighten {
  const e = tightenOverlayError(overlay);
  if (e) throw new TypeError('signTighten: ' + e);
  return { overlay, signer: signerPublic, sig: b64u(sign(secret, domainMessage(TIGHTEN_SIG_DOMAIN, hashCanonical(overlay)))) };
}

export function verifyTighten(t: SignedTighten, trusted: readonly string[]): { ok: boolean; reason?: string } {
  try {
    const e = tightenOverlayError(t?.overlay);
    if (e) return { ok: false, reason: e };
    if (!trusted.includes(t.signer)) return { ok: false, reason: 'overlay signer is not trusted' };
    if (typeof t.sig !== 'string' || !verifyB64u(t.signer, domainMessage(TIGHTEN_SIG_DOMAIN, hashCanonical(t.overlay)), t.sig)) return { ok: false, reason: 'bad overlay signature' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'overlay verification error (fail closed)' };
  }
}

// ---- instantiation ---------------------------------------------------------------------

function slotValueError(name: string, d: SlotDecl, v: unknown): string | null {
  switch (d.type) {
    case 'string':
      if (typeof v !== 'string' || v.length === 0 || v.length > MAX_SLOT_STRING) return `slot '${name}' must be a string of 1..${MAX_SLOT_STRING} characters`;
      if (d.values !== undefined && !d.values.includes(v)) return `slot '${name}' is outside its closed value set`;
      return null;
    case 'integer':
      if (!Number.isSafeInteger(v)) return `slot '${name}' must be a safe integer`;
      if (d.min !== undefined && (v as number) < d.min) return `slot '${name}' is below its minimum`;
      if (d.max !== undefined && (v as number) > d.max) return `slot '${name}' is above its maximum`;
      return null;
    case 'set':
      if (!Array.isArray(v) || v.length === 0 || v.length > MAX_SLOT_SET || v.some((x) => typeof x !== 'string')) return `slot '${name}' must be a non-empty list of strings`;
      if (new Set(v).size !== v.length) return `slot '${name}' has duplicate members`;
      if (d.values !== undefined && v.some((x) => !(d.values as string[]).includes(x as string))) return `slot '${name}' has a member outside its closed set`;
      return null;
  }
}

/** A slot value placed where the policy reads a verb or a resource may not smuggle in a wildcard or a regex matcher. */
function matcherSafe(name: string, val: unknown): void {
  for (const x of Array.isArray(val) ? val : [val]) {
    if (typeof x === 'string' && (x.includes('*') || x.startsWith('re:'))) throw new Error(`slot '${name}' would inject a wildcard or regex matcher into a verb or resource`);
  }
}

function fill(v: unknown, decl: Record<string, SlotDecl>, slots: Record<string, unknown>, key?: string): unknown {
  if (Array.isArray(v)) return v.map((x) => fill(x, decl, slots, key));
  if (!isObj(v)) return v;
  if (has(v, '$slot')) {
    const name = v.$slot as string;
    const val = slots[name];
    if (key === 'verb' || key === 'resource') matcherSafe(name, val);
    const pre = typeof v.pre === 'string' ? v.pre : '';
    const post = typeof v.post === 'string' ? v.post : '';
    if (pre === '' && post === '') return val;
    if (typeof val !== 'string' || val.includes('*') || val.includes('\u0000')) throw new Error(`slot '${name}' cannot be spliced into a string (wildcard or non-string)`);
    const out = pre + val + post;
    if (pre === '' && out.startsWith('re:')) throw new Error(`slot '${name}' would inject a regex matcher`);
    return out;
  }
  const o: Record<string, unknown> = {};
  for (const k of Object.keys(v)) o[k] = fill(v[k], decl, slots, k);
  return o;
}

/** Fill a template's slots. Refuses unfilled, extra, mistyped and out-of-domain slots. */
export function instantiateTemplate(def: TemplateDef, slots: Record<string, unknown>): { ok: true; policy: PolicyBody } | { ok: false; reason: string } {
  try {
    const e = templateDefError(def);
    if (e) return { ok: false, reason: e };
    if (!isObj(slots)) return { ok: false, reason: 'slots must be an object' };
    for (const k of Object.keys(slots)) if (!has(def.slots, k)) return { ok: false, reason: `slot '${k}' is not declared by the template` };
    for (const [n, d] of Object.entries(def.slots)) {
      if (!has(slots, n)) return { ok: false, reason: `slot '${n}' is not filled` }; // no silent defaults: every slot is filled
      const se = slotValueError(n, d, slots[n]);
      if (se) return { ok: false, reason: se };
    }
    const policy = fill(def.body, def.slots, slots) as PolicyBody;
    return { ok: true, policy: { predicates: policy.predicates, caveats: policy.caveats ?? [] } };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'instantiation error (fail closed)' };
  }
}

// ---- references ------------------------------------------------------------------------

export interface TemplateRegistry {
  /** Signed templates by version digest. */
  templates: Record<string, SignedTemplate>;
  /** Signed tighten overlays (any order); each applies to the one digest it names. */
  overlays?: SignedTighten[];
  /** Organisation public keys (b64u) trusted to sign templates and overlays. */
  trusted: readonly string[];
  /** Parameter objects by digest, for references that cite `bind_params_digest` instead of carrying their slots. */
  params?: Record<string, Record<string, unknown>>;
}

/** The digest a `bind_params_digest` reference cites: `hashCanonical` of the slot object. */
export const slotsDigest = (slots: Record<string, unknown>): string => hashCanonical(slots);

export function createLink(def: TemplateDef, slots: Record<string, unknown>, o: { bindParams?: boolean } = {}): TemplateRef {
  const r = instantiateTemplate(def, slots);
  if (!r.ok) throw new TypeError('createLink: ' + r.reason);
  if (o.bindParams) return { template_id: def.id, version_digest: templateDigest(def), bind_params_digest: slotsDigest(slots) };
  return { template_id: def.id, version_digest: templateDigest(def), slots: structuredClone(slots) };
}

/** The policy a reference denotes: template (signature checked) filled with the slots, then every matching verified overlay. */
export function resolveLink(ref: TemplateRef, reg: TemplateRegistry): { ok: true; policy: PolicyBody; overlays: number } | { ok: false; reason: string } {
  try {
    const re = templateRefError(ref);
    if (re) return { ok: false, reason: re };
    const t = has(reg.templates, ref.version_digest) ? reg.templates[ref.version_digest] : undefined;
    if (!t) return { ok: false, reason: 'template version is not in the registry' };
    const v = verifyTemplate(t, reg.trusted);
    if (!v.ok) return { ok: false, reason: v.reason ?? 'template refused' };
    if (templateDigest(t.def) !== ref.version_digest) return { ok: false, reason: 'registry entry does not match its digest' };
    if (t.def.id !== ref.template_id) return { ok: false, reason: 'template id does not match the reference' };
    let slots = ref.slots as Record<string, unknown>;
    if (ref.bind_params_digest !== undefined) {
      const bound = reg.params !== undefined && has(reg.params, ref.bind_params_digest) ? reg.params[ref.bind_params_digest] : undefined;
      if (!isObj(bound)) return { ok: false, reason: 'parameter object is not available' };
      if (slotsDigest(bound) !== ref.bind_params_digest) return { ok: false, reason: 'parameter object does not match bind_params_digest' };
      slots = bound;
    }
    const inst = instantiateTemplate(t.def, slots);
    if (!inst.ok) return inst;
    let predicates = inst.policy.predicates;
    let caveats = inst.policy.caveats ?? [];
    let applied = 0;
    for (const o of reg.overlays ?? []) {
      // An overlay that names this version but fails verification is a refusal: a silently dropped tightening would surprise its author.
      if (!isObj(o?.overlay) || o.overlay.version_digest !== ref.version_digest || o.overlay.template_id !== ref.template_id) continue;
      const ov = verifyTighten(o, reg.trusted);
      if (!ov.ok) return { ok: false, reason: ov.reason ?? 'overlay refused' };
      const add = o.overlay.add_where ?? [];
      predicates = predicates.map((p) => ({ ...p, where: [...(p.where ?? []), ...add] }));
      caveats = [...caveats, ...(o.overlay.add_caveats ?? [])];
      applied++;
    }
    return { ok: true, policy: { predicates, caveats }, overlays: applied };
  } catch {
    return { ok: false, reason: 'link resolution error (fail closed)' };
  }
}

/** A grant carrying a `template_ref` must hold exactly the policy the reference denotes. */
export function verifyLinkedPolicy(envelope: { template_ref?: unknown; predicates: Predicate[]; caveats: Caveat[] }, reg: TemplateRegistry): { ok: boolean; reason?: string; template?: string } {
  try {
    if (envelope.template_ref === undefined) return { ok: true };
    const ref = envelope.template_ref as TemplateRef;
    const r = resolveLink(ref, reg);
    if (!r.ok) return { ok: false, reason: r.reason };
    if (hashCanonical({ predicates: envelope.predicates, caveats: envelope.caveats }) !== hashCanonical({ predicates: r.policy.predicates, caveats: r.policy.caveats ?? [] })) {
      return { ok: false, reason: 'grant policy differs from the linked template instantiation' };
    }
    return { ok: true, template: ref.version_digest };
  } catch {
    return { ok: false, reason: 'link verification error (fail closed)' };
  }
}

/** The digest the principal's grant signature covers for a link (also usable in an audit report). */
export const linkDigest = (ref: TemplateRef): string => hashCanonical(ref);
