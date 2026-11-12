// build.ts - `pca actions build|sign` (spec section 4.2): from loaded defs to the unsigned schema, the pack, the policy cards,
// the ontology fragment, the MCP tool map and generated TypeScript types, and the signing and consistency checks of the pack.
// There is no second place to write a fact: every output is a pure function of the defs and the trait registry.

import { b64u, canonicalBytesStrict, decodeB64uStrict, publicKeyOf, signSuiteArtifact, suiteKeysOf, utf8, verifyPinnedSuite } from '@atlasauth/pca';
import type { UnsignedActionSchema } from '@atlasauth/pca/ext/intent';
import { MAX_PACK_DEFS, type ActionDef, type ParamDef } from './def';
import { cardOf, mcpAnnotationsOf, operationOf, toOntology, toSchemaDoc, type CardOut, type McpAnnotations, type OntologyOut } from './derive';
import { PACK_DIGEST_DOMAIN, defDigest, packRoot, tablesDigest, traitsDigest } from './digest';
import { effective, type ReviewOpts } from './effective';
import { lintRulesDigest } from './lint';
import type { Registry } from './traits';
import { validateDef } from './validate';

export type Stability = 'draft' | 'beta' | 'stable';
export interface BuildConfig { ns: string; version: string; stability: Stability; site: string; aud: string }

export interface ActionPackBody {
  v: 1;
  kind: 'pca-action-pack';
  ns: string;
  version: string;
  stability: Stability;
  traits_digest: string;
  roles_digest: string;
  rules_digest: string;
  root: string;
  defs: ActionDef[];
  prev: string | null;
  evolution: unknown[];
}
export interface PackSig { alg: 'ed25519'; kid: string; value: string }
export type SignedActionPack = ActionPackBody & { sig: PackSig };

export interface BuildOutput {
  schema: UnsignedActionSchema;
  pack: ActionPackBody;
  cards: CardOut[];
  ontology: OntologyOut;
  mcp: { tools: Record<string, { verb: string; annotations: McpAnnotations }> };
  types: string;
}

const byVerb = (a: ActionDef, b: ActionDef): number => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0);

/** Build every output. Throws on a pack above the unsharded limit, a duplicate verb, or a unit conflict (never a partial build). */
export function buildArtifacts(defsIn: readonly ActionDef[], cfg: BuildConfig, reg: Registry, opts: ReviewOpts = {}): BuildOutput {
  const defs = [...defsIn].sort(byVerb);
  if (defs.length > MAX_PACK_DEFS) throw new Error(`a pack above ${MAX_PACK_DEFS} defs must be sharded (${defs.length} given)`);
  for (let i = 1; i < defs.length; i++) if (defs[i]!.verb === defs[i - 1]!.verb) throw new Error(`verb '${defs[i]!.verb}' appears twice`);
  const root = packRoot(defs.map(defDigest));
  const schema = toSchemaDoc(defs, reg, { site: cfg.site, aud: cfg.aud, version: cfg.version, pack: { ns: cfg.ns, version: cfg.version, root } }, opts);
  const pack: ActionPackBody = {
    v: 1, kind: 'pca-action-pack', ns: cfg.ns, version: cfg.version, stability: cfg.stability,
    traits_digest: traitsDigest(reg), roles_digest: tablesDigest(), rules_digest: lintRulesDigest(), root, defs, prev: null, evolution: [],
  };
  const cards = defs.map((d) => cardOf(d, effective(d, reg, opts), reg));
  const tools: BuildOutput['mcp']['tools'] = {};
  for (const d of defs) if (d.bindings?.mcp) tools[d.bindings.mcp.tool] = { verb: d.verb, annotations: mcpAnnotationsOf(d, effective(d, reg, opts)) };
  return { schema, pack, cards, ontology: toOntology(defs, reg, opts), mcp: { tools }, types: generateTypes(defs) };
}

/** The ToolActionMap (`pca-mcp`) of the defs' MCP bindings: tool name and arguments to {verb, resource}, or null. */
export function toolActionMapOf(defs: readonly ActionDef[]): (tool: string, args: Record<string, unknown>) => { verb: string; resource: string } | null {
  const m = new Map<string, ActionDef>();
  for (const d of defs) if (d.bindings?.mcp) m.set(d.bindings.mcp.tool, d);
  return (tool, args) => {
    const d = m.get(tool);
    if (!d) return null;
    const r = operationOf(d, { params: args });
    return r.ok ? { verb: r.op.verb, resource: r.op.resource } : null;
  };
}

// ---- generated types -----------------------------------------------------------------------------------------------------------

const pascal = (s: string): string => s.split(/[._]/).map((x) => x.charAt(0).toUpperCase() + x.slice(1)).join('');
const key = (k: string): string => (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) ? k : JSON.stringify(k));

function tsType(p: ParamDef): string {
  switch (p.type) {
    case 'integer': case 'duration': return 'number';
    case 'boolean': return 'boolean';
    case 'set': return `Array<${(p.values ?? []).map((v) => JSON.stringify(v)).join(' | ') || 'string'}>`;
    case 'array': return p.items === 'integer' ? 'number[]' : 'string[]';
    default: return p.values ? p.values.map((v) => JSON.stringify(v)).join(' | ') : 'string';
  }
}

interface Node { leaf?: ParamDef; kids: Map<string, Node> }
function render(n: Node, indent: string): string {
  const lines: string[] = [];
  for (const k of [...n.kids.keys()].sort()) {
    const c = n.kids.get(k)!;
    if (c.leaf) lines.push(`${indent}${key(k)}${c.leaf.required === false ? '?' : ''}: ${tsType(c.leaf)};`);
    else lines.push(`${indent}${key(k)}: {\n${render(c, indent + '  ')}\n${indent}};`);
  }
  return lines.join('\n');
}

/** TypeScript declarations for typed call sites: one params interface per verb, `ActionParams` and `ActionVerb`. */
export function generateTypes(defs: readonly ActionDef[]): string {
  const out = ['// Generated by `pca actions build`. Do not edit.', ''];
  const names: string[] = [];
  for (const d of [...defs].sort(byVerb)) {
    const root: Node = { kids: new Map() };
    for (const name of Object.keys(d.params).sort()) {
      let n = root;
      const segs = name.split('.');
      segs.forEach((s, i) => {
        if (!n.kids.has(s)) n.kids.set(s, { kids: new Map() });
        n = n.kids.get(s)!;
        if (i === segs.length - 1) n.leaf = d.params[name]!;
      });
    }
    const iface = `${pascal(d.verb)}Params`;
    names.push(`  ${JSON.stringify(d.verb)}: ${iface};`);
    out.push(`export interface ${iface} {`, render(root, '  '), '}', '');
  }
  out.push('export interface ActionParams {', ...names, '}', '', 'export type ActionVerb = keyof ActionParams;', '');
  return out.join('\n');
}

// ---- pack signing and consistency --------------------------------------------------------------------------------------------------

/** Domain of the pack signature; it differs from the schema's, so a signature of one is never valid for the other. */
export const PACK_SIGN_DOMAIN = `${PACK_DIGEST_DOMAIN}\0`;

function packMessage(p: ActionPackBody): Uint8Array {
  const dom = utf8(PACK_SIGN_DOMAIN);
  const b = canonicalBytesStrict(p);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
}

/** Null when the pack is internally consistent: every def valid and sorted-unique, the Merkle root and digests recomputed. */
export function packConsistencyError(p: unknown, reg: Registry): string | null {
  try {
    if (p === null || typeof p !== 'object' || Array.isArray(p)) return 'the pack must be an object';
    const q = p as ActionPackBody;
    if (q.kind !== 'pca-action-pack' || q.v !== 1) return 'not a pca-action-pack v1';
    if (!Array.isArray(q.defs) || q.defs.length > MAX_PACK_DEFS) return 'defs must be a list within the unsharded limit';
    const seen = new Set<string>();
    for (const d of q.defs) {
      const e = validateDef(d);
      if (e) return `def ${(d as { verb?: string })?.verb ?? '?'}: ${e}`;
      if (seen.has(d.verb)) return `verb '${d.verb}' is defined twice`;
      seen.add(d.verb);
    }
    if (q.root !== packRoot(q.defs.map(defDigest))) return 'the pack root does not match its defs';
    if (q.traits_digest !== traitsDigest(reg)) return 'traits_digest does not match the trait registry';
    return null;
  } catch (e) {
    return `malformed pack: ${(e as Error).message}`;
  }
}

/** Sign a pack as the registry (Ed25519; the 32-byte secret). Refuses an inconsistent pack. */
export function signPack(pack: ActionPackBody, kid: string, secret: Uint8Array, reg: Registry): SignedActionPack {
  const bad = packConsistencyError(pack, reg);
  if (bad) throw new Error(`signPack: ${bad}`);
  const { sig: _s, ...body } = pack as SignedActionPack;
  void _s;
  const parts = signSuiteArtifact(undefined, suiteKeysOf(secret, undefined), packMessage(body));
  return { ...body, sig: { alg: 'ed25519', kid, value: parts.sig } };
}

export interface PackKey { kid: string; alg: 'ed25519'; pk: string }
export const packKeyOf = (kid: string, secret: Uint8Array): PackKey => ({ kid, alg: 'ed25519', pk: b64u(publicKeyOf(secret)) });

/** Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never throws. */
export function verifyPack(pack: unknown, keys: readonly PackKey[], reg: Registry): { ok: true } | { ok: false; reason: string } {
  try {
    const bad = packConsistencyError(pack, reg);
    if (bad) return { ok: false, reason: bad };
    const { sig, ...body } = pack as SignedActionPack;
    if (!sig || sig.alg !== 'ed25519' || typeof sig.kid !== 'string' || typeof sig.value !== 'string') return { ok: false, reason: 'missing or malformed signature' };
    const k = keys.find((x) => x.kid === sig.kid);
    if (!k) return { ok: false, reason: `no registry key with kid '${sig.kid}'` };
    if (k.alg !== 'ed25519' || decodeB64uStrict(k.pk, 32) === null) return { ok: false, reason: 'the registry key entry is malformed' };
    return verifyPinnedSuite('ed25519', k.pk, undefined, packMessage(body as ActionPackBody), { sig: sig.value }, {}) ? { ok: true } : { ok: false, reason: 'pack signature invalid' };
  } catch (e) {
    return { ok: false, reason: `pack verification error: ${(e as Error).message}` };
  }
}
