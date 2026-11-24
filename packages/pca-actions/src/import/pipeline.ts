// pipeline.ts - `import -> suggest` as one call, and the text forms the CLI prints and reads (JSON Lines of defs). Pure:
// no file system, no network (the caller fetches and writes).

import { canonicalizeStrict } from '@atlasauth/pca';
import { ActionKitError, type ActionDef } from '../def';
import { CORE_REGISTRY } from '../core-traits';
import type { Registry } from '../traits';
import { validateDef } from '../validate';
import { IMPORT_KINDS, type ImportKind, type ImportOpts, type ImportReport } from './common';
import { importAsyncApi } from './asyncapi';
import { importGraphql } from './graphql';
import { importGrpc } from './grpc';
import { importJsonSchema, type JsonSchemaImportOpts } from './jsonschema';
import { importMcp } from './mcp';
import { suggestWithModels, type ModelAdapter } from './model';
import { importOpenApi } from './openapi';
import { DEFAULT_RULES, DEFAULT_RULES_SEALED } from './rules';
import { applySuggestion, rulesDigest, suggestWithRules, type SuggestedBy, type SuggestRules } from './suggest';

/** Import one source of the given kind. Every def is `unreviewed`. */
export function importActions(kind: ImportKind, source: unknown, opts: ImportOpts | JsonSchemaImportOpts): ImportReport {
  switch (kind) {
    case 'openapi': return importOpenApi(source, opts);
    case 'mcp': return importMcp(source, opts);
    case 'graphql': return importGraphql(source, opts);
    case 'grpc': return importGrpc(source, opts);
    case 'asyncapi': return importAsyncApi(source, opts);
    case 'jsonschema': return importJsonSchema(source, opts as JsonSchemaImportOpts);
    default: throw new ActionKitError('bad_kind', `unknown import kind '${String(kind)}' (one of ${IMPORT_KINDS.join(', ')})`);
  }
}

export interface SuggestOpts {
  /** `rules` (default), `model` (rules plus the adapters) or `none`. */
  mode?: 'rules' | 'model' | 'none';
  rules?: SuggestRules;
  /** The registry whose trait ids form the closed vocabulary. */
  registry?: Registry;
  models?: readonly ModelAdapter[];
}

/** Suggest for already imported defs. Returns new defs (state `suggested`) and the model errors, if any. */
export async function suggestDefs(defs: readonly ActionDef[], o: SuggestOpts = {}): Promise<{ defs: ActionDef[]; errors: { verb: string; model: string; error: string }[] }> {
  const mode = o.mode ?? 'rules';
  if (mode === 'none') return { defs: [...defs], errors: [] };
  const registry = o.registry ?? CORE_REGISTRY;
  const rules = o.rules ?? DEFAULT_RULES;
  const digest = rules === DEFAULT_RULES ? DEFAULT_RULES_SEALED.digest : rulesDigest(rules);
  const out: ActionDef[] = [];
  const errors: { verb: string; model: string; error: string }[] = [];
  for (const d of defs) {
    let s = suggestWithRules(d, rules, registry);
    let models: SuggestedBy['models'];
    if (mode === 'model') {
      const run = await suggestWithModels(d, o.models ?? [], registry);
      for (const e of run.errors) errors.push({ verb: d.verb, ...e });
      s = { traits: [...new Set([...s.traits, ...run.suggestion.traits])].sort(), roles: s.roles, tags: s.tags, fired: s.fired };
      models = run.models;
    }
    out.push(applySuggestion(d, s, { rules: { version: rules.version, digest, fired: s.fired }, ...(models && models.length > 0 ? { models } : {}) }));
  }
  return { defs: out, errors };
}

/** Import then suggest. */
export async function importAndSuggest(kind: ImportKind, source: unknown, opts: (ImportOpts | JsonSchemaImportOpts) & { suggest?: SuggestOpts }): Promise<ImportReport & { suggestErrors: { verb: string; model: string; error: string }[] }> {
  const r = importActions(kind, source, opts);
  const s = await suggestDefs(r.defs, opts.suggest);
  return { ...r, defs: s.defs, suggestErrors: s.errors };
}

// ---- JSON Lines -------------------------------------------------------------------------------------------------------

/** One def per line, strict canonical JSON, sorted by verb: byte-reproducible. */
export function defsToJsonl(defs: readonly ActionDef[]): string {
  return [...defs].sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0)).map((d) => canonicalizeStrict(d)).join('\n') + (defs.length > 0 ? '\n' : '');
}

/** Parse and validate a JSONL file of defs. Throws ActionKitError('bad_defs') naming the first bad line. */
export function jsonlToDefs(text: string): ActionDef[] {
  const out: ActionDef[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!.trim();
    if (l.length === 0) continue;
    let v: unknown;
    try { v = JSON.parse(l); } catch { throw new ActionKitError('bad_defs', `line ${i + 1}: not JSON`); }
    const bad = validateDef(v);
    if (bad !== null) throw new ActionKitError('bad_defs', `line ${i + 1}: ${bad}`);
    out.push(v as ActionDef);
  }
  return out;
}
