// graphql.ts - GraphQL SDL or introspection JSON -> drafts. Query fields are reads, Mutation fields are writes, Subscription
// fields are streaming reads; arguments and input objects are flattened to dotted params. There is no method signal, so the
// name tokens drive the suggestion engine and everything stays `unreviewed`.

import { ActionKitError, type Effect, type ParamDef } from '../def';
import { addTodo, clip, emitDef, finish, flattenObject, isObj, newBudget, newCtx, withTrait, type Budget, type Ctx, type ImportOpts, type ImportReport, type JsonSchemaLike } from './common';
import { compareUtf8 } from '@atlasauth/pca';

// ---- model -----------------------------------------------------------------------------------------------------------

export type GqlType = { k: 'named'; name: string } | { k: 'list'; of: GqlType } | { k: 'nonnull'; of: GqlType };
export interface GqlArg { name: string; type: GqlType; desc?: string }
export interface GqlField { name: string; args: GqlArg[]; type: GqlType; desc?: string; deprecated: boolean }
export interface GqlTypeDef { kind: 'object' | 'input' | 'enum' | 'scalar' | 'interface' | 'union'; name: string; fields: GqlField[]; values: string[] }
export interface GqlSchema { types: Map<string, GqlTypeDef>; query?: string; mutation?: string; subscription?: string }

// ---- SDL lexer -------------------------------------------------------------------------------------------------------

type Tok = { t: 'name' | 'int' | 'str' | 'punct' | 'eof'; v: string };

function lex(src: string, maxTokens: number): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  const n = src.length;
  const push = (t: Tok) => {
    if (out.length >= maxTokens) throw new ActionKitError('import_limit', 'the GraphQL source has too many tokens');
    out.push(t);
  };
  while (i < n) {
    const ch = src[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',' || ch === '\uFEFF') { i++; continue; }
    if (ch === '#') { while (i < n && src[i] !== '\n') i++; continue; }
    if (ch === '"') {
      if (src.startsWith('"""', i)) {
        let j = i + 3;
        let s = '';
        while (j < n && !src.startsWith('"""', j)) {
          if (src.startsWith('\\"""', j)) { s += '"""'; j += 4; } else s += src[j++];
        }
        if (j >= n) throw new ActionKitError('bad_source', 'unterminated GraphQL block string');
        push({ t: 'str', v: s });
        i = j + 3;
      } else {
        let j = i + 1;
        let s = '';
        while (j < n && src[j] !== '"') {
          if (src[j] === '\n') throw new ActionKitError('bad_source', 'unterminated GraphQL string');
          if (src[j] === '\\') { s += src[j + 1] ?? ''; j += 2; } else s += src[j++];
        }
        if (j >= n) throw new ActionKitError('bad_source', 'unterminated GraphQL string');
        push({ t: 'str', v: s });
        i = j + 1;
      }
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) { let j = i + 1; while (j < n && /[_0-9A-Za-z]/.test(src[j]!)) j++; push({ t: 'name', v: src.slice(i, j) }); i = j; continue; }
    if (/[-0-9]/.test(ch)) { let j = i + 1; while (j < n && /[-+.0-9eE]/.test(src[j]!)) j++; push({ t: 'int', v: src.slice(i, j) }); i = j; continue; }
    if (src.startsWith('...', i)) { push({ t: 'punct', v: '...' }); i += 3; continue; }
    if ('!$&():=@[]{|}'.includes(ch)) { push({ t: 'punct', v: ch }); i++; continue; }
    throw new ActionKitError('bad_source', `unexpected character in GraphQL source at offset ${i}`);
  }
  push({ t: 'eof', v: '' });
  return out;
}

// ---- SDL parser (type system definitions only; executable documents are rejected) ------------------------------------

class P {
  i = 0;
  constructor(readonly toks: Tok[], readonly schema: GqlSchema, readonly maxDepth: number) {}
  get cur(): Tok { return this.toks[this.i]!; }
  next(): Tok { const t = this.toks[this.i]!; if (t.t !== 'eof') this.i++; return t; }
  is(v: string): boolean { return this.cur.t !== 'str' && this.cur.v === v; }
  eat(v: string): boolean { if (this.is(v)) { this.i++; return true; } return false; }
  expect(v: string): void { if (!this.eat(v)) throw new ActionKitError('bad_source', `GraphQL parse error: expected '${v}' near '${clip(this.cur.v, 30)}'`); }
  name(): string { const t = this.next(); if (t.t !== 'name') throw new ActionKitError('bad_source', `GraphQL parse error: expected a name near '${clip(t.v, 30)}'`); return t.v; }
  desc(): string | undefined { return this.cur.t === 'str' ? this.next().v : undefined; }

  type(depth = 0): GqlType {
    if (depth > this.maxDepth) throw new ActionKitError('import_limit', 'GraphQL type nesting is too deep');
    let t: GqlType;
    if (this.eat('[')) { t = { k: 'list', of: this.type(depth + 1) }; this.expect(']'); } else t = { k: 'named', name: this.name() };
    return this.eat('!') ? { k: 'nonnull', of: t } : t;
  }

  /** Skip a constant value (default values, directive arguments). Returns the raw string for strings. */
  value(depth = 0): string | undefined {
    if (depth > this.maxDepth) throw new ActionKitError('import_limit', 'GraphQL value nesting is too deep');
    const t = this.cur;
    if (t.t === 'str') { this.i++; return t.v; }
    if (t.t === 'int' || t.t === 'name') { this.i++; return t.v; }
    if (this.eat('[')) { while (!this.is(']') && this.cur.t !== 'eof') this.value(depth + 1); this.expect(']'); return undefined; }
    if (this.eat('{')) { while (!this.is('}') && this.cur.t !== 'eof') { this.name(); this.expect(':'); this.value(depth + 1); } this.expect('}'); return undefined; }
    if (this.eat('$')) { this.name(); return undefined; }
    throw new ActionKitError('bad_source', `GraphQL parse error: unexpected '${clip(t.v, 30)}'`);
  }

  directives(): { deprecated: boolean } {
    let deprecated = false;
    while (this.eat('@')) {
      const n = this.name();
      if (n === 'deprecated') deprecated = true;
      if (this.eat('(')) { while (!this.is(')') && this.cur.t !== 'eof') { this.name(); this.expect(':'); this.value(); } this.expect(')'); }
    }
    return { deprecated };
  }

  args(): GqlArg[] {
    const out: GqlArg[] = [];
    if (!this.eat('(')) return out;
    while (!this.is(')')) {
      if (this.cur.t === 'eof') throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated argument list');
      const desc = this.desc();
      const name = this.name();
      this.expect(':');
      const type = this.type();
      if (this.eat('=')) this.value();
      this.directives();
      out.push({ name, type, ...(desc ? { desc } : {}) });
    }
    this.expect(')');
    return out;
  }

  fields(input: boolean): GqlField[] {
    const out: GqlField[] = [];
    if (!this.eat('{')) return out;
    while (!this.is('}')) {
      if (this.cur.t === 'eof') throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated field list');
      const desc = this.desc();
      const name = this.name();
      const args = input ? [] : this.args();
      this.expect(':');
      const type = this.type();
      if (input && this.eat('=')) this.value();
      const d = this.directives();
      out.push({ name, args, type, deprecated: d.deprecated, ...(desc ? { desc } : {}) });
    }
    this.expect('}');
    return out;
  }

  def(): void {
    this.desc();
    const kw = this.name();
    if (kw === 'extend') { this.def(); return; }
    if (kw === 'schema') {
      this.directives();
      this.expect('{');
      while (!this.is('}')) {
        if (this.cur.t === 'eof') throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated schema block');
        const op = this.name(); this.expect(':'); const ty = this.name();
        if (op === 'query') this.schema.query = ty; else if (op === 'mutation') this.schema.mutation = ty; else if (op === 'subscription') this.schema.subscription = ty;
      }
      this.expect('}');
      return;
    }
    if (kw === 'scalar') { const n = this.name(); this.directives(); this.merge({ kind: 'scalar', name: n, fields: [], values: [] }); return; }
    if (kw === 'directive') {
      this.expect('@'); this.name(); this.args();
      if (this.cur.v === 'repeatable') this.i++;
      if (this.cur.v === 'on') this.i++;
      this.eat('|');
      this.name();
      while (this.eat('|')) this.name();
      return;
    }
    if (kw === 'type' || kw === 'interface' || kw === 'input') {
      const n = this.name();
      if (this.cur.v === 'implements') { this.i++; this.eat('&'); this.name(); while (this.eat('&')) this.name(); }
      this.directives();
      this.merge({ kind: kw === 'type' ? 'object' : kw === 'input' ? 'input' : 'interface', name: n, fields: this.fields(kw === 'input'), values: [] });
      return;
    }
    if (kw === 'union') {
      const n = this.name(); this.directives();
      if (this.eat('=')) { this.eat('|'); this.name(); while (this.eat('|')) this.name(); }
      this.merge({ kind: 'union', name: n, fields: [], values: [] });
      return;
    }
    if (kw === 'enum') {
      const n = this.name(); this.directives();
      const values: string[] = [];
      if (this.eat('{')) {
        while (!this.is('}')) {
          if (this.cur.t === 'eof') throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated enum');
          this.desc(); values.push(this.name()); this.directives();
        }
        this.expect('}');
      }
      this.merge({ kind: 'enum', name: n, fields: [], values });
      return;
    }
    throw new ActionKitError('bad_source', `GraphQL parse error: unsupported definition '${clip(kw, 30)}' (only type-system definitions are imported)`);
  }

  merge(d: GqlTypeDef): void {
    const old = this.schema.types.get(d.name);
    if (old === undefined) { this.schema.types.set(d.name, d); return; }
    old.fields.push(...d.fields);
    old.values.push(...d.values);
  }
}

export function parseGraphqlSdl(src: string, maxTokens = 2_000_000): GqlSchema {
  const toks = lex(src, maxTokens);
  const schema: GqlSchema = { types: new Map() };
  const p = new P(toks, schema, 32);
  while (p.cur.t !== 'eof') p.def();
  return schema;
}

// ---- introspection -> model ------------------------------------------------------------------------------------------

function introspectType(t: unknown, depth = 0): GqlType {
  if (depth > 16 || !isObj(t)) throw new ActionKitError('bad_source', 'malformed introspection type reference');
  if (t.kind === 'NON_NULL') return { k: 'nonnull', of: introspectType(t.ofType, depth + 1) };
  if (t.kind === 'LIST') return { k: 'list', of: introspectType(t.ofType, depth + 1) };
  if (typeof t.name !== 'string') throw new ActionKitError('bad_source', 'malformed introspection type reference');
  return { k: 'named', name: t.name };
}

export function fromIntrospection(doc: unknown): GqlSchema {
  const root = isObj(doc) && isObj(doc.data) ? doc.data : doc;
  const s = isObj(root) && isObj(root.__schema) ? root.__schema : undefined;
  if (s === undefined || !Array.isArray(s.types)) throw new ActionKitError('bad_source', 'not a GraphQL introspection result (no __schema.types)');
  const schema: GqlSchema = { types: new Map() };
  const rootName = (k: string): string | undefined => (isObj(s[k]) && typeof (s[k] as Record<string, unknown>).name === 'string' ? ((s[k] as Record<string, unknown>).name as string) : undefined);
  const q = rootName('queryType'), m = rootName('mutationType'), sub = rootName('subscriptionType');
  if (q) schema.query = q;
  if (m) schema.mutation = m;
  if (sub) schema.subscription = sub;
  const fieldOf = (f: unknown): GqlField | undefined => {
    if (!isObj(f) || typeof f.name !== 'string') return undefined;
    const argsRaw = Array.isArray(f.args) ? f.args : [];
    return {
      name: f.name,
      args: argsRaw.filter(isObj).filter((a) => typeof a.name === 'string').map((a) => ({ name: a.name as string, type: introspectType(a.type), ...(typeof a.description === 'string' ? { desc: a.description } : {}) })),
      type: f.type === undefined ? { k: 'named', name: 'String' } : introspectType(f.type),
      deprecated: f.isDeprecated === true,
      ...(typeof f.description === 'string' ? { desc: f.description } : {}),
    };
  };
  for (const t of s.types) {
    if (!isObj(t) || typeof t.name !== 'string' || typeof t.kind !== 'string') continue;
    if (t.name.startsWith('__')) continue;
    const kind = ({ OBJECT: 'object', INPUT_OBJECT: 'input', ENUM: 'enum', SCALAR: 'scalar', INTERFACE: 'interface', UNION: 'union' } as Record<string, GqlTypeDef['kind']>)[t.kind];
    if (kind === undefined) continue;
    const fieldsRaw = kind === 'input' ? t.inputFields : t.fields;
    schema.types.set(t.name, {
      kind, name: t.name,
      fields: (Array.isArray(fieldsRaw) ? fieldsRaw : []).map(fieldOf).filter((f): f is GqlField => f !== undefined),
      values: (Array.isArray(t.enumValues) ? t.enumValues : []).filter(isObj).map((e) => e.name).filter((x): x is string => typeof x === 'string'),
    });
  }
  return schema;
}

// ---- model -> JSON-schema-like -> params ------------------------------------------------------------------------------

const SCALARS: Readonly<Record<string, JsonSchemaLike>> = {
  Int: { type: 'integer', format: 'int32' }, String: { type: 'string' }, ID: { type: 'string' }, Boolean: { type: 'boolean' },
  Float: { type: 'number' }, Date: { type: 'string', format: 'date' }, DateTime: { type: 'string', format: 'date-time' }, Email: { type: 'string', format: 'email' },
  UUID: { type: 'string', format: 'uuid' }, URL: { type: 'string', format: 'url' }, URI: { type: 'string', format: 'url' },
};

/** A GraphQL type as a JSON-schema-like node; input objects expand with a cycle guard and a node budget. */
function schemaOf(t: GqlType, gs: GqlSchema, c: Ctx, bud: Budget, stack: readonly string[], where: string): { s: JsonSchemaLike; nonnull: boolean } {
  let nonnull = false;
  let cur = t;
  while (cur.k === 'nonnull') { nonnull = true; cur = cur.of; }
  if (cur.k === 'list') {
    return { s: { type: 'array', items: schemaOf(cur.of, gs, c, bud, stack, where).s }, nonnull };
  }
  const name = cur.name;
  if (bud.left-- <= 0) {
    if (!bud.exhausted) { bud.exhausted = true; addTodo(c, where, 'ref_budget', 'type expansion stopped at the node budget (declared string; refine or drop)'); }
    return { s: {}, nonnull };
  }
  if (Object.prototype.hasOwnProperty.call(SCALARS, name)) return { s: { ...SCALARS[name]! }, nonnull };
  const def = gs.types.get(name);
  if (def === undefined) { addTodo(c, where, 'unknown_type', `type '${clip(name, 60)}' is not defined in the schema (declared string)`); return { s: {}, nonnull }; }
  if (def.kind === 'enum') return { s: { type: 'string', enum: [...new Set(def.values)] }, nonnull };
  if (def.kind === 'scalar') return { s: { type: 'string' }, nonnull };
  if (def.kind === 'input') {
    if (stack.includes(name)) { addTodo(c, where, 'cyclic_ref', `input type '${clip(name, 60)}' is recursive (declared string; refine or drop)`); return { s: {}, nonnull }; }
    const properties: Record<string, JsonSchemaLike> = {};
    const required: string[] = [];
    for (const f of def.fields) {
      const r = schemaOf(f.type, gs, c, bud, [...stack, name], where);
      properties[f.name] = { ...r.s, ...(f.desc ? { description: f.desc } : {}) };
      if (r.nonnull) required.push(f.name);
    }
    return { s: { type: 'object', properties, required }, nonnull };
  }
  addTodo(c, where, 'output_type', `type '${clip(name, 60)}' is an output type and cannot be an argument (declared string)`);
  return { s: {}, nonnull };
}

export function importGraphql(source: unknown, opts: ImportOpts): ImportReport {
  const c = newCtx('graphql', source, opts);
  let gs: GqlSchema;
  if (typeof source === 'string') gs = parseGraphqlSdl(source);
  else gs = fromIntrospection(source);
  const roots: [string | undefined, 'query' | 'mutation' | 'subscription'][] = [
    [gs.query ?? 'Query', 'query'], [gs.mutation ?? 'Mutation', 'mutation'], [gs.subscription ?? 'Subscription', 'subscription'],
  ];
  for (const [rootName, op] of roots) {
    const rt = rootName === undefined ? undefined : gs.types.get(rootName);
    if (rt === undefined) continue;
    for (const f of [...rt.fields].sort((a, b) => compareUtf8(a.name, b.name))) {
      const where = `${op} ${clip(f.name, 80)}`;
      c.root = undefined;
      const bud = newBudget(c);
      const properties: Record<string, JsonSchemaLike> = {};
      const required: string[] = [];
      for (const a of f.args) {
        const r = schemaOf(a.type, gs, c, bud, [], `${where}(${a.name})`);
        properties[a.name] = { ...r.s, ...(a.desc ? { description: a.desc } : {}) };
        if (r.nonnull) required.push(a.name);
      }
      const params: Record<string, ParamDef> = {};
      // args are flattened exactly as an object schema's properties are; nesting stops at MAX_PARAM_PATH_DEPTH segments
      flattenObject({ type: 'object', properties, required }, c, bud, where, params);
      if (f.deprecated) addTodo(c, where, 'deprecated', 'the field is marked @deprecated');
      const effects: Effect[] = op === 'mutation' ? ['update'] : ['read'];
      emitDef(c, {
        name: f.name,
        title: f.desc ? f.desc.split('\n')[0] : f.name,
        description: f.desc,
        effects,
        scope: 'one',
        params,
        ...(op === 'subscription' ? { traits: withTrait(undefined, 'pca.bulk') } : {}),
        ...(op !== 'mutation' ? { idempotency: { mode: 'natural' as const } } : {}),
        bindings: { graphql: { op, field: clip(f.name, 200) } },
      });
    }
  }
  return finish(c);
}
