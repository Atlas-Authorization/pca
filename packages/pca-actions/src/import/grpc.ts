// grpc.ts - protobuf services -> drafts, from `.proto` text or a binary FileDescriptorSet (`.binpb`). `service.method`
// becomes the verb; `google.api.http` gives method and path; `idempotency_level` gives read / idempotent; field behavior
// (REQUIRED, OUTPUT_ONLY) refines params; streaming methods get `pca.bulk`. Offline, bounded, no code generation.

import { compareUtf8 } from '@atlasauth/pca';
import { ActionKitError, type Effect, type ParamDef } from '../def';
import { addTodo, clip, emitDef, finish, flattenObject, newBudget, newCtx, withTrait, type Ctx, type ImportOpts, type ImportReport, type JsonSchemaLike } from './common';

// ---- model -----------------------------------------------------------------------------------------------------------

export interface PField { name: string; type: string; scope: string; repeated: boolean; optional: boolean; map?: [string, string]; behavior: string[] }
export interface PMsg { full: string; fields: PField[]; mapEntry: boolean }
export interface PEnum { full: string; values: string[] }
export interface PMethod { name: string; input: string; output: string; cs: boolean; ss: boolean; http?: { method: string; path: string; body?: string }; idem?: string; scope: string }
export interface PService { full: string; name: string; methods: PMethod[] }
export interface ProtoModel { messages: Map<string, PMsg>; enums: Map<string, PEnum>; services: PService[] }

const newModel = (): ProtoModel => ({ messages: new Map(), enums: new Map(), services: [] });
const SCALAR_NAMES = new Set(['double', 'float', 'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'fixed32', 'fixed64', 'sfixed32', 'sfixed64', 'bool', 'string', 'bytes']);

// ---- .proto text -----------------------------------------------------------------------------------------------------

type Tok = { t: 'id' | 'str' | 'num' | 'p'; v: string };

function lex(src: string, maxTokens: number): Tok[] {
  const out: Tok[] = [];
  const n = src.length;
  let i = 0;
  const push = (t: Tok) => {
    if (out.length >= maxTokens) throw new ActionKitError('import_limit', 'the proto source has too many tokens');
    out.push(t);
  };
  while (i < n) {
    const ch = src[i]!;
    if (/\s/.test(ch)) { i++; continue; }
    if (src.startsWith('//', i)) { while (i < n && src[i] !== '\n') i++; continue; }
    if (src.startsWith('/*', i)) { const j = src.indexOf('*/', i + 2); if (j < 0) throw new ActionKitError('bad_source', 'unterminated comment in proto source'); i = j + 2; continue; }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      let s = '';
      while (j < n && src[j] !== ch) {
        if (src[j] === '\n') throw new ActionKitError('bad_source', 'unterminated string in proto source');
        if (src[j] === '\\') { s += src[j + 1] ?? ''; j += 2; } else s += src[j++];
      }
      if (j >= n) throw new ActionKitError('bad_source', 'unterminated string in proto source');
      push({ t: 'str', v: s });
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_.]/.test(ch)) { let j = i + 1; while (j < n && /[A-Za-z0-9_.]/.test(src[j]!)) j++; push({ t: 'id', v: src.slice(i, j) }); i = j; continue; }
    if (/[-0-9]/.test(ch)) { let j = i + 1; while (j < n && /[-+.0-9A-Za-z]/.test(src[j]!)) j++; push({ t: 'num', v: src.slice(i, j) }); i = j; continue; }
    if ('{}[]()<>=;,:'.includes(ch)) { push({ t: 'p', v: ch }); i++; continue; }
    throw new ActionKitError('bad_source', `unexpected character in proto source at offset ${i}`);
  }
  return out;
}

class PP {
  i = 0;
  pkg = '';
  constructor(readonly toks: Tok[], readonly m: ProtoModel, readonly maxDepth: number) {}
  get cur(): Tok | undefined { return this.toks[this.i]; }
  is(v: string): boolean { const t = this.cur; return t !== undefined && t.t !== 'str' && t.v === v; }
  eat(v: string): boolean { if (this.is(v)) { this.i++; return true; } return false; }
  fail(msg: string): never { throw new ActionKitError('bad_source', `proto parse error: ${msg} near '${clip(this.cur?.v ?? '<end>', 30)}'`); }
  expect(v: string): void { if (!this.eat(v)) this.fail(`expected '${v}'`); }
  id(): string { const t = this.cur; if (t === undefined || t.t !== 'id') this.fail('expected an identifier'); this.i++; return t!.v; }
  str(): string { const t = this.cur; if (t === undefined || t.t !== 'str') this.fail('expected a string'); this.i++; return t!.v; }

  /** Skip to the matching close of an already-opened bracket. */
  skipTo(open: string, close: string, depth = 1): void {
    while (depth > 0) {
      const t = this.toks[this.i++];
      if (t === undefined) this.fail('unterminated block');
      if (t!.t === 'p') { if (t!.v === open) depth++; else if (t!.v === close) depth--; }
    }
  }
  skipStatement(): void {
    while (this.cur !== undefined && !this.is(';')) {
      if (this.is('{')) { this.i++; this.skipTo('{', '}'); return; }
      this.i++;
    }
    this.eat(';');
  }

  file(): void {
    while (this.cur !== undefined) {
      if (this.eat(';')) continue;
      const kw = this.id();
      if (kw === 'package') { this.pkg = this.id(); this.expect(';'); } else if (kw === 'message') this.message(this.pkg, 0);
      else if (kw === 'enum') this.enumDef(this.pkg);
      else if (kw === 'service') this.service();
      else if (kw === 'extend') { this.id(); this.expect('{'); this.skipTo('{', '}'); } else this.skipStatement();
    }
  }

  qual = (scope: string, name: string): string => (scope === '' ? name : `${scope}.${name}`);

  enumDef(scope: string): void {
    const name = this.id();
    const full = this.qual(scope, name);
    this.expect('{');
    const values: string[] = [];
    while (!this.is('}')) {
      if (this.cur === undefined) this.fail('unterminated enum');
      if (this.is('option') || this.is('reserved')) { this.skipStatement(); continue; }
      const v = this.id();
      values.push(v);
      this.skipStatement();
    }
    this.expect('}');
    this.m.enums.set(full, { full, values });
  }

  /** Field options: collect `field_behavior` names; everything else is skipped. */
  fieldOptions(): string[] {
    const behavior: string[] = [];
    if (!this.eat('[')) return behavior;
    let depth = 1;
    let inBehavior = false;
    while (depth > 0) {
      const t = this.toks[this.i++];
      if (t === undefined) this.fail('unterminated field options');
      if (t!.t === 'p') {
        if (t!.v === '[' || t!.v === '{') depth++;
        else if (t!.v === ']' || t!.v === '}') depth--;
        else if (t!.v === ',') inBehavior = false;
      } else if (t!.t === 'id') {
        if (t!.v.endsWith('field_behavior')) inBehavior = true;
        else if (inBehavior && /^[A-Z_]+$/.test(t!.v)) behavior.push(t!.v);
      }
    }
    return behavior;
  }

  message(scope: string, depth: number): void {
    if (depth > this.maxDepth) throw new ActionKitError('import_limit', 'proto message nesting is too deep');
    const name = this.id();
    const full = this.qual(scope, name);
    const msg: PMsg = { full, fields: [], mapEntry: false };
    this.m.messages.set(full, msg);
    this.expect('{');
    const field = (label: string | undefined, oneof: boolean) => {
      let repeated = label === 'repeated';
      let type = this.id();
      let map: [string, string] | undefined;
      if (type === 'map' && this.eat('<')) { const k = this.id(); this.expect(','); const v = this.id(); this.expect('>'); map = [k, v]; type = 'map'; repeated = false; }
      const fname = this.id();
      this.expect('=');
      this.i++; // field number
      const behavior = this.fieldOptions();
      this.expect(';');
      msg.fields.push({ name: fname, type, scope: full, repeated, optional: label === 'optional' || oneof, ...(map ? { map } : {}), behavior });
    };
    while (!this.is('}')) {
      if (this.cur === undefined) this.fail('unterminated message');
      if (this.eat(';')) continue;
      const kw = this.cur.t === 'id' ? this.cur.v : '';
      if (kw === 'message') { this.i++; this.message(full, depth + 1); continue; }
      if (kw === 'enum') { this.i++; this.enumDef(full); continue; }
      if (kw === 'oneof') {
        this.i++; this.id(); this.expect('{');
        while (!this.is('}')) {
          if (this.cur === undefined) this.fail('unterminated oneof');
          if (this.is('option')) { this.skipStatement(); continue; }
          field(undefined, true);
        }
        this.expect('}');
        continue;
      }
      if (kw === 'option' || kw === 'reserved' || kw === 'extensions') { this.skipStatement(); continue; }
      if (kw === 'extend') { this.i++; this.id(); this.expect('{'); this.skipTo('{', '}'); continue; }
      if (kw === 'group') { this.skipStatement(); continue; }
      if (kw === 'repeated' || kw === 'optional' || kw === 'required') { this.i++; field(kw, false); continue; }
      field(undefined, false);
    }
    this.expect('}');
  }

  service(): void {
    const name = this.id();
    const full = this.qual(this.pkg, name);
    const svc: PService = { full, name, methods: [] };
    this.expect('{');
    while (!this.is('}')) {
      if (this.cur === undefined) this.fail('unterminated service');
      if (this.eat(';')) continue;
      const kw = this.id();
      if (kw !== 'rpc') { this.skipStatement(); continue; }
      const mname = this.id();
      this.expect('(');
      const cs = this.cur?.v === 'stream' && this.cur.t === 'id' ? (this.i++, true) : false;
      const input = this.id();
      this.expect(')');
      if (this.id() !== 'returns') this.fail("expected 'returns'");
      this.expect('(');
      const ss = this.cur?.v === 'stream' && this.cur.t === 'id' ? (this.i++, true) : false;
      const output = this.id();
      this.expect(')');
      const m: PMethod = { name: mname, input, output, cs, ss, scope: this.pkg };
      if (this.eat('{')) {
        while (!this.is('}')) {
          if (this.cur === undefined) this.fail('unterminated rpc body');
          if (!this.is('option')) { this.skipStatement(); continue; }
          this.i++;
          let oname = '';
          if (this.eat('(')) { oname = this.id(); this.expect(')'); } else oname = this.id();
          this.expect('=');
          if (this.is('{')) {
            this.i++;
            let depth = 1;
            while (depth > 0) {
              const t = this.toks[this.i++];
              if (t === undefined) this.fail('unterminated option');
              if (t!.t === 'p') { if (t!.v === '{') depth++; else if (t!.v === '}') depth--; continue; }
              if (depth === 1 && oname.endsWith('http') && t!.t === 'id' && ['get', 'put', 'post', 'delete', 'patch'].includes(t!.v) && this.is(':')) {
                this.i++;
                const path = this.cur?.t === 'str' ? this.cur.v : '';
                this.i++;
                if (m.http === undefined) m.http = { method: t!.v.toUpperCase(), path };
              } else if (depth === 1 && oname.endsWith('http') && t!.t === 'id' && t!.v === 'body' && this.is(':')) {
                this.i++;
                if (this.cur?.t === 'str' && m.http) m.http.body = this.cur.v;
                this.i++;
              }
            }
            this.eat(';');
          } else {
            const v = this.cur; this.i++;
            if (oname.endsWith('idempotency_level') && v !== undefined) m.idem = v.v;
            this.eat(';');
          }
        }
        this.expect('}');
        this.eat(';');
      } else this.expect(';');
      svc.methods.push(m);
    }
    this.expect('}');
    this.m.services.push(svc);
  }
}

export function parseProto(src: string, maxTokens = 2_000_000): ProtoModel {
  const m = newModel();
  new PP(lex(src, maxTokens), m, 32).file();
  return m;
}

// ---- binary descriptor set -----------------------------------------------------------------------------------------

class Reader {
  p = 0;
  constructor(readonly b: Uint8Array, readonly end = b.length) {}
  more(): boolean { return this.p < this.end; }
  varint(): number {
    let r = 0, mul = 1;
    for (let k = 0; k < 10; k++) {
      if (this.p >= this.end) throw new ActionKitError('bad_source', 'truncated descriptor');
      const byte = this.b[this.p++]!;
      r += (byte & 0x7f) * mul;
      if ((byte & 0x80) === 0) return r;
      mul *= 128;
    }
    throw new ActionKitError('bad_source', 'overlong varint in descriptor');
  }
  len(): Reader {
    const n = this.varint();
    if (n > this.end - this.p) throw new ActionKitError('bad_source', 'descriptor length exceeds the buffer');
    const r = new Reader(this.b, this.p + n);
    r.p = this.p;
    this.p += n;
    return r;
  }
  skip(wt: number): void {
    if (wt === 0) this.varint();
    else if (wt === 1) this.adv(8);
    else if (wt === 2) this.len();
    else if (wt === 5) this.adv(4);
    else throw new ActionKitError('bad_source', `unsupported wire type ${wt} in descriptor`);
  }
  adv(n: number): void { if (n > this.end - this.p) throw new ActionKitError('bad_source', 'truncated descriptor'); this.p += n; }
  str(): string { const r = this.len(); return new TextDecoder('utf-8', { fatal: false }).decode(this.b.subarray(r.p, r.end)); }
}
const tag = (r: Reader): [number, number] => { const t = r.varint(); return [Math.floor(t / 8), t % 8]; };

const FTYPES: Readonly<Record<number, string>> = { 1: 'double', 2: 'float', 3: 'int64', 4: 'uint64', 5: 'int32', 6: 'fixed64', 7: 'fixed32', 8: 'bool', 9: 'string', 12: 'bytes', 13: 'uint32', 15: 'sfixed32', 16: 'sfixed64', 17: 'sint32', 18: 'sint64' };

export function parseDescriptorSet(bytes: Uint8Array): ProtoModel {
  const m = newModel();
  const top = new Reader(bytes);
  const readEnum = (r: Reader, scope: string) => {
    let name = '';
    const values: string[] = [];
    while (r.more()) {
      const [f, wt] = tag(r);
      if (f === 1 && wt === 2) name = r.str();
      else if (f === 2 && wt === 2) { const v = r.len(); while (v.more()) { const [vf, vw] = tag(v); if (vf === 1 && vw === 2) values.push(v.str()); else v.skip(vw); } } else r.skip(wt);
    }
    const full = scope === '' ? name : `${scope}.${name}`;
    m.enums.set(full, { full, values });
  };
  const readMsg = (r: Reader, scope: string, depth: number) => {
    if (depth > 32) throw new ActionKitError('import_limit', 'descriptor message nesting is too deep');
    let name = '';
    const fields: { name: string; type: number; label: number; typeName: string; proto3opt: boolean; behavior: string[] }[] = [];
    const nested: Reader[] = [];
    const enums: Reader[] = [];
    let mapEntry = false;
    while (r.more()) {
      const [f, wt] = tag(r);
      if (f === 1 && wt === 2) name = r.str();
      else if (f === 2 && wt === 2) {
        const fr = r.len();
        const fd = { name: '', type: 0, label: 1, typeName: '', proto3opt: false, behavior: [] as string[] };
        while (fr.more()) {
          const [ff, fw] = tag(fr);
          if (ff === 1 && fw === 2) fd.name = fr.str();
          else if (ff === 4 && fw === 0) fd.label = fr.varint();
          else if (ff === 5 && fw === 0) fd.type = fr.varint();
          else if (ff === 6 && fw === 2) fd.typeName = fr.str();
          else if (ff === 17 && fw === 0) fd.proto3opt = fr.varint() === 1;
          else if (ff === 8 && fw === 2) {
            const o = fr.len();
            while (o.more()) {
              const [of, ow] = tag(o);
              if (of === 1052 && ow === 0) fd.behavior.push(String(o.varint()));
              else if (of === 1052 && ow === 2) { const pk = o.len(); while (pk.more()) fd.behavior.push(String(pk.varint())); } else o.skip(ow);
            }
          } else fr.skip(fw);
        }
        fields.push(fd);
      } else if (f === 3 && wt === 2) nested.push(r.len());
      else if (f === 4 && wt === 2) enums.push(r.len());
      else if (f === 7 && wt === 2) { const o = r.len(); while (o.more()) { const [of, ow] = tag(o); if (of === 7 && ow === 0) mapEntry = o.varint() === 1; else o.skip(ow); } } else r.skip(wt);
    }
    const full = scope === '' ? name : `${scope}.${name}`;
    const BEHAV: Record<string, string> = { '2': 'REQUIRED', '3': 'OUTPUT_ONLY', '4': 'INPUT_ONLY', '5': 'IMMUTABLE' };
    m.messages.set(full, {
      full, mapEntry,
      fields: fields.map((f) => ({
        name: f.name, scope: full, repeated: f.label === 3, optional: f.proto3opt,
        type: f.typeName !== '' ? f.typeName : (FTYPES[f.type] ?? 'bytes'),
        behavior: f.behavior.map((b) => BEHAV[b] ?? ''),
      })),
    });
    for (const n of nested) readMsg(n, full, depth + 1);
    for (const e of enums) readEnum(e, full);
  };
  while (top.more()) {
    const [f, wt] = tag(top);
    if (f !== 1 || wt !== 2) { top.skip(wt); continue; }
    const fr = top.len();
    let pkg = '';
    const msgs: Reader[] = [], enums: Reader[] = [], svcs: Reader[] = [];
    // package may follow the messages in the wire order: collect first, then resolve scopes
    while (fr.more()) {
      const [ff, fw] = tag(fr);
      if (ff === 2 && fw === 2) pkg = fr.str();
      else if (ff === 4 && fw === 2) msgs.push(fr.len());
      else if (ff === 5 && fw === 2) enums.push(fr.len());
      else if (ff === 6 && fw === 2) svcs.push(fr.len());
      else fr.skip(fw);
    }
    for (const r of msgs) readMsg(r, pkg, 0);
    for (const r of enums) readEnum(r, pkg);
    for (const r of svcs) {
      let name = '';
      const methods: PMethod[] = [];
      while (r.more()) {
        const [sf, sw] = tag(r);
        if (sf === 1 && sw === 2) name = r.str();
        else if (sf === 2 && sw === 2) {
          const mr = r.len();
          const me: PMethod = { name: '', input: '', output: '', cs: false, ss: false, scope: pkg };
          while (mr.more()) {
            const [mf, mw] = tag(mr);
            if (mf === 1 && mw === 2) me.name = mr.str();
            else if (mf === 2 && mw === 2) me.input = mr.str();
            else if (mf === 3 && mw === 2) me.output = mr.str();
            else if (mf === 5 && mw === 0) me.cs = mr.varint() === 1;
            else if (mf === 6 && mw === 0) me.ss = mr.varint() === 1;
            else if (mf === 4 && mw === 2) {
              const o = mr.len();
              while (o.more()) {
                const [of, ow] = tag(o);
                if (of === 34 && ow === 0) me.idem = ({ 1: 'NO_SIDE_EFFECTS', 2: 'IDEMPOTENT' } as Record<number, string>)[o.varint()] ?? 'IDEMPOTENCY_UNKNOWN';
                else if (of === 72295728 && ow === 2) {
                  const h = o.len();
                  while (h.more()) {
                    const [hf, hw] = tag(h);
                    const verbs: Record<number, string> = { 2: 'GET', 3: 'PUT', 4: 'POST', 5: 'DELETE', 6: 'PATCH' };
                    if (verbs[hf] !== undefined && hw === 2) { if (me.http === undefined) me.http = { method: verbs[hf]!, path: h.str() }; else h.str(); }
                    else if (hf === 7 && hw === 2) { const b = h.str(); if (me.http) me.http.body = b; } else h.skip(hw);
                  }
                } else o.skip(ow);
              }
            } else mr.skip(mw);
          }
          methods.push(me);
        } else r.skip(sw);
      }
      m.services.push({ full: pkg === '' ? name : `${pkg}.${name}`, name, methods });
    }
  }
  return m;
}

// ---- model -> params -------------------------------------------------------------------------------------------------

function resolveName(m: ProtoModel, name: string, scope: string): string | undefined {
  if (name.startsWith('.')) { const a = name.slice(1); return m.messages.has(a) || m.enums.has(a) ? a : a; }
  const parts = scope === '' ? [] : scope.split('.');
  for (let k = parts.length; k >= 0; k--) {
    const cand = [...parts.slice(0, k), name].join('.');
    if (m.messages.has(cand) || m.enums.has(cand)) return cand;
  }
  return m.messages.has(name) || m.enums.has(name) ? name : undefined;
}

const WKT_STRING = new Set(['google.protobuf.StringValue', 'google.protobuf.BytesValue']);
const WKT_INT = new Set(['google.protobuf.Int32Value', 'google.protobuf.Int64Value', 'google.protobuf.UInt32Value', 'google.protobuf.UInt64Value']);

function fieldSchema(m: ProtoModel, f: PField, c: Ctx, stack: readonly string[], where: string, budget: { n: number }): JsonSchemaLike {
  const one = (type: string, scope: string): JsonSchemaLike => {
    if (SCALAR_NAMES.has(type)) {
      if (/int|fixed/.test(type)) return { type: 'integer', format: 'int64' };
      if (type === 'bool') return { type: 'boolean' };
      if (type === 'string') return { type: 'string' };
      if (type === 'bytes') return { type: 'string' };
      return { type: 'number' };
    }
    const abs = type.startsWith('.') ? type.slice(1) : undefined;
    if (abs === 'google.protobuf.Timestamp' || type === 'google.protobuf.Timestamp') return { type: 'string', format: 'date-time' };
    if (WKT_STRING.has(abs ?? type)) return { type: 'string' };
    if (WKT_INT.has(abs ?? type)) return { type: 'integer', format: 'int64' };
    if ((abs ?? type) === 'google.protobuf.BoolValue') return { type: 'boolean' };
    if ((abs ?? type).startsWith('google.protobuf.')) return {};
    const full = resolveName(m, type, scope);
    if (full === undefined) { addTodo(c, where, 'unknown_type', `type '${clip(type, 60)}' is not defined in the proto source (declared string)`); return {}; }
    const en = m.enums.get(full);
    if (en) return { type: 'string', enum: [...new Set(en.values)] };
    return msgSchema(m, full, c, stack, where, budget);
  };
  if (f.map) return { type: 'object' };
  const s = one(f.type, f.scope);
  return f.repeated ? { type: 'array', items: s } : s;
}

function msgSchema(m: ProtoModel, full: string, c: Ctx, stack: readonly string[], where: string, budget: { n: number }): JsonSchemaLike {
  const msg = m.messages.get(full);
  if (msg === undefined) return {};
  if (stack.includes(full)) { addTodo(c, where, 'cyclic_ref', `message '${clip(full, 80)}' is recursive (declared string; refine or drop)`); return {}; }
  if (stack.length > c.lim.max_ref_depth || --budget.n <= 0) { addTodo(c, where, 'ref_budget', 'message expansion stopped at the bound (declared string; refine or drop)'); return {}; }
  const properties: Record<string, JsonSchemaLike> = {};
  const required: string[] = [];
  for (const f of msg.fields) {
    if (f.behavior.includes('OUTPUT_ONLY')) continue;
    properties[f.name] = fieldSchema(m, f, c, [...stack, full], `${where}.${f.name}`, budget);
    if (f.behavior.includes('REQUIRED')) required.push(f.name);
  }
  return { type: 'object', properties, required };
}

export function importGrpc(source: unknown, opts: ImportOpts): ImportReport {
  const c = newCtx('grpc', source, opts);
  let m: ProtoModel;
  if (typeof source === 'string') m = parseProto(source);
  else if (source instanceof Uint8Array) m = parseDescriptorSet(source);
  else throw new ActionKitError('bad_source', 'a gRPC source is .proto text or a binary FileDescriptorSet');
  for (const svc of [...m.services].sort((a, b) => compareUtf8(a.full, b.full))) {
    for (const me of [...svc.methods].sort((a, b) => compareUtf8(a.name, b.name))) {
      const where = `${svc.name}/${me.name}`;
      c.root = undefined;
      const bud = newBudget(c);
      const input = resolveName(m, me.input, me.scope) ?? me.input.replace(/^\./, '');
      const schema = msgSchema(m, input, c, [], where, { n: c.lim.max_ref_nodes });
      const params: Record<string, ParamDef> = {};
      if (schema.properties) flattenObject(schema, c, bud, where, params);
      else if (!m.messages.has(input) && !input.startsWith('google.protobuf.')) addTodo(c, where, 'unknown_type', `request type '${clip(me.input, 60)}' is not defined in the source (no parameters)`);
      const hm = me.http?.method;
      const effects: Effect[] = hm === 'GET' ? ['read'] : hm === 'DELETE' ? ['delete'] : hm === 'POST' ? ['create'] : hm === 'PUT' || hm === 'PATCH' ? ['update'] : me.idem === 'NO_SIDE_EFFECTS' ? ['read'] : ['update'];
      const natural = me.idem === 'NO_SIDE_EFFECTS' || me.idem === 'IDEMPOTENT' || hm === 'GET' || hm === 'PUT' || hm === 'DELETE';
      let traits: string[] | undefined;
      if (me.cs || me.ss) { traits = withTrait(traits, 'pca.bulk'); addTodo(c, where, 'streaming', 'a streaming method: acts on many messages (pca.bulk added)'); }
      emitDef(c, {
        name: `${svc.name} ${me.name}`,
        title: me.name.replace(/([a-z0-9])([A-Z])/g, '$1 $2'),
        effects,
        scope: 'one',
        params,
        ...(natural ? { idempotency: { mode: 'natural' as const } } : {}),
        ...(traits ? { traits } : {}),
        bindings: { grpc: { service: clip(svc.full, 250), method: clip(me.name, 250) }, ...(me.http && me.http.path ? { http: { method: me.http.method, path: clip(me.http.path, 250) } } : {}) },
      });
    }
  }
  return finish(c);
}
