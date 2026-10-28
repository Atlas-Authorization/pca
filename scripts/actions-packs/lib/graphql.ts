// graphql.ts - GraphQL SDL importer: Query and Mutation root fields become operations; arguments (and the fields of a single
// input-object argument) become parameters. Offline, bounded.
import { parse, type DocumentNode, type FieldDefinitionNode, type InputValueDefinitionNode, type TypeNode } from 'graphql';
import { fit, snake } from './naming';
import type { RawOp, RawParam, RawType } from './types';

export interface GraphqlOpts {
  /** Namespace segment kept in the op path (e.g. a sub-area); default none. */
  queries?: boolean;
}

const named = (t: TypeNode): { name: string; list: boolean; required: boolean } => {
  let list = false;
  const required = t.kind === 'NonNullType';
  let cur: TypeNode = t;
  for (;;) {
    if (cur.kind === 'NonNullType') cur = cur.type;
    else if (cur.kind === 'ListType') { list = true; cur = cur.type; }
    else return { name: cur.name.value, list, required };
  }
};

const SCALARS: Record<string, RawType> = { Int: 'integer', Float: 'string', Boolean: 'boolean', String: 'string', ID: 'string', UUID: 'string', DateTime: 'string', DateTimeOrDuration: 'string', TimelessDate: 'string', JSON: 'object', JSONObject: 'object' };

export function importGraphql(sdl: string, o: GraphqlOpts = {}): RawOp[] {
  const doc: DocumentNode = parse(sdl, { noLocation: true });
  const inputs = new Map<string, readonly InputValueDefinitionNode[]>();
  const enums = new Map<string, string[]>();
  const objects = new Map<string, readonly FieldDefinitionNode[]>();
  for (const d of doc.definitions) {
    if (d.kind === 'InputObjectTypeDefinition') inputs.set(d.name.value, d.fields ?? []);
    else if (d.kind === 'EnumTypeDefinition') enums.set(d.name.value, (d.values ?? []).map((v) => v.name.value));
    else if (d.kind === 'ObjectTypeDefinition') objects.set(d.name.value, d.fields ?? []);
  }
  const param = (name: string, t: TypeNode, required: boolean): RawParam => {
    const n = named(t);
    const p: RawParam = { name, where: 'arg', required, type: 'string' };
    if (n.list) { p.type = 'array'; p.items = SCALARS[n.name] === 'integer' ? 'integer' : SCALARS[n.name] === 'boolean' ? 'boolean' : inputs.has(n.name) ? 'object' : 'string'; p.maxItems = 250; }
    else if (enums.has(n.name)) { p.values = enums.get(n.name)!.slice(0, 64); }
    else if (inputs.has(n.name)) p.type = 'object';
    else p.type = SCALARS[n.name] ?? 'string';
    if (p.type === 'string' && (n.name === 'DateTime')) p.format = 'date-time';
    return p;
  };
  const ops: RawOp[] = [];
  const roots: [string, 'query' | 'mutation'][] = [['Mutation', 'mutation'], ...(o.queries === false ? [] : [['Query', 'query'] as [string, 'query']])];
  for (const [rootName, kind] of roots) {
    for (const f of [...(objects.get(rootName) ?? [])].sort((a, b) => (a.name.value < b.name.value ? -1 : 1))) {
      const params: RawParam[] = [];
      for (const a of f.arguments ?? []) {
        const n = named(a.type);
        const req = a.type.kind === 'NonNullType';
        const sub = !n.list && inputs.get(n.name);
        if (sub && sub.length <= 40 && ['input', 'data'].includes(a.name.value)) {
          for (const sf of sub) {
            const st = named(sf.type);
            if (inputs.has(st.name) && !st.list) { params.push({ ...param(`${a.name.value}.${sf.name.value}`, sf.type, false), type: 'object' }); continue; }
            params.push(param(`${a.name.value}.${sf.name.value}`, sf.type, req && sf.type.kind === 'NonNullType'));
          }
        } else params.push(param(a.name.value, a.type, req));
      }
      const segs = snake(f.name.value).split('_');
      // Linear style: issueCreate / issueArchive -> noun first, action last
      const ACTIONS = new Set(['create', 'update', 'delete', 'archive', 'unarchive', 'remove', 'add', 'subscribe', 'unsubscribe', 'send', 'resend', 'sync', 'join', 'leave', 'merge', 'move', 'import', 'export', 'login', 'logout', 'revoke', 'reset', 'verify', 'invite', 'suspend', 'unsuspend', 'promote', 'demote', 'convert', 'refresh', 'regenerate', 'duplicate', 'restore', 'pause', 'resume']);
      let path: string[];
      const last = segs[segs.length - 1]!;
      if (kind === 'mutation' && ACTIONS.has(last) && segs.length > 1) path = [fit(segs.slice(0, -1).join('_')), last];
      else path = [fit(snake(f.name.value))];
      ops.push({
        path, kind, summary: f.description?.value.split(/(?<=\.)\s/)[0]?.slice(0, 110) ?? '', desc: '', tags: [], params,
        opId: f.name.value,
        bindings: { graphql: { op: kind, field: f.name.value } },
      });
    }
  }
  return ops;
}
