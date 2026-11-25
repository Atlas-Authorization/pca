// discovery.ts - Google API discovery document importer (offline, bounded).
import { fit, snake } from './naming';
import type { RawOp, RawParam, RawType } from './types';

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export interface DiscoveryOpts {
  /** Namespace override (default: the document's `name`). */
  ns?: string;
  /** Leading resource segments to drop from the verb (e.g. `users`). */
  dropSegments?: string[];
  include?: RegExp;
  exclude?: RegExp;
  /** Keep the service name as the first verb segment after the namespace (gcp.compute.instances.insert). */
  servicePath?: boolean;
}

const safeInt = (v: unknown): number | undefined => {
  const n = typeof v === 'string' ? Number(v) : v;
  return typeof n === 'number' && Number.isSafeInteger(n) ? n : undefined;
};

function typeOf(s: J): RawType {
  if (s.$ref) return 'object';
  switch (s.type) {
    case 'integer': return 'integer';
    case 'boolean': return 'boolean';
    case 'array': return 'array';
    case 'object': return 'object';
    default: return 'string';
  }
}

function rawOf(name: string, where: RawParam['where'], required: boolean, s: J, schemas: J): RawParam {
  const ref = s.$ref ? schemas[s.$ref] ?? {} : s;
  const type = s.$ref ? 'object' : typeOf(s);
  const p: RawParam = { name, where, required, type };
  if (typeof s.format === 'string') p.format = s.format === 'google-datetime' || s.format === 'date-time' ? 'date-time' : s.format;
  if (Array.isArray(s.enum) && s.enum.every((x: unknown) => typeof x === 'string' && x.length > 0 && x.length < 100)) p.values = s.enum.slice(0, 64);
  if (type === 'integer') {
    const mn = safeInt(s.minimum), mx = safeInt(s.maximum);
    if (mn !== undefined) p.min = mn;
    if (mx !== undefined) p.max = mx;
  }
  if (type === 'string' && s.type === 'string' && (s.format === 'int64' || s.format === 'uint64')) p.format = 'int64';
  if (type === 'array') {
    const it = s.items ? (s.items.$ref ? 'object' : typeOf(s.items)) : 'string';
    p.items = it === 'array' ? 'object' : it;
  }
  void ref;
  return p;
}

export function importDiscovery(doc: J, o: DiscoveryOpts): RawOp[] {
  const out: RawOp[] = [];
  const schemas: J = doc.schemas ?? {};
  const topParams: J = doc.parameters ?? {};
  void topParams;
  const walk = (node: J, trail: string[]) => {
    for (const mn of Object.keys(node.methods ?? {}).sort()) {
      const m: J = node.methods[mn];
      const id: string = m.id ?? [...trail, mn].join('.');
      if (o.include && !o.include.test(id)) continue;
      if (o.exclude && o.exclude.test(id)) continue;
      const params: RawParam[] = [];
      const order: string[] = Array.isArray(m.parameterOrder) ? m.parameterOrder : [];
      const names = [...order, ...Object.keys(m.parameters ?? {}).sort().filter((k) => !order.includes(k))];
      for (const k of names) {
        const s = m.parameters?.[k];
        if (!s) continue;
        const where = s.location === 'path' ? 'path' : 'query';
        params.push(rawOf(k, where, s.required === true || where === 'path', s, schemas));
      }
      // request body: top-level properties of the request schema
      const reqRef: string | undefined = m.request?.$ref;
      if (reqRef && schemas[reqRef]) {
        const props: J = schemas[reqRef].properties ?? {};
        for (const k of Object.keys(props).sort()) {
          const s = props[k];
          if (typeof s.readOnly === 'boolean' && s.readOnly) continue;
          if (/read[- ]only|output only/i.test(s.description ?? '') && /output only|read-only|read only/i.test((s.description ?? '').slice(0, 80))) continue;
          params.push(rawOf(k, 'body', false, s, schemas));
        }
      }
      const parts = id.split('.');
      let segs = (o.servicePath ? parts : parts.slice(1)).map(snake).filter(Boolean);
      for (const d of o.dropSegments ?? []) segs = segs.filter((x, i) => !(x === d && i < segs.length - 1));
      out.push({
        path: segs.length ? segs.slice(0, -1).map((x) => fit(x)).concat([fit(segs[segs.length - 1]!)]) : [snake(mn)],
        method: (m.httpMethod as string | undefined)?.toUpperCase(),
        httpPath: `/${m.flatPath ?? m.path ?? ''}`.replace('//', '/'),
        opId: id,
        summary: typeof m.description === 'string' ? m.description.split(/(?<=\.)\s/)[0]!.slice(0, 110) : '',
        desc: '',
        tags: [],
        params,
        bindings: { openapi: { operationId: id, method: (m.httpMethod as string | undefined)?.toUpperCase(), path: `/${m.path ?? ''}`.slice(0, 250) } },
      });
    }
    for (const rn of Object.keys(node.resources ?? {}).sort()) walk(node.resources[rn], [...trail, rn]);
  };
  walk(doc, [doc.name ?? 'svc']);
  return out;
}
