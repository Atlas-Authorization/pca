// botocore.ts - AWS service model (botocore service-2.json) importer. Operation names are PascalCase verb-noun; members become params.
import { fit, snake } from './naming';
import type { RawOp, RawParam, RawType } from './types';

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const safeInt = (v: unknown): number | undefined => (typeof v === 'number' && Number.isSafeInteger(v) ? v : undefined);
const NEW_ID_OPS = /^(create|run|allocate|register|import|copy|put|send|publish|start|request|launch|purchase|tag|untag|add|batch|restore|upload|invoke|initiate|generate|assume|get|list|describe|query|scan|search)/;

export interface BotocoreOpts {
  /** Service namespace segment (default: serviceId snake-cased). */
  service?: string;
  /** Skip operations matching this (deprecated/legacy/internal). */
  exclude?: RegExp;
}

function typeOf(sh: J): RawType {
  switch (sh?.type) {
    case 'integer': case 'long': return 'integer';
    case 'boolean': return 'boolean';
    case 'list': return 'array';
    case 'structure': case 'map': return 'object';
    default: return 'string'; // string, timestamp, blob, float/double (no floats in the model)
  }
}

export function importBotocore(doc: J, o: BotocoreOpts): RawOp[] {
  const shapes: J = doc.shapes ?? {};
  const svc = o.service ?? snake(String(doc.metadata?.serviceId ?? doc.metadata?.endpointPrefix ?? 'svc'));
  const out: RawOp[] = [];
  for (const name of Object.keys(doc.operations ?? {}).sort()) {
    const op: J = doc.operations[name];
    if (o.exclude?.test(name) || op.deprecated === true) continue;
    const input: J = op.input ? shapes[op.input.shape] ?? {} : {};
    const req = new Set<string>(Array.isArray(input.required) ? input.required : []);
    const params: RawParam[] = [];
    const members: J = input.members ?? {};
    for (const mn of Object.keys(members).sort()) {
      const m = members[mn];
      const sh: J = shapes[m.shape] ?? {};
      const t = typeOf(sh);
      const p: RawParam = { name: mn, where: m.location === 'uri' ? 'path' : 'body', required: req.has(mn), type: t };
      if (t === 'string') {
        if (Array.isArray(sh.enum) && sh.enum.every((x: unknown) => typeof x === 'string' && x.length > 0 && x.length < 100)) p.values = sh.enum.slice(0, 64);
        if (sh.type === 'timestamp') p.format = 'date-time';
        const mx = safeInt(sh.max);
        if (mx !== undefined && sh.type === 'string') p.maxLength = mx;
      }
      if (t === 'integer') { const mn2 = safeInt(sh.min), mx = safeInt(sh.max); if (mn2 !== undefined) p.min = mn2; if (mx !== undefined) p.max = mx; }
      if (t === 'array') {
        const it = typeOf(shapes[sh.member?.shape] ?? {});
        p.items = it === 'array' ? 'object' : it;
        const mx = safeInt(sh.max);
        if (mx !== undefined) p.maxItems = mx;
      }
      params.push(p);
    }
    // the resource a call acts on: the last required string identifier, unless the op makes a new one (REST uri params already carry it)
    if (!params.some((p) => p.where === 'path') && (!NEW_ID_OPS.test(snake(name)) || /export|store_image/.test(snake(name)))) {
      const idp = [...params].reverse().find((p) => p.required && p.type === 'string' && /(Id|Name|Bucket|Identifier)$/.test(p.name) && !/Arn$/.test(p.name));
      if (idp) idp.where = 'path';
    }
    const verbName = snake(name);
    const http: J = op.http ?? {};
    out.push({
      path: [svc, fit(verbName)],
      method: typeof http.method === 'string' ? http.method : 'POST',
      httpPath: typeof http.requestUri === 'string' ? http.requestUri : '/',
      opId: name,
      summary: verbName.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()),
      desc: '',
      tags: [],
      params,
      bindings: { http: { method: String(http.method ?? 'POST'), path: String(http.requestUri ?? '/').slice(0, 250) }, openapi: { operationId: `${doc.metadata?.endpointPrefix ?? svc}:${name}` } },
    });
  }
  return out;
}
