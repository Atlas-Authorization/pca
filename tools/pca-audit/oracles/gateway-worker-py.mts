// Oracle (python lane): the Cloudflare Worker adapter of @atlasauth/pca-gateway. Writes out/ref-gateway-worker-py.json.gz.
// Specs are taken from the committed gateway corpus (sdks/python-pca/test-data/ref-gateway.json.gz, authorizeScenario cases), so no proof is minted here.
// PORTING: workerScenario({spec, req: {method, url, headers}, mode}) -> cloudflare_worker(opts, next, respond, rewrite_request) called once;
//   mode: 'plain' (enumerable headers, default rewrite = drop the named headers), 'getonly' (headers expose get only), 'norewrite' (rewriteRequest null).
//   out: ['next', method, url, sorted lower-case header names] | ['respond', body, status, headers] | {create: message}
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import zlib from 'node:zlib';
import * as G0 from '@atlasauth/pca-gateway';
import { Oracle, refWrite } from './lib.mjs';

const G: any = (G0 as any).default ?? G0;
const o = new Oracle('gateway-worker-py', 'tools/pca-audit/oracles/gateway-worker-py.mts', 'TS-reference oracle for the PCA gateway Cloudflare Worker adapter (python lane).');
const src = JSON.parse(zlib.gunzipSync(fs.readFileSync(fileURLToPath(new URL('../../../sdks/python-pca/test-data/ref-gateway.json.gz', import.meta.url)))).toString('utf8'));
const SPECS: any[] = src.cases.filter((c: any) => c.fn === 'authorizeScenario').map((c: any) => c.args[0]);

function mask(s: any): any {
  if (typeof s === 'string') return s.replace(/undecodable PCA-Action header: (?!PCA-Action header)[\s\S]*/g, 'undecodable PCA-Action header: <json>');
  return s;
}
function buildOpts(spec: any) {
  const clockNow = spec.now;
  const opts: any = { audience: spec.audience, routes: spec.routes, resolveGrant: (ref: any) => spec.grants[ref] ?? null, now: () => clockNow };
  if (spec.bindRequest === 'off') opts.bindRequest = false; else if (spec.bindRequest !== undefined) opts.bindRequest = spec.bindRequest;
  if (spec.unmatched !== undefined) opts.unmatchedRoute = spec.unmatched;
  if (spec.pathPolicy !== undefined) opts.pathPolicy = spec.pathPolicy;
  if (spec.requireChecks !== undefined) opts.requireChecks = spec.requireChecks;
  if (spec.realm !== undefined) opts.realm = spec.realm;
  if (spec.skipPlan) opts.insecureSkipPlanRootCheck = true;
  if (spec.planRoots !== undefined) opts.authorizedPlanRoots = spec.planRoots;
  const rg: any = { always: { claim: () => true }, false: { claim: () => false }, throws: { claim: () => { throw new Error('store down'); } }, memory: G.memoryReplayGuard(100_000, () => clockNow), 'memory-full': G.memoryReplayGuard(1, () => clockNow) };
  if (spec.replay !== 'none') opts.replayGuard = rg[spec.replay];
  const rv: any = { ok: () => ({ enforced: true, ok: true }), revoked: () => ({ enforced: true, ok: false, reason: 'grant revoked' }), 'revoked-noreason': () => ({ enforced: true, ok: false }), notEnforced: () => ({ enforced: false }), throws: () => { throw new Error('rev down'); } };
  if (spec.revocation !== 'none') opts.hooks = { revocation: rv[spec.revocation] };
  const cp: any = { true: () => true, false: () => false, 'obj-true': () => ({ allow: true }), 'obj-false': () => ({ allow: false }), 'obj-false-reason': () => ({ allow: false, reason: 'over limit' }), throws: () => { throw new Error('policy down'); } };
  if (spec.checkProof) opts.checkProof = cp[spec.checkProof];
  if (spec.policy === 'sig') opts.policy = { mode: 'signature-only' };
  else if (spec.policy === 'bogus') opts.policy = { mode: 'bogus' };
  else if (spec.policy === 'full-missing') opts.policy = { mode: 'full', params: 'body' };
  return opts;
}
const fake = (h: Record<string, string>, enumerable: boolean) => {
  const m = new Map(Object.entries(h).map(([k, v]) => [k.toLowerCase(), [k, v] as [string, string]]));
  const headers: any = { get: (n: string) => m.get(n.toLowerCase())?.[1] ?? null };
  if (enumerable) headers.forEach = (cb: (v: string, k: string) => void) => { for (const [k, v] of m.values()) cb(v, k); };
  return headers;
};
const names = (r: any) => { const out: string[] = []; r.headers.forEach?.((_v: string, k: string) => out.push(k.toLowerCase())); return out.sort(); };

async function workerScenario(a: any) {
  const enumerable = a.mode !== 'getonly';
  const request: any = { method: a.req.method, url: a.req.url, headers: fake(a.req.headers, enumerable) };
  let mw: any;
  try {
    mw = G.cloudflareWorker({
      ...buildOpts(a.spec),
      next: (r: any) => ['next', r.method, r.url, names(r)],
      respond: (body: string, init: any) => ['respond', mask(body), init.status, init.headers],
      ...(a.mode === 'norewrite' ? { rewriteRequest: null } : { rewriteRequest: (r: any, drop: string[]) => ({ method: r.method, url: r.url, headers: fake(Object.fromEntries(Object.entries(a.req.headers).filter(([k]) => !drop.includes(k.toLowerCase()))) as any, true) }) }),
    });
  } catch (e: any) { return { create: e.message }; }
  try { return await mw(request); } catch (e: any) { return { threw: e.message }; }
}

const url = (r: any) => `https://${r.authority ?? 'edge.example'}${r.path}${r.query ? '?' + r.query : ''}`;
const strHeaders = (h: any) => Object.fromEntries(Object.entries(h ?? {}).filter(([, v]) => typeof v === 'string')) as Record<string, string>;
const FORGE = [{}, { 'x-pca-verdict': 'forged' }, { 'X-PCA-Extra': 'y', 'x-pca-grant': 'g' }];
let n = 0;
for (const spec of SPECS) {
  const { requests, ...rest } = spec;
  for (const [ri, r] of (requests as any[]).slice(0, 2).entries()) {
    const forge = FORGE[(n + ri) % FORGE.length];
    const mode = ['plain', 'getonly', 'norewrite'][(n + ri) % 3];
    const req = { method: r.method, url: url(r), headers: { ...strHeaders(r.headers), ...forge } };
    await o.run('workerScenario', `${n}.${ri}`, workerScenario, [{ spec: rest, req, mode }]);
  }
  n++;
}
// every forged-header shape against the first allowing spec
const ok = SPECS[0];
for (const mode of ['plain', 'getonly', 'norewrite']) for (const [fi, forge] of FORGE.entries()) {
  const { requests, ...rest } = ok; const r = requests[0];
  await o.run('workerScenario', `forged ${mode} ${fi}`, workerScenario, [{ spec: rest, req: { method: r.method, url: url(r), headers: { ...strHeaders(r.headers), ...forge } }, mode }]);
}
refWrite(o, 'gateway-worker-py');
