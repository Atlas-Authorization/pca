// Oracle: @atlasauth/pca-fetch (withPCA / createPcaFetchGuard): construction guards and the pre-verification refusals
// (no / undecodable / malformed proof, unknown grant, a resolver that throws, a grant that cannot verify). The verifier's own
// reason text and challenge string belong to the core guard and differ per language, so only their SHAPE is compared.
// PORTING (fn(args) -> native entry point, compared by JSON value; a throw requires the native to throw):
//   constructScenario(kind)   Fetch.withPCA(options, handler) / createPcaFetchGuard: kind 'ok' (audience + resolveGrant +
//                             insecureAllowUnboundOperation) | 'noaudience' | 'nooperation' (both throw) -> {built: true}
//   requestScenario(spec)     spec {resolve: 'null' | 'throws', headers?, body?}: one POST through withPCA with the 'ok' options;
//                             result {status, handlerRan, decision, challenge, contentType, bodyKeys, errorIsString}
//                             decision = body.decision; challenge = (401 only, else null) WWW-Authenticate starts with 'PCA realm="'; bodyKeys sorted
import * as F0 from '@atlasauth/pca-fetch';
import { Oracle, refWrite } from './lib.mjs';

const F: any = (F0 as any).default ?? F0;
const o = new Oracle('fetch', 'tools/pca-audit/oracles/fetch.mts', 'TS-reference oracle for the Web Fetch guard.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

const AUD = 'rs_fetch';
const b64 = (v: any) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

function construct(kind: string) {
  const handler = async () => new Response('ok');
  const resolveGrant = async () => null;
  if (kind === 'ok') F.withPCA({ audience: AUD, resolveGrant, insecureAllowUnboundOperation: true }, handler);
  else if (kind === 'noaudience') F.withPCA({ audience: '', resolveGrant, insecureAllowUnboundOperation: true }, handler);
  else if (kind === 'nooperation') F.withPCA({ audience: AUD, resolveGrant }, handler);
  else throw new Error('unknown kind');
  return { built: true };
}
for (const k of ['ok', 'noaudience', 'nooperation']) await add('constructScenario', k, construct, [k]);

async function request(spec: any) {
  let ran = false;
  const resolveGrant = async () => {
    if (spec.resolve === 'throws') throw new Error('store down');
    return null;
  };
  const fetch = F.withPCA({ audience: AUD, resolveGrant, insecureAllowUnboundOperation: true }, async () => { ran = true; return new Response('{"ok":true}'); });
  const init: any = { method: 'POST', headers: spec.headers ?? {} };
  if (spec.body !== undefined) init.body = spec.body;
  const res = await fetch(new Request('http://localhost/refunds', init));
  let body: any = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  const www = res.headers.get('www-authenticate');
  return {
    status: res.status, handlerRan: ran, decision: body?.decision ?? null, challenge: res.status === 401 ? www !== null && www.startsWith('PCA realm="') : null,
    contentType: res.headers.get('content-type'), bodyKeys: body && typeof body === 'object' ? Object.keys(body).sort() : null, errorIsString: typeof body?.error === 'string',
  };
}
const HEADERS: [string, any][] = [
  ['none', {}], ['empty', { 'PCA-Action': '' }], ['junk', { 'PCA-Action': 'junk!!' }], ['padded', { 'PCA-Action': 'e30=' }], ['std alphabet', { 'PCA-Action': '+/+/' }],
  ['no grant_ref', { 'PCA-Action': b64({ a: 1 }) }], ['array', { 'PCA-Action': b64([]) }], ['string', { 'PCA-Action': b64('"x"') }], ['null', { 'PCA-Action': b64('null') }],
  ['number', { 'PCA-Action': b64('5') }], ['bad json', { 'PCA-Action': b64('{bad') }], ['dup keys', { 'PCA-Action': b64('{"grant_ref":"g","grant_ref":"h"}') }],
  ['grant_ref number', { 'PCA-Action': b64({ grant_ref: 1 }) }], ['grant_ref null', { 'PCA-Action': b64({ grant_ref: null }) }], ['grant_ref object', { 'PCA-Action': b64({ grant_ref: {} }) }],
  ['grant_ref ok', { 'PCA-Action': b64({ grant_ref: 'g1' }) }], ['lower-case name', { 'pca-action': b64({ grant_ref: 'g1' }) }],
];
const BODIES: [string, string | undefined][] = [
  ['no body', undefined], ['envelope', '{"pcactn":{"grant_ref":"g1"}}'], ['envelope no grant', '{"pcactn":{"a":1}}'], ['not json', 'not json'], ['pcactn number', '{"pcactn":5}'],
  ['pcactn null', '{"pcactn":null}'], ['array', '[]'], ['other', '{"other":1}'], ['envelope bad grant', '{"pcactn":{"grant_ref":7}}'],
];
for (const res of ['null', 'throws']) {
  for (const [hl, h] of HEADERS) await add('requestScenario', `${res}/${hl}`, request, [{ resolve: res, headers: h }]);
  for (const [bl, b] of BODIES) await add('requestScenario', `${res}/body ${bl}`, request, [{ resolve: res, body: b }]);
  await add('requestScenario', `${res}/header + body`, request, [{ resolve: res, headers: { 'PCA-Action': b64({ grant_ref: 'g1' }) }, body: '{"pcactn":{"grant_ref":"g2"}}' }]);
  await add('requestScenario', `${res}/empty header + body`, request, [{ resolve: res, headers: { 'PCA-Action': '' }, body: '{"pcactn":{"grant_ref":"g2"}}' }]);
}

refWrite(o, 'fetch');
