// Drives a running Lambda Runtime Interface Emulator container (official AWS Lambda base image) with the
// documented API Gateway authorizer event shapes and records every real invocation request/response.
//   node drive.mjs <port> <handler: rest|simple|restReplay> <imageTag> <fixturesDir> <proofsJson> <outJsonl>
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [port, handler, imageTag, fxDir, proofsPath, outPath] = process.argv.slice(2);
const { mintedAtMs, proofs } = JSON.parse(readFileSync(proofsPath, 'utf8'));
const fx = (n) => JSON.parse(readFileSync(join(fxDir, n), 'utf8'));
const REST = fx('aws-rest-request-authorizer.json');
const V1 = fx('aws-http-api-payload-v1.json');
const V2 = fx('aws-http-api-payload-v2.json');
const url = `http://127.0.0.1:${port}/2015-03-31/functions/function/invocations`;

const withHeader = (ev, key, value) => ({ ...ev, headers: { ...(ev.headers ?? {}), ...(value === undefined ? {} : { [key]: value }) } });
const rest = (p) => withHeader(REST, 'PCA-Action', p);
const v1 = (p) => withHeader(V1, 'PCA-Action', p);
const v2 = (p) => withHeader(V2, 'pca-action', p);
const arn = (m, path) => `arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/${m}/${path}`;
const restPost = (p, path) => ({ ...withHeader(REST, 'PCA-Action', p), httpMethod: 'POST', path: `/${path}`, resource: `/${path}`, methodArn: arn('POST', path) });

let fails = 0;
async function invoke(scenario, event, check) {
  const t0 = performance.now();
  const res = await fetch(url, { method: 'POST', body: JSON.stringify(event) });
  const text = await res.text();
  const ms = Math.round(performance.now() - t0);
  let body; try { body = JSON.parse(text); } catch { body = text; }
  let ok = false, why = '';
  try { ok = check(body, res.status) === true; } catch (e) { why = String(e); }
  if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  [${imageTag}/${handler}] ${scenario} (http ${res.status}, ${ms} ms)${why}`);
  appendFileSync(outPath, JSON.stringify({ image: imageTag, handler, scenario, event, httpStatus: res.status, response: body, ms, pass: ok, mintedAtMs }) + '\n');
  return body;
}
const effect = (b) => b?.policyDocument?.Statement?.[0]?.Effect;
const code = (b) => b?.context?.pcaCode;
const strCtx = (b) => Object.values(b?.context ?? {}).every((v) => typeof v === 'string');

if (handler === 'rest') {
  await invoke('REST REQUEST allow', rest(proofs.valid), (b) => effect(b) === 'Allow' && b.policyDocument.Statement[0].Resource === REST.methodArn && b.policyDocument.Version === '2012-10-17' && strCtx(b) && typeof b.principalId === 'string' && b.principalId !== 'anonymous' && typeof b.context.pcaVerdict === 'string');
  await invoke('REST REQUEST no proof', REST, (b) => effect(b) === 'Deny' && code(b) === 'no-proof' && b.context.pcaStatus === '401' && b.principalId === 'anonymous');
  await invoke('REST REQUEST tampered proof', rest(proofs.tampered), (b) => effect(b) === 'Deny' && ['invalid-proof', 'verify-failed'].includes(code(b)));
  await invoke('REST REQUEST wrong audience', rest(proofs['wrong-aud']), (b) => effect(b) === 'Deny' && code(b) === 'wrong-audience' && b.context.pcaStatus === '403');
  await invoke('REST REQUEST payout-verb proof at refund route', rest(proofs['payout-verb']), (b) => effect(b) === 'Deny' && code(b) === 'insufficient-capability');
  await invoke('REST REQUEST unmapped route (POST /unknown)', restPost(proofs.valid, 'unknown'), (b) => effect(b) === 'Deny' && code(b) === 'unmapped-route');
  await invoke('REST REQUEST POST /refunds allow', restPost(proofs.valid2, 'refunds'), (b) => effect(b) === 'Allow');
  await invoke('REST REQUEST POST /payouts with refund proof', restPost(proofs.valid3, 'payouts'), (b) => effect(b) === 'Deny' && code(b) === 'insufficient-capability');
  await invoke('REST REQUEST path traversal /refunds/../payouts', restPost(proofs.valid4, 'refunds/../payouts'), (b) => effect(b) === 'Deny' && code(b) === 'invalid-path');
  await invoke('HTTP API payload 1.0 allow', v1(proofs.valid), (b) => effect(b) === 'Allow' && b.policyDocument.Statement[0].Resource === V1.methodArn);
  await invoke('HTTP API payload 1.0 no proof', V1, (b) => effect(b) === 'Deny' && code(b) === 'no-proof');
  await invoke('HTTP API payload 2.0 allow (IAM policy response)', v2(proofs.valid), (b) => effect(b) === 'Allow' && b.policyDocument.Statement[0].Resource === V2.routeArn);
  await invoke('HTTP API payload 2.0 no proof', V2, (b) => effect(b) === 'Deny' && code(b) === 'no-proof');
  await invoke('REST TOKEN-type event with a valid proof as authorizationToken (not supported: fail closed)', { type: 'TOKEN', authorizationToken: proofs.valid, methodArn: REST.methodArn }, (b) => effect(b) === 'Deny');
  await invoke('empty event {} (fail closed)', {}, (b) => effect(b) === 'Deny');
} else if (handler === 'simple') {
  await invoke('HTTP API 2.0 simple response allow', v2(proofs.valid), (b) => b?.isAuthorized === true && Object.keys(b).sort().join() === 'context,isAuthorized' && strCtx(b));
  await invoke('HTTP API 2.0 simple response no proof', V2, (b) => b?.isAuthorized === false && code(b) === 'no-proof');
  await invoke('HTTP API 2.0 simple response tampered', v2(proofs.tampered), (b) => b?.isAuthorized === false);
  await invoke('HTTP API 2.0 simple response wrong audience', v2(proofs['wrong-aud']), (b) => b?.isAuthorized === false && code(b) === 'wrong-audience');
  await invoke('empty event {} (fail closed)', {}, (b) => b?.isAuthorized === false);
} else if (handler === 'restReplay') {
  await invoke('replay guard: first presentation of a proof', rest(proofs.replay), (b) => effect(b) === 'Allow');
  await invoke('replay guard: second presentation, same warm container', rest(proofs.replay), (b) => effect(b) === 'Deny' && code(b) === 'replayed-proof');
  await invoke('replay guard: a different fresh proof is still allowed', rest(proofs.valid), (b) => effect(b) === 'Allow');
  // A Lambda execution environment never runs two invocations at once (the RIE even drops overlapping
  // connections), so repeated presentation is sequential: of 8 presentations of one proof exactly one may Allow.
  const burst = [];
  for (let i = 0; i < 8; i++) burst.push(await (await fetch(url, { method: 'POST', body: JSON.stringify(rest(proofs.valid2)) })).json());
    const allows = burst.filter((b) => effect(b) === 'Allow').length;
  const ok = allows === 1;
  if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  [${imageTag}/${handler}] 8 sequential presentations of one proof -> ${allows} Allow`);
  appendFileSync(outPath, JSON.stringify({ image: imageTag, handler, scenario: '8 sequential presentations of one proof', allows, responses: burst.map((b) => effect(b)), pass: ok }) + '\n');
}
process.exit(fails === 0 ? 0 : 1);
