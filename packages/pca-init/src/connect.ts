/**
 * `pca init --connect <token>`: register the locally generated source key with the control plane, then keep only what the generated
 * wiring needs to report events (`.pca/connect.json`, gitignored, 0600). The token is single-use and short-lived, scoped to one
 * instance; it is sent once and never written anywhere.
 *
 * Contract (agreed with the guided setup; see the status file): POST {url}/v1/pca/control/connect, no Authorization header, JSON
 *   { token, source, public_key, agent }   (source: a new source id; public_key: the Ed25519 public key, base64url)
 * answers 200 with { source, ingest_key, instance_id, kind, signer }. The server pins the key under the setup run's source id and IGNORES
 * ours, so reports use the returned `source`. `ingest_key` is an `sk_` key scoped to `pca:ingest` (it works on POST
 * /v1/pca/control/events and nothing else; the batches themselves are signed with the source key). `signer` is the guardian key that
 * signs issued grants: it is kept so `pca init --enforce --grant` can verify under it. The same token with the same public key again
 * (a lost reply) returns a fresh ingest key, which is why the key is written before the call and a retry simply repeats it.
 */
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { read } from './detect';
import type { InitDeps, InitResult, Plan } from './types';
import { CONNECT_FILE, SOURCE_KEY_FILE } from './wiring';
import { SOURCE_PUB_FILE } from './plan';

export const DEFAULT_CONTROL_URL = 'https://api.atlasauth.net';

export async function connectSource(plan: Plan, o: { token: string; url?: string; ns: string }, deps: InitDeps): Promise<InitResult> {
  const dir = plan.detection.dir;
  if (existsSync(join(dir, CONNECT_FILE))) return { ok: true, text: `Already connected (${CONNECT_FILE} exists); the setup token was not used.` };
  const pub = read(join(dir, SOURCE_PUB_FILE))?.trim();
  if (pub === undefined || pub === '' || read(join(dir, SOURCE_KEY_FILE)) === null) return { ok: false, text: `Cannot connect: ${SOURCE_KEY_FILE} is missing. Run \`pca init --yes --connect <token>\` again.` };
  const url = (o.url ?? DEFAULT_CONTROL_URL).replace(/\/+$/, '');
  if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/.test(url)) return { ok: false, text: '--connect-url must be https (plain http is allowed only for localhost).' };
  const source = `${o.ns}-${pub.slice(0, 8).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`;
  const f = deps.fetch ?? fetch;
  let res: Response;
  try {
    res = await f(`${url}/v1/pca/control/connect`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: o.token, source, public_key: pub, agent: o.ns }) });
  } catch (e) {
    return { ok: false, text: `Could not reach the control plane at ${url}: ${e instanceof Error ? e.message : 'network error'}. If the reply was lost the token may already be spent: run the same command again, the same token with the same key is accepted and returns a fresh ingest key.` };
  }
  const text = await res.text();
  if (!res.ok) {
    return { ok: false, text: `The control plane refused the setup token (${res.status}): ${text.replace(o.token, '[token]').slice(0, 200)}. Tokens are single-use and short-lived: create a new one in the dashboard.` };
  }
  let body: { source?: unknown; ingest_key?: unknown; instance_id?: unknown; kind?: unknown; signer?: unknown };
  try {
    body = JSON.parse(text) as typeof body;
  } catch {
    return { ok: false, text: 'The control plane answered, but not with JSON.' };
  }
  if (typeof body.ingest_key !== 'string' || body.ingest_key.length === 0) return { ok: false, text: 'The control plane did not return an ingest key.' };
  const abs = join(dir, CONNECT_FILE);
  mkdirSync(dirname(abs), { recursive: true });
  // The server pins the key under the setup run's source id and ignores ours: events under any other id are refused, so keep ITS id.
  if (typeof body.source !== 'string' || body.source.length === 0) return { ok: false, text: 'The control plane did not return the source id to report under.' };
  const pinned = body.source;
  writeFileSync(
    abs,
    JSON.stringify({ url, source: pinned, ingestKey: body.ingest_key, ...(typeof body.instance_id === 'string' ? { instanceId: body.instance_id } : {}), ...(typeof body.kind === 'string' ? { kind: body.kind } : {}), ...(typeof body.signer === 'string' ? { signer: body.signer } : {}) }, null, 2) + '\n',
    { mode: 0o600 },
  );
  chmodSync(abs, 0o600);
  return { ok: true, text: `Connected: source ${pinned} is pinned to the key in ${SOURCE_KEY_FILE}. Observed events are reported to ${url}.` };
}
