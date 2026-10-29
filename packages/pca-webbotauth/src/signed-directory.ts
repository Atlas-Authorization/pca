import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import type { DirectoryJwk, KeyDirectory, KeyPair } from './index';

/**
 * Signed key-directory responses (draft-meunier-http-message-signatures-directory section 5.2): the directory body is
 * signed with RFC 9421, covering `"@authority";req`, `tag="http-message-signatures-directory"`, `alg="ed25519"`, a
 * `keyid` that is the RFC 7638 thumbprint of the signing key, with `created` and `expires`. One signature per key.
 * A client keeps only the keys that have a valid signature.
 */
export const DIRECTORY_SIGNATURE_TAG = 'http-message-signatures-directory';
const DEFAULT_LIFETIME_SEC = 86_400;

const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const thumbprintOfX = (x: string): string => createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');

/** Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string `kid`. Throws otherwise. */
export function parseKeyDirectory(text: string): KeyDirectory {
  const doc: unknown = JSON.parse(text);
  const keys = (doc as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys) || keys.length === 0) throw new Error('directory has no keys');
  for (const k of keys) {
    const j = k as Record<string, unknown> | null;
    if (typeof j !== 'object' || j === null || j.kty !== 'OKP' || j.crv !== 'Ed25519' || typeof j.kid !== 'string' || j.kid === '') {
      throw new Error('directory contains a malformed key');
    }
    if (typeof j.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(j.x) || Buffer.from(j.x, 'base64url').length !== 32) throw new Error('directory contains a malformed key');
    for (const f of ['nbf', 'exp'] as const) if (j[f] !== undefined && !Number.isFinite(j[f])) throw new Error('directory contains a malformed key');
  }
  return doc as KeyDirectory;
}

export interface SignDirectoryInput {
  /** The signing keys: one signature is made per key, and each key's thumbprint is the `keyid`. */
  keys: readonly KeyPair[];
  /** The directory document to serve (as built by `buildKeyDirectory`); every signing key must be in it. */
  directory: KeyDirectory;
  /** The authority of the request being answered (`host` or `host:port`, lower case). */
  authority: string;
  created?: number;
  expiresInSec?: number;
}

/** Sign a directory response. Returns the exact `body` to serve and the headers to send with it. */
export function signDirectoryResponse(input: SignDirectoryInput): { body: string; headers: Record<string, string> } {
  if (input.keys.length === 0) throw new Error('signDirectoryResponse: at least one signing key is required');
  if (!/^[a-z0-9.\-\[\]:]+$/.test(input.authority)) throw new Error('signDirectoryResponse: authority must be a lower-case host or host:port');
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const expires = created + (input.expiresInSec ?? DEFAULT_LIFETIME_SEC);
  const body = JSON.stringify(input.directory);
  const inputs: string[] = [];
  const sigs: string[] = [];
  input.keys.forEach((k, i) => {
    const x = b64url(k.publicKey);
    if (!input.directory.keys.some((j) => j.x === x)) throw new Error('signDirectoryResponse: a signing key is not in the directory');
    const keyid = thumbprintOfX(x);
    const label = `sig${i + 1}`;
    const params = `("@authority";req);created=${created};expires=${expires};keyid="${keyid}";alg="ed25519";tag="${DIRECTORY_SIGNATURE_TAG}"`;
    const base = `"@authority";req: ${input.authority}\n"@signature-params": ${params}`;
    const priv = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x, d: b64url(k.secretKey) }, format: 'jwk' });
    inputs.push(`${label}=${params}`);
    sigs.push(`${label}=:${nodeSign(null, Buffer.from(base), priv).toString('base64')}:`);
  });
  return {
    body,
    headers: { 'content-type': 'application/http-message-signatures-directory+json', 'signature-input': inputs.join(', '), signature: sigs.join(', ') },
  };
}

export interface VerifyDirectoryInput {
  /** The authority the client requested (`host` or `host:port`, lower case). */
  authority: string;
  /** The response headers (`signature-input` and `signature`, lower-case names). */
  headers: Record<string, string>;
  /** The response body exactly as received. */
  body: string;
  /** Clock (epoch seconds). Default now. */
  now?: number;
  clockSkewSec?: number;
  /** Cap on `expires - created` (default 86400 s). */
  maxLifetimeSec?: number;
}

export type VerifyDirectoryResult = { valid: true; keys: DirectoryJwk[] } | { valid: false; reason: string; keys: [] };

const ENTRY = /^([a-z][a-z0-9_.*-]*)=\("@authority";req\)((?:;[a-z]+=(?:[0-9]+|"[A-Za-z0-9_.\-]*"))*)$/;

/**
 * Verify a signed directory response. Fail closed: returns `{ valid: false, reason }` for a missing or malformed signature
 * header, a body that is not a well-formed directory, or when NO signature is valid. When valid, `keys` holds only the
 * directory keys that carry a valid signature (the draft: ignore the rest).
 */
export function verifyDirectoryResponse(input: VerifyDirectoryInput): VerifyDirectoryResult {
  const fail = (reason: string): VerifyDirectoryResult => ({ valid: false, reason, keys: [] });
  try {
    const sigInput = input.headers['signature-input'];
    const sigHeader = input.headers.signature;
    if (!sigInput || !sigHeader) return fail('missing signature-input or signature header');
    const dir = parseKeyDirectory(input.body);
    const sigs = new Map<string, Buffer>();
    for (const part of sigHeader.split(', ')) {
      const m = /^([a-z][a-z0-9_.*-]*)=:([A-Za-z0-9+/]+={0,2}):$/.exec(part);
      if (!m) return fail('malformed signature header');
      sigs.set(m[1]!, Buffer.from(m[2]!, 'base64'));
    }
    const now = input.now ?? Math.floor(Date.now() / 1000);
    const skew = input.clockSkewSec ?? 0;
    const maxLife = input.maxLifetimeSec ?? DEFAULT_LIFETIME_SEC;
    const good = new Map<string, DirectoryJwk>();
    let lastReason = 'no signature entry';
    for (const raw of sigInput.split(', ')) {
      const m = ENTRY.exec(raw);
      if (!m) { lastReason = 'malformed signature-input entry (must cover exactly "@authority";req)'; continue; }
      const label = m[1]!;
      const params = new Map<string, string>();
      for (const p of m[2]!.split(';').slice(1)) {
        const eq = p.indexOf('=');
        const k = p.slice(0, eq);
        if (params.has(k)) { params.set('__dup', '1'); }
        params.set(k, p.slice(eq + 1));
      }
      if (params.has('__dup')) { lastReason = 'duplicate signature parameter'; continue; }
      const str = (k: string): string | undefined => { const v = params.get(k); return v !== undefined && v.startsWith('"') ? v.slice(1, -1) : undefined; };
      const num = (k: string): number | undefined => { const v = params.get(k); return v !== undefined && /^[0-9]+$/.test(v) ? Number(v) : undefined; };
      if (str('tag') !== DIRECTORY_SIGNATURE_TAG) { lastReason = 'wrong tag'; continue; }
      const alg = params.get('alg');
      if (alg !== undefined && alg !== '"ed25519"') { lastReason = 'unsupported alg'; continue; }
      const created = num('created');
      const expires = num('expires');
      if (created === undefined || expires === undefined) { lastReason = 'created and expires are required'; continue; }
      if (created > now + skew) { lastReason = 'signature created-time is in the future'; continue; }
      if (now > expires + skew) { lastReason = 'signature has expired'; continue; }
      if (expires - created > maxLife) { lastReason = 'signature lifetime exceeds maxLifetimeSec'; continue; }
      const keyid = str('keyid');
      if (keyid === undefined) { lastReason = 'missing keyid'; continue; }
      const key = dir.keys.find((j) => thumbprintOfX(j.x) === keyid);
      if (!key) { lastReason = 'keyid is not the thumbprint of any directory key'; continue; }
      if ((typeof key.nbf === 'number' && now + skew < key.nbf) || (typeof key.exp === 'number' && now - skew > key.exp)) { lastReason = 'directory key is outside its validity window'; continue; }
      const sig = sigs.get(label);
      if (!sig || sig.length !== 64) { lastReason = 'no valid signature bytes for the label'; continue; }
      const base = `"@authority";req: ${input.authority}\n"@signature-params": ${raw.slice(label.length + 1)}`;
      const pub = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' });
      if (!nodeVerify(null, Buffer.from(base), pub, sig)) { lastReason = 'signature does not verify'; continue; }
      good.set(key.kid, key);
    }
    if (good.size === 0) return fail(lastReason);
    return { valid: true, keys: [...good.values()] };
  } catch (e) {
    return fail(`verification failed (fail closed): ${(e as Error).message}`);
  }
}
