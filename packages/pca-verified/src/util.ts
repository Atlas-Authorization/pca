import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export const sha256hex = (b: string | Uint8Array): string => createHash('sha256').update(b).digest('hex');

export const isObj = (v: unknown): v is Record<string, Json> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Deterministic JSON: object keys sorted, no whitespace. Throws on values JSON cannot carry (NaN, Infinity, undefined, functions). */
export function canonicalJson(v: Json): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new TypeError('canonicalJson: non-finite number');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  if (isObj(v)) {
    return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
  }
  throw new TypeError('canonicalJson: unsupported value');
}

export const sameJson = (a: Json, b: Json): boolean => {
  try {
    return canonicalJson(a) === canonicalJson(b);
  } catch {
    return false;
  }
};

export const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
export const fromB64u = (s: string): Uint8Array => {
  // strict: the canonical unpadded alphabet only, so one byte string has exactly one spelling
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new TypeError('not base64url');
  const out = Buffer.from(s, 'base64url');
  if (out.toString('base64url') !== s) throw new TypeError('non-canonical base64url');
  return out;
};

let pkgVersion: string | undefined;
/** The version of this package (read at run time so tests and the built bin agree). */
export function runnerVersion(): string {
  if (pkgVersion === undefined) {
    const p = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as { version: string };
    pkgVersion = p.version;
  }
  return pkgVersion;
}
export const RUNNER_NAME = '@atlasauth/pca-verified';
