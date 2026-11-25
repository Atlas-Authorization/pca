/**
 * The server's grant store: a directory of JSON files (default ./.grants, or GRANT_DIR).
 *
 * A grant is registered with the server OUT OF BAND, before the agent makes any call. In this quickstart the agent
 * process writes the file, because both run on your machine. In production this is your admin flow or a database
 * insert, over a channel the agent cannot write to. The server never trusts a grant that arrives inside a request.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Capability } from '@atlasauth/pca';

const GRANT_DIR = resolve(process.env['GRANT_DIR'] ?? '.grants');
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export interface GrantStore {
  get(grantRef: string): Capability | null;
  isRevoked(grantRef: string): boolean;
}

/** The principal registers a grant with the server. */
export function registerGrant(grant: Capability, dir: string = GRANT_DIR): void {
  if (!SAFE_ID.test(grant.id)) throw new Error('unsafe grant id');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${grant.id}.json`), JSON.stringify(grant), 'utf8');
}

/** The principal revokes a grant: every later call under it is refused. */
export function revokeGrant(grantId: string, dir: string = GRANT_DIR): void {
  if (!SAFE_ID.test(grantId)) throw new Error('unsafe grant id');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${grantId}.revoked`), '', 'utf8');
}

export function fileGrantStore(dir: string = GRANT_DIR): GrantStore {
  return {
    get(ref) {
      if (!SAFE_ID.test(ref)) return null; // never build a path from an unvalidated request value
      const file = join(dir, `${ref}.json`);
      return existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as Capability) : null;
    },
    isRevoked(ref) {
      return !SAFE_ID.test(ref) || existsSync(join(dir, `${ref}.revoked`));
    },
  };
}
