/**
 * A tiny file-backed grant store for the demo, in GRANT_DIR (default ./.grants):
 *   <grant id>.json         the grant the principal registered
 *   <grant id>.plans.json   the plan roots the principal authorized for it
 *   <grant id>.revoked      present once the principal revoked the grant
 *
 * In this demo the "principal registers a grant / authorizes a plan with the server out-of-band" step is
 * `src/client.ts` writing the files. In production that step is your admin flow or database insert; the
 * point is that it reaches the server by a channel the ATTACKER cannot write to, never inside the request.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Capability } from '@atlasauth/pca';
import type { GrantStore } from './guard.js';

export const GRANT_DIR = resolve(process.env['GRANT_DIR'] ?? '.grants');
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export function registerGrant(grant: Capability, dir: string = GRANT_DIR): void {
  if (!SAFE_ID.test(grant.id)) throw new Error('unsafe grant id');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${grant.id}.json`), JSON.stringify(grant), 'utf8');
}

function readPlans(dir: string, grantId: string): string[] {
  const file = join(dir, `${grantId}.plans.json`);
  return existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as string[]) : [];
}

/** The principal authorizes one plan root (the Merkle root of the plan its agent will act under). */
export function authorizePlan(grantId: string, planRoot: string, dir: string = GRANT_DIR): void {
  if (!SAFE_ID.test(grantId)) throw new Error('unsafe grant id');
  mkdirSync(dir, { recursive: true });
  const plans = readPlans(dir, grantId);
  if (!plans.includes(planRoot)) plans.push(planRoot);
  writeFileSync(join(dir, `${grantId}.plans.json`), JSON.stringify(plans), 'utf8');
}

/** The principal revokes a grant: every later action under it is denied. */
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
    isPlanAuthorized(ref, planRoot) {
      return SAFE_ID.test(ref) && readPlans(dir, ref).includes(planRoot);
    },
    isRevoked(ref) {
      return !SAFE_ID.test(ref) || existsSync(join(dir, `${ref}.revoked`));
    },
  };
}
