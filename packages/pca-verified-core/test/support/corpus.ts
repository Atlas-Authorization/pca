import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { join } from 'node:path';

const CONF = join(__dirname, '..', '..', '..', 'pca', 'conformance');

export interface CorpusVector {
  name: string;
  grant: any;
  context: { now: number; aud: string };
  pcactn?: any;
  pcactn_json?: string;
  expect: { allow: boolean; checks: Record<string, boolean> };
}

export function loadCorpus(): { core: CorpusVector[]; adversarial: CorpusVector[] } {
  const core = JSON.parse(readFileSync(join(CONF, 'vectors.json'), 'utf8')) as { vectors: CorpusVector[] };
  const adv = JSON.parse(gunzipSync(readFileSync(join(CONF, 'vectors-adversarial.json.gz'))).toString('utf8')) as { vectors: CorpusVector[] };
  return { core: core.vectors, adversarial: adv.vectors };
}

/** Deterministic PRNG over a fast-check supplied entropy stream (so failures shrink + replay by seed). */
export class Rng {
  private i = 0;
  constructor(private readonly pool: readonly number[]) {}
  next(n: number): number {
    const v = this.pool.length === 0 ? 0 : this.pool[this.i++ % this.pool.length]!;
    return n <= 0 ? 0 : Math.abs(v) % n;
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.next(xs.length)]!;
  }
  bool(): boolean {
    return this.next(2) === 1;
  }
}

/**
 * Production's pre-walk caveat cap (capability.ts `caveatLimitExceeded`: > 256 caveats on one hop or > 1024 over the chain). The frozen
 * legacy copies predate it, so vectors over the cap are compared against the expected REJECT instead of against legacy.
 */
export const CAVEAT_CAP_PER_HOP = 256;
export const CAVEAT_CAP_PER_CHAIN = 1024;
export function overCaveatCap(chain: unknown): boolean {
  if (!Array.isArray(chain) || chain.length === 0 || chain.length > 16) return false; // empty / too long are rejected before the cap
  let total = 0;
  for (const c of chain) {
    const cv = c !== null && typeof c === 'object' ? (c as { caveats?: unknown }).caveats : undefined;
    const n = Array.isArray(cv) ? cv.length : 0;
    if (n > CAVEAT_CAP_PER_HOP) return true;
    total += n;
  }
  return total > CAVEAT_CAP_PER_CHAIN;
}
/**
 * Intent Layer v2 (rules 13-19: `intent_session`, the v2 / committed-map goal, schema, accumulators, layers, W-B) postdates the
 * frozen legacy copies: production opens the v2 goal commitment (the legacy reads it as an M2 goal and fails `intent`) and then
 * runs the v2 checks, which fail closed without the verifier's v2 state (`opts.intentV2`, never passed by these loops: the
 * first is "schema: this verifier has no action schema configured"). So a PCActn carrying `intent_session` is out of the
 * legacy oracle's scope and is compared against the expected REJECT instead (like the caveat cap).
 */
export function carriesIntentSession(p: unknown): boolean {
  return p !== null && typeof p === 'object' && !Array.isArray(p) && Object.prototype.hasOwnProperty.call(p, 'intent_session');
}
/** The cap_chain of a vector (decoded object or raw JSON text), or undefined. */
export function vectorChain(p: unknown, raw?: string): unknown {
  if (p && typeof p === 'object') return (p as { cap_chain?: unknown }).cap_chain;
  if (typeof raw === 'string') {
    try {
      return (JSON.parse(raw) as { cap_chain?: unknown })?.cap_chain;
    } catch {
      return undefined;
    }
  }
  return undefined;
}
