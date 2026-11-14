import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { normalizePqQuorumPool, pqQuorumRepresentative, verifyPqQuorum } from './frost-pq';

type Vectors = { message: string; pool: string[]; representative: string; cases: { name: string; block: unknown; pqT: number; expect: unknown }[] };
const V = JSON.parse(readFileSync(new URL('../testdata/pq-quorum-vectors.json', import.meta.url), 'utf8')) as Vectors;
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

describe('pq quorum vectors (v1 to v2 rejection)', () => {
  const message = unb64(V.message);
  const pool = normalizePqQuorumPool(V.pool);
  it('the committed representative is the domain-separated message', () => {
    expect(b64u(pqQuorumRepresentative(message))).toBe(V.representative);
  });
  it.each(V.cases.map((c) => [c.name, c] as const))('%s', (_n, c) => {
    expect(verifyPqQuorum(c.block, message, pool, c.pqT)).toEqual(c.expect);
  });
  it('exactly one case is accepted: the v2 block, and every pre-0.5 shape is refused', () => {
    expect(V.cases.filter((c) => (c.expect as { ok: boolean }).ok).map((c) => c.name)).toEqual(['v2 two-of-two accepted']);
  });
});
