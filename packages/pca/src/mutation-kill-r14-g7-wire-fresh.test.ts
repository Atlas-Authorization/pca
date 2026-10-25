/**
 * r14 static-mutant kills for wire.ts (fresh module): KNOWN (every real field is accepted), the type-test helpers
 * (isObj / isStr / isInt / isNum / u8len: a real PCActn validates and each type error is reported), and every member of
 * HOP_KEYS (a hop carrying each optional key in a valid shape is accepted).
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { agent } from './facade';
import { generateKeyPair } from './keys';

const bytes = (n: number, l: string) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 32) out.set(sha256(utf8(`${l}/${i}`)).subarray(0, Math.min(32, n - i)), i);
  return b64u(out);
};
const principal = generateKeyPair();
const a = agent({ principal, goal: 'g', permissions: { stripe: ['refund'] }, aud: 'rs.example', now: 1_800_000_000_000 });
const sub = a.subAgent();
const P = JSON.parse(JSON.stringify(sub.act('stripe.refund', 'ch_1', { amount: 5 }).pcactn)) as Record<string, unknown> & { cap_chain: Record<string, unknown>[] };

async function fresh() {
  vi.resetModules();
  return import('./wire');
}

describe('wire.ts statics (fresh module)', () => {
  it('a real two-hop PCActn validates', async () => {
    const m = await fresh();
    expect(P.cap_chain.length).toBe(2);
    expect(P.cap_chain[1]!.parent).toBeTypeOf('string');
    expect(m.validateWireV2(P)).toBeNull();
  });
  it('each type check reports its own reason', async () => {
    const m = await fresh();
    expect([
      m.validateWireV2({ ...P, ver: 1.5 }),
      m.validateWireV2({ ...P, aud: 7 }),
      m.validateWireV2({ ...P, aud: 'é'.repeat(129) }),
      m.validateWireV2({ ...P, aud: 'a'.repeat(256) }),
      m.validateWireV2({ ...P, provenance: { ...(P.provenance as object), taint_level: '1' } }),
      m.validateWireV2({ ...P, action: [] }),
    ]).toEqual([
      "'ver' must be a safe integer",
      "'aud' must be a non-empty string (<= 256 UTF-8 bytes)",
      "'aud' must be a non-empty string (<= 256 UTF-8 bytes)",
      null,
      "'provenance' is malformed",
      "'action' must be an object",
    ]);
  });
  it('a hop may carry holder_pq and the hybrid suite fields', async () => {
    const m = await fresh();
    const hop = { ...P.cap_chain[0]!, holder_pq: bytes(32, 'hpq'), alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: bytes(1952, 'pk'), pq_sig: bytes(3309, 'sig') };
    expect(m.validateWireV2({ ...P, cap_chain: [hop, P.cap_chain[1]] })).toBeNull();
    expect(m.validateWireV2({ ...P, cap_chain: [{ ...P.cap_chain[0], extra: 1 }, P.cap_chain[1]] })).toBe("unknown field 'cap_chain[0].extra'");
  });
});
