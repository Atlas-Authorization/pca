/**
 * Cross-verification of the native producers' post-quantum output (conformance/producer-native/<lang>.json, written by each
 * native SDK's producer tests in its own CI run with PCA_PRODUCER_OUT set). ML-DSA / SLH-DSA signatures are randomised, so they
 * cannot be byte vectors like producer-vectors.json: instead the reference verifier must accept every PCActn a native SDK signed,
 * and must refuse it once a byte of the post-quantum signature changes (so the PQ half is really checked, not skipped).
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyPCActnCore } from './pcactn-full';
import type { Capability } from './capability';
import type { PCActn } from './pcactn';

const DIR = join(__dirname, '..', 'conformance', 'producer-native');
type Doc = { lang: string; aud: string; now: number; cases: Array<{ alg: string; grant: Capability; pcactn: PCActn & { alg?: string; pq_sig?: string } }> };
const docs: Doc[] = readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(DIR, f), 'utf8')) as Doc);

const flip = (s: string): string => (s[10] === 'A' ? s.slice(0, 10) + 'B' + s.slice(11) : s.slice(0, 10) + 'A' + s.slice(11));

describe('native producers: post-quantum PCActns verify under the reference', () => {
  it('every native signing SDK contributed its file', () => {
    expect(docs.map((d) => d.lang).sort()).toEqual(['dotnet', 'java', 'kotlin', 'swift']);
    for (const d of docs) expect(d.cases.length, d.lang).toBeGreaterThan(0);
  });

  for (const d of docs) {
    for (const c of d.cases) {
      it(`${d.lang}: ${c.alg}`, async () => {
        expect(c.pcactn.alg ?? 'ed25519').not.toBe('ed25519');
        const opts = { grant: c.grant, nowEpoch: d.now, audience: d.aud, insecureSkipPlanRootCheck: true } as const;
        const ok = await verifyPCActnCore(c.pcactn, opts);
        expect(ok.allow, JSON.stringify(ok.checks)).toBe(true);
        const sigField = c.pcactn.pq_sig !== undefined ? 'pq_sig' : 'sig';
        const tampered = { ...c.pcactn, [sigField]: flip(c.pcactn[sigField]!) } as PCActn;
        expect((await verifyPCActnCore(tampered, opts)).allow).toBe(false);
      });
    }
  }
});
