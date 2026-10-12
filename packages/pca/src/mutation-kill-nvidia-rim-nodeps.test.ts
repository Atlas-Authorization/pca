/** The RIM verifier degrades to a clear refusal when its optional XML dependencies are not installed. */
import { describe, expect, it, vi } from 'vitest';

vi.mock('xml-crypto', () => {
  throw new Error('xml-crypto is not installed');
});

import { verifyNvidiaRim } from './attest-nvidia-rim';

describe('verifyNvidiaRim without xml-crypto', () => {
  it('fails closed with the install hint', async () => {
    const r = await verifyNvidiaRim('<SoftwareIdentity/>', { rimRootSpkiSha256: ['00'.repeat(32)], nowMs: 1 });
    expect(r).toEqual({ ok: false, reason: 'RIM verification needs the optional dependencies xml-crypto and @xmldom/xmldom (not installed)' });
  });
});
