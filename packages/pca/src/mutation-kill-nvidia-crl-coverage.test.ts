/**
 * NVIDIA CRL coverage: by default every non-root chain certificate that names a CRL distribution point must be covered by a
 * verified CRL from its issuer. Before 0.5 any ONE fresh CRL (e.g. only the root's) satisfied the check, so a revoked device
 * certificate passed. Forged chain (leaf 0, 1, 2, 3, root 4): certificates 2 and 3 carry a CDP; 0 and 1 do not.
 */
import { X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { checkNvidiaChainRevocation, nvidiaCollateralHook } from './attest-nvidia-rim';
import { parsePemChain } from './attest-nvidia-spdm';
import { forgeNvidiaCrl, forgeNvidiaScenario } from './test-support/forge-spdm';

const sc = forgeNvidiaScenario({ seed: 'crl-coverage' });
const chain: X509Certificate[] = parsePemChain(sc.device.chainPem);
const NOW = sc.nowMs;
const crl = (issuerIdx: number, revoked: string[] = []) => forgeNvidiaCrl(sc.device, issuerIdx, { revoked });
const subj = (i: number) => chain[i]!.subject.replace(/\n/g, ', ');
const missing = (i: number) => ({ ok: false, reason: `no verified CRL from the issuer of chain certificate '${subj(i)}'` });
const CDP = Buffer.from('0603551d1f', 'hex');

describe('NVIDIA CRL coverage (requireCrlFor)', () => {
  it('fixture precondition: exactly certificates 2 and 3 name a CDP', () => {
    expect(chain.map((c) => c.raw.includes(CDP))).toEqual([false, false, true, true, false]);
  });
  it('1. the root CRL alone no longer satisfies the default: the CDP-bearing certificate it does not issue is uncovered', () => {
    expect(checkNvidiaChainRevocation(chain, [crl(4)], NOW)).toEqual(missing(2));
    expect(checkNvidiaChainRevocation(chain, [crl(4)], NOW, [], 'cdp')).toEqual(missing(2));
    // the issuer-3 CRL alone leaves certificate 3 (CDP, issued by the root) uncovered
    expect(checkNvidiaChainRevocation(chain, [crl(3)], NOW)).toEqual(missing(3));
  });
  it('2. a CRL from the issuer of every CDP-bearing certificate passes', () => {
    expect(checkNvidiaChainRevocation(chain, [crl(3), crl(4)], NOW)).toEqual({ ok: true, verifiedCrls: 2 });
  });
  it('3. a revoked certificate on its issuer\'s CRL still fails as revoked', () => {
    const r = checkNvidiaChainRevocation(chain, [crl(3, [chain[2]!.serialNumber]), crl(4)], NOW);
    expect(r).toEqual({ ok: false, reason: `chain certificate '${subj(2)}' is revoked` });
  });
  it('4. "all" also demands a CRL for certificates without a CDP; "cdp" does not', () => {
    expect(checkNvidiaChainRevocation(chain, [crl(3), crl(4)], NOW, [], 'cdp').ok).toBe(true);
    expect(checkNvidiaChainRevocation(chain, [crl(3), crl(4)], NOW, [], 'all')).toEqual(missing(0));
    expect(checkNvidiaChainRevocation(chain, [crl(1), crl(2), crl(3), crl(4)], NOW, [], 'all')).toEqual({ ok: true, verifiedCrls: 4 });
  });
  it('an explicit index list demands exactly those certificates', () => {
    expect(checkNvidiaChainRevocation(chain, [crl(3)], NOW, [], [2])).toEqual({ ok: true, verifiedCrls: 1 });
    expect(checkNvidiaChainRevocation(chain, [crl(3)], NOW, [], [1])).toEqual(missing(1));
    expect(checkNvidiaChainRevocation(chain, [crl(3)], NOW, [], [])).toEqual({ ok: true, verifiedCrls: 1 });
  });
  it('5. an index that is not a non-root chain certificate fails with its number', () => {
    for (const bad of [4, 5, -1, 1.5]) {
      expect(checkNvidiaChainRevocation(chain, [crl(3), crl(4)], NOW, [], [bad])).toEqual({ ok: false, reason: `requireCrlFor index ${bad} is not a non-root chain certificate` });
    }
  });
  it('"none" demands no coverage but still enforces what was supplied', () => {
    expect(checkNvidiaChainRevocation(chain, [crl(4)], NOW, [], 'none')).toEqual({ ok: true, verifiedCrls: 1 });
    expect(checkNvidiaChainRevocation(chain, [crl(3, [chain[2]!.serialNumber])], NOW, [], 'none').ok).toBe(false);
  });
  it('a chain with no CDP anywhere demands nothing beyond the supplied CRLs', () => {
    const one = [chain[0]!, chain[4]!];
    expect(checkNvidiaChainRevocation(one, [crl(4)], NOW)).toEqual({ ok: true, verifiedCrls: 1 });
  });
});

describe('NVIDIA CRL coverage through nvidiaCollateralHook', () => {
  it('rejects a malformed requireCrlFor at construction', () => {
    const mk = (requireCrlFor: unknown) => () => nvidiaCollateralHook({ rimRootSpkiSha256: ['aa'], resolve: () => undefined, requireCrlFor } as never);
    for (const bad of ['everything', 3, [1.5], [-1], ['0']]) expect(mk(bad), String(bad)).toThrow(/malformed requireCrlFor/);
    for (const ok of [undefined, 'cdp', 'all', [0, 1]]) expect(mk(ok), String(ok)).not.toThrow();
  });
});
