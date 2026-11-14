import { describe, expect, it } from 'vitest';
import { canonicalBytesStrict, encodeKey, encodeSig, generateKeyPair, sign } from '@atlasauth/pca';
import {
  RUNTIME_CLAIM_DOMAIN,
  confineArgs,
  evidenceDigest,
  landlockRuleset,
  passportDigest,
  policyFromNeeds,
  satisfiesRuntimeClass,
  trustFromAttestation,
  verifiedRuntimeClass,
  type ClaimTrust,
} from './index';

const kp = generateKeyPair();
const PD = passportDigest({ agent: 'a1' });
const trust = (over: Partial<ClaimTrust> = {}): ClaimTrust => ({ pinnedAttestors: [encodeKey(kp.publicKey)], passportDigest: PD, verifiedEvidenceDigests: ['ev1'], now: 1, ...over });
/** A claim signed over exactly the members given (so only the verifier's own checks can refuse it). */
function forge(over: Record<string, unknown> = {}): Record<string, unknown> {
  const unsigned = { v: 1, class: 'wasi_no_ambient', passport_digest: PD, evidence_digest: 'ev1', iat: 0, exp: 10, attestor: encodeKey(kp.publicKey), ...over };
  const d = new TextEncoder().encode(RUNTIME_CLAIM_DOMAIN);
  return { ...unsigned, sig: encodeSig(sign(kp.secretKey, Uint8Array.from([...d, ...canonicalBytesStrict(unsigned)]))) };
}

describe('verifiedRuntimeClass with validly signed but defective claims', () => {
  it('the control claim proves its class', () => {
    expect(verifiedRuntimeClass(forge(), trust())).toBe('wasi_no_ambient');
  });
  it('a member beyond the eight, a wrong version and an unknown class are each refused on their own', () => {
    expect(verifiedRuntimeClass(forge({ extra: 1 }), trust())).toBe('none');
    expect(verifiedRuntimeClass(forge({ v: 2 }), trust())).toBe('none');
    expect(verifiedRuntimeClass(forge({ class: 'root' }), trust())).toBe('none');
  });
  it('zero is a valid issue or expiry time; only the validity window decides', () => {
    expect(verifiedRuntimeClass(forge({ iat: 0, exp: 5 }), trust({ now: 1 }))).toBe('wasi_no_ambient');
    expect(verifiedRuntimeClass(forge({ iat: -5, exp: 0 }), trust({ now: -1 }))).toBe('wasi_no_ambient');
    expect(verifiedRuntimeClass(forge(), trust({ now: 0 }))).toBe('wasi_no_ambient');
    expect(verifiedRuntimeClass(forge(), trust({ now: 9 }))).toBe('wasi_no_ambient');
    expect(verifiedRuntimeClass(forge(), trust({ now: 10 }))).toBe('none');
    expect(verifiedRuntimeClass(forge(), trust({ now: -1 }))).toBe('none');
    expect(verifiedRuntimeClass(forge(), trust({ now: 1.5 }))).toBe('none');
  });
  it('an unusable trust object is none, not an exception or undefined', () => {
    expect(verifiedRuntimeClass(forge(), undefined as never)).toBe('none');
    expect(verifiedRuntimeClass(forge(), null as never)).toBe('none');
    expect(verifiedRuntimeClass(null, trust())).toBe('none');
  });
});

describe('trustFromAttestation', () => {
  const document = { kind: 'x', data: 1 } as never;
  const common = { document, ctx: { c: 1 } as never, expected: { e: 1 } as never, nowMs: 5, pinnedAttestors: ['p'], passportDigest: 'pd' };
  it('hands the verifier exactly the document, context, clock and expected binding, and trusts the digest only when ok and bound', async () => {
    const seen: unknown[] = [];
    const verifier = { verify: async (a: unknown) => (seen.push(a), { ok: true, bound: true }) } as never;
    const t = await trustFromAttestation({ ...common, verifier });
    expect(seen).toEqual([{ document, ctx: common.ctx, nowMs: 5, expected: common.expected }]);
    expect(t).toEqual({ pinnedAttestors: ['p'], passportDigest: 'pd', verifiedEvidenceDigests: [evidenceDigest(document)], now: 5 });
    for (const answer of [{ ok: true, bound: false }, { ok: false, bound: true }, undefined, null, {}]) {
      const r = await trustFromAttestation({ ...common, verifier: { verify: async () => answer } as never });
      expect(r.verifiedEvidenceDigests).toEqual([]);
    }
    const thrown = await trustFromAttestation({ ...common, verifier: { verify: async () => { throw new Error('x'); } } as never });
    expect(thrown.verifiedEvidenceDigests).toEqual([]);
  });
});

describe('runtime class ordering', () => {
  it('an unknown name never satisfies, even against another unknown name', () => {
    expect(satisfiesRuntimeClass('bogus', 'bogus')).toBe(false);
    expect(satisfiesRuntimeClass('bogus', 'none')).toBe(false);
    expect(satisfiesRuntimeClass('none', 'bogus')).toBe(false);
    expect(satisfiesRuntimeClass('os_confined', 'none')).toBe(true);
    expect(satisfiesRuntimeClass('none', 'os_confined')).toBe(false);
  });
});

describe('policyFromNeeds bounds', () => {
  it('needs may carry only files or only network', () => {
    expect(policyFromNeeds([{ net: [{ host: 'a.example', port: 80 }] }], 9)).toMatchObject({ fs: { read: [], write: [], exec: [] }, net: { hosts: ['a.example:80'] } });
    expect(policyFromNeeds([{ fs: [{ path: '/a', mode: 'r' }] }])).toMatchObject({ fs: { read: ['/a'] }, net: { hosts: [] } });
    expect(policyFromNeeds([{}])).toMatchObject({ fs: { read: [] }, net: { proxy: null, hosts: [] } });
  });
  it('ports 1 and 65535 are valid, 0 and 65536 are not', () => {
    const net = (port: number) => [{ net: [{ host: 'a.example', port }] }];
    for (const port of [1, 65535]) expect(policyFromNeeds(net(port), 9).net.hosts).toEqual([`a.example:${port}`]);
    for (const port of [0, 65536]) expect(() => policyFromNeeds(net(port), 9)).toThrow('bad_net_need');
    for (const proxy of [1, 65535]) expect(policyFromNeeds([], proxy).net.proxy).toEqual({ host: '127.0.0.1', port: proxy });
    for (const proxy of [0, 65536]) expect(() => policyFromNeeds([], proxy)).toThrow('bad_proxy_port');
  });
  it('a bad path is reported truncated to 80 characters of its JSON form', () => {
    const long = `/${'a'.repeat(200)}"`;
    let msg = '';
    try {
      policyFromNeeds([{ fs: [{ path: long, mode: 'r' }] }]);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toBe(`bad_path: ${JSON.stringify(long).slice(0, 80)}`);
    expect(msg).toHaveLength('bad_path: '.length + 80);
  });
});

describe('confineArgs', () => {
  it('a proxy with no listed hosts still handles network access, joined with commas', () => {
    const policy = policyFromNeeds([], 9);
    const ll = landlockRuleset(policy);
    expect(ll.rules.net).toEqual([expect.anything()]);
    const args = confineArgs(policy);
    const i = args.indexOf('--net-handled');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe(ll.handled_access_net.map((n) => n.replace(/^LANDLOCK_ACCESS_/, '')).join(','));
    expect(ll.handled_access_net.length).toBeGreaterThan(1);
    expect(args[i + 1]).toContain(',');
    expect(args[i + 1]).not.toContain('LANDLOCK_ACCESS_');
    const fsIdx = args.indexOf('--fs-handled');
    expect(args[fsIdx + 1]).not.toContain('LANDLOCK_ACCESS_');
  });
  it('no proxy and no hosts means no network flag', () => {
    expect(confineArgs(policyFromNeeds([{ fs: [{ path: '/a', mode: 'r' }] }])).includes('--net-handled')).toBe(false);
  });
});
