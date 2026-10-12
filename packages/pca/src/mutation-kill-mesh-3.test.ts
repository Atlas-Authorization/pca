/**
 * Mutation-kill tests for mesh.ts (part 3): residual guards found by the first mutation run.
 */
import { describe, expect, it } from 'vitest';
import { type Capability, type Caveat, delegate, mintRoot } from './capability';
import { generateKeyPair, encodeKey, publicKeyOf } from './keys';
import {
  assembleMeshProof,
  checkHeadAdvance,
  type MeshAction,
  MeshDomain,
  MeshWitness,
  translateCapability,
  verifyCrossReference,
  verifyMeshProof,
  verifyTranslatedCapability,
  type MeshTrust,
} from './mesh';

const kp = () => generateKeyPair();
const pubOf = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const NOW = 1_800_000_000_000;

function scenario(rootCaveats: Caveat[], steps: Caveat[][] = []) {
  const human = kp();
  const holders = [kp(), ...steps.map(() => kp())];
  const D = new MeshDomain('D', kp().secretKey);
  const ws = [new MeshWitness(kp().secretKey), new MeshWitness(kp().secretKey)];
  const chain: Capability[] = [mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(holders[0]!.secretKey), caveats: rootCaveats })];
  steps.forEach((cv, i) => chain.push(delegate(chain[i]!, pubOf(holders[i + 1]!.secretKey), cv, holders[i]!.secretKey)));
  for (const c of chain) D.record(c);
  const head = D.publishHead(ws, NOW - 1000);
  const hops = chain.map((c, i) => D.evidence(c, head, i === 0 ? undefined : D.enroll(c.issuer, 'r')));
  const action: MeshAction = { type: 't', resource: '/r/1', amount: 5, service_domain: D.id, nonce: 'n', at: NOW };
  const proof = assembleMeshProof({ chain, hops, action, leafSecret: holders[holders.length - 1]!.secretKey });
  const trust: MeshTrust = { humanPrincipal: pubOf(human.secretKey), witnesses: ws.map((w) => w.id), threshold: 2, now: NOW, allowedDomains: [D.id], rootDomain: D.id };
  return { proof, trust, D };
}

describe('mesh residuals', () => {
  it('inclusion.size must equal the head size even when the path shape would still fold to the root', () => {
    // 3-entry log: leaf 0 has path shape [R, R]; so does leaf 0 of a 4-entry log - only the explicit size check tells them apart
    const s = scenario([], [[], []]);
    const p = JSON.parse(JSON.stringify(s.proof));
    expect(verifyMeshProof(p, s.trust).ok).toBe(true);
    expect(p.hops[0].inclusion.size).toBe(3);
    p.hops[0].inclusion.size = 4;
    const r = verifyMeshProof(p, s.trust);
    expect({ ok: r.ok, reason: r.reason, hop: r.hop }).toEqual({ ok: false, reason: 'hop not included in the issuing domain log', hop: 0 });
  });
  it('maxChainLength of exactly 1 is a legal configuration', () => {
    const s = scenario([]);
    expect(verifyMeshProof(s.proof, { ...s.trust, maxChainLength: 1 }).ok).toBe(true);
    const two = scenario([], [[]]);
    expect(verifyMeshProof(two.proof, { ...two.trust, maxChainLength: 1 }).reason).toBe('chain length out of bounds');
  });
  it('allowedDomains: EVERY entry must be a string, not just one', () => {
    const s = scenario([]);
    const r = verifyMeshProof(s.proof, { ...s.trust, allowedDomains: [s.D.id, 5 as never] });
    expect(r.reason).toBe('invalid trust configuration: allowedDomains is required');
    expect(verifyMeshProof(s.proof, { ...s.trust, allowedDomains: [5 as never, s.D.id] }).reason).toBe('invalid trust configuration: allowedDomains is required');
  });
  it('the witness revocation-list cap is inclusive of exactly 1,000,000 ids', () => {
    const dk = kp();
    const d = new MeshDomain('x', dk.secretKey);
    const w = new MeshWitness(kp().secretKey);
    const ch = d.publishHead([], 1);
    // exactly at the cap the shape check passes (the hole-filled list then fails inside the revocation set, with ITS message)
    expect(() => w.cosign({ head: ch, rev_ids: new Array(1_000_000) as never })).toThrow('revoke: id must be a string');
    expect(() => w.cosign({ head: ch, rev_ids: new Array(1_000_001) as never })).toThrow('witness: malformed revocation list');
  });
  it('hostile objects whose property access throws are verdicts, not exceptions', () => {
    const boom = (): never => {
      throw new Error('boom');
    };
    const head = { domain: 'd', size: 1, root: 'r', rev_root: 'x', rev_size: 0, timestamp: 1 };
    expect(checkHeadAdvance({ get domain() { return boom(); } } as never, head)).toBe('malformed head');
    expect(checkHeadAdvance(head, { ...head, get size() { return boom(); } } as never)).toBe('malformed head');
    expect(verifyCrossReference({ action_digest: 'a', fromGuardian: 'f', toGuardian: 't', nonce: 'n', get at() { return boom(); } } as never, {} as never)).toEqual({ ok: false, reason: 'malformed cross-reference' });
    const human = kp();
    const r = mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(human.secretKey), caveats: [] });
    const tc = translateCapability([r], { fromGuardian: 'a', toGuardian: 'b', bridgeSecret: kp().secretKey, issued_at: 1 });
    expect(verifyTranslatedCapability({ ...tc, get sig() { return boom(); } } as never)).toEqual({ ok: false, reason: 'malformed translated capability' });
  });
});
