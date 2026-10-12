/**
 * Mutation-kill tests for threshold.ts (security-relevant branches).
 *
 * Written from a Stryker survivor report: every assertion here pins a behaviour that a plausible
 * single-token regression (dropped guard, flipped operator, weakened tie-break, emptied reason) would
 * otherwise change without any existing test noticing. Exact `reason` strings are asserted because the
 * reason is the only observable that distinguishes WHICH fail-closed guard fired.
 */
import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { mintGrant } from './envelope';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair, publicKeyOf, sign } from './keys';
import { PCACTN_VERSION, thresholdMessage, type PCActn, type VerifyContext } from './pcactn';
import { mlDsa65Keygen, type SigAlg } from './pq';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  assembleThreshold,
  createThresholdVerifier,
  shareMessage,
  signPreparedShare,
  signShare,
  signerSetHash,
  verifyThreshold,
  type Signer,
} from './threshold';

const MSG = utf8('mutation-kill-message');
const enc = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const cat = (...p: Uint8Array[]) => {
  const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let i = 0;
  for (const x of p) {
    o.set(x, i);
    i += x.length;
  }
  return o;
};
const trio = () => {
  const agent = generateKeyPair();
  const guardian = generateKeyPair();
  const principal = generateKeyPair();
  const set: Signer[] = [
    { role: 'agent', publicKey: enc(agent) },
    { role: 'guardian', publicKey: enc(guardian) },
    { role: 'principal', publicKey: enc(principal) },
  ];
  return { agent, guardian, principal, set };
};

describe('signerSetHash: canonical, total, order-insensitive', () => {
  it('tie-breaks same-role entries by public key (list order never changes the hash)', () => {
    const a = enc(generateKeyPair());
    const b = enc(generateKeyPair());
    const s1: Signer[] = [{ role: 'guardian', publicKey: a }, { role: 'guardian', publicKey: b }];
    const s2: Signer[] = [{ role: 'guardian', publicKey: b }, { role: 'guardian', publicKey: a }];
    expect(Buffer.from(signerSetHash(s1)).toString('hex')).toBe(Buffer.from(signerSetHash(s2)).toString('hex'));
  });

  it('binds the registered pq_pk, and distinct pq_pk values hash differently', () => {
    const k = enc(generateKeyPair());
    const base: Signer = { role: 'guardian', publicKey: k };
    const h0 = Buffer.from(signerSetHash([base])).toString('hex');
    const h1 = Buffer.from(signerSetHash([{ ...base, pq_pk: 'AAAA' }])).toString('hex');
    const h2 = Buffer.from(signerSetHash([{ ...base, pq_pk: 'BBBB' }])).toString('hex');
    expect(new Set([h0, h1, h2]).size).toBe(3);
    // a non-string pq_pk is NOT carried (byte-identical to the pre-agility set)
    expect(Buffer.from(signerSetHash([{ ...base, pq_pk: 5 as never }])).toString('hex')).toBe(h0);
  });

  it('is total: null members and non-array input never throw and hash as their stringified form', () => {
    const viaNull = Buffer.from(signerSetHash([null as never])).toString('hex');
    const viaStr = Buffer.from(signerSetHash([{ role: 'undefined' as never, publicKey: 'undefined' }])).toString('hex');
    expect(viaNull).toBe(viaStr);
    expect(Buffer.from(signerSetHash('nope' as never)).toString('hex')).toBe(Buffer.from(signerSetHash([])).toString('hex'));
  });

  it('is exactly sha256(domain || canonical rows) (known structure, not just self-consistent)', () => {
    const k = 'k'.repeat(43);
    const got = signerSetHash([{ role: 'agent', publicKey: k }]);
    const want = sha256(cat(utf8('atlas-pca/signerset/v1\0'), utf8(`[{"publicKey":"${k}","role":"agent"}]`)));
    expect(Buffer.from(got).toString('hex')).toBe(Buffer.from(want).toString('hex'));
  });
});

describe('shareMessage: exact signed bytes', () => {
  const { set } = trio();
  it('= "atlas-pca/share/<role>\\0" || sha256(msg) || signerSetHash || t', () => {
    const want = cat(utf8('atlas-pca/share/guardian\0'), sha256(MSG), signerSetHash(set), new Uint8Array([2]));
    expect(Buffer.from(shareMessage('guardian', MSG, set, 2)).toString('hex')).toBe(Buffer.from(want).toString('hex'));
  });

  it('ed25519, absent and UNKNOWN alg add no suite tag; non-default suites append the exact tag', () => {
    const plain = shareMessage('agent', MSG, set, 1);
    expect(shareMessage('agent', MSG, set, 1, 'ed25519')).toEqual(plain);
    expect(shareMessage('agent', MSG, set, 1, 'bogus' as SigAlg)).toEqual(plain);
    const tagged = shareMessage('agent', MSG, set, 1, 'hybrid-ed25519-ml-dsa-65');
    expect(Buffer.from(tagged.slice(plain.length)).toString('latin1')).toBe('\0atlas-pca/share-suite/v1\0hybrid-ed25519-ml-dsa-65');
    const tagged2 = shareMessage('agent', MSG, set, 1, 'ml-dsa-65');
    expect(Buffer.from(tagged2.slice(plain.length)).toString('latin1')).toBe('\0atlas-pca/share-suite/v1\0ml-dsa-65');
  });

  it('refuses every t outside {1,2,3} with a RangeError naming the rule', () => {
    for (const t of [0, 4, -1, 1.5, NaN, '1' as never, undefined as never]) {
      expect(() => shareMessage('agent', MSG, set, t as number)).toThrow(new RangeError('shareMessage: t must be 1, 2 or 3'));
    }
  });

  it('the role is part of the signed bytes (no cross-role replay)', () => {
    expect(shareMessage('agent', MSG, set, 2)).not.toEqual(shareMessage('guardian', MSG, set, 2));
    expect(shareMessage('agent', MSG, set, 2)).not.toEqual(shareMessage('agent', MSG, set, 3));
  });
});

describe('signShare / signPreparedShare / assembleThreshold', () => {
  it('an ed25519 share carries exactly {role, publicKey, sig}', () => {
    const { agent, set } = trio();
    const s = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    expect(Object.keys(s).sort()).toEqual(['publicKey', 'role', 'sig']);
    expect(s.publicKey).toBe(b64u(publicKeyOf(agent.secretKey)));
  });

  it('a bare share (no bind) is refused with a TypeError', () => {
    const { agent } = trio();
    expect(() => signShare('principal', agent.secretKey, MSG)).toThrow(new TypeError("signShare: a 'principal' share must bind {signerSet, t}"));
  });

  it('an unknown alg is refused with a RangeError that names the alg', () => {
    const { agent } = trio();
    expect(() => signPreparedShare('agent', agent.secretKey, MSG, { alg: 'rot13' as SigAlg })).toThrow(new RangeError("signPreparedShare: unknown signature alg 'rot13'"));
  });

  it('pure ml-dsa-65 shares carry no pq_sig field; hybrid shares carry both signatures', () => {
    const { agent } = trio();
    const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(9));
    const pure = signPreparedShare('agent', agent.secretKey, MSG, { alg: 'ml-dsa-65', mlDsa });
    expect('pq_sig' in pure).toBe(false);
    expect(pure.alg).toBe('ml-dsa-65');
    const hyb = signPreparedShare('agent', agent.secretKey, MSG, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa });
    expect(typeof hyb.pq_sig).toBe('string');
    expect(hyb.alg).toBe('hybrid-ed25519-ml-dsa-65');
  });

  it('assembleThreshold copies the shares and maps non-arrays to an empty bag', () => {
    const { agent, set } = trio();
    const sh = [signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 })];
    const bag = assembleThreshold(sh);
    expect(bag.shares).toEqual(sh);
    expect(bag.shares).not.toBe(sh);
    expect(assembleThreshold('x' as never)).toEqual({ shares: [] });
  });
});

describe('verifyThreshold: fail-closed guards report the guard that fired', () => {
  it('invalid t is named in the reason', () => {
    const { set } = trio();
    for (const t of [0, 4, 2.5, NaN]) {
      expect(verifyThreshold({ shares: [] }, MSG, set, t)).toEqual({ ok: false, count: 0, roles: [], reason: `invalid threshold t=${String(t)} (must be 1, 2 or 3)` });
    }
  });

  it('a malformed signer set (null member, unknown role, bad key) fails closed even with valid shares', () => {
    const { agent, set } = trio();
    const share = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    const bag = { shares: [share] };
    for (const bad of [
      [null as never],
      [{ role: 'root' as never, publicKey: enc(agent) }],
      [{ role: 'agent' as const, publicKey: 'not-a-key' }],
      [{ role: 'agent' as const, publicKey: 5 as never }],
    ]) {
      const v = verifyThreshold(bag, MSG, [...set, ...bad], 1);
      expect(v).toEqual({ ok: false, count: 0, roles: [], reason: 'malformed signer set' });
    }
  });

  it('a malformed registered pq_pk fails closed; a well-formed one is accepted', () => {
    const { agent } = trio();
    const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const good: Signer[] = [{ role: 'agent', publicKey: enc(agent), pq_pk: b64u(mlDsa.publicKey) }];
    const bad: Signer[] = [{ role: 'agent', publicKey: enc(agent), pq_pk: 'AAAA' }];
    expect(verifyThreshold({ shares: [] }, MSG, bad, 1)).toEqual({ ok: false, count: 0, roles: [], reason: 'malformed signer set (pq_pk)' });
    expect(verifyThreshold({ shares: [] }, MSG, good, 1).reason).toBe('only 0 distinct valid key(s), need 1');
  });

  it('two keys for one role, and one key under two roles, are refused', () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(verifyThreshold({ shares: [] }, MSG, [{ role: 'agent', publicKey: enc(a) }, { role: 'agent', publicKey: enc(b) }], 1).reason).toBe(
      'signer set registers more than one key for role agent',
    );
    expect(verifyThreshold({ shares: [] }, MSG, [{ role: 'agent', publicKey: enc(a) }, { role: 'guardian', publicKey: enc(a) }], 1).reason).toBe(
      'signer set registers one key under two roles',
    );
  });

  it('listing the very same (role, key) twice is harmless (not a conflict)', () => {
    const { agent } = trio();
    const set: Signer[] = [{ role: 'agent', publicKey: enc(agent) }, { role: 'agent', publicKey: enc(agent) }];
    const share = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    expect(verifyThreshold({ shares: [share] }, MSG, set, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });

  it('a passing verdict carries no reason; a failing one always does', () => {
    const { agent, set } = trio();
    const share = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    const ok = verifyThreshold({ shares: [share] }, MSG, set, 1);
    expect(Object.keys(ok).sort()).toEqual(['count', 'ok', 'roles']);
    const share2 = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 2 });
    const no = verifyThreshold({ shares: [share2] }, MSG, set, 2);
    expect(no.ok).toBe(false);
    expect(no.reason).toBe('only 1 distinct valid key(s), need 2');
  });

  it('malformed shares are skipped (not fatal) and the FIRST reason is kept', () => {
    const { agent, set } = trio();
    const good = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 });
    const junk = [null, 7, { role: 5, publicKey: 'x' }, { role: 'agent', publicKey: 9 }, { role: 'agent' }] as never[];
    expect(verifyThreshold({ shares: [...junk, good] }, MSG, set, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
    const v = verifyThreshold({ shares: junk }, MSG, set, 1);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('malformed share');
    expect(verifyThreshold(null as never, MSG, set, 1).reason).toBe('only 0 distinct valid key(s), need 1');
    expect(verifyThreshold({ shares: 'x' } as never, MSG, set, 1).reason).toBe('only 0 distinct valid key(s), need 1');
  });

  it('a role absent from the signer set, a key not registered for the role, an unknown alg and a bad signature each report their own reason', () => {
    const { agent, guardian, principal } = trio();
    const set: Signer[] = [{ role: 'agent', publicKey: enc(agent) }, { role: 'guardian', publicKey: enc(guardian) }];
    const pShare = signShare('principal', principal.secretKey, MSG, { signerSet: set, t: 3 });
    expect(verifyThreshold({ shares: [pShare] }, MSG, set, 1).reason).toBe('role principal is not in the signer set');

    const forged = { ...signShare('guardian', agent.secretKey, MSG, { signerSet: set, t: 1 }), role: 'guardian' as const };
    expect(verifyThreshold({ shares: [forged] }, MSG, set, 1).reason).toBe('share for role guardian uses a key not registered for that role');

    const gShare = signShare('guardian', guardian.secretKey, MSG, { signerSet: set, t: 1 });
    expect(verifyThreshold({ shares: [{ ...gShare, alg: 'bogus' as SigAlg }] }, MSG, set, 1).reason).toBe(
      'share for role guardian declares an unknown signature alg',
    );
    expect(verifyThreshold({ shares: [{ ...gShare, sig: 7 as never }] }, MSG, set, 1).reason).toBe('invalid signature for role guardian');
    const flipped = { ...gShare, sig: b64u(sign(guardian.secretKey, utf8('other'))) };
    expect(verifyThreshold({ shares: [flipped] }, MSG, set, 1).reason).toBe('invalid signature for role guardian');
  });

  it('the first failure reason wins, and a later valid share still counts', () => {
    const { agent, guardian, set } = trio();
    const bad = { ...signShare('guardian', guardian.secretKey, MSG, { signerSet: set, t: 2 }), sig: b64u(new Uint8Array(64)) };
    const good = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 2 });
    const v = verifyThreshold({ shares: [bad, good] }, MSG, set, 2);
    expect(v).toEqual({ ok: false, count: 1, roles: ['agent'], reason: 'invalid signature for role guardian' });
  });

  it('a duplicated share counts once', () => {
    const { agent, set } = trio();
    const s = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 2 });
    expect(verifyThreshold({ shares: [s, s, s] }, MSG, set, 2)).toMatchObject({ ok: false, count: 1, roles: ['agent'] });
  });

  it('a share minted for another signer set or threshold does not verify here', () => {
    const { agent, set } = trio();
    const other = [{ role: 'agent' as const, publicKey: enc(agent) }];
    expect(verifyThreshold({ shares: [signShare('agent', agent.secretKey, MSG, { signerSet: other, t: 1 })] }, MSG, set, 1).ok).toBe(false);
    expect(verifyThreshold({ shares: [signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 2 })] }, MSG, set, 1).ok).toBe(false);
  });

  it('a hybrid share verifies against the registered pq_pk and fails against a different one or a stripped suite', () => {
    const { agent } = trio();
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(1));
    const ml2 = mlDsa65Keygen(new Uint8Array(32).fill(2));
    const set: Signer[] = [{ role: 'agent', publicKey: enc(agent), pq_pk: b64u(ml.publicKey) }];
    const suite = { alg: 'hybrid-ed25519-ml-dsa-65' as const, mlDsa: ml };
    const share = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 1 }, suite);
    expect(verifyThreshold({ shares: [share] }, MSG, set, 1).ok).toBe(true);
    const swapped: Signer[] = [{ role: 'agent', publicKey: enc(agent), pq_pk: b64u(ml2.publicKey) }];
    expect(verifyThreshold({ shares: [share] }, MSG, swapped, 1).ok).toBe(false);
    const { alg: _a, pq_sig: _p, ...stripped } = share;
    expect(verifyThreshold({ shares: [stripped] }, MSG, set, 1).ok).toBe(false);
  });
});

describe('verifyThreshold: the agent-leaf baseline is admitted only for the registered agent key', () => {
  const baselineFor = (holderKp: { secretKey: Uint8Array; publicKey: Uint8Array }, msg = MSG) => ({
    holder: enc(holderKp),
    sig: b64u(sign(holderKp.secretKey, msg)),
  });

  it('admits a valid leaf signature by the registered agent and records the role "agent"', () => {
    const { agent, set } = trio();
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, baselineFor(agent))).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });

  it('rejects a baseline whose holder is not the registered agent key (even with a valid signature by that holder)', () => {
    const { guardian, set } = trio();
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, baselineFor(guardian)).ok).toBe(false);
    const stranger = generateKeyPair();
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, baselineFor(stranger)).ok).toBe(false);
  });

  it('rejects a baseline when the signer set registers no agent, and a non-string holder', () => {
    const { agent, guardian } = trio();
    const noAgent: Signer[] = [{ role: 'guardian', publicKey: enc(guardian) }];
    expect(verifyThreshold({ shares: [] }, MSG, noAgent, 1, baselineFor(agent)).ok).toBe(false);
    const withAgent: Signer[] = [{ role: 'agent', publicKey: enc(agent) }];
    expect(verifyThreshold({ shares: [] }, MSG, withAgent, 1, { holder: 5 as never, sig: b64u(sign(agent.secretKey, MSG)) }).ok).toBe(false);
  });

  it('rejects an invalid baseline signature and a baseline over a different message', () => {
    const { agent, set } = trio();
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, { holder: enc(agent), sig: b64u(new Uint8Array(64)) }).ok).toBe(false);
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, baselineFor(agent, utf8('other'))).ok).toBe(false);
  });

  it('does not double-count: an explicit agent share and the baseline are one key', () => {
    const { agent, set } = trio();
    const explicit = signShare('agent', agent.secretKey, MSG, { signerSet: set, t: 2 });
    const v = verifyThreshold({ shares: [explicit] }, MSG, set, 2, baselineFor(agent));
    expect(v).toMatchObject({ ok: false, count: 1, roles: ['agent'] });
  });

  it('the baseline cannot repair a malformed signer set', () => {
    const { agent, set } = trio();
    const v = verifyThreshold({ shares: [] }, MSG, [...set, { role: 'agent', publicKey: 'x' }], 1, baselineFor(agent));
    expect(v.reason).toBe('malformed signer set');
  });
});

describe('createThresholdVerifier: hook wiring', () => {
  const principal = generateKeyPair();
  const pPub = enc(principal);
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: pPub,
    goal: 'g',
    envelope: { predicates: [{ verb: 'v', resource: 'r' }], caveats: [], agent_binding: {} as never, risk_policy: DEFAULT_RISK_POLICY },
  });

  const mkP = (over: Partial<PCActn> = {}): PCActn =>
    ({
      ver: PCACTN_VERSION,
      action: { verb: 'v', resource: 'r', params_digest: 'd', reversibility_class: 'reversible' },
      grant_ref: grant.id,
      cap_chain: [grant],
      plan: { root: 'r', inclusion_proof: { index: 0, size: 1, path: [] }, node_id: 'n' },
      attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
      provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
      freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
      counter: 1,
      risk_claim: { r: 0, inputs: {} },
      aud: 'a',
      iat: 1,
      exp: 2,
      sig: '',
      ...over,
    }) as unknown as PCActn;
  const ctxOf = (p: PCActn, g = grant): VerifyContext => ({ pcactn: p, grant: g, nowEpoch: 1 });
  const signed = (over: Partial<PCActn> = {}): PCActn => {
    const p = mkP(over);
    for (const k of Object.keys(p)) if ((p as never)[k] === undefined) delete (p as never)[k];
    return { ...p, sig: b64u(sign(principal.secretKey, thresholdMessage(p))) } as PCActn;
  };
  const set: Signer[] = [{ role: 'agent', publicKey: pPub }];
  const tv = (o: Parameters<typeof createThresholdVerifier>[0]) => (c: VerifyContext) =>
    createThresholdVerifier(o)(c) as { enforced: boolean; ok?: boolean; reason?: string };

  it('a leaf-signed t=1 action passes with the baseline alone', () => {
    expect(tv({ signerSet: set, t: 1 })(ctxOf(signed()))).toEqual({ enforced: true, ok: true, t: 1 });
  });

  it('failure surfaces the concrete verifyThreshold reason, not a generic one', () => {
    const r = tv({ signerSet: set, t: 2 })(ctxOf(signed()));
    expect(r).toEqual({ enforced: true, ok: false, reason: 'only 1 distinct valid key(s), need 2', t: 2 });
  });

  it('no baseline is formed when the leaf holder / chain / sig is unusable', () => {
    const v = tv({ signerSet: set, t: 1 });
    const good = signed();
    expect(v(ctxOf({ ...good, sig: undefined as never })).ok).toBe(false);
    expect(v(ctxOf({ ...good, cap_chain: [] as never })).ok).toBe(false);
    expect(v(ctxOf({ ...good, cap_chain: 'x' as never })).ok).toBe(false);
    expect(v(ctxOf({ ...good, cap_chain: [{ ...grant, holder: 5 } as never] })).ok).toBe(false);
  });

  it('explicit shares in pcactn.threshold are verified; a non-array shares field is ignored', () => {
    const guardian = generateKeyPair();
    const set2: Signer[] = [...set, { role: 'guardian', publicKey: enc(guardian) }];
    const p0 = signed();
    const share = signShare('guardian', guardian.secretKey, thresholdMessage(p0), { signerSet: set2, t: 2 });
    const v = tv({ signerSet: set2, t: 2 });
    expect(v(ctxOf({ ...p0, threshold: { shares: [share] } } as PCActn))).toEqual({ enforced: true, ok: true, t: 2 });
    expect(v(ctxOf({ ...p0, threshold: { shares: 'x' } } as never)).ok).toBe(false);
    expect(v(ctxOf({ ...p0, threshold: 'x' } as never)).ok).toBe(false);
  });

  it('requiredT overrides t', () => {
    const p = signed();
    expect(tv({ signerSet: set, t: 3, requiredT: () => 1 })(ctxOf(p)).ok).toBe(true);
    expect(tv({ signerSet: set, t: 1, requiredT: () => 2 })(ctxOf(p)).ok).toBe(false);
  });

  it('F-1: there is NO risk_claim-derived default: t or requiredT is mandatory', () => {
    expect(() => createThresholdVerifier({ signerSet: set } as never)).toThrow(/requiredT/);
    expect(() => createThresholdVerifier({ signerSet: set, t: undefined } as never)).toThrow(TypeError);
    // an agent claiming r=0 does not lower an explicit server t
    const v = tv({ signerSet: set, t: 3 });
    expect(v(ctxOf(signed({ risk_claim: { r: 0, inputs: {} } }))).ok).toBe(false);
  });
});
