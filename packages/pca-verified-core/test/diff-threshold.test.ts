import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from '../../pca/src/hash';
import { encodeKey, generateKeyPair, sign } from '../../pca/src/keys';
import { assembleThreshold, signShare, verifyThreshold, type AgentLeafBaseline, type Signer, type ThresholdSignature } from '../../pca/src/threshold';
import { Rng } from './support/corpus';
import { verifyThreshold as verifyThresholdLegacy } from './support/legacy/threshold';

const MSG = utf8('the-same-canonical-message');
const K = { agent: generateKeyPair(), guardian: generateKeyPair(), principal: generateKeyPair(), rogue: generateKeyPair() };
const pk = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const SET: Signer[] = [
  { role: 'agent', publicKey: pk(K.agent) },
  { role: 'guardian', publicKey: pk(K.guardian) },
  { role: 'principal', publicKey: pk(K.principal) },
];
const shares = (t: number, roles: Array<'agent' | 'guardian' | 'principal'>) => roles.map((r) => signShare(r, K[r].secretKey, MSG, { signerSet: SET, t }));
const leafBaseline = (): AgentLeafBaseline => ({ holder: pk(K.agent), sig: b64u(sign(K.agent.secretKey, MSG)) });
const JUNK: unknown[] = [undefined, null, 0, 1, 2, 3, 4, -1, 1.5, NaN, '2', '', 'x', [], {}, true];

function mutateSet(set: Signer[], r: Rng): Signer[] {
  const s: any[] = structuredClone(set);
  const o = (): any => {
    const e = s[r.next(s.length)];
    return e !== null && typeof e === 'object' ? e : {};
  };
  switch (r.next(9)) {
    case 0:
      s.push(structuredClone(s[r.next(s.length)]));
      break;
    case 1:
      s.push({ role: r.pick(['agent', 'guardian', 'principal', 'bogus']), publicKey: pk(K[r.pick(['agent', 'guardian', 'principal', 'rogue'] as const)]) });
      break;
    case 2:
      o().publicKey = r.pick(JUNK);
      break;
    case 3:
      o().role = r.pick(JUNK);
      break;
    case 4:
      o().pq_pk = r.pick(JUNK);
      break;
    case 5:
      s.splice(r.next(s.length), 1);
      break;
    case 6:
      s[r.next(s.length)] = r.pick(JUNK);
      break;
    case 7:
      o().publicKey = pk(K.rogue);
      break;
    default:
      break;
  }
  return s;
}

function mutateSig(sig: ThresholdSignature, r: Rng): any {
  const x: any = structuredClone(sig);
  const sh: any[] = x.shares;
  const o = (): any => {
    const e = sh.length ? sh[r.next(sh.length)] : undefined;
    return e !== null && typeof e === 'object' ? e : {};
  };
  for (let k = 0, n = r.next(4); k < n; k++) {
    switch (r.next(10)) {
      case 0:
        sh.push(structuredClone(sh[r.next(Math.max(1, sh.length))]));
        break;
      case 1:
        o().role = r.pick(['agent', 'guardian', 'principal', 'bogus', 3, undefined]);
        break;
      case 2:
        o().publicKey = r.pick([pk(K.rogue), pk(K.agent), pk(K.guardian), 5, undefined]);
        break;
      case 3:
        {
          const s = o();
          if (typeof s.sig === 'string') s.sig = s.sig.slice(0, -2) + (s.sig.endsWith('AA') ? 'BB' : 'AA');
        }
        break;
      case 4:
        o().alg = r.pick(['ed25519', 'ml-dsa-65', 'bogus', 7, undefined]);
        break;
      case 5:
        if (sh.length) sh[r.next(sh.length)] = r.pick(JUNK);
        break;
      case 6:
        if (sh.length) sh.splice(r.next(sh.length), 1);
        break;
      case 7:
        delete o().sig;
        break;
      case 8:
        o().pq_sig = r.pick(['x', 5]);
        break;
      default:
        if (sh.length) sh.reverse();
    }
  }
  if (r.next(12) === 0) return r.pick(JUNK);
  return x;
}

describe('differential: verifyThreshold (TS) (production, verified core) vs legacy (frozen TS)', () => {
  it('agrees on the honest cases (t=1,2,3; with and without the agent leaf baseline)', () => {
    for (const t of [1, 2, 3]) {
      for (const roles of [[], ['agent'], ['guardian'], ['agent', 'guardian'], ['guardian', 'principal'], ['agent', 'guardian', 'principal'], ['agent', 'agent', 'guardian']] as const) {
        const sig = assembleThreshold(shares(t, [...roles]));
        for (const bl of [undefined, leafBaseline()]) expect(verifyThreshold(sig, MSG, SET, t, bl)).toEqual(verifyThresholdLegacy(sig, MSG, SET, t, bl));
      }
    }
    expect(verifyThreshold(assembleThreshold(shares(3, ['agent', 'guardian', 'principal'])), MSG, SET, 3).ok).toBe(true);
  });

  it('agrees on 8000 random mutations of signer sets, shares, t and baseline (verdict, count, roles, reason)', () => {
    let ok = 0;
    let bad = 0;
    fc.assert(
      fc.property(fc.array(fc.nat(), { minLength: 6, maxLength: 30 }), (pool) => {
        const r = new Rng(pool);
        const t = r.pick([1, 2, 3, 3, 2, 0, 4, 1.5, '2' as unknown as number, NaN]);
        const tSign = r.pick([1, 2, 3]);
        const set = r.bool() ? mutateSet(SET, r) : SET;
        const roles = r.pick([['agent'], ['guardian'], ['agent', 'guardian'], ['agent', 'guardian', 'principal'], ['guardian', 'principal'], ['agent', 'agent', 'principal'], []] as const);
        const sig = mutateSig(assembleThreshold(shares(tSign, [...roles])), r);
        const bl = r.pick([undefined, leafBaseline(), { ...leafBaseline(), holder: pk(K.guardian) }, { ...leafBaseline(), sig: 5 }, { ...leafBaseline(), alg: 'bogus' }, { ...leafBaseline(), holder: 5 as unknown as string }]);
        const a = verifyThresholdLegacy(sig, MSG, set as Signer[], t, bl as AgentLeafBaseline | undefined);
        const b = verifyThreshold(sig, MSG, set as Signer[], t, bl as AgentLeafBaseline | undefined);
        expect(b).toEqual(a);
        if (a.ok) ok++; else bad++;
      }),
      { numRuns: 8000 },
    );
    expect(ok).toBeGreaterThan(100);
    expect(bad).toBeGreaterThan(1000);
  });
});
