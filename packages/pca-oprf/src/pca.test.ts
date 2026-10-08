import { describe, expect, it } from 'vitest';
import {
  buildRevocationSet,
  isRevokedPrivate,
  makeRateEvaluator,
  makeRevocationEvaluator,
  privateRateToken,
  RateWindowCounter,
  rateToken,
  rateTokenHex,
} from './pca';
import {
  type EvaluateResult,
  hashToGroup,
  randomKeyPair,
  serializeElement,
  toHex,
} from './oprf';

const te = new TextEncoder();

describe('Private revocation check (PSI-style membership)', () => {
  it('detects a revoked cap id and clears a non-revoked one', () => {
    const { secretKey } = randomKeyPair();
    const revoked = ['cap_root#abc', 'cap_leaf#def', 'cap_subtree#ghi'];
    const revokedSet = buildRevocationSet(secretKey, revoked);
    const blindEval = makeRevocationEvaluator(secretKey);

    expect(isRevokedPrivate('cap_leaf#def', { blindEval, revokedSet })).toBe(true);
    expect(isRevokedPrivate('cap_root#abc', { blindEval, revokedSet })).toBe(true);
    expect(isRevokedPrivate('cap_not_revoked#zzz', { blindEval, revokedSet })).toBe(false);
  });

  it('the service only ever sees blinded group elements — never the raw cap id or its input element', () => {
    const { secretKey } = randomKeyPair();
    const capId = 'cap_secret#000';
    const revokedSet = buildRevocationSet(secretKey, [capId, 'cap_other#111']);
    const inner = makeRevocationEvaluator(secretKey);

    const seen: Uint8Array[] = [];
    const blindEval = (blindedElement: Uint8Array): EvaluateResult => {
      seen.push(Uint8Array.from(blindedElement));
      return inner(blindedElement);
    };

    expect(isRevokedPrivate(capId, { blindEval, revokedSet })).toBe(true);

    // Exactly one boundary crossing, and it is a 32-byte ristretto element...
    expect(seen).toHaveLength(1);
    const crossed = seen[0] ?? new Uint8Array();
    expect(crossed.length).toBe(32);

    // ...that is NOT the raw id bytes, and NOT the unblinded HashToGroup(capId) input element.
    const rawId = te.encode(capId);
    const inputElement = serializeElement(hashToGroup(rawId, 'oprf'));
    expect(toHex(crossed)).not.toBe(toHex(rawId));
    expect(toHex(crossed)).not.toBe(toHex(inputElement));
  });

  it('verifiable (VOPRF) revocation set: honest service passes, a lying service is rejected', () => {
    const server = randomKeyPair();
    const revokedSet = buildRevocationSet(server.secretKey, ['cap_v#1'], 'voprf');
    const honest = makeRevocationEvaluator(server.secretKey, 'voprf');
    expect(isRevokedPrivate('cap_v#1', { blindEval: honest, revokedSet })).toBe(true);
    expect(isRevokedPrivate('cap_v#2', { blindEval: honest, revokedSet })).toBe(false);

    // A service that evaluates under a DIFFERENT key (trying to hide a revocation) is caught by the proof.
    const attacker = randomKeyPair();
    const lying = makeRevocationEvaluator(attacker.secretKey, 'voprf');
    expect(() => isRevokedPrivate('cap_v#1', { blindEval: lying, revokedSet })).toThrow(
      /proof verification failed/,
    );
  });
});

describe('Private rate-limiting (POPRF: identifier hidden, window public)', () => {
  it('the rate token is stable per (identifier, window) and differs across windows', () => {
    const { secretKey } = randomKeyPair();
    const t1 = rateTokenHex(secretKey, 'agent_pk_xyz', '2026-10-08T12');
    const t1b = rateTokenHex(secretKey, 'agent_pk_xyz', '2026-10-08T12');
    const t2 = rateTokenHex(secretKey, 'agent_pk_xyz', '2026-10-08T13');
    const other = rateTokenHex(secretKey, 'agent_pk_abc', '2026-10-08T12');

    expect(t1).toBe(t1b); // same (id, window) -> same token (counts aggregate)
    expect(t1).not.toBe(t2); // new window -> new token (count resets)
    expect(t1).not.toBe(other); // different identifier -> different token
  });

  it('the private client flow yields the same token without the server seeing the identifier', () => {
    const { secretKey, publicKey } = randomKeyPair();
    const identifier = 'agent_pk_xyz';
    const window = '2026-10-08T12';

    const seen: { blinded: Uint8Array; window: string }[] = [];
    const inner = makeRateEvaluator(secretKey);
    const blindEval = (blindedElement: Uint8Array, w: string): EvaluateResult => {
      seen.push({ blinded: Uint8Array.from(blindedElement), window: w });
      return inner(blindedElement, w);
    };

    const privateTok = privateRateToken(identifier, window, { blindEval, publicKey });
    const serverTok = rateToken(secretKey, identifier, window);
    expect(toHex(privateTok)).toBe(toHex(serverTok));

    // The server saw the window (public, by design) but only a blinded element, never the identifier.
    expect(seen).toHaveLength(1);
    const entry = seen[0];
    expect(entry?.window).toBe(window);
    const blinded = entry?.blinded ?? new Uint8Array();
    expect(blinded.length).toBe(32);
    expect(toHex(blinded)).not.toBe(toHex(te.encode(identifier)));
    expect(toHex(blinded)).not.toBe(toHex(serializeElement(hashToGroup(te.encode(identifier), 'poprf'))));
  });

  it('RateWindowCounter counts and limits by token without the identifier', () => {
    const { secretKey } = randomKeyPair();
    const counter = new RateWindowCounter(3);
    const tok = rateToken(secretKey, 'agent_pk_xyz', 'w-now');

    expect(counter.hit(tok)).toEqual({ count: 1, allowed: true });
    expect(counter.hit(tok)).toEqual({ count: 2, allowed: true });
    expect(counter.hit(tok)).toEqual({ count: 3, allowed: true });
    expect(counter.hit(tok)).toEqual({ count: 4, allowed: false }); // over the limit

    // A token for a different window is counted independently (fresh budget).
    const next = rateToken(secretKey, 'agent_pk_xyz', 'w-next');
    expect(counter.hit(next)).toEqual({ count: 1, allowed: true });
    expect(counter.count(tok)).toBe(4);
  });

  it('rejects a non-positive limit', () => {
    expect(() => new RateWindowCounter(0)).toThrow(/positive integer/);
  });
});
