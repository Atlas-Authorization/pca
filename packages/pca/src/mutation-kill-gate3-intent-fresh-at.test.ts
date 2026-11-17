/**
 * Mutation kills for the 0.5.0 flagship gate survivors in fresh-at.ts: the string / integer guards of the token and its
 * wire member (each guard on its own, with the exact refusal), signFreshAt's state check, the verifier's catch path, the
 * re-signed v / signer / counter refusals, the digest, the field-wise merge, every verdict object, gateDecision's table,
 * FreshAtIssuer's copies and age option, and decideFreshAt's `none` result.
 */
import { describe, expect, it } from 'vitest';
import {
  FRESH_AT_DOMAIN, FRESH_AT_REF_DOMAIN, FreshAtIssuer, checkFreshAt, decideFreshAt, freshAtDigest, gateDecision, mergeFreshAt, signFreshAt, validateFreshAtWire, verifyFreshAt,
  type FreshAt, type FreshAtState, type FreshAtVerdict,
} from './fresh-at';
import { b64u, canonicalBytesStrict, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';

const SK = sha256(utf8('gate3-fresh-at/signer'));
const SK2 = sha256(utf8('gate3-fresh-at/other'));
const PUB = b64u(publicKeyOf(SK));
const PUB2 = b64u(publicKeyOf(SK2));
const NOW = 1_800_000_000_000;
const ST: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };
const tok = (over: Partial<FreshAtState> = {}, scope = 'inst_A', at = NOW - 1000) => signFreshAt(SK, scope, { ...ST, ...over }, at);

/** Re-sign arbitrary (possibly malformed) token content with `sk`, the way signFreshAt would. */
function resign(t: Record<string, unknown>, sk: Uint8Array = SK): Record<string, unknown> {
  const { sig: _s, ...body } = t;
  void _s;
  const d = utf8(FRESH_AT_DOMAIN);
  const b = canonicalBytesStrict(body);
  const m = new Uint8Array(d.length + b.length);
  m.set(d);
  m.set(b, d.length);
  return { ...body, sig: b64u(sign(sk, m)) };
}

describe('validateFreshAtWire: the string and integer guards, each on its own', () => {
  const W = tok() as unknown as Record<string, unknown>;
  const SCOPE = "'fresh_at' scope and policy_digest must be non-empty strings";
  it('a well formed member passes; a 256-char scope is inside the bound, 257 is not', () => {
    expect(validateFreshAtWire(W)).toBeNull();
    expect(validateFreshAtWire({ ...W, scope: 's'.repeat(256) })).toBeNull();
    expect(validateFreshAtWire({ ...W, scope: 's'.repeat(257) })).toBe(SCOPE);
    expect(validateFreshAtWire({ ...W, policy_digest: 'd'.repeat(128) })).toBeNull();
    expect(validateFreshAtWire({ ...W, policy_digest: 'd'.repeat(129) })).toBe(SCOPE);
  });
  it('an empty scope, a non-string scope and an array scope are refused (the digest alone being fine)', () => {
    for (const scope of ['', 5, ['a'], null]) expect(validateFreshAtWire({ ...W, scope }), JSON.stringify(scope)).toBe(SCOPE);
    expect(validateFreshAtWire({ ...W, policy_digest: '' })).toBe(SCOPE);
  });
  it('v must be 1 (all else well formed)', () => {
    expect(validateFreshAtWire({ ...W, v: 2 })).toBe("'fresh_at.v' must be 1");
  });
  it('a counter that is a fraction or a numeric string is refused by name', () => {
    expect(validateFreshAtWire({ ...W, budget_version: 1.5 })).toBe("'fresh_at.budget_version' must be a non-negative safe integer");
    expect(validateFreshAtWire({ ...W, revocation_epoch: '5' })).toBe("'fresh_at.revocation_epoch' must be a non-negative safe integer");
    expect(validateFreshAtWire({ ...W, issued_at: 2 ** 53 })).toBe("'fresh_at.issued_at' must be a non-negative safe integer");
  });
  it('the signer and the signature are each checked (the other one well formed)', () => {
    expect(validateFreshAtWire({ ...W, signer: 'AAAA' })).toBe("'fresh_at.signer' is not canonical base64url (32 bytes)");
    expect(validateFreshAtWire({ ...W, sig: 'AAAA' })).toBe("'fresh_at.sig' is not canonical base64url (64 bytes)");
  });
});

describe('signFreshAt: every malformed state is refused with the exact message', () => {
  const MSG = 'signFreshAt: a malformed state';
  it('accepts a well formed state', () => {
    expect(verifyFreshAt(tok(), PUB)).toBe(true);
  });
  it('a bad scope, a bad digest, any one bad counter and a bad issue time each throw', () => {
    expect(() => signFreshAt(SK, '', ST, NOW)).toThrow(new RangeError(MSG));
    expect(() => signFreshAt(SK, 'inst_A', { ...ST, policy_digest: '' }, NOW)).toThrow(new RangeError(MSG));
    for (const k of ['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision'] as const) {
      expect(() => signFreshAt(SK, 'inst_A', { ...ST, [k]: 1.5 }, NOW), k).toThrow(new RangeError(MSG));
    }
    expect(() => signFreshAt(SK, 'inst_A', ST, 1.5)).toThrow(new RangeError(MSG));
    expect(() => signFreshAt(SK, 'inst_A', ST, -1)).toThrow(new RangeError(MSG));
  });
});

describe('verifyFreshAt: re-signed malformed content, the signer field, the catch path', () => {
  it('a v other than 1 is refused even when the signature covers it', () => {
    expect(verifyFreshAt(resign({ ...tok(), v: 2 }), PUB)).toBe(false);
  });
  it('a token naming another signer is refused even when signed by the expected key over that content', () => {
    expect(verifyFreshAt(resign({ ...tok(), signer: PUB2 }), PUB)).toBe(false);
  });
  it('one negative counter is refused even when signed', () => {
    expect(verifyFreshAt(resign({ ...tok(), ledger_tree_size: -1 }), PUB)).toBe(false);
    expect(verifyFreshAt(resign({ ...tok(), revocation_epoch: '5' }), PUB)).toBe(false);
  });
  it('content that cannot be canonicalised (an undefined signer) is false, never undefined or true', () => {
    const t = { ...tok(), signer: undefined };
    expect(verifyFreshAt(t, undefined as never)).toBe(false);
  });
});

describe('freshAtDigest', () => {
  it('is the canonical hash of {d, t} and differs between tokens', () => {
    const a = tok();
    const b = tok({ budget_version: 8 });
    expect(freshAtDigest(a)).toBe(hashCanonical({ d: FRESH_AT_REF_DOMAIN, t: a }));
    expect(freshAtDigest(a)).not.toBe(freshAtDigest(b));
  });
});

describe('mergeFreshAt: the field-wise maximum and the digest of the higher revision', () => {
  const a: FreshAtState = { revocation_epoch: 9, ledger_tree_size: 1, budget_version: 9, policy_revision: 1, policy_digest: 'A' };
  const b: FreshAtState = { revocation_epoch: 1, ledger_tree_size: 9, budget_version: 1, policy_revision: 2, policy_digest: 'B' };
  it('takes the larger counter from either side', () => {
    expect(mergeFreshAt(a, b)).toEqual({ revocation_epoch: 9, ledger_tree_size: 9, budget_version: 9, policy_revision: 2, policy_digest: 'B' });
    expect(mergeFreshAt(b, a)).toEqual({ revocation_epoch: 9, ledger_tree_size: 9, budget_version: 9, policy_revision: 2, policy_digest: 'B' });
  });
  it("equal revisions keep a's digest", () => {
    expect(mergeFreshAt({ ...a, policy_revision: 2 }, b).policy_digest).toBe('A');
  });
});

describe('checkFreshAt: every verdict object exactly', () => {
  const o = { signer: PUB, scope: 'inst_A', now: NOW };
  it('bad token, wrong scope, from the future, too old, policy fork, stale state', () => {
    expect(checkFreshAt({}, ST, o)).toEqual({ decision: 'deny', code: 'bad_token' });
    expect(checkFreshAt(tok({}, 'inst_B'), ST, o)).toEqual({ decision: 'deny', code: 'wrong_scope' });
    expect(checkFreshAt(tok({}, 'inst_A', NOW + 60_001), ST, o)).toEqual({ decision: 'deny', code: 'token_from_the_future' });
    expect(checkFreshAt(tok(), ST, { ...o, maxTokenAgeMs: 999 })).toEqual({ decision: 'deny', code: 'token_too_old' });
    expect(checkFreshAt(tok({ policy_digest: 'other' }), ST, o)).toEqual({ decision: 'deny', code: 'policy_fork' });
    expect(checkFreshAt(tok({ budget_version: 8 }), ST, o)).toEqual({ decision: 'escalate', code: 'stale_state', behind: ['budget_version'] });
    expect(checkFreshAt(tok(), ST, o)).toEqual({ decision: 'ok' });
  });
});

describe('gateDecision: a freshness verdict only tightens', () => {
  const ok: FreshAtVerdict = { decision: 'ok' };
  const esc: FreshAtVerdict = { decision: 'escalate', code: 'stale_state', behind: [] };
  const den: FreshAtVerdict = { decision: 'deny', code: 'bad_token' };
  it('the full table', () => {
    expect(gateDecision('deny', ok)).toBe('deny');
    expect(gateDecision('deny', esc)).toBe('deny');
    expect(gateDecision('allow', den)).toBe('deny');
    expect(gateDecision('escalate', den)).toBe('deny');
    expect(gateDecision('allow', esc)).toBe('escalate');
    expect(gateDecision('allow', ok)).toBe('allow');
    expect(gateDecision('escalate', ok)).toBe('escalate');
  });
});

describe('FreshAtIssuer', () => {
  it('copies the initial state in and the current state out', () => {
    const init = { ...ST };
    const iss = new FreshAtIssuer(SK, 'inst_A', init);
    init.budget_version = 999;
    expect(iss.current).toEqual(ST);
    const cur = iss.current;
    cur.budget_version = 555;
    expect(iss.current).toEqual(ST);
  });
  it('advance merges the patch forward and signs the new state; check honours the age option only when given', () => {
    const iss = new FreshAtIssuer(SK, 'inst_A', ST);
    const t: FreshAt = iss.advance({ budget_version: 8 }, NOW - 5000);
    expect(iss.current).toEqual({ ...ST, budget_version: 8 });
    expect(verifyFreshAt(t, PUB)).toBe(true);
    expect(t.budget_version).toBe(8);
    expect(t.revocation_epoch).toBe(5);
    iss.advance({ budget_version: 1 }, NOW);
    expect(iss.current.budget_version).toBe(8);
    expect(iss.check(t, NOW)).toEqual({ decision: 'ok' });
    expect(iss.check(t, NOW, 10_000)).toEqual({ decision: 'ok' });
    expect(iss.check(t, NOW, 4_999)).toEqual({ decision: 'deny', code: 'token_too_old' });
  });
});

describe('decideFreshAt: the none result is exactly {status: none}', () => {
  const policy = { signer: PUB, scope: 'inst_A', local: ST };
  it('no member and no policy; no member and a non-requiring policy', () => {
    expect(decideFreshAt(undefined, undefined, NOW)).toEqual({ status: 'none' });
    expect(decideFreshAt(undefined, policy, NOW)).toEqual({ status: 'none' });
  });
});
