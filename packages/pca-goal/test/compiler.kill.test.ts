import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Tape, Tok } from '@atlasauth/pca-verified-core';
import { IrError } from '../src/codec';
import { canonicalPolicy, compileGoal, decideGoal, decidePolicy, policyDigest, renderTape, typecheck } from '../src/compiler';
import type { Act, Hist, Policy } from '../src/ir';
import { ONT, baseGoal } from './fixtures';

// goalCall is replaced by a canned tape while `h.next` is set, so every status/shape branch of the typed wrappers is reachable.
const h = vi.hoisted(() => ({ next: null as Tape | null }));
vi.mock('@atlasauth/pca-verified-core', async (orig) => {
  const m = await orig<typeof import('@atlasauth/pca-verified-core')>();
  return { ...m, goalCall: (...a: Parameters<typeof m.goalCall>): Tape => h.next ?? m.goalCall(...a) };
});
afterEach(() => { h.next = null; });

const I = (n: number): Tok => ['i', n];
const S = (s: string): Tok => ['s', s];
const g = baseGoal();
const act: Act = { verb: 'pay.read', res: 'r', params: {}, t: 1, sess: 's', prin: 'P1', org: 'O', agent: 'a', depth: 0 };
const hist: Hist = { adms: [], last: -1, aggs: {} };
const REJECT = new IrError('compiler rejected the input tape');

describe('compiler wrappers: malformed and rejected tapes', () => {
  it('a missing or non-integer status token is a malformed-output error', () => {
    for (const t of [[], [S('a')]] as Tape[]) {
      h.next = t;
      expect(() => typecheck(g, ONT)).toThrow(new IrError('malformed compiler output'));
    }
  });
  it('typecheck: status 0 is [], status 2 is rejected, reasons are the declared strings only', () => {
    h.next = [I(0)];
    expect(typecheck(g, ONT)).toStrictEqual([]);
    h.next = [I(2)];
    expect(() => typecheck(g, ONT)).toThrow(REJECT);
    h.next = [I(1)];
    expect(typecheck(g, ONT)).toStrictEqual([]);
    h.next = [I(1), I(3), S('a'), I(7), S('c'), S('extra')];
    expect(typecheck(g, ONT)).toStrictEqual(['a', '', 'c']);
  });
  it('compileGoal: status 1 carries reasons, any other non-zero status is rejected', () => {
    h.next = [I(1), I(2), S('x'), S('y'), S('z')];
    expect(compileGoal(g, ONT)).toStrictEqual({ ok: false, reasons: ['x', 'y'] });
    h.next = [I(2)];
    expect(() => compileGoal(g, ONT)).toThrow(REJECT);
  });
  it('decideGoal: a non-zero status is rejected, otherwise the decision code maps to allow/escalate/deny', () => {
    h.next = [I(1)];
    expect(() => decideGoal(g, ONT, act, hist)).toThrow(REJECT);
    for (const [n, d] of [[2, 'allow'], [1, 'escalate'], [0, 'deny']] as const) {
      h.next = [I(0), I(n)];
      expect(decideGoal(g, ONT, act, hist)).toBe(d);
    }
  });
  it('renderTape: a non-zero status is rejected', () => {
    h.next = [I(1)];
    expect(() => renderTape(g)).toThrow(new IrError('goal tape rejected'));
  });
});

describe('decidePolicy tape decoding', () => {
  it('status 1 returns the reasons, status 2 is rejected', () => {
    h.next = [I(1), I(2), S('r1'), S('r2'), S('r3')];
    expect(decidePolicy(g, ONT, act, hist)).toStrictEqual({ ok: false, reasons: ['r1', 'r2'] });
    h.next = [I(2)];
    expect(() => decidePolicy(g, ONT, act, hist)).toThrow(REJECT);
  });
  it('an allow carries the grant id and exactly n bound ids, and the checker flag', () => {
    h.next = [I(0), I(2), S('gid'), I(2), S('b1'), S('b2'), I(1)];
    expect(decidePolicy(g, ONT, act, hist)).toStrictEqual({ ok: true, decision: 'allow', witness: { gid: 'gid', bids: ['b1', 'b2'] }, witnessChecked: true });
  });
  it('a non-string bound token maps to the empty string and a checker flag other than 1 is false', () => {
    h.next = [I(0), I(2), S('gid'), I(2), I(9), S('b2'), I(0)];
    expect(decidePolicy(g, ONT, act, hist)).toStrictEqual({ ok: true, decision: 'allow', witness: { gid: 'gid', bids: ['', 'b2'] }, witnessChecked: false });
  });
  it('a non-allow decision has no witness', () => {
    h.next = [I(0), I(1), S('gid'), I(0), I(1)];
    expect(decidePolicy(g, ONT, act, hist)).toStrictEqual({ ok: true, decision: 'escalate', witness: null, witnessChecked: true });
    h.next = [I(0), I(0), S('gid'), I(0), I(0)];
    expect(decidePolicy(g, ONT, act, hist)).toStrictEqual({ ok: true, decision: 'deny', witness: null, witnessChecked: false });
  });
});

describe('canonicalPolicy and policyDigest', () => {
  // keys deliberately unsorted; `note: null` is what an unvalidated JSON policy may carry
  const p: Policy = JSON.parse('{"validity":{"notBefore":1,"notAfter":9,"maxIdle":0},"deleg":{"narrowOnly":true,"maxDepth":2,"mayTouch":["g2","g1"]},"preds":[{"verb":"v","res":{"k":"set","ids":["b","a"]},"gid":"g","cond":{"k":"true"}},{"gid":"h","verb":"w","res":{"k":"star"},"cond":{"k":"false"}}],"prohs":[],"ceils":[],"escs":[],"note":null}');
  const want = '{"ceils":[],"deleg":{"maxDepth":2,"mayTouch":["g2","g1"],"narrowOnly":true},"escs":[],"note":null,"preds":[{"cond":{"k":"true"},"gid":"g","res":{"ids":["b","a"],"k":"set"},"verb":"v"},{"cond":{"k":"false"},"gid":"h","res":{"k":"star"},"verb":"w"}],"prohs":[],"validity":{"maxIdle":0,"notAfter":9,"notBefore":1}}';
  it('sorts object keys at every depth, keeps array order, comma-joins, renders null and primitives as JSON', () => {
    expect(canonicalPolicy(p)).toBe(want);
  });
  it('the digest is the unpadded base64url sha256 of the canonical bytes', () => {
    const d = policyDigest(p);
    expect(typeof d).toBe('string');
    expect(d).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(d).toBe(createHash('sha256').update(want).digest('base64url'));
  });
});
