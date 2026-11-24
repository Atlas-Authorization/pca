import { describe, expect, it } from 'vitest';
import { b64u, buildEscalationRequest, escalationPolicyDigest, generateKeyPair, hashCanonical, paramsDigest, signEscalationAnswer, type Capability, type PCActn } from '@atlasauth/pca';
import { buildSpace, mkAct, type Case } from '../src/examples';
import type { Goal, RelDecl, Value } from '../src/ir';
import { instantiateTemplate, ontologyForGoal, type SlotValue } from '../src/ontology';
import { ALL_ONTOLOGIES } from '../src/ontologies';
import { answerBodyFor, authorizeWithPrecedents, ceilingsOf, PrecedentLog, signRevocation, type AnsweredCase, type AppendResult, type Entry, type RevocationBody } from '../src/precedent';
import { signerId } from '../src/sign';

const pay = ALL_ONTOLOGIES.payments!;
const mk = (t: string, v: Record<string, SlotValue>): Goal => instantiateTemplate(pay, t, v, { principal: 'p', nl: t });
const g = mk('refund_customer_charges', { customer: 'cus_1', max_per: { ccy: 'USD', minor: 2000 }, max_total: { ccy: 'USD', minor: 5000 }, max_count: { n: 3 } });
const ont = ontologyForGoal(pay, g);
const sp = buildSpace([g]);
const money = (ccy: string, n: number): Value => ({ k: 'q', q: { u: { k: 'money', ccy }, n } });
const refund = (ch: string, minor: number, cust = 'cus_1', ccy = 'USD'): Case => ({ act: mkAct('refund', ch, { amount: money(ccy, minor) }), rels: [{ rel: 'charges_of', anchor: cust, members: [ch] }] as RelDecl[] });
const key = () => { const sk = generateKeyPair().secretKey; return { sk, pin: signerId(sk) }; };
const k = key();
const other = key();
const grant = { id: 'grant-1' } as Capability;
const policyDigest = escalationPolicyDigest(grant);
const nonce = () => b64u(crypto.getRandomValues(new Uint8Array(16)));
const pcactnOf = (c: Case): PCActn => ({ action: { verb: c.act.verb, resource: c.act.res, params_digest: paramsDigest(c.act.params), reversibility_class: 'irreversible' }, counter: 7, aud: 'rs', iat: 1, exp: 5000 }) as PCActn;
const answeredLc = (c: Case, lastCounter: number | undefined): AnsweredCase => ({ pcactn: pcactnOf(c), params: c.act.params, rels: c.rels, lastCounter });
const answered = (c: Case): AnsweredCase => answeredLc(c, 6);
/** lc: the history counter the question was asked at (null = none yet) */
const ask = (c: Case, o: { signer?: { sk: Uint8Array; pin: string }; decision?: 'allow' | 'deny'; expires?: number; lc?: number | null } = {}) => {
  const lastCounter = o.lc === null ? undefined : (o.lc ?? 6);
  const req = buildEscalationRequest({ aud: 'rs', grant, pcactn: pcactnOf(c), lastCounter, reasons: ['unit'], now: 1 });
  const s = o.signer ?? k;
  return signEscalationAnswer(answerBodyFor(req, { principal: s.pin, decision: o.decision ?? 'allow', iat: 1, expires_at: o.expires ?? 1000, nonce: nonce() }), s.sk);
};
const must = (r: AppendResult): Entry => {
  if (!r.ok) throw new Error(r.reason);
  return r.entry;
};
/** the chain digest of an entry, computed independently of the implementation */
const digestOf = (e: Omit<Entry, 'digest'>): string =>
  hashCanonical({ d: 'atlas-pca/goal-precedent-entry/v1', seq: e.seq, prev: e.prev, kind: e.kind, answer: e.answer ?? null, answered: e.answered ? { ...e.answered, lastCounter: e.answered.lastCounter ?? null } : null, cell: e.cell ?? null, ceilings: e.ceilings ?? null, revocation: e.revocation ?? null });
/** replace entry i by a tampered copy whose digest is recomputed, so only the tampered member can fail verification */
const retamper = (log: PrecedentLog, i: number, patch: Partial<Entry>): void => {
  const e: Entry = { ...log.entries[i]!, ...patch };
  log.entries[i] = { ...e, digest: digestOf(e) };
};
const escAct = refund('ch_1', 100, 'cus_1', 'EUR');
const otherCell = refund('ch_1', 100, 'cus_2', 'EUR');
const one = () => {
  const log = new PrecedentLog([k.pin]);
  const e = must(log.append(ask(escAct), answered(escAct), grant, sp, 10));
  return { log, e };
};
const revBody = (e: Entry, over: Partial<RevocationBody> = {}): RevocationBody => ({ policy_digest: policyDigest, cell: e.cell!, target_entry: e.digest, ts: 12, ...over });

describe('ceilingsOf', () => {
  it('keys a ceiling by parameter and unit, and only quantities carry one', () => {
    expect(ceilingsOf({
      a: { k: 'q', q: { u: { k: 'count' }, n: 3 } },
      b: money('USD', 5),
      c: { k: 's', s: 'x' },
    })).toEqual({ 'a|count': 3, 'b|money:USD': 5 });
    expect(ceilingsOf({ c: { k: 's', s: 'x' } })).toEqual({});
  });
});

describe('entry digest', () => {
  it('is the hash of the exact documented members, for answers and revocations', () => {
    const { log, e } = one();
    const { digest, ...rest } = e;
    expect(digest).toBe(digestOf(rest));
    expect(e.prev).toBe('0'.repeat(64));
    const rev = must(log.revoke(signRevocation(revBody(e), k.sk)));
    const { digest: rd, ...rrest } = rev;
    expect(rd).toBe(digestOf(rrest));
    expect(rev.prev).toBe(e.digest);
  });
  it('binds a missing history counter as null', () => {
    const log = new PrecedentLog([k.pin]);
    const e = must(log.append(ask(escAct, { lc: null }), answeredLc(escAct, undefined), grant, sp, 10));
    const { digest, ...rest } = e;
    expect(digest).toBe(digestOf(rest));
  });
});

describe('pinned signers', () => {
  it('finds the pin of the answering principal among several, string or object', () => {
    const second = new PrecedentLog([other.pin, k.pin]);
    expect(second.append(ask(escAct), answered(escAct), grant, sp, 10).ok).toBe(true);
    const objects = new PrecedentLog([{ pk: other.pin }, { pk: k.pin }]);
    expect(objects.append(ask(escAct), answered(escAct), grant, sp, 10).ok).toBe(true);
    expect(objects.verifyChain(sp)).toBe(true);
  });
});

describe('answerFault', () => {
  const fault = (log: PrecedentLog, answer: ReturnType<typeof ask>, a: AnsweredCase) => log['answerFault']({ answer, answered: a });
  it('is null for a sound answer', () => {
    expect(fault(new PrecedentLog([k.pin]), ask(escAct), answered(escAct))).toBeNull();
  });
  it('names each fault', () => {
    const log = new PrecedentLog([k.pin]);
    expect(fault(log, { ...ask(escAct), principal: 'x' }, answered(escAct))).toBe('malformed answer');
    expect(fault(log, { ...ask(escAct), decision: 'deny' }, answered(escAct))).toBe('bad signature');
    expect(fault(log, ask(escAct, { signer: other }), answered(escAct))).toBe('bad signature');
    expect(fault(log, ask(escAct), answered(refund('ch_1', 100, 'cus_1', 'GBP')))).toBe('answer is bound to another action');
    expect(fault(log, ask(escAct), { ...answered(escAct), lastCounter: 99 })).toBe('answer is bound to another history state');
    expect(fault(log, ask(escAct), { ...answered(escAct), params: refund('ch_1', 1, 'cus_1', 'EUR').act.params })).toBe('params do not match the signed action');
  });
});

describe('verifyChain', () => {
  it('accepts an untampered chain of answers and revocations', () => {
    const { log, e } = one();
    expect(log.verifyChain(sp)).toBe(true);
    log.revoke(signRevocation(revBody(e), k.sk));
    expect(log.verifyChain(sp)).toBe(true);
  });
  it('refuses each member of an entry that no longer matches, even when its digest is recomputed', () => {
    const cases: [string, (log: PrecedentLog, e: Entry) => void][] = [
      ['seq', (log) => retamper(log, 0, { seq: 5 })],
      ['prev', (log) => retamper(log, 0, { prev: 'f'.repeat(64) })],
      ['digest', (log) => { log.entries[0]!.digest = 'z'.repeat(43); }],
      ['answer', (log, e) => retamper(log, 0, { answer: { ...e.answer!, decision: 'deny' } })],
      ['cell', (log) => retamper(log, 0, { cell: 'elsewhere' })],
      ['ceilings', (log) => retamper(log, 0, { ceilings: { 'amount|money:EUR': 5 } })],
      ['answered', (log) => retamper(log, 0, { answered: undefined })],
      ['answer missing', (log) => retamper(log, 0, { answer: undefined })],
    ];
    for (const [name, tamper] of cases) {
      const { log, e } = one();
      expect(log.verifyChain(sp), `${name} before`).toBe(true);
      tamper(log, e);
      expect(log.verifyChain(sp), name).toBe(false);
    }
  });
  it('refuses a revocation whose signature or presence is gone', () => {
    const forged = one();
    const rev = must(forged.log.revoke(signRevocation(revBody(forged.e), k.sk)));
    expect(forged.log.verifyChain(sp)).toBe(true);
    retamper(forged.log, 1, { revocation: { ...rev.revocation!, payload: { ...rev.revocation!.payload, ts: 99 } } });
    expect(forged.log.verifyChain(sp)).toBe(false);
    const gone = one();
    gone.log.revoke(signRevocation(revBody(gone.e), k.sk));
    retamper(gone.log, 1, { revocation: undefined });
    expect(gone.log.verifyChain(sp)).toBe(false);
  });
  it('answers false (never throws, never undefined) on an entry that cannot even be hashed', () => {
    const { log } = one();
    log.entries[0]!.ceilings = { a: Number.NaN };
    expect(log.verifyChain(sp)).toBe(false);
  });
});

describe('lookup', () => {
  it('returns the latest live entry of the cell, never one of another cell', () => {
    const log = new PrecedentLog([k.pin]);
    const first = must(log.append(ask(escAct), answered(escAct), grant, sp, 10));
    const second = must(log.append(ask(escAct, { expires: 2000 }), answered(escAct), grant, sp, 10));
    expect(log.lookup(policyDigest, sp, escAct, 10)?.entry).toBe(second);
    expect(log.lookup(policyDigest, sp, escAct, 10)?.entry).not.toBe(first);
    const denyOther = must(log.append(ask(otherCell, { decision: 'deny' }), answered(otherCell), grant, sp, 10));
    expect(log.lookup(policyDigest, sp, escAct, 10)?.entry).toBe(second);
    expect(log.lookup(policyDigest, sp, escAct, 10)?.decision).toBe('allow');
    expect(log.lookup(policyDigest, sp, otherCell, 10)?.entry).toBe(denyOther);
    expect(log.lookup(policyDigest, sp, otherCell, 10)?.decision).toBe('deny');
  });
  it('an answer is live strictly before its expiry', () => {
    const { log } = one();
    expect(log.lookup(policyDigest, sp, escAct, 999)?.decision).toBe('allow');
    expect(log.lookup(policyDigest, sp, escAct, 1000)).toBeUndefined();
  });
  it('needs the same parameters and units as the signed witness', () => {
    const extra: Value = { k: 'q', q: { u: { k: 'count' }, n: 1 } };
    const withExtra: Case = { act: mkAct('refund', 'ch_1', { amount: money('EUR', 100), extra }), rels: escAct.rels };
    const log = new PrecedentLog([k.pin]);
    must(log.append(ask(withExtra), answered(withExtra), grant, sp, 10));
    expect(log.lookup(policyDigest, sp, withExtra, 10)?.decision).toBe('allow');
    expect(log.lookup(policyDigest, sp, escAct, 10)).toBeUndefined();
  });
});

describe('append', () => {
  it('records a repeat of the same decision and refuses the opposite one with its reason', () => {
    const log = new PrecedentLog([k.pin]);
    must(log.append(ask(escAct), answered(escAct), grant, sp, 10));
    expect(log.append(ask(escAct), answered(escAct), grant, sp, 11).ok).toBe(true);
    expect(log.append(ask(escAct, { decision: 'deny' }), answered(escAct), grant, sp, 12)).toEqual({ ok: false, reason: 'conflicts with a recorded decision; revoke it first' });
    expect(log.entries.length).toBe(2);
  });
});

describe('revoke', () => {
  it('refuses a revocation signed by an unpinned signer', () => {
    const { log, e } = one();
    expect(log.revoke(signRevocation(revBody(e), other.sk))).toEqual({ ok: false, reason: 'bad signature' });
  });
  it('only revokes an existing answer of the same policy and cell', () => {
    const { log, e } = one();
    const no = { ok: false, reason: 'no such precedent' };
    expect(log.revoke(signRevocation(revBody(e, { policy_digest: 'another-policy' }), k.sk))).toEqual(no);
    expect(log.revoke(signRevocation(revBody(e, { cell: 'another-cell' }), k.sk))).toEqual(no);
    expect(log.revoke(signRevocation(revBody(e, { target_entry: 'no-such-digest' }), k.sk))).toEqual(no);
    expect(log.entries.length).toBe(1);
    const rev = log.revoke(signRevocation(revBody(e), k.sk));
    expect(rev.ok).toBe(true);
    expect(must(rev).kind).toBe('revocation');
    // a revocation entry is not an answer: its digest is not a revocable target
    expect(log.revoke(signRevocation(revBody(e, { target_entry: must(rev).digest }), k.sk))).toEqual(no);
    expect(log.entries.length).toBe(2);
    expect(log.lookup(policyDigest, sp, escAct, 13)).toBeUndefined();
  });
});

describe('authorizeWithPrecedents', () => {
  const auth = (log: PrecedentLog, c: Case, now = 10) => authorizeWithPrecedents(g, ont, policyDigest, log, { act: c.act, rels: c.rels }, now);
  it('leaves a policy allow to the policy', () => {
    expect(auth(new PrecedentLog([k.pin]), refund('ch_1', 100))).toEqual({ decision: 'allow', via: 'policy' });
  });
  it('escalates without a precedent, via the policy', () => {
    expect(auth(new PrecedentLog([k.pin]), escAct)).toEqual({ decision: 'escalate', via: 'policy' });
  });
  it('a recorded allow and a recorded deny both come back via the precedent', () => {
    const allow = one();
    expect(auth(allow.log, escAct)).toEqual({ decision: 'allow', via: 'precedent', precedent: allow.e });
    const log = new PrecedentLog([k.pin]);
    const denied = must(log.append(ask(escAct, { decision: 'deny' }), answered(escAct), grant, sp, 10));
    expect(auth(log, escAct)).toEqual({ decision: 'deny', via: 'precedent', precedent: denied });
  });
  it('fails closed on a tampered log, via the policy', () => {
    const { log } = one();
    expect(auth(log, escAct)).toMatchObject({ decision: 'allow' });
    log.entries[0]!.seq = 5;
    expect(auth(log, escAct)).toEqual({ decision: 'escalate', via: 'policy' });
  });
});
