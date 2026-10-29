import { describe, expect, it } from 'vitest';
import {
  EVOLUTION_RECORD_KIND, MAX_EVOLUTION_STEPS, actionPinError, decidePin, evolutionDiffDigest, evolutionRecordError, reapprovalValid, registryKeyOf, signEvolutionRecord, signReapproval, verifyEvolutionRecord,
  type EvolutionRecord, type UnsignedEvolutionRecord,
} from './action-pin';
import { intentV2ContextError } from './intent-v2';
import { confirmationShapeError } from './action-schema';
import { generateKeyPair } from './keys';

const reg = generateKeyPair();
const other = generateKeyPair();
const KEYS = [registryKeyOf('r1', reg.secretKey)];
const dg = (c: string) => c.repeat(43);
const A = dg('A'), B = dg('B'), C = dg('C');
const VERB = 'acme.thing.do';
const PIN = { pack: { ns: 'acme', root: dg('R') }, defs: { [VERB]: A }, on_new_action: 'deny' as const };
const rec = (from: string | null, to: string | null, cls: UnsignedEvolutionRecord['class'], over: Partial<UnsignedEvolutionRecord> = {}, key = reg.secretKey): EvolutionRecord =>
  signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'acme', verb: VERB, from, to, class: cls, reasons: [], ...over }, 'r1', key);
const doc = (def: string | undefined, pack: unknown = { ns: 'acme', root: dg('R') }) => ({ pack: pack as never, verbs: [{ verb: VERB, def }] });
const principal = generateKeyPair();
const grant = { id: dg('G'), issuer: Buffer.from(principal.publicKey).toString('base64url') };
const decide = (def: string | undefined, records: unknown[] = [], reapprovals: unknown[] = [], pin: unknown = PIN, d = doc(def)) => decidePin({ pin, doc: d, verb: VERB, records, keys: KEYS, reapprovals, grant });

describe('actionPinError', () => {
  it('accepts a well formed pin and rejects every malformed member', () => {
    expect(actionPinError(PIN)).toBeNull();
    expect(actionPinError({ ...PIN, max_esc: 2, preauth_esc: 1, caveats: ['amount_cap'] })).toBeNull();
    const bad: unknown[] = [null, [], { ...PIN, extra: 1 }, { ...PIN, pack: { ns: 'Bad', root: dg('R') } }, { ...PIN, pack: { ns: 'acme', root: 'short' } }, { ...PIN, on_new_action: 'allow' }, { ...PIN, defs: { 'Bad Verb': A } },
      { ...PIN, defs: { [VERB]: 'x' } }, { ...PIN, max_esc: 4 }, { ...PIN, max_esc: 1, preauth_esc: 2 }, { ...PIN, caveats: ['nope'] }, { ...PIN, caveats: ['window', 'window'] }, { ...PIN, defs: [] }];
    for (const b of bad) expect(actionPinError(b), JSON.stringify(b)).not.toBeNull();
  });
});

describe('evolution records', () => {
  it('sign and verify; the class is part of the signed content; a foreign key or tamper is refused', () => {
    const r = rec(A, B, 'narrow');
    expect(verifyEvolutionRecord(r, KEYS)).toEqual({ ok: true });
    expect(verifyEvolutionRecord({ ...r, class: 'equal' }, KEYS).ok).toBe(false);
    expect(verifyEvolutionRecord({ ...r, to: C }, KEYS).ok).toBe(false);
    expect(verifyEvolutionRecord(rec(A, B, 'narrow', {}, other.secretKey), KEYS).ok).toBe(false);
    expect(verifyEvolutionRecord(r, []).ok).toBe(false);
  });
  it('endpoints must match the class, and the shape is closed', () => {
    expect(evolutionRecordError({ ...rec(A, B, 'narrow'), from: null })).toMatch(/endpoints/);
    expect(evolutionRecordError({ ...rec(null, B, 'added') })).toBeNull();
    expect(evolutionRecordError({ ...rec(A, null, 'removed') })).toBeNull();
    expect(evolutionRecordError({ ...rec(A, B, 'narrow'), extra: 1 })).toMatch(/unknown member/);
    expect(evolutionRecordError({ ...rec(A, B, 'narrow'), class: 'sideways' })).toMatch(/class/);
    expect(() => signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'acme', verb: VERB, from: A, to: B, class: 'added', reasons: [] }, 'r1', reg.secretKey)).toThrow(/endpoints/);
  });
});

describe('reapproval', () => {
  const r = rec(A, B, 'widen');
  it('is bound to the grant, the verb and the diff', () => {
    const a = signReapproval({ grantId: grant.id, record: r, principalSecret: principal.secretKey });
    const diff = evolutionDiffDigest(r);
    expect(reapprovalValid(a, grant.id, grant.issuer, VERB, diff)).toBe(true);
    expect(reapprovalValid(a, dg('X'), grant.issuer, VERB, diff)).toBe(false);
    expect(reapprovalValid(a, grant.id, grant.issuer, 'acme.other.do', diff)).toBe(false);
    expect(reapprovalValid(a, grant.id, grant.issuer, VERB, evolutionDiffDigest(rec(A, C, 'widen')))).toBe(false);
    expect(reapprovalValid(a, grant.id, Buffer.from(other.publicKey).toString('base64url'), VERB, diff)).toBe(false);
    expect(reapprovalValid({ ...a, extra: 1 }, grant.id, grant.issuer, VERB, diff)).toBe(false);
    expect(reapprovalValid(null, grant.id, grant.issuer, VERB, diff)).toBe(false);
  });
});

describe('decidePin', () => {
  it('the pinned digest passes', () => {
    expect(decide(A)).toEqual({ ok: true, via: 'exact' });
  });
  it('a different digest with no chain is def_changed', () => {
    expect(decide(B)).toMatchObject({ ok: false, code: 'def_changed' });
  });
  it('follows equal/narrow steps across several hops; a missing hop breaks the chain', () => {
    expect(decide(C, [rec(A, B, 'equal'), rec(B, C, 'narrow')])).toEqual({ ok: true, via: 'chain' });
    expect(decide(C, [rec(A, B, 'equal')])).toMatchObject({ ok: false, code: 'def_changed' });
  });
  it('a widen/incomparable step blocks the chain and names the diff to approve; the principal unblocks exactly that step', () => {
    for (const cls of ['widen', 'incomparable'] as const) {
      const r = rec(A, B, cls);
      const blocked = decide(B, [r]);
      expect(blocked).toMatchObject({ ok: false, code: 'def_changed', needs_reapproval: evolutionDiffDigest(r) });
      const a = signReapproval({ grantId: grant.id, record: r, principalSecret: principal.secretKey });
      expect(decide(B, [r], [a])).toEqual({ ok: true, via: 'chain' });
    }
  });
  it('an unblocked path is preferred over a blocked shortcut', () => {
    expect(decide(C, [rec(A, C, 'widen'), rec(A, B, 'narrow'), rec(B, C, 'equal')])).toEqual({ ok: true, via: 'chain' });
  });
  it('records that are unsigned, from another key, for another verb or namespace, or backwards never move the pin', () => {
    expect(decide(B, [rec(A, B, 'narrow', {}, other.secretKey)]).ok).toBe(false);
    expect(decide(B, [{ ...rec(A, B, 'narrow'), to: B, class: 'equal' }]).ok).toBe(false);
    expect(decide(B, [rec(A, B, 'narrow', { verb: 'acme.other.do' })]).ok).toBe(false);
    expect(decide(B, [rec(A, B, 'narrow', { ns: 'other' })]).ok).toBe(false);
    expect(decide(A, [rec(B, A, 'narrow')])).toEqual({ ok: true, via: 'exact' });
    expect(decide(B, [rec(B, A, 'narrow')]).ok).toBe(false);
    expect(decide(B, [rec(null, B, 'added')]).ok).toBe(false);
  });
  it('the chain is bounded and cycles terminate', () => {
    const ds = Array.from({ length: MAX_EVOLUTION_STEPS + 3 }, (_, i) => dg(String.fromCharCode(97 + (i % 26))) .replace(/^(.)(.*)$/, (_m, c, rest) => c + rest.slice(0, 40) + String(i).padStart(2, '0')));
    const recs = ds.slice(0, -1).map((d, i) => rec(i === 0 ? A : ds[i - 1]!, d, 'narrow'));
    expect(decide(ds[ds.length - 1]!, recs).ok).toBe(false);
    expect(decide(C, [rec(A, B, 'equal'), rec(B, A, 'equal')]).ok).toBe(false);
  });
  it('a verb the pin does not name follows on_new_action; pack-level pin needs the exact root', () => {
    const d = decidePin({ pin: { ...PIN, defs: { 'acme.x.y': A } }, doc: doc(A), verb: VERB, grant });
    expect(d).toMatchObject({ ok: false, code: 'new_action', escalate: false });
    expect(decidePin({ pin: { ...PIN, defs: { 'acme.x.y': A }, on_new_action: 'escalate' }, doc: doc(A), verb: VERB, grant })).toMatchObject({ ok: false, code: 'new_action', escalate: true });
    const packOnly = { pack: PIN.pack, on_new_action: 'deny' };
    expect(decide(A, [], [], packOnly)).toEqual({ ok: true, via: 'pack' });
    expect(decide(A, [], [], packOnly, doc(A, { ns: 'acme', root: dg('S') }))).toMatchObject({ ok: false, code: 'pack_mismatch' });
  });
  it('a schema from another namespace, an undeclared verb, a missing digest and a malformed pin are refused', () => {
    expect(decide(A, [], [], PIN, doc(A, { ns: 'other', root: dg('R') }))).toMatchObject({ ok: false, code: 'pack_mismatch' });
    expect(decide(A, [], [], PIN, doc(A, null))).toMatchObject({ ok: false, code: 'pack_mismatch' });
    expect(decidePin({ pin: PIN, doc: { pack: PIN.pack, verbs: [] }, verb: VERB, grant })).toMatchObject({ ok: false, code: 'unknown_verb' });
    expect(decide(undefined)).toMatchObject({ ok: false, code: 'def_changed' });
    expect(decide(A, [], [], { ...PIN, on_new_action: 'maybe' })).toMatchObject({ ok: false, code: 'bad_pin' });
    expect(decidePin({ pin: PIN, doc: null as never, verb: VERB, grant })).toMatchObject({ ok: false });
  });
});

describe('verifier context for rule 22 and pins', () => {
  it('rejects a malformed rule22 engine, call_context and actions evidence', () => {
    expect(intentV2ContextError({ rule22: {} })).toMatch(/rule22/);
    expect(intentV2ContextError({ rule22: { schemaError: () => null, decide: () => 'allow' } })).toBeNull();
    expect(intentV2ContextError({ call_context: 'fresh_revocation' })).toMatch(/call_context/);
    expect(intentV2ContextError({ call_context: [1] })).toMatch(/call_context/);
    expect(intentV2ContextError({ actions: [] })).toMatch(/actions/);
    expect(intentV2ContextError({ actions: { records: 'x' } })).toMatch(/actions.records/);
    expect(intentV2ContextError({ actions: { records: [], keys: [], reapprovals: [] } })).toBeNull();
  });
  it('reviewers (the pinned human-review keys) must be {keys: [...]} when present', () => {
    expect(intentV2ContextError({ reviewers: { keys: [] } })).toBeNull();
    expect(intentV2ContextError({ reviewers: { keys: [{ kid: 'r', pk: 'x', roles: ['reviewer'] }] } })).toBeNull();
    expect(intentV2ContextError({ reviewers: [] })).toMatch(/reviewers/);
    expect(intentV2ContextError({ reviewers: {} })).toMatch(/reviewers/);
    expect(intentV2ContextError({ reviewers: 'k' })).toMatch(/reviewers/);
  });
});

describe('the confirmation member of a v2 schema verb (shape only; rule 22 checks the signature)', () => {
  const good = { def_digest: 'Q'.repeat(43), traits_digest: 'A'.repeat(43), facts_digest: 'A'.repeat(43), final_traits: ['pca.irreversible', 'pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'one item' }], reviewer_kid: 'rev-1', ts: 1_700_000_000, sig: 'Q'.repeat(86) };
  it('accepts the exact shape and refuses every deviation', () => {
    expect(confirmationShapeError(good)).toBeNull();
    for (const bad of [null, 'x', [], { ...good, extra: 1 }, { ...good, sig: 'Q'.repeat(43) }, { ...good, def_digest: 'x' }, { ...good, traits_digest: '' }, { ...good, facts_digest: 'x' },
      { ...good, final_traits: ['pca.money_moving', 'pca.irreversible'] }, { ...good, final_traits: ['Bad Id'] }, { ...good, dismissed: {} }, { ...good, dismissed: [{ trait: 'pca.bulk', reason: '' }] },
      { ...good, dismissed: [{ trait: 'pca.bulk', reason: 'r', x: 1 }] }, { ...good, reviewer_kid: '' }, { ...good, ts: -1 }, { ...good, ts: 1.5 }, { ...good, ts: '1' }]) {
      expect(confirmationShapeError(bad), JSON.stringify(bad)).not.toBeNull();
    }
  });
});
